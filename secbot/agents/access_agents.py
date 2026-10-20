"""Pipeline 3 agen untuk review pembukaan akses:

1. **Assessment Agent** - memanggil tool :func:`~secbot.agents.access_tools.assess_connection`
   untuk menghasilkan data assessment (compliance, vulnerability, skor risiko).
2. **Policy Agent** - mengambil aturan yang relevan dari knowledge base (tool ``search_knowledge``).
3. **Reviewer Agent** - menyusun keputusan akhir + rekomendasi dari data assessment dan aturan.

Hasil tool diambil MENTAH dari riwayat pesan (bukan dari ringkasan LLM) supaya angka
yang dinilai tetap deterministik.
"""
import json

from langchain_core.messages import ToolMessage
from langgraph.prebuilt import create_react_agent

from ..llm import build_chat_model, message_text
from ..tools import search_knowledge
from .access_tools import assess_connection

ASSESS_PROMPT = """Kamu Assessment Agent. Tugasmu HANYA memanggil tool assess_connection satu kali
dengan src_ip, dst_ip, port, protocol dari permintaan, lalu menjawab 'Assessment selesai'.
Jangan menafsirkan atau mengubah hasil tool."""

POLICY_PROMPT = """Kamu Policy Agent. Tugasmu mengambil aturan dari knowledge base memakai tool search_knowledge.
Lakukan 2-3 pencarian berbeda: (1) syarat wajib pembukaan akses, (2) pedoman port yang diminta,
(3) aturan zona/segment yang relevan. Lalu rangkum aturan yang relevan sebagai daftar poin.
Sebutkan nama file sumber di tiap poin. JANGAN menambah aturan yang tidak ada di hasil pencarian."""

REVIEWER_PROMPT = """Kamu Access Reviewer untuk tim cybersecurity. Jawab dalam Bahasa Indonesia.
Kamu menerima (1) DATA ASSESSMENT (hasil hitung kode) dan (2) ATURAN dari knowledge.

ATURAN KERAS:
- Jangan mengarang data. Gunakan hanya angka dan fakta dari DATA ASSESSMENT dan ATURAN.
- Keputusanmu TIDAK BOLEH lebih longgar dari preliminary_decision. Urutan ketat -> longgar:
  DENY, REVIEW_REQUIRED, APPROVE_WITH_CONDITIONS, APPROVE.
- Jika DATA ASSESSMENT memuat conditions atau review_reasons, sebutkan sebagai syarat
  yang wajib dipenuhi; jangan menyatakan APPROVE tanpa memenuhinya.
- Jika asset_type adalah endpoint (segmen LAN), sebut sebagai PC/endpoint, jangan
    kategorikan sebagai server, dan jangan menilai environment endpoint sebagai environment
    server. Gunakan aturan workstation/LAN untuk arah aksesnya; aturan server S-1..S-4
    hanya berlaku jika kedua sisi adalah server.
- Rekomendasi harus konkret dan merujuk pada temuan (IP/hostname/CVE/port).

FORMAT JAWABAN:
1. Keputusan: <keputusan> | Risiko: <level> (skor)
2. Ringkasan singkat (2-3 kalimat)
3. Compliance (EDR/PAM/VA) source dan destination sesuai required_controls
4. Severity vulnerability source dan destination + SLA remediasi
5. Penilaian port, segmen, dan environment (sebutkan rule ID yang relevan)
6. Rekomendasi (daftar bernomor: perbaikan, modifikasi permintaan, alternatif yang lebih aman)
7. Referensi kebijakan (nama file knowledge + policy_refs)"""


def _llm():
    """Model chat untuk ketiga agen (provider mengikuti ``SECBOT_PROVIDER``)."""
    return build_chat_model()


def _run(agent, text: str) -> list:
    """Jalankan satu agen sampai selesai dan kembalikan seluruh riwayat pesannya."""
    return agent.invoke({"messages": [("user", text)]}, {"recursion_limit": 10})["messages"]


def _tool_json(messages: list, tool_name: str) -> dict | None:
    """Ambil output MENTAH sebuah tool dari riwayat pesan (bukan dari ringkasan LLM).

    Kembalikan ``None`` bila tool tersebut tidak dipanggil atau outputnya bukan JSON valid.
    """
    for m in reversed(messages):
        if isinstance(m, ToolMessage) and m.name == tool_name:
            try:
                return json.loads(m.content)
            except (TypeError, json.JSONDecodeError):
                return None
    return None


def review_access(
    src_ip: str,
    dst_ip: str,
    port: int,
    protocol: str = "tcp",
    verbose: bool = True,
    assessment: dict | None = None,
) -> str:
    """Jalankan ketiga agen dan kembalikan teks keputusan akhir.

    ``verbose=True`` mencetak progres tiap tahap ke stdout. Bila Assessment Agent tidak
    memanggil tool-nya, ``assess_connection`` dipanggil langsung agar hasil tetap deterministik.

    ``assessment`` boleh diisi hasil :func:`secbot.assessment.assess_connection_data`
    yang sudah dihitung pemanggil. Tahap Assessment Agent dilewati karena datanya
    identik, sehingga menghemat satu putaran LLM (dipakai UI web).
    """
    log = print if verbose else (lambda *a, **k: None)
    llm = _llm()
    policy_agent = create_react_agent(llm, [search_knowledge], prompt=POLICY_PROMPT)

    # Tahap 1: data assessment
    if assessment is None:
        assess_agent = create_react_agent(llm, [assess_connection], prompt=ASSESS_PROMPT)
        log("[1/3] Assessment Agent: mengumpulkan data compliance, vuln, risiko...")
        msgs = _run(assess_agent, f"Nilai akses: source {src_ip}, destination {dst_ip}, port {port}, protocol {protocol}")
        data = _tool_json(msgs, "assess_connection")
        if data is None:  # agen tidak memanggil tool -> panggil langsung agar tetap deterministik
            log("      (agen tidak memanggil tool, memanggil langsung)")
            data = assess_connection.invoke(
                {"src_ip": src_ip, "dst_ip": dst_ip, "port": port, "protocol": protocol}
            )
    else:
        log("[1/3] Assessment Agent: memakai hasil deterministik...")
        data = assessment
    if "error" in data:
        return f"Permintaan tidak dapat dinilai: {data['error']}"

    # Tahap 2: aturan dari knowledge (query diperkaya konteks hasil assessment)
    log("[2/3] Policy Agent: mengambil aturan dari knowledge...")
    s, d = data["source"], data["destination"]
    policy_context = {
        "source": {
            "asset_type": s.get("asset_type", "unknown"),
            "environment": s.get("environment"),
            "segment": s.get("segment"),
            "ip_category": s.get("ip_category"),
            "required_controls": s.get("required_controls", []),
        },
        "destination": {
            "asset_type": d.get("asset_type", "unknown"),
            "environment": d.get("environment"),
            "segment": d.get("segment"),
            "ip_category": d.get("ip_category"),
            "required_controls": d.get("required_controls", []),
        },
        "port_info": {
            "port": port,
            "protocol": protocol,
            "service": data["port_info"].get("service"),
            "level": data["port_info"].get("level"),
            "rule": data["port_info"].get("rule"),
        },
        "conditions": data.get("conditions", []),
        "review_reasons": data.get("review_reasons", []),
        "policy_refs": data.get("policy_refs", []),
    }
    q = ("Cari aturan pembukaan akses berdasarkan DATA ASSESSMENT STAGE 1 berikut. "
            "Jika salah satu sisi asset_type endpoint/segmen LAN, gunakan aturan LAN/workstation "
            "untuk arah tersebut dan abaikan environment endpoint; jangan terapkan aturan server S-1..S-4. "
            "Gunakan environment hanya untuk sisi server saat aturan LAN membedakan tujuan produksi/non-produksi. "
            "Jika kedua sisi server, gunakan environment source dan destination untuk aturan lintas environment; "
            "sebutkan secara spesifik rule yang cocok dan jangan sajikan rule untuk pasangan lain "
            "sebagai aturan yang berlaku. "
         "pertahankan klasifikasi port dan rule yang sudah diberikan, jangan menebaknya ulang. "
         "Cari syarat wajib server, pedoman port, aturan zona, dan dampak vulnerability. "
         "Prioritaskan policy_refs yang tercantum dan sebutkan nama file sumber tiap aturan.\n"
         f"{json.dumps(policy_context, ensure_ascii=False, indent=2)}")
    policy_text = message_text(_run(policy_agent, q)[-1])

    # Tahap 3: penilaian dan rekomendasi
    log("[3/3] Reviewer Agent: menyusun penilaian dan rekomendasi...\n")
    user_msg = (f"DATA ASSESSMENT:\n{json.dumps(data, ensure_ascii=False, indent=1)}\n\n"
                f"ATURAN DARI KNOWLEDGE:\n{policy_text}")
    return message_text(llm.invoke([("system", REVIEWER_PROMPT), ("user", user_msg)]))
