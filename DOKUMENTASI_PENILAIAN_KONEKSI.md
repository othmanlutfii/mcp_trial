# Dokumentasi Lengkap — Penilaian Koneksi dari IP ke IP

Dokumen ini menelusuri **satu permintaan nyata** dari input pengguna sampai jawaban akhir,
dengan menunjukkan input dan output setiap fungsi yang dilewati.

Contoh dijalankan pada kode saat ini (20 Oktober 2026) memakai data asli:

- `data/assets.json` — data CMDB
- `data/vulns.json` — hasil scan VA
- `knowledge/*.md` — dokumen kebijakan untuk RAG
- `secbot/policies.py` — aturan deterministik yang mencerminkan dokumen knowledge

> **Prinsip utama:** semua angka, gate, skor, dan keputusan awal dihitung kode deterministik.
> LLM hanya (1) memilih dan memanggil tool, (2) merangkum aturan knowledge, dan
> (3) menulis narasi keputusan.

### File yang terlibat

| File | Peran |
|---|---|
| `main.py` | entry point CLI |
| `app.py` | entry point web UI |
| `secbot/graph.py` | LangGraph supervisor + CLI |
| `secbot/router.py` | ekstraksi IP/port + penentuan rute |
| `secbot/assessment.py` | mesin penilaian deterministik |
| `secbot/policies.py` | aturan deterministik (COMP/PORT/NET/ENV/SLA) |
| `secbot/agents/access_agents.py` | orkestrasi Assessment → Policy → Reviewer |
| `secbot/agents/access_tools.py` | tool `assess_connection` |
| `secbot/tools.py` | tool `search_knowledge` dan 5 tool chat |
| `secbot/knowledge.py` | akses Chroma + embedding |
| `secbot/llm.py` | pabrik model + normalisasi output |
| `knowledge/*.md` | sumber aturan untuk RAG |
| `data/assets.json` | data CMDB |
| `data/vulns.json` | data hasil VA |

### Daftar isi

1. [Contoh kasus](#1-contoh-kasus)
2. [Peta alur end-to-end](#2-peta-alur-end-to-end)
3. [Entry point dan grafik](#3-step-0--entry-point-dan-grafik)
4. [Router](#4-step-1--router)
5. [Node access_review](#5-step-2--node-access_review)
6. [Stage 1 — Assessment](#6-step-3--stage-1-assessment-agent--assess_connection_data)
7. [Stage 2 — Policy Agent](#7-step-4--stage-2-policy-agent)
8. [Stage 3 — Reviewer](#8-step-5--stage-3-reviewer)
9. [Kembali ke CLI/UI](#9-step-6--jawaban-kembali-ke-cli--ui)
10. [Ringkasan input/output fungsi](#10-ringkasan-inputoutput-setiap-fungsi)
11. [Contoh kasus lain](#11-contoh-hasil-kasus-lain)
12. [Troubleshooting](#12-troubleshooting-dan-batasan)

---

## 1. Contoh kasus

### Input pengguna

```text
Buka akses dari 192.168.5.22 ke 10.45.56.143 port 443
```

### Hasil akhir

```text
Keputusan : APPROVE_WITH_CONDITIONS
Risiko    : MEDIUM (skor 30)
Syarat    : P-2 — HTTPS sebagai target redirect HTTP; PROD wajib SSL
```

Pada run dokumentasi ini, total waktu proses ± **181 detik** (3 agen, 3 pencarian RAG,
dan satu panggilan Reviewer). Durasi bergantung pada provider/model dan bisa berbeda
setiap run.

### Data asli source — `192.168.5.22`

```json
{
  "asset_id": "A006",
  "ip": "192.168.5.22",
  "hostname": "srv-core-app02",
  "application": "Core Banking",
  "environment": "PROD",
  "segment": "Server Farm",
  "dc": "DC-JKT",
  "edr": true,
  "pam": true,
  "va": true,
  "operating_system": "Ubuntu 22.04",
  "ip_category": "data"
}
```

Hasil VA source:

```json
{
  "id": 5,
  "ip": "192.168.5.22",
  "dnsName": "srv-core-app02.corp.local",
  "operatingSystem": "Ubuntu 22.04",
  "severity": "Low",
  "score": 3.1,
  "lastSeen": "2026-10-10",
  "vulnerabilities": [
    {
      "cve": "CVE-2023-5678",
      "name": "OpenSSL DH excessive time",
      "severity": "Low",
      "cvss": 3.1,
      "solution": "Perbarui OpenSSL melalui repositori resmi dan verifikasi versi paket yang terpasang"
    }
  ]
}
```

### Data asli destination — `10.45.56.143`

```json
{
  "asset_id": "A056",
  "ip": "10.45.56.143",
  "hostname": "srv-api-dmz06",
  "application": "API Management",
  "environment": "PROD",
  "segment": "DMZ",
  "dc": "DC-BDG",
  "edr": true,
  "pam": true,
  "va": true,
  "operating_system": "Windows Server 2016",
  "ip_category": "IP Data"
}
```

Hasil VA destination: **tidak ada record** di `data/vulns.json` (`null`).
Artinya server terdaftar di CMDB dan agen VA aktif, tetapi **belum ada data hasil scan**.

---

## 2. Peta alur end-to-end

### Jalur CLI

```text
main.py
  └─ secbot.graph.main()
       ├─ build_graph()
       │    ├─ build_chat_model()
       │    └─ StateGraph(router, chat, access_review) + MemorySaver
       └─ run_once(graph, cfg, pertanyaan)
            └─ graph.stream(...)
                 ├─ router_node()
                 │    └─ router.decide()
                 │         ├─ resolve_request()
                 │         ├─ extract_request()
                 │         ├─ extract_ips()
                 │         ├─ is_complete()
                 │         └─ has_access_intent()
                 └─ access_review_node()
                      └─ review_access(assessment=None)
                           ├─ Stage 1: Assessment Agent (ReAct)
                           │    └─ tool assess_connection
                           │         └─ assess_connection_data()
                           ├─ Stage 2: Policy Agent (ReAct)
                           │    └─ tool search_knowledge
                           │         └─ knowledge.search_documents()
                           │              └─ Chroma
                           └─ Stage 3: Reviewer (llm.invoke langsung)
                                └─ string jawaban
```

### Jalur Web UI (`/`)

```text
app.py: POST /
  ├─ assess_connection_data()          # deterministik, dihitung dulu
  └─ _run_ai_review()
       └─ review_access(assessment=result)
            ├─ Stage 1 DILEWATI          # data sudah identik
            ├─ Stage 2: Policy Agent
            └─ Stage 3: Reviewer
```

Contoh pada dokumen ini mengikuti **urutan jalur web**: `assess_connection_data()` dihitung
lebih dulu, lalu Stage 2 dan Stage 3 dijalankan dengan komponen yang sama seperti
`review_access(assessment=...)`. Di CLI, satu-satunya perbedaan adalah adanya pembungkus
**Assessment Agent** di depan; tool-nya memanggil fungsi deterministik yang sama, sehingga
`data` assessment normalnya identik.

---

## 3. Step 0 — Entry point dan grafik

### 3.1 `main.py`

Hanya meneruskan ke grafik:

```python
from secbot.graph import main

if __name__ == "__main__":
    main()
```

| Item | Nilai |
|---|---|
| Input | `python main.py "Buka akses dari 192.168.5.22 ke 10.45.56.143 port 443"` |
| Output | Teks jawaban di stdout |

### 3.2 `secbot.graph.main()`

Lokasi: `secbot/graph.py`.

Langkah:

1. `build_graph()` — membangun LLM + StateGraph + `MemorySaver`.
2. `cfg = {"configurable": {"thread_id": "sesi-1"}}` — identitas memori percakapan.
3. Mode argumen → `run_once(graph, cfg, " ".join(sys.argv[1:]))`.

| Item | Nilai |
|---|---|
| Input | Argumen CLI / input interaktif |
| Output | `run_once()` atau loop interaktif |

### 3.3 `secbot.graph.build_graph(verbose=True)`

```python
llm = build_chat_model()
graph = StateGraph(BotState)
graph.add_node("router", make_router_node(llm, verbose))
graph.add_node("chat", build_agent(llm))
graph.add_node("access_review", make_access_review_node(verbose))

graph.add_edge(START, "router")
graph.add_conditional_edges(
    "router",
    lambda state: state["route"],
    {"chat": "chat", "access_review": "access_review"},
)
graph.add_edge("chat", END)
graph.add_edge("access_review", END)
return graph.compile(checkpointer=MemorySaver())
```

| Item | Nilai |
|---|---|
| Input | `verbose: bool` |
| Output | Compiled LangGraph dengan checkpointer `MemorySaver` |
| State | `BotState`: `messages`, `route`, `request`, `pending_request` |

### 3.4 `secbot.graph.run_once(graph, cfg, question)`

```python
for step in graph.stream({"messages": [("user", question)]}, cfg, stream_mode="updates"):
    ...
answer = _final_answer(graph, cfg)
print(f"\nBot > {answer}\n")
return answer
```

| Item | Nilai |
|---|---|
| Input | `graph`, `cfg`, `question = "Buka akses ..."` |
| Output | String jawaban akhir |
| Efek samping | Mencetak `[tool] ...` dan `Bot > ...` |

### 3.5 `secbot.graph._final_answer(graph, cfg)`

Mengambil pesan AI terakhir yang **tidak punya tool_calls** dan teksnya tidak kosong.

| Item | Nilai |
|---|---|
| Input | `graph`, `cfg` |
| Output | String jawaban akhir |

---

## 4. Step 1 — Router

### 4.1 `make_router_node()` → `router_node(state)`

```python
text = _last_user_text(state)
pending = state.get("pending_request") or {}
route, request = router_mod.decide(text, pending, llm)
return {"route": route, "request": request, ...}
```

| Item | Nilai pada contoh |
|---|---|
| Input | `state["messages"]` berisi pesan user |
| `text` | `"Buka akses dari 192.168.5.22 ke 10.45.56.143 port 443"` |
| `pending` | `{}` |
| Output | `{"route": "access_review", "request": {...}}` |

### 4.2 `secbot.router.decide(text, pending, llm)`

Urutan keputusan:

1. `resolve_request(text, pending)` — ekstrak IP/port/protocol.
2. `is_complete(request)` — source + destination + port terisi?
3. `has_access_intent(text)` — ada kata kunci akses?
4. `_classify_with_llm(text, llm)` — cadangan terakhir.

Pada contoh, langkah 1 sudah lengkap sehingga **LLM tidak dipanggil**.

### 4.3 `resolve_request(text, pending)`

Memanggil `extract_request(text)`, lalu menggabungkan dengan `pending` bila ada.

| Item | Nilai |
|---|---|
| Input | `text`, `pending = {}` |
| Output | `{"src_ip": "192.168.5.22", "dst_ip": "10.45.56.143", "port": 443, "protocol": "tcp"}` |

### 4.4 `extract_request(text)`

| Item | Nilai |
|---|---|
| Input | Kalimat user |
| `extract_ips()` | `["192.168.5.22", "10.45.56.143"]` |
| Regex port | `443` |
| Protocol | `tcp` (default) |
| Output | `{"src_ip": ..., "dst_ip": ..., "port": 443, "protocol": "tcp"}` |

### 4.5 `is_complete(request)`

```python
return all(request.get(f) for f in ("src_ip", "dst_ip", "port"))
```

| Item | Nilai |
|---|---|
| Input | Request di atas |
| Output | `True` |

### 4.6 `has_access_intent(text)` dan `_classify_with_llm()`

Tidak dipakai pada contoh karena `is_complete()` sudah `True`.

| Fungsi | Input | Output | Kapan dipakai |
|---|---|---|---|
| `has_access_intent` | Teks user | `bool` | Jika request belum lengkap |
| `_classify_with_llm` | Teks + LLM | `"chat"` / `"access_review"` | Jika bukan request lengkap dan tidak ada kata kunci akses |

### 4.7 `clarification_message(request)`

Tidak dipakai pada contoh. Dipakai bila `is_complete()` false:

```text
Permintaan ini terlihat seperti review pembukaan akses, tetapi datanya belum lengkap.
Mohon lengkapi: **port**.
```

---

## 5. Step 2 — Node `access_review`

### 5.1 `make_access_review_node()` → `access_review_node(state)`

```python
request = state.get("request") or {}
if not router_mod.is_complete(request):
    return {
        "messages": [AIMessage(content=router_mod.clarification_message(request))],
        "pending_request": request,
    }
jawaban = review_access(
    request["src_ip"], request["dst_ip"], int(request["port"]),
    request.get("protocol") or "tcp", verbose=verbose,
)
return {"messages": [AIMessage(content=jawaban)], "pending_request": {}}
```

| Item | Nilai |
|---|---|
| Input | `state["request"]` |
| Output | `{"messages": [AIMessage(jawaban)], "pending_request": {}}` |
| Jika tidak lengkap | `clarification_message` + `pending_request` dipertahankan |

### 5.2 `review_access(...)` — pintu masuk tiga agen

Lokasi: `secbot/agents/access_agents.py`.

```python
def review_access(
    src_ip, dst_ip, port, protocol="tcp",
    verbose=True, assessment=None,
) -> str:
```

| Item | Nilai pada contoh |
|---|---|
| `src_ip` | `192.168.5.22` |
| `dst_ip` | `10.45.56.143` |
| `port` | `443` |
| `protocol` | `tcp` |
| `assessment` | `None` (CLI) atau hasil deterministik (web) |
| Output | String jawaban akhir |

Di dalamnya:

```python
llm = _llm()
policy_agent = create_react_agent(llm, [search_knowledge], prompt=POLICY_PROMPT)
```

- `_llm()` → `build_chat_model()` sesuai `SECBOT_PROVIDER`.
- Policy Agent adalah ReAct agent dengan satu tool: `search_knowledge`.

---

## 6. Step 3 — Stage 1: Assessment Agent + `assess_connection_data`

### 6.1 Assessment Agent (ReAct, hanya di CLI)

```python
assess_agent = create_react_agent(llm, [assess_connection], prompt=ASSESS_PROMPT)
msgs = _run(
    assess_agent,
    f"Nilai akses: source {src_ip}, destination {dst_ip}, port {port}, protocol {protocol}",
)
data = _tool_json(msgs, "assess_connection")
```

`ASSESS_PROMPT` memerintahkan agent **hanya memanggil tool satu kali** dan tidak menafsirkan
hasilnya.

Tool call yang diharapkan:

```json
{
  "name": "assess_connection",
  "args": {
    "src_ip": "192.168.5.22",
    "dst_ip": "10.45.56.143",
    "port": 443,
    "protocol": "tcp"
  }
}
```

Jika agent tidak memanggil tool, kode memanggil langsung:

```python
data = assess_connection.invoke({"src_ip": ..., "dst_ip": ..., "port": ..., "protocol": ...})
```

Di web UI, Stage 1 dilewati karena `app.py` sudah menghitung `assess_connection_data()`.

### 6.2 Tool `assess_connection`

Lokasi: `secbot/agents/access_tools.py`.

```python
@tool
def assess_connection(src_ip, dst_ip, port, protocol="tcp") -> dict:
    return assess_connection_data(src_ip, dst_ip, port, protocol)
```

| Item | Nilai |
|---|---|
| Input | 2 IP, port, protocol |
| Output | Dict assessment lengkap |

### 6.3 `assess_connection_data(src_ip, dst_ip, port, protocol)`

Lokasi: `secbot/assessment.py`.

Urutan kerjanya:

#### (a) Validasi input

| Validasi | Hasil pada contoh |
|---|---|
| Format IP | valid |
| Port 1–65535 | valid (443) |
| Protocol `tcp`/`udp` | valid (tcp) |

Jika salah → return `{"error": "..."}` dan pipeline berhenti.

#### (b) `_side(ip)` — profil source

`_side("192.168.5.22")`:

1. `datasource.find_asset(ip)` → asset dari `data/assets.json`.
2. `policies.required_controls("PROD", "Server Farm")` → `["edr", "pam", "va"]`.
3. Cek kontrol: `edr=True`, `pam=True`, `va=True` → `missing=[]`, `gate="PASS"`.
4. `_vuln_summary(ip)` → baca `data/vulns.json`:
   - `scanned=True`
   - `counts={"Low": 1}`
   - `top=[CVE-2023-5678]`
5. Output `side`:

```json
{
  "ip": "192.168.5.22",
  "registered": true,
  "hostname": "srv-core-app02",
  "application": "Core Banking",
  "environment": "PROD",
  "segment": "Server Farm",
  "dc": "DC-JKT",
  "ip_category": "data",
  "operating_system": "Ubuntu 22.04",
  "zone": "data",
  "edr": true,
  "pam": true,
  "va": true,
  "required_controls": ["EDR", "PAM", "VA"],
  "gate": "PASS",
  "gate_missing": [],
  "vuln": { "scanned": true, "counts": {"Low": 1}, "top": [...] },
  "sla": null
}
```

#### (c) `_side(ip)` — profil destination

`_side("10.45.56.143")`:

1. `find_asset` → asset DMZ.
2. `required_controls("PROD", "DMZ")` → `["edr", "pam", "va"]`.
3. Kontrol aktif semua → `gate="PASS"`.
4. `_vuln_summary` → **tidak ada record VA**:
   - `scanned=False`
   - `counts={}`
   - `top=[]`
5. Output `side` dengan `vuln.scanned=false`.

#### (d) Klasifikasi port

```python
port_info = policies.classify_port(443)
```

Output:

```json
{
  "service": "HTTPS",
  "level": "RESTRICTED",
  "rule": "P-2",
  "note": "HTTPS sebagai target redirect HTTP; PROD wajib SSL"
}
```

Karena `RESTRICTED`:

```python
conditional(
    20,
    "Port 443/tcp (HTTPS) terbatas: HTTPS sebagai target redirect HTTP; PROD wajib SSL",
    "P-2",
    "HTTPS sebagai target redirect HTTP; PROD wajib SSL",
)
```

Efek: `score += 20`, `conditions += ["P-2: ..."]`.

#### (e) Pemeriksaan RDP

Port 443 bukan 3389/103389 → tidak ada `review_reason` RDP.

#### (f) Aturan segmen `NET.md`

```python
seg = policies.segment_rule(
    "Server Farm", "data", "PROD",
    "DMZ", "IP Data", "PROD",
    443,
)
```

Proses:

- `segment_kind("Server Farm")` → `server-farm`
- `segment_kind("DMZ")` → `dmz`
- `zone_kind("data")` → `data`
- `zone_kind("IP Data")` → `data`
- `_server_segment_rule(server-farm, data, dmz, data, 443)`:
  - source data → destination data
  - 443 bukan management port
  - hasil: `ALLOW`, rule `SS-7/SS-9`

Output:

```json
{
  "level": "ALLOW",
  "rule": "SS-7/SS-9",
  "points": 0,
  "note": "non-management port Server Farm -> DMZ Data/VS"
}
```

Tidak ada skor tambahan; findings mendapat `[info] ... (SS-7/SS-9)`.

#### (g) Aturan environment `ENV.md`

```python
env = policies.environment_rule("PROD", "PROD")
```

Output:

```json
{"level": "ALLOW", "rule": "ENV", "points": 0, "note": "sesama environment PROD"}
```

Tidak ada dokumen lintas environment karena PROD → PROD.

#### (h) Vulnerability + SLA

Destination:

- `scanned=False` → `add(10, "Destination ... belum memiliki data VA", "VA")`
- `score += 10`

Source:

- `_highest(source)` → `"Low"`
- `policies.sla_for("Low", "PROD", public_facing=False)`:

```json
{
  "severity": "Low",
  "environment": "PROD",
  "days": 90,
  "priority": 4,
  "public_facing": false
}
```

- `add(0, "Source ... SLA remediasi Low PROD 90 hari (prioritas 4)", "SLA")`
- `"Low"` tidak ada di bobot source (`Critical/High`) → tidak ada skor tambahan.

#### (i) Skor dan keputusan

```text
score = 20 (port) + 10 (VA destination) = 30
risk  = MEDIUM (30 <= score < 60)
blocks = []
review_reasons = []
conditions = ["P-2: ..."]
```

Keputusan:

```text
if blocks: DENY
elif review_reasons or score >= 60: REVIEW_REQUIRED
elif score >= 30 or dst_critical or conditions: APPROVE_WITH_CONDITIONS
else: APPROVE
```

Hasil: **`APPROVE_WITH_CONDITIONS`**.

### 6.4 Output lengkap `assess_connection_data`

```json
{
  "request": {
    "src_ip": "192.168.5.22",
    "dst_ip": "10.45.56.143",
    "port": 443,
    "protocol": "tcp"
  },
  "port_info": {
    "service": "HTTPS",
    "level": "RESTRICTED",
    "rule": "P-2",
    "note": "HTTPS sebagai target redirect HTTP; PROD wajib SSL"
  },
  "source": {
    "ip": "192.168.5.22",
    "registered": true,
    "hostname": "srv-core-app02",
    "application": "Core Banking",
    "environment": "PROD",
    "segment": "Server Farm",
    "dc": "DC-JKT",
    "ip_category": "data",
    "operating_system": "Ubuntu 22.04",
    "zone": "data",
    "edr": true,
    "pam": true,
    "va": true,
    "required_controls": ["EDR", "PAM", "VA"],
    "gate": "PASS",
    "gate_missing": [],
    "vuln": {
      "scanned": true,
      "counts": {"Low": 1},
      "top": [
        {
          "cve": "CVE-2023-5678",
          "name": "OpenSSL DH excessive time",
          "severity": "Low",
          "cvss": 3.1,
          "solution": "Perbarui OpenSSL melalui repositori resmi dan verifikasi versi paket yang terpasang"
        }
      ]
    },
    "sla": {
      "severity": "Low",
      "environment": "PROD",
      "days": 90,
      "priority": 4,
      "public_facing": false
    }
  },
  "destination": {
    "ip": "10.45.56.143",
    "registered": true,
    "hostname": "srv-api-dmz06",
    "application": "API Management",
    "environment": "PROD",
    "segment": "DMZ",
    "dc": "DC-BDG",
    "ip_category": "IP Data",
    "operating_system": "Windows Server 2016",
    "zone": "data",
    "edr": true,
    "pam": true,
    "va": true,
    "required_controls": ["EDR", "PAM", "VA"],
    "gate": "PASS",
    "gate_missing": [],
    "vuln": {
      "scanned": false,
      "counts": {},
      "top": []
    },
    "sla": null
  },
  "findings": [
    "[info] Source srv-core-app02 memenuhi kontrol wajib (EDR, PAM, VA) (C-7)",
    "[info] Destination srv-api-dmz06 memenuhi kontrol wajib (EDR, PAM, VA) (C-7)",
    "[+20] Port 443/tcp (HTTPS) terbatas: HTTPS sebagai target redirect HTTP; PROD wajib SSL (P-2)",
    "[info] Segmen Server Farm → DMZ sesuai aturan (SS-7/SS-9)",
    "[info] Environment PROD → PROD sesuai aturan (ENV)",
    "[+10] Destination srv-api-dmz06 belum memiliki data VA (VA)",
    "[info] Source srv-core-app02 SLA remediasi Low PROD 90 hari (prioritas 4) (SLA)"
  ],
  "hard_blocks": [],
  "conditions": [
    "P-2: HTTPS sebagai target redirect HTTP; PROD wajib SSL"
  ],
  "review_reasons": [],
  "policy_refs": ["C-7", "ENV", "P-2", "SLA", "SS-7/SS-9", "VA"],
  "risk_score": 30,
  "risk_level": "MEDIUM",
  "preliminary_decision": "APPROVE_WITH_CONDITIONS"
}
```

### 6.5 `_tool_json(messages, "assess_connection")`

| Item | Nilai |
|---|---|
| Input | Riwayat pesan Assessment Agent |
| Proses | Cari `ToolMessage` terakhir dengan `name == "assess_connection"`, lalu `json.loads(content)` |
| Output | Dict assessment di atas |
| Jika gagal | `None` → kode memanggil `assess_connection.invoke(...)` langsung |

---

## 7. Step 4 — Stage 2: Policy Agent

### 7.1 Input yang dibangun

Lokasi: `secbot/agents/access_agents.py`, bagian `policy_context`.

```python
policy_context = {
    "source": {
        "environment": s.get("environment", "UNKNOWN"),
        "segment": s.get("segment"),
        "ip_category": s.get("ip_category"),
        "required_controls": s.get("required_controls", []),
    },
    "destination": {
        "environment": d.get("environment", "UNKNOWN"),
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
```

Nilai nyata:

```json
{
  "source": {
    "environment": "PROD",
    "segment": "Server Farm",
    "ip_category": "data",
    "required_controls": ["EDR", "PAM", "VA"]
  },
  "destination": {
    "environment": "PROD",
    "segment": "DMZ",
    "ip_category": "IP Data",
    "required_controls": ["EDR", "PAM", "VA"]
  },
  "port_info": {
    "port": 443,
    "protocol": "tcp",
    "service": "HTTPS",
    "level": "RESTRICTED",
    "rule": "P-2"
  },
  "conditions": ["P-2: HTTPS sebagai target redirect HTTP; PROD wajib SSL"],
  "review_reasons": [],
  "policy_refs": ["C-7", "ENV", "P-2", "SLA", "SS-7/SS-9", "VA"]
}
```

### 7.2 Query yang dikirim ke agent

```text
Cari aturan pembukaan akses berdasarkan DATA ASSESSMENT STAGE 1 berikut. Gunakan
environment source dan destination untuk menentukan aturan lintas environment;
sebutkan secara spesifik rule yang cocok dan jangan sajikan rule untuk pasangan lain
sebagai aturan yang berlaku. pertahankan klasifikasi port dan rule yang sudah diberikan,
jangan menebaknya ulang. Cari syarat wajib server, pedoman port, aturan zona, dan dampak
vulnerability. Prioritaskan policy_refs yang tercantum dan sebutkan nama file sumber tiap aturan.
<JSON policy_context>
```

### 7.3 Agent dan tool

```python
policy_agent = create_react_agent(llm, [search_knowledge], prompt=POLICY_PROMPT)
msgs = _run(policy_agent, q)
policy_text = message_text(msgs[-1])
```

`POLICY_PROMPT` meminta 2–3 pencarian berbeda:

1. Syarat wajib pembukaan akses.
2. Pedoman port yang diminta.
3. Aturan zona/segmen yang relevan.

Pada contoh, agent melakukan **3 tool call**:

```json
[
  {"name": "search_knowledge", "args": {"query": "syarat wajib pembukaan akses server PROD DMZ"}},
  {"name": "search_knowledge", "args": {"query": "pedoman port 443 HTTPS RESTRICTED P-2"}},
  {"name": "search_knowledge", "args": {"query": "aturan zona Server Farm DMZ policy_refs"}}
]
```

### 7.4 Di dalam `search_knowledge`

Lokasi: `secbot/tools.py` dan `secbot/knowledge.py`.

```python
@tool
def search_knowledge(query: str) -> list[dict]:
    return knowledge_lookup(query)


def knowledge_lookup(query: str) -> list[dict]:
    masalah = knowledge.index_problem()
    if masalah:
        return [{"error": masalah}]
    return knowledge.search_documents(query)
```

`knowledge.index_problem()`:

| Cek | Hasil pada contoh |
|---|---|
| `vectordb/` ada? | ya |
| `embedding.json` cocok dengan provider/model aktif? | ya |
| Output | `None` (tidak ada masalah) |

`knowledge.search_documents(query, k=3)`:

1. `get_vectorstore()` — buka Chroma sekali, thread-safe.
2. `get_embeddings()` — model embedding aktif.
3. `similarity_search(query, k=3)`.
4. Output: daftar `{"sumber": "PORT.md", "bagian": "...", "isi": "..."}`.
5. Hasil di-cache dengan `lru_cache(maxsize=128)`.

### 7.5 Output Stage 2 — `policy_text`

```text
Berikut adalah rangkuman aturan pembukaan akses berdasarkan DATA ASSESSMENT STAGE 1 dan
policy_refs yang diminta:

1. Syarat Wajib Server & Kontrol:
   - Berdasarkan environment PROD di Server Farm dan DMZ, server tidak mendapat
     pengecualian kontrol dan tetap wajib memiliki EDR, PAM, dan VA (Sumber: COMP.md).

2. Pedoman Port & Rule P-2:
   - Berdasarkan Rule P-2, HTTP (port 80 atau custom) diblokir secara default
     (default deny), dapat dibuka dengan exception form, dan wajib direarahkan ke HTTPS.
     Environment PROD wajib menggunakan SSL (Sumber: PORT.md).
   - Port yang diminta (443 / TCP / HTTPS dengan level RESTRICTED) merupakan port aman
     yang diperbolehkan sesuai ketentuan layanan target (Sumber: PORT.md & NET.md).

3. Aturan Zona & Lintas Environment (Server Farm ke DMZ):
   - Berdasarkan Rule SS-7 / Rule SS-9, akses dari IP Data/VS - Server Farm ke
     IP Data/VS - DMZ dapat dibuka untuk kebutuhan port spesifik non-manajemen
     (di luar port 22, 3389, 445, 7001-7002) (Sumber: NET.md).
   - Berdasarkan ketentuan environment PROD ke PROD, tidak ada dokumen tambahan khusus
     lintas environment yang dipersyaratkan (Sumber: ENV.md).

4. Referensi Kebijakan Terkait (policy_refs):
   - C-7 / COMP.md (Kepatuhan dan Kontrol Aset)
   - ENV.md (Aturan Lintas Environment, Rule S-1 s.d S-4)
   - P-2 / PORT.md (Aturan Port HTTP/HTTPS dan SSL wajib untuk PROD)
   - SLA / SS-7/SS-9 / NET.md (Aturan Segmen Jaringan Server Farm Data ke DMZ Data)
   - VA (Kewajiban Vulnerability Assessment untuk environment PROD)
```

**Penting:** Stage 2 **tidak** membaca `secbot/policies.py`. Ia membaca dokumen
`knowledge/*.md` lewat Chroma. `policies.py` dipakai Stage 1 dan `compliance.py`.

---

## 8. Step 5 — Stage 3: Reviewer

### 8.1 Input

Lokasi: `secbot/agents/access_agents.py`.

```python
user_msg = (
    f"DATA ASSESSMENT:\n{json.dumps(data, ensure_ascii=False, indent=1)}\n\n"
    f"ATURAN DARI KNOWLEDGE:\n{policy_text}"
)
return message_text(llm.invoke([
    ("system", REVIEWER_PROMPT),
    ("user", user_msg),
]))
```

Input terdiri dari:

1. **System prompt `REVIEWER_PROMPT`**:

```text
Kamu Access Reviewer untuk tim cybersecurity. Jawab dalam Bahasa Indonesia.
Kamu menerima (1) DATA ASSESSMENT (hasil hitung kode) dan (2) ATURAN dari knowledge.

ATURAN KERAS:
- Jangan mengarang data. Gunakan hanya angka dan fakta dari DATA ASSESSMENT dan ATURAN.
- Keputusanmu TIDAK BOLEH lebih longgar dari preliminary_decision. Urutan ketat -> longgar:
  DENY, REVIEW_REQUIRED, APPROVE_WITH_CONDITIONS, APPROVE.
- Jika DATA ASSESSMENT memuat conditions atau review_reasons, sebutkan sebagai syarat
  yang wajib dipenuhi; jangan menyatakan APPROVE tanpa memenuhinya.
- Rekomendasi harus konkret dan merujuk pada temuan (IP/hostname/CVE/port).

FORMAT JAWABAN:
1. Keputusan: <keputusan> | Risiko: <level> (skor)
2. Ringkasan singkat (2-3 kalimat)
3. Compliance (EDR/PAM/VA) source dan destination sesuai required_controls
4. Severity vulnerability source dan destination + SLA remediasi
5. Penilaian port, segmen, dan environment (sebutkan rule ID yang relevan)
6. Rekomendasi (daftar bernomor: perbaikan, modifikasi permintaan, alternatif yang lebih aman)
7. Referensi kebijakan (nama file knowledge + policy_refs)
```

2. **User message** = `"DATA ASSESSMENT:\n"` + JSON lengkap dari Bagian 6.4 +
   `"\n\nATURAN DARI KNOWLEDGE:\n"` + `policy_text` dari Bagian 7.5.

Panjang `user_msg` pada contoh: **4.107 karakter**.

### 8.2 Apa yang dilakukan

- **Satu panggilan `llm.invoke`**, tanpa tool, tanpa RAG.
- Menyusun narasi 7 bagian.
- Tidak menghitung ulang skor/rule; memakai `data` dan `policy_text`.
- Secara prompt diminta tidak memilih keputusan yang lebih longgar dari
  `preliminary_decision`.

### 8.3 Output — jawaban akhir

```text
1. **Keputusan:** APPROVE_WITH_CONDITIONS | Risiko: MEDIUM (skor: 30)

2. **Ringkasan singkat:** Permohonan akses dari `srv-core-app02` (IP: `192.168.5.22`,
   Core Banking, PROD) ke `srv-api-dmz06` (IP: `10.45.56.143`, API Management, PROD)
   melalui port `443/tcp` disetujui bersyarat. Meskipun kontrol keamanan dan pemetaan
   segmen sudah terpenuhi, terdapat catatan terkait kepatuhan SSL dan belum adanya
   data VA pada destinasi.

3. **Compliance (EDR/PAM/VA) source dan destination sesuai required_controls:**
   - Source (`srv-core-app02`): Memenuhi kontrol wajib EDR, PAM, dan VA (Status: `PASS`).
   - Destination (`srv-api-dmz06`): Memenuhi kontrol wajib EDR dan PAM, namun belum
     memiliki data VA yang terindeks (`VA` finding).

4. **Severity vulnerability source dan destination + SLA remediasi:**
   - Source (`srv-core-app02`): Terdapat 1 kerentanan Severity **Low**
     (CVE-2023-5678, OpenSSL DH excessive time, CVSS 3.1). SLA remediasi untuk
     environment PROD dengan severity Low adalah **90 hari** (Prioritas 4).
   - Destination (`srv-api-dmz06`): Belum dis scanning / belum ada data VA
     (`counts`: nihil).

5. **Penilaian port, segmen, dan environment (sebutkan rule ID yang relevan):**
   - Port: Port `443/tcp` (HTTPS) berstatus `RESTRICTED` (Rule **P-2**), di mana HTTPS
     digunakan sebagai target redirect dan PROD wajib menggunakan SSL.
   - Segmen: Pergerakan dari *Server Farm* ke *DMZ* diizinkan sesuai aturan **SS-7/SS-9**.
   - Environment: Lintas environment `PROD` ke `PROD` diizinkan sesuai aturan **ENV**.

6. **Rekomendasi (daftar bernomor):**
   1. Melakukan pemindaian Vulnerability Assessment (VA) segera pada server destinasi
      `srv-api-dmz06` untuk memastikan tidak ada celah keamanan kritis yang terbuka.
   2. Memastikan aplikasi pada trafik ini menggunakan enkripsi SSL yang valid sesuai
      ketentuan Rule **P-2** untuk environment PROD.
   3. Melakukan remediasi terhadap temuan CVE-2023-5678 pada source `srv-core-app02`
      dalam rentang SLA 90 hari.

7. **Referensi kebijakan:**
   - `COMP.md` (C-7)
   - `ENV.md` (ENV)
   - `PORT.md` (P-2)
   - `NET.md` (SS-7/SS-9)
   - `VA` / `SLA`
```

> **Catatan kualitas:** pada data deterministik, destination `gate="PASS"` karena
> EDR/PAM/VA aktif, tetapi `vuln.scanned=false` karena belum ada hasil scan.
> Reviewer menulis “EDR dan PAM” dan menyebut VA “belum terindeks”; ini menunjukkan
> Reviewer adalah LLM yang menarasikan, bukan sumber kebenaran. Angka dan status
> sebenarnya tetap ada di `data` assessment.

### 8.4 Tidak ada validasi pasca-generate

Kode langsung mengembalikan `message_text(...)`. Tidak ada parser yang:

- membaca bagian “Keputusan” dan membandingkannya dengan `preliminary_decision`;
- memvalidasi bahwa rule ID yang dikutip ada di `policy_refs`;
- memaksa output menjadi JSON.

Jadi guardrail “tidak boleh lebih longgar” hanya berupa instruksi prompt.

---

## 9. Step 6 — Jawaban kembali ke CLI / UI

### 9.1 CLI

`review_access()` → `access_review_node()` membungkus menjadi `AIMessage` →
state `messages` → `_final_answer()` → `run_once()` mencetak:

```text
Bot > 1. Keputusan: APPROVE_WITH_CONDITIONS | Risiko: MEDIUM (skor: 30)
...
```

### 9.2 Web UI

`app.py`:

```python
result = assess_connection_data(form["src_ip"], form["dst_ip"], port)
ai_answer, ai_elapsed = _run_ai_review(form["src_ip"], form["dst_ip"], port, result)
```

`_run_ai_review()`:

```python
started = time.perf_counter()
answer = review_access(src_ip, dst_ip, port, verbose=False, assessment=assessment)
return answer, time.perf_counter() - started
```

Template `templates/assessment.html` menampilkan:

- hasil deterministik: decision, port level, risk score, source/destination, findings,
  hard blocks;
- hasil AI: `ai_answer` + durasi.

Jika provider gagal, `app.py` menangkap exception dan menampilkan `ai_error`;
hasil deterministik tetap tampil.

---

## 10. Ringkasan input/output setiap fungsi

### 10.1 Entry point dan orkestrasi

| Fungsi | File | Input | Output |
|---|---|---|---|
| `main()` | `secbot/graph.py` | argumen CLI / input interaktif | jawaban / loop |
| `build_graph(verbose)` | `secbot/graph.py` | `bool` | compiled graph |
| `run_once(graph, cfg, question)` | `secbot/graph.py` | graph, cfg, `str` | `str` jawaban |
| `_final_answer(graph, cfg)` | `secbot/graph.py` | graph, cfg | `str` |
| `make_router_node(llm, verbose)` | `secbot/graph.py` | llm, bool | fungsi `router_node(state)` |
| `router_node(state)` | `secbot/graph.py` | `BotState` | `{"route", "request", "pending_request"}` |
| `make_access_review_node(verbose)` | `secbot/graph.py` | bool | fungsi `access_review_node(state)` |
| `access_review_node(state)` | `secbot/graph.py` | `BotState` | `{"messages", "pending_request"}` |

### 10.2 Router

| Fungsi | File | Input | Output |
|---|---|---|---|
| `decide(text, pending, llm)` | `secbot/router.py` | teks, pending, llm | `(route, request)` |
| `resolve_request(text, pending)` | `secbot/router.py` | teks, pending | `dict` request |
| `extract_request(text)` | `secbot/router.py` | teks | `{"src_ip", "dst_ip", "port", "protocol"}` |
| `extract_ips(text)` | `secbot/router.py` | teks | `list[str]` |
| `is_complete(request)` | `secbot/router.py` | request | `bool` |
| `has_access_intent(text)` | `secbot/router.py` | teks | `bool` |
| `_classify_with_llm(text, llm)` | `secbot/router.py` | teks, llm | `"chat"` / `"access_review"` |
| `clarification_message(request)` | `secbot/router.py` | request | `str` |

### 10.3 Stage 1 — Assessment

| Fungsi | File | Input | Output |
|---|---|---|---|
| `review_access(...)` | `secbot/agents/access_agents.py` | IP, port, protocol, assessment | `str` jawaban |
| `_llm()` | `secbot/agents/access_agents.py` | — | chat model |
| `_run(agent, text)` | `secbot/agents/access_agents.py` | agent, teks | `list` messages |
| `_tool_json(messages, name)` | `secbot/agents/access_agents.py` | messages, nama tool | `dict` / `None` |
| `assess_connection(...)` | `secbot/agents/access_tools.py` | IP, port, protocol | `dict` assessment |
| `assess_connection_data(...)` | `secbot/assessment.py` | IP, port, protocol | `dict` assessment |
| `_side(ip)` | `secbot/assessment.py` | IP | `dict` profil sisi |
| `_vuln_summary(ip)` | `secbot/assessment.py` | IP | `dict` ringkasan vuln |
| `_highest(side)` | `secbot/assessment.py` | side | `str` / `None` |
| `_is_public_facing(side)` | `secbot/assessment.py` | side | `bool` |
| `required_controls(env, segment)` | `secbot/policies.py` | environment, segmen | `list[str]` / `None` |
| `classify_port(port)` | `secbot/policies.py` | port | `dict` |
| `segment_rule(...)` | `secbot/policies.py` | segmen/zona/env/port | `dict` |
| `environment_rule(src, dst)` | `secbot/policies.py` | environment | `dict` |
| `sla_for(severity, env, public)` | `secbot/policies.py` | severity, env, bool | `dict` / `None` |
| `normalize_environment(env)` | `secbot/policies.py` | nama environment | `str` ternormalisasi |
| `segment_kind(segment)` | `secbot/policies.py` | nama segmen | `server-farm` / `dmz` / `lan` / `unknown` |
| `zone_kind(category)` | `secbot/policies.py` | `ip_category` | `data` / `management` / `workstation` |
| `_server_segment_rule(...)` | `secbot/policies.py` | jenis/zona segmen + port | `dict` aturan SS |
| `_workstation_rule(...)` | `secbot/policies.py` | segmen/env tujuan + port | `dict` aturan W/WS |
| `_rule(level, rule, points, note)` | `secbot/policies.py` | komponen aturan | `dict` |
| `build_chat_model()` | `secbot/llm.py` | konfigurasi provider | chat model |
| `build_embeddings()` | `secbot/llm.py` | konfigurasi embedding | objek embedding |
| `create_react_agent(llm, tools, prompt)` | LangGraph | model, tool, prompt | agent ReAct |

### 10.4 Stage 2 — Policy / RAG

| Fungsi | File | Input | Output |
|---|---|---|---|
| `search_knowledge(query)` | `secbot/tools.py` | query | `list[dict]` |
| `knowledge_lookup(query)` | `secbot/tools.py` | query | `list[dict]` |
| `index_problem()` | `secbot/knowledge.py` | — | `str` / `None` |
| `search_documents(query, k=3)` | `secbot/knowledge.py` | query, k | `list[dict]` |
| `get_vectorstore()` | `secbot/knowledge.py` | — | `Chroma` |
| `get_embeddings()` | `secbot/knowledge.py` | — | embeddings |
| `message_text(message)` | `secbot/llm.py` | pesan LLM | `str` |

### 10.5 Stage 3 — Reviewer

| Fungsi | File | Input | Output |
|---|---|---|---|
| `llm.invoke([system, user])` | LangChain | dua pesan | `AIMessage` |
| `message_text(message)` | `secbot/llm.py` | `AIMessage` | `str` jawaban 7 bagian |

### 10.6 Web UI

| Fungsi | File | Input | Output |
|---|---|---|---|
| `assessment()` | `app.py` | form POST | HTML |
| `_run_ai_review(...)` | `app.py` | IP, port, assessment | `(str, float)` |
| `compliance()` | `app.py` | form POST | HTML deterministik |

---

## 11. Contoh hasil kasus lain

Semua nilai di bawah dihasilkan oleh `assess_connection_data()` dengan data asli.

| Source → Destination | Port | Keputusan | Skor | Alasan utama |
|---|---|---|---:|---|
| `192.168.5.21` → `192.168.6.30` | 1433 | `DENY` | 75 HIGH | Source PROD belum PAM → hard block |
| `192.168.5.22` → `192.168.6.30` | 1433 | `APPROVE_WITH_CONDITIONS` | 45 MEDIUM | P-7 port database |
| `192.168.5.22` → `192.168.6.30` | 3389 | `DENY` | 80 CRITICAL | SS-1: management port Data→Data |
| `192.168.5.22` → `192.168.6.30` | 12345 | `DENY` | 65 HIGH | P-1 default deny |
| `10.45.18.127` → `10.45.21.148` | 443 | `DENY` | 80 CRITICAL | Source IP Management diblokir |
| `10.45.21.148` → `192.168.5.22` | 22 | `DENY` | 85 CRITICAL | Management port ke Data/VS |

---

## 12. Troubleshooting dan batasan

1. **Vector DB belum siap**
   - `search_knowledge` mengembalikan `[{"error": "Knowledge base belum dibangun..."}]`.
   - Solusi: `python ingest.py`.

2. **Model embedding berubah**
   - `embedding.json` tidak cocok → `index_problem()` memberi pesan.
   - Solusi: jalankan ulang `python ingest.py`.

3. **Provider LLM gagal**
   - CLI: exception dari `llm.invoke`.
   - Web: ditangkap `app.py`, ditampilkan sebagai `ai_error`; hasil deterministik tetap ada.

4. **Output LLM tidak deterministik**
   - Walaupun `TEMPERATURE=0`, teks bisa berbeda antar-run.
   - Angka/decision tetap mengikuti `data` assessment.

5. **Guardrail hanya prompt**
   - Tidak ada validasi pasca-generate terhadap `preliminary_decision`.
   - Untuk produksi, tambahkan parser + pengecekan keputusan.

6. **Knowledge vs `policies.py`**
   - Stage 1 memakai `policies.py`; Stage 2 memakai `knowledge/*.md`.
   - Keduanya harus dijaga sinkron. Jika dokumen berubah, ubah `policies.py` juga,
     lalu jalankan ulang `python ingest.py`.

7. **OS support**
   - `OS.md` belum dipakai sebagai faktor skor karena mapping kanoniknya berupa JSON
     yang tidak ada di repo dan nilai `operating_system` aset tidak selalu versi eksak.
   - Nilai OS tetap dibawa di output assessment.

---

## 13. Ringkasan satu baris

```text
User → router (regex) → access_review → assessment.py (deterministik)
     → Policy Agent (RAG knowledge/*.md) → Reviewer (LLM) → teks jawaban
```

Yang **menentukan** keputusan adalah `assessment.py` + `policies.py`.
Yang **menjelaskan** keputusan adalah Policy Agent + Reviewer.
