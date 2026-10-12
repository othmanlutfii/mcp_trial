"""Penentu rute: memilih antara rute ``chat`` dan ``access_review``.

Urutan keputusan sengaja **deterministik dulu, LLM belakangan**:

1. Ada 2 IP valid + nomor port      -> ``access_review`` (paling pasti, itu memang permintaan koneksi)
2. Ada kata kunci permintaan akses  -> ``access_review``
   (bila datanya belum lengkap, node review yang meminta kelengkapannya)
3. Selain itu                       -> ditanyakan ke LLM sebagai cadangan terakhir

Dengan aturan ini, pertanyaan seperti "IP 10.10.5.21 ada di mana?" tetap masuk
rute ``chat``, sedangkan "Buka akses dari A ke B port C" langsung ke ``access_review``.
"""
import re

from . import datasource
from .llm import message_text

# ---------- Pola ekstraksi ----------
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# "port 1433" / "port: 1433" / "portnya 1433" / "port-nya = 1433"
_PORT_KEYWORD = re.compile(r"port(?:nya|-nya)?\s*[:=]?\s*(\d{1,5})(?![\d.])", re.IGNORECASE)
# "10.10.6.30:1433" (harus menempel pada IP agar jam seperti 10:30 tidak ikut terbaca)
_PORT_IP_COLON = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}\s*:\s*(\d{1,5})(?![\d.])")
# "1433/tcp"
_PORT_SLASH_PROTO = re.compile(r"(?<![\d.])(\d{1,5})\s*/\s*(tcp|udp)\b", re.IGNORECASE)

# Kata/frasa yang kuat menandakan permintaan pembukaan akses.
ACCESS_KEYWORDS = (
    "buka akses", "membuka akses", "pembukaan akses", "permintaan akses",
    "review akses", "review koneksi", "izinkan akses", "izin akses",
    "minta akses", "ajukan akses", "akses dari",
    "boleh dibuka", "boleh buka", "boleh dibukakan", "dibukakan",
    "buka koneksi", "buka port", "open port", "buka firewall",
    "firewall rule", "permintaan koneksi",
)

IP_LABELS = {"src_ip": "IP source", "dst_ip": "IP destination", "port": "port"}
REQUIRED_FIELDS = ("src_ip", "dst_ip", "port")

_LLM_PROMPT = """Kamu pengklasifikasi intent untuk Security Bot.

Jawab dengan SATU kata saja, tanpa penjelasan:
- 'access_review' bila pesan meminta PEMBUKAAN/REVIEW koneksi jaringan antara dua server.
- 'chat' bila pesan hanya bertanya informasi (aset, compliance, CVE, SLA, kebijakan).

Yang termasuk 'chat': pertanyaan lokasi aset, status compliance, daftar CVE, cara patching,
atau pertanyaan kebijakan. Jangan pilih 'access_review' kalau tidak ada maksud membuka koneksi."""


# ---------- Ekstraksi data permintaan ----------
def extract_ips(text: str) -> list[str]:
    """Semua IP valid di dalam teks, sesuai urutan kemunculan."""
    return [ip for ip in IP_RE.findall(text or "") if datasource.is_valid_ip(ip)]


def extract_request(text: str) -> dict:
    """Tarik ``src_ip``, ``dst_ip``, ``port``, dan ``protocol`` dari kalimat bebas.

    IP pertama dianggap **source**, IP kedua **destination**. Field yang tidak ada
    dikembalikan sebagai ``None``. Port hanya diakui bila ditulis sebagai ``port 1433``,
    menempel pada IP (``10.10.6.30:1433``), atau ``1433/tcp``.
    """
    text = text or ""
    ips = extract_ips(text)

    port = None
    m = _PORT_KEYWORD.search(text) or _PORT_IP_COLON.search(text) or _PORT_SLASH_PROTO.search(text)
    if m:
        nilai = int(m.group(1))
        if 1 <= nilai <= 65535:
            port = nilai

    protocol = None
    ms = _PORT_SLASH_PROTO.search(text)
    if ms:
        protocol = ms.group(2).lower()
    elif re.search(r"\budp\b", text, re.IGNORECASE):
        protocol = "udp"
    elif re.search(r"\btcp\b", text, re.IGNORECASE):
        protocol = "tcp"

    return {
        "src_ip": ips[0] if len(ips) >= 1 else None,
        "dst_ip": ips[1] if len(ips) >= 2 else None,
        "port": port,
        "protocol": protocol,
    }


def is_complete(request: dict) -> bool:
    """``True`` bila source, destination, dan port sudah terisi (protocol opsional)."""
    return all(request.get(f) for f in REQUIRED_FIELDS)


def missing_fields(request: dict) -> list[str]:
    """Label human-readable untuk field yang masih kosong."""
    return [IP_LABELS[f] for f in REQUIRED_FIELDS if not (request or {}).get(f)]


def has_access_intent(text: str) -> bool:
    """``True`` bila teks memuat kata kunci permintaan pembukaan akses."""
    low = (text or "").lower()
    return any(kw in low for kw in ACCESS_KEYWORDS)


def resolve_request(text: str, pending: dict | None = None) -> dict:
    """Gabungkan data pesan terbaru dengan permintaan yang sedang menunggu kelengkapan.

    ``pending`` adalah permintaan yang pada giliran sebelumnya diminta dilengkapi
    (mis. baru menyebut source dan destination, port belum ada).

    Aturan agar permintaan lama tidak bocor ke permintaan/pertanyaan baru:

    * Bila pesan terbaru **sudah lengkap** (dua IP + port), pesan itu berdiri sendiri
      dan ``pending`` diabaikan sepenuhnya.
    * Selain itu, IP/port dari pesan terbaru dipakai untuk mengisi slot yang masih
      kosong di ``pending``.
    * Bila pesan terbaru tidak memasok satu pun field yang kurang, ``pending``
      diabaikan -- artinya user sedang membicarakan hal lain, bukan menjawab klarifikasi.

    Protocol selalu diisi default ``tcp`` bila kosong.
    """
    own = extract_request(text)
    if not pending or is_complete(own):
        if not own.get("protocol"):
            own["protocol"] = "tcp"
        return own

    hasil = dict(pending)
    terpakai = False

    ips = extract_ips(text)
    if len(ips) >= 2:
        hasil["src_ip"], hasil["dst_ip"] = ips[0], ips[1]
        terpakai = True
    elif len(ips) == 1:
        for slot in ("src_ip", "dst_ip"):
            if not hasil.get(slot):
                hasil[slot] = ips[0]
                terpakai = True
                break

    if own.get("port"):
        hasil["port"] = own["port"]
        if own.get("protocol"):
            hasil["protocol"] = own["protocol"]
        terpakai = True

    if not terpakai:  # pesan terbaru tidak menjawab kekurangan -> pakai pesan terbaru saja
        if not own.get("protocol"):
            own["protocol"] = "tcp"
        return own

    if not hasil.get("protocol"):
        hasil["protocol"] = "tcp"
    return hasil


def clarification_message(request: dict) -> str:
    """Susun pesan yang meminta user melengkapi data permintaan akses."""
    daftar = ", ".join(f"**{label}**" for label in missing_fields(request))
    return (
        "Permintaan ini terlihat seperti review pembukaan akses, "
        "tetapi datanya belum lengkap.\n"
        f"Mohon lengkapi: {daftar}."
    )


# ---------- Penentuan rute ----------
def _classify_with_llm(text: str, llm) -> str:
    """Cadangan terakhir: minta LLM memilih rute. Apa pun yang tidak jelas -> ``chat``."""
    if llm is None:
        return "chat"
    pesan = f"Pesan user:\n{text}\n\nJawab satu kata:"
    try:
        jawaban = llm.invoke([("system", _LLM_PROMPT), ("user", pesan)])
        teks = message_text(jawaban).lower()
    except Exception:  # noqa: BLE001 - router tidak boleh gagal; apa pun error-nya -> rute chat
        return "chat"
    return "access_review" if "access_review" in teks else "chat"


def decide(text: str, pending: dict | None = None, llm=None) -> tuple[str, dict]:
    """Tentukan ``(route, request)`` untuk satu pesan user.

    ``route`` bernilai ``"chat"`` atau ``"access_review"``. ``request`` hanya berisi
    data permintaan akses pada rute ``access_review`` (boleh belum lengkap).
    ``pending`` adalah permintaan dari giliran sebelumnya yang masih menunggu
    kelengkapan data.
    """
    request = resolve_request(text, pending)

    if is_complete(request):
        return "access_review", request
    if has_access_intent(text):
        return "access_review", request

    route = _classify_with_llm(text, llm)
    return route, (request if route == "access_review" else {})
