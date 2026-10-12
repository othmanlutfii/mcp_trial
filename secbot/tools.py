"""Tool yang dipakai agen chat.

Pola tiap tool ada dua lapis:

1. fungsi polos (deterministik, gampang diuji manual) -- mis. :func:`asset_by_ip`
2. pembungkus ``@tool`` yang docstring-nya dibaca LLM sebagai deskripsi tool.

Semua perhitungan tetap dilakukan kode, bukan ditebak oleh LLM.
"""
from langchain_core.tools import tool

from . import datasource, knowledge, policies


# ---------- Fungsi inti (deterministik) ----------
def asset_by_ip(ip: str) -> dict:
    """Data aset untuk satu IP, atau ``{"error": ...}`` bila IP invalid / tidak terdaftar."""
    if not datasource.is_valid_ip(ip):
        return {"error": f"'{ip}' bukan format IP yang valid"}
    asset = datasource.find_asset(ip)
    if asset is None:
        return {"error": f"Aset dengan IP {ip} tidak ditemukan"}
    return asset


def assets_by_keyword(keyword: str) -> list[dict]:
    """Daftar aset yang cocok dengan ``keyword``, atau satu item ``{"error": ...}`` bila kosong."""
    hasil = datasource.find_assets(keyword)
    return hasil or [{"error": f"Tidak ada aset yang cocok dengan '{keyword}'"}]


def vulns_by_ip(ip: str) -> dict:
    """Ringkasan vulnerability satu server.

    Berisi jumlah temuan per severity, tanggal scan terakhir, dan maksimal 10 CVE
    dengan CVSS tertinggi beserta solusinya.
    """
    if not datasource.is_valid_ip(ip):
        return {"error": f"'{ip}' bukan format IP yang valid"}
    data = datasource.find_vulns(ip)
    if data is None:
        return {"error": f"Tidak ada data VA untuk IP {ip} (mungkin belum pernah discan)"}

    daftar = sorted(data["vulnerabilities"], key=lambda x: -x["cvss"])[:10]  # batasi output
    counts: dict[str, int] = {}
    for x in data["vulnerabilities"]:
        counts[x["severity"]] = counts.get(x["severity"], 0) + 1
    return {
        "ip": ip,
        "lastSeen": data["lastSeen"],
        "severityCounts": counts,
        "vulnerabilities": daftar,
    }


def compliance_status(ip: str) -> dict:
    """Status compliance satu server terhadap kontrol wajib environment-nya."""
    asset = asset_by_ip(ip)
    if "error" in asset:
        return asset
    env = asset["environment"]
    wajib = policies.REQUIRED_CONTROLS.get(env, [])
    kurang = [k.upper() for k in wajib if not asset.get(k)]
    return {
        "ip": ip,
        "hostname": asset["hostname"],
        "environment": env,
        "kontrol_wajib": [k.upper() for k in wajib],
        "kontrol_belum_terpenuhi": kurang,
        "status": "COMPLIANT" if not kurang else "NON-COMPLIANT",
    }


def knowledge_lookup(query: str) -> list[dict]:
    """Cari kebijakan/SLA/panduan di knowledge base.

    Kembalikan satu item ``{"error": ...}`` bila vector DB belum dibangun atau
    dibuat dengan model embedding yang berbeda dari konfigurasi sekarang.
    """
    masalah = knowledge.index_problem()
    if masalah:
        return [{"error": masalah}]
    return knowledge.search_documents(query)


# ---------- Wrapper untuk LLM ----------
@tool
def get_asset_by_ip(ip: str) -> dict:
    """Ambil data aset (hostname, aplikasi, environment, segment, dc, edr, pam, va, OS) berdasarkan alamat IP."""
    return asset_by_ip(ip)


@tool
def search_asset(keyword: str) -> list[dict]:
    """Cari aset berdasarkan nama aplikasi atau hostname (pencarian sebagian, tidak case-sensitive).
    Gunakan ini bila user menyebut nama aplikasi, misalnya 'Core Banking'."""
    return assets_by_keyword(keyword)


@tool
def get_vulns_by_ip(ip: str) -> dict:
    """Ambil ringkasan vulnerability sebuah server berdasarkan IP: jumlah per severity dan daftar CVE beserta solusinya."""
    return vulns_by_ip(ip)


@tool
def check_compliance(ip: str) -> dict:
    """Cek apakah server sudah comply terhadap kebijakan EDR/PAM/VA sesuai environment-nya. Hasil dihitung oleh kode, bukan tebakan."""
    return compliance_status(ip)


@tool
def search_knowledge(query: str) -> list[dict]:
    """Cari kebijakan, standar compliance, SLA, dan panduan remediasi dari knowledge base internal."""
    return knowledge_lookup(query)


ALL_TOOLS = [get_asset_by_ip, search_asset, get_vulns_by_ip, check_compliance, search_knowledge]
