"""Pemeriksaan compliance aset (deterministik, tanpa dependensi LLM).

Dipisahkan dari :mod:`secbot.tools` supaya bisa dipakai aplikasi web tanpa
memuat LangChain/Chroma.
"""
from . import datasource, policies


def compliance_status(ip: str) -> dict:
    """Status compliance satu server terhadap kontrol wajib environment-nya."""
    if not datasource.is_valid_ip(ip):
        return {"error": f"'{ip}' bukan format IP yang valid"}
    asset = datasource.find_asset(ip)
    if asset is None:
        return {"error": f"Aset dengan IP {ip} tidak ditemukan"}

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
