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
    segment = asset["segment"]
    wajib = policies.required_controls(env, segment)
    if wajib is None:
        return {
            "ip": ip,
            "hostname": asset["hostname"],
            "environment": env,
            "segment": segment,
            "kontrol_wajib": [],
            "kontrol_belum_terpenuhi": [],
            "status": "UNKNOWN",
            "catatan": (
                f"Kewajiban kontrol untuk environment {env} tidak dinyatakan "
                "di knowledge/COMP.md"
            ),
        }

    kurang = [k.upper() for k in wajib if not asset.get(k)]
    return {
        "ip": ip,
        "hostname": asset["hostname"],
        "environment": env,
        "segment": segment,
        "kontrol_wajib": [k.upper() for k in wajib],
        "kontrol_belum_terpenuhi": kurang,
        "status": "COMPLIANT" if not kurang else "NON-COMPLIANT",
    }
