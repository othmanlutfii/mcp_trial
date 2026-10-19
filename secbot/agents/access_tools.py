"""Tool penilaian permintaan pembukaan koneksi (connection request).

Perhitungan deterministiknya ada di :mod:`secbot.assessment`; file ini hanya
membungkusnya sebagai tool LangChain yang dipakai agen.
"""
from langchain_core.tools import tool

from ..assessment import assess_connection_data


@tool
def assess_connection(src_ip: str, dst_ip: str, port: int, protocol: str = "tcp") -> dict:
    """Nilai permintaan pembukaan koneksi dari server source ke server destination pada port tertentu.
    Mengembalikan: status gate EDR/PAM/VA kedua server, severity vulnerability, level port,
    temuan, skor risiko, dan keputusan awal. Semua dihitung oleh kode."""
    return assess_connection_data(src_ip, dst_ip, port, protocol)
