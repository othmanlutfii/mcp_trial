"""Lapisan data: membaca data aset (CMDB) dan hasil scan VA.

Saat ini sumbernya file JSON dummy. Untuk produksi, cukup ubah isi
:func:`load_assets` dan :func:`load_vulns` menjadi ``requests.get()`` ke API
CMDB (:8001) dan API VA (:8002) -- seluruh kode lain tidak perlu berubah.
"""
import ipaddress
import json

from . import config


def load_assets() -> list[dict]:
    """Baca seluruh data aset dari ``data/assets.json``."""
    with open(config.ASSETS_FILE, encoding="utf-8") as f:
        return json.load(f)


def load_vulns() -> list[dict]:
    """Baca seluruh hasil scan vulnerability dari ``data/vulns.json``."""
    with open(config.VULNS_FILE, encoding="utf-8") as f:
        return json.load(f)


def is_valid_ip(ip: str) -> bool:
    """Kembalikan ``True`` bila ``ip`` berformat IPv4/IPv6 yang valid."""
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except (ValueError, AttributeError):
        return False


def find_asset(ip: str) -> dict | None:
    """Cari satu aset berdasarkan IP persis. Kembalikan ``None`` bila tidak terdaftar."""
    target = ip.strip()
    return next((a for a in load_assets() if a["ip"] == target), None)


def find_assets(keyword: str) -> list[dict]:
    """Cari aset yang ``application`` atau ``hostname``-nya mengandung ``keyword``.

    Pencarian sebagian dan tidak case-sensitive.
    """
    kw = keyword.lower().strip()
    return [
        a for a in load_assets()
        if kw in a["application"].lower() or kw in a["hostname"].lower()
    ]


def find_vulns(ip: str) -> dict | None:
    """Cari hasil scan VA satu server berdasarkan IP persis.

    Kembalikan ``None`` bila server belum pernah discan.
    """
    target = ip.strip()
    return next((v for v in load_vulns() if v["ip"] == target), None)
