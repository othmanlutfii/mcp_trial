"""Konfigurasi global: pilih provider LLM, model, dan lokasi folder proyek.

Cukup isi API key provider yang mau dipakai; provider lain tidak perlu dikonfigurasi.
Nilai bisa lewat environment variable **atau** file ``.env`` di root proyek
(lihat ``.env.example``), misalnya::

    SECBOT_PROVIDER=gemini
    SECBOT_GEMINI_API_KEY=AIza...

Override cepat dari terminal juga bisa::

    SECBOT_PROVIDER=deepseek SECBOT_DEEPSEEK_API_KEY=sk-... python main.py
"""
import os
from pathlib import Path

from dotenv import load_dotenv

# ---------- Lokasi folder ----------
# Dihitung dari posisi file ini, bukan dari current working directory,
# supaya aplikasi tetap jalan walau dijalankan dari folder lain.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
KNOWLEDGE_DIR = PROJECT_ROOT / "knowledge"
VECTOR_DIR = PROJECT_ROOT / "vectordb"

load_dotenv(PROJECT_ROOT / ".env")  # opsional; aman bila file .env tidak ada


def _env(nama: str, default: str = "") -> str:
    """Baca environment variable dan rapikan spasi di ujungnya."""
    return (os.getenv(nama) or default).strip()


def _env_bool(nama: str, default: bool) -> bool:
    """Baca environment variable boolean ("1/true/yes/on" dianggap True)."""
    nilai = os.getenv(nama)
    if nilai is None or not nilai.strip():
        return default
    return nilai.strip().lower() in {"1", "true", "yes", "on", "y"}


# ---------- Provider yang dipakai: "ollama" | "gemini" | "deepseek" ----------
PROVIDER = (_env("SECBOT_PROVIDER", "ollama") or "ollama").lower()
SUPPORTED_PROVIDERS = ("ollama", "gemini", "deepseek")

# ---------- Ollama (lokal, tanpa API key) ----------
OLLAMA_URL = _env("SECBOT_OLLAMA_URL", "http://localhost:11434")
OLLAMA_LLM_MODEL = _env("SECBOT_LLM_MODEL", "qwen3:latest")
OLLAMA_EMBED_MODEL = _env("SECBOT_EMBED_MODEL", "bge-m3:latest")

# ---------- Google Gemini (free tier tersedia; model paling ringan & murah) ----------
# gemini-3.5-flash-lite = model multimodal tercepat dan termurah di keluarga 3.x.
# (gemini-2.5-flash-lite sudah tidak tersedia untuk pengguna API baru.)
GEMINI_API_KEY = _env("SECBOT_GEMINI_API_KEY") or _env("GEMINI_API_KEY")
GEMINI_MODEL = _env("SECBOT_GEMINI_MODEL", "gemini-3.5-flash-lite")
GEMINI_EMBED_MODEL = _env("SECBOT_GEMINI_EMBED_MODEL", "gemini-embedding-001")

# ---------- DeepSeek (OpenAI-compatible; model paling ringan = deepseek-flash) ----------
# Catatan: DeepSeek tidak menyediakan API embedding, jadi embedding tetap dari
# Ollama atau Gemini (lihat EMBED_PROVIDER di bawah).
DEEPSEEK_API_KEY = _env("SECBOT_DEEPSEEK_API_KEY") or _env("DEEPSEEK_API_KEY")
DEEPSEEK_MODEL = _env("SECBOT_DEEPSEEK_MODEL", "deepseek-flash")
DEEPSEEK_BASE_URL = _env("SECBOT_DEEPSEEK_BASE_URL")  # kosong = pakai default pustaka

# ---------- Provider embedding untuk vector DB ----------
# Default mengikuti provider chat. Khusus DeepSeek (tidak punya API embedding),
# dipakai Gemini bila API key-nya ada, kalau tidak Ollama. Dengan begitu berpindah
# antara gemini <-> deepseek tidak perlu membangun ulang vector DB.
# Bisa dipaksa lewat SECBOT_EMBED_PROVIDER.
_EMBED_DEFAULT = (
    PROVIDER if PROVIDER in ("ollama", "gemini") else ("gemini" if GEMINI_API_KEY else "ollama")
)
EMBED_PROVIDER = (_env("SECBOT_EMBED_PROVIDER") or _EMBED_DEFAULT).lower()

# ---------- Umum ----------
TEMPERATURE = float(_env("SECBOT_TEMPERATURE", "0") or 0)
# False = matikan mode berpikir. Jauh lebih cepat, dan penting untuk qwen3
# (tanpa ini satu jawaban bisa >1 menit). True = aktifkan penalaran.
THINKING = _env_bool("SECBOT_THINKING", False)

# ---------- Sumber data dummy ----------
# Ganti pemakaian file ini di secbot/datasource.py dengan API asli (:8001 / :8002).
ASSETS_FILE = DATA_DIR / "assets.json"
VULNS_FILE = DATA_DIR / "vulns.json"
