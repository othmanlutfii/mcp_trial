"""Agen chat: ReAct agent dengan 5 tool dasar (aset, compliance, CVE, knowledge).

Modul ini hanya membangun agennya. CLI-nya ada di :mod:`secbot.graph` karena
pintu masuk aplikasi sekarang satu: chat dan review akses lewat grafik supervisor.
"""
from langchain_core.language_models import BaseChatModel
from langgraph.prebuilt import create_react_agent

from .llm import build_chat_model
from .tools import ALL_TOOLS

SYSTEM_PROMPT = """Kamu adalah Security Assistant untuk tim cybersecurity. Jawab dalam Bahasa Indonesia.

ATURAN:
1. Jawab HANYA berdasarkan hasil tool. Jangan mengarang IP, CVE, atau kebijakan.
2. Jika user menyebut nama aplikasi, gunakan search_asset dulu untuk mendapat IP-nya.
3. Untuk pertanyaan lokasi/aset gunakan get_asset_by_ip. Untuk compliance gunakan check_compliance.
   Untuk CVE gunakan get_vulns_by_ip. Untuk SLA/kebijakan/cara perbaikan gunakan search_knowledge.
4. Jika tool mengembalikan error atau data kosong, katakan apa adanya.
5. Format jawaban: (a) Lokasi aset, (b) Status compliance, (c) Daftar CVE, (d) Analisa singkat, (e) Rekomendasi perbaikan beserta SLA.
   Tampilkan hanya bagian yang relevan dengan pertanyaan; bagian yang tidak ditanyakan dan datanya belum diambil cukup dilewati.
6. JANGAN pernah menyatakan 'tidak ada CVE' atau 'tidak ada data' bila tool terkait belum dipanggil. Panggil tool-nya dulu, baru simpulkan.
7. Sebutkan sumber: 'data aset', 'data VA', atau nama file knowledge."""


def build_llm() -> BaseChatModel:
    """Model chat bersama untuk seluruh agen (provider mengikuti ``SECBOT_PROVIDER``)."""
    return build_chat_model()


def build_agent(llm: BaseChatModel | None = None):
    """Buat ReAct agent (LLM + 5 tool dasar).

    Tanpa ``checkpointer`` agar bisa dipasang sebagai subgraph di dalam grafik
    supervisor; memori percakapan dipegang oleh grafik induk.
    """
    return create_react_agent(llm or build_llm(), ALL_TOOLS, prompt=SYSTEM_PROMPT)
