"""Security Bot: asisten keamanan berbasis LangChain + LangGraph + Ollama.

Satu pintu masuk, satu grafik, dua kemampuan (tanya-jawab dan review pembukaan akses).
Router di dalam grafik yang memilih rutenya, jadi pengguna cukup menulis pertanyaan.

- :mod:`secbot.config`     pengaturan provider/model (ollama, gemini, deepseek) dan lokasi folder
- :mod:`secbot.llm`        pabrik model chat & embedding per provider
- :mod:`secbot.datasource` baca data aset/vulnerability (dummy JSON, siap diganti API)
- :mod:`secbot.policies`   aturan bisnis deterministik (compliance & port)
- :mod:`secbot.knowledge`  akses vector DB knowledge base
- :mod:`secbot.tools`      5 tool agen chat
- :mod:`secbot.router`     deteksi intent + ekstraksi data permintaan akses
- :mod:`secbot.chat`       agen ReAct untuk tanya-jawab
- :mod:`secbot.graph`      grafik supervisor + CLI (pintu masuk tunggal)
- :mod:`secbot.ingest`     bangun vector DB dari folder knowledge/
- :mod:`secbot.agents`     mesin review pembukaan akses (3 agen)
"""

__version__ = "1.0.0"
