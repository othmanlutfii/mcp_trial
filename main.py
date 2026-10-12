"""Entry point aplikasi: ``python main.py`` (logikanya ada di ``secbot/graph.py``).

Satu pintu untuk dua alur:
- pertanyaan informasi  -> agen chat
- permintaan review akses -> pipeline 3 agen

Router di dalam grafik memilih jalurnya sendiri, jadi tidak perlu perintah terpisah.

Sekali jalan tanpa mode interaktif: ``python main.py "pertanyaan"``
"""
from secbot.graph import main

if __name__ == "__main__":
    main()
