"""Akses knowledge base: embedding (sesuai provider) + vector DB Chroma.

Vector DB dibangun sekali oleh ``ingest.py`` lalu hanya dibaca (read-only) saat
pencarian. Embedding dan koneksi Chroma dibuat sekali lalu dipakai ulang.

Dua hal penting:

1. LangGraph menjalankan beberapa tool call secara paralel di beberapa thread, dan
   membuat client Chroma untuk folder yang sama dari beberapa thread sekaligus bisa
   merusak state internal Chroma. Karena itu inisialisasi di bawah dikunci
   (double-checked locking).
2. Vector DB terikat pada model embedding yang membuatnya. Bila provider/model
   embedding diganti, ``python ingest.py`` wajib dijalankan ulang. Marker
   ``vectordb/embedding.json`` dipakai untuk mendeteksi ketidakcocokan itu --
   tanpa deteksi ini, pencarian bisa mengembalikan hasil ngawur tanpa error.
"""
import json
import threading

from langchain_chroma import Chroma

from . import config, llm

EMBEDDING_MARKER = "embedding.json"

_embeddings_lock = threading.Lock()
_vectorstore_lock = threading.Lock()
_embeddings = None
_vectorstore: Chroma | None = None


def embedding_signature() -> dict:
    """Identitas model embedding yang aktif (provider + nama model)."""
    return {"provider": config.EMBED_PROVIDER, "model": llm.active_embed_model_name()}


def get_embeddings():
    """Embedding untuk vector DB, dibuat sekali dan dipakai ulang.

    Model wajib sama saat ingest dan saat pencarian; kalau berbeda hasil pencarian tidak akurat.
    """
    global _embeddings
    if _embeddings is None:
        with _embeddings_lock:
            if _embeddings is None:
                _embeddings = llm.build_embeddings()
    return _embeddings


def get_vectorstore() -> Chroma:
    """Buka vector DB yang sudah di-ingest (jalankan ``python ingest.py`` lebih dulu).

    Client dibuat tepat satu kali, aman dipanggil dari beberapa thread.
    """
    global _vectorstore
    if _vectorstore is None:
        embeddings = get_embeddings()  # diambil di luar lock untuk menghindari deadlock
        with _vectorstore_lock:
            if _vectorstore is None:
                _vectorstore = Chroma(
                    persist_directory=str(config.VECTOR_DIR),
                    embedding_function=embeddings,
                )
    return _vectorstore


def is_index_ready() -> bool:
    """``True`` bila folder vector DB sudah ada (artinya ingest pernah dijalankan)."""
    return config.VECTOR_DIR.exists()


def save_embedding_signature() -> None:
    """Tulis marker model embedding ke dalam folder vector DB (dipanggil oleh ingest)."""
    marker = config.VECTOR_DIR / EMBEDDING_MARKER
    marker.write_text(
        json.dumps(embedding_signature(), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def index_problem() -> str | None:
    """Kembalikan pesan masalah bila vector DB belum siap atau dibuat model embedding lain.

    ``None`` berarti vector DB siap dipakai.
    """
    if not is_index_ready():
        return "Knowledge base belum dibangun. Jalankan dulu: python ingest.py"

    marker = config.VECTOR_DIR / EMBEDDING_MARKER
    if not marker.exists():
        return None  # vector DB lama tanpa marker: anggap cocok

    try:
        tersimpan = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None

    if tersimpan != embedding_signature():
        return (
            f"Knowledge base dibuat dengan embedding {tersimpan.get('provider')}:{tersimpan.get('model')}, "
            f"sedangkan konfigurasi sekarang {config.EMBED_PROVIDER}:{llm.active_embed_model_name()}. "
            "Jalankan ulang: python ingest.py"
        )
    return None


def search_documents(query: str, k: int = 3) -> list[dict]:
    """Ambil ``k`` potongan dokumen paling relevan dengan ``query``.

    Kembalikan daftar berisi ``sumber`` (nama file), ``bagian`` (heading), dan ``isi`` (teks).
    """
    hasil = get_vectorstore().similarity_search(query, k=k)
    return [
        {
            "sumber": d.metadata.get("sumber"),
            "bagian": d.metadata.get("bagian"),
            "isi": d.page_content,
        }
        for d in hasil
    ]
