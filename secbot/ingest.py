"""Bangun vector DB dari folder ``knowledge/``.

Alur: baca semua ``.md`` -> pecah per heading (``#`` dan ``##``) -> embed -> simpan ke Chroma.
Folder vector DB lama dihapus dulu supaya hasilnya bersih (tidak ada chunk ganda).

Jalankan: ``python ingest.py``
Ulangi setiap kali file ``.md`` berubah **atau** provider/model embedding diganti
(``SECBOT_PROVIDER`` / ``SECBOT_EMBED_PROVIDER`` / ``SECBOT_EMBED_MODEL``), karena
vector DB terikat pada model embedding yang membuatnya.
"""
import glob
import os
import shutil

from langchain_chroma import Chroma
from langchain_core.documents import Document
from langchain_text_splitters import MarkdownHeaderTextSplitter

from . import config, knowledge
from .llm import ProviderError, active_embed_model_name, describe


def load_documents() -> list[Document]:
    """Baca seluruh file ``.md`` di ``knowledge/`` dan pecah per heading.

    Metadata ``sumber`` (nama file) dan ``bagian`` (heading ``##``) dipakai saat
    menampilkan jawaban agar pengguna tahu asal aturannya.
    """
    splitter = MarkdownHeaderTextSplitter(
        headers_to_split_on=[("#", "judul"), ("##", "bagian")]
    )
    docs: list[Document] = []
    for path in sorted(glob.glob(os.path.join(str(config.KNOWLEDGE_DIR), "*.md"))):
        with open(path, encoding="utf-8") as f:
            for chunk in splitter.split_text(f.read()):
                chunk.metadata["sumber"] = os.path.basename(path)
                docs.append(chunk)
    return docs


def build_index() -> int:
    """Buat ulang vector DB dari nol. Kembalikan jumlah chunk yang di-ingest."""
    docs = load_documents()
    if os.path.exists(config.VECTOR_DIR):
        shutil.rmtree(config.VECTOR_DIR)  # rebuild bersih
    Chroma.from_documents(
        docs,
        knowledge.get_embeddings(),
        persist_directory=str(config.VECTOR_DIR),
    )
    # Catat model embedding supaya ketidakcocokan konfigurasi bisa dideteksi saat pencarian.
    knowledge.save_embedding_signature()
    return len(docs)


def main() -> None:
    """Entry point CLI: bangun vector DB lalu cetak ringkasannya."""
    try:
        total = build_index()
    except ProviderError as e:
        raise SystemExit(f"\nKonfigurasi model belum lengkap:\n{e}")
    print(
        f"Selesai: {total} chunk dari folder '{config.KNOWLEDGE_DIR.name}' "
        f"masuk ke vector DB '{config.VECTOR_DIR.name}'.\n"
        f"Embedding: {config.EMBED_PROVIDER}:{active_embed_model_name()}  ({describe()})"
    )
