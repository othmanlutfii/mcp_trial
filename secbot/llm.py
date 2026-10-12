"""Pabrik model: satu tempat yang tahu cara membuat LLM & embedding tiap provider.

Provider chat dipilih lewat ``SECBOT_PROVIDER`` (``ollama`` | ``gemini`` | ``deepseek``),
provider embedding lewat ``SECBOT_EMBED_PROVIDER`` (``ollama`` | ``gemini``).

Import paket provider dilakukan **malas** (di dalam fungsi) supaya paket yang belum
terpasang tidak menggagalkan provider lain -- misalnya kalau Anda hanya memakai Ollama,
paket Google/DeepSeek tidak perlu ada.
"""
from . import config


class ProviderError(RuntimeError):
    """Konfigurasi provider belum lengkap atau provider tidak dikenal."""


def _need_key(nilai: str, nama_env: str, provider: str) -> str:
    """Pastikan API key terisi; kalau kosong beri pesan yang langsung bisa ditindak."""
    if not nilai:
        raise ProviderError(
            f"Provider '{provider}' butuh API key, tetapi {nama_env} belum diisi.\n"
            f"  Isi di file .env (lihat .env.example) atau lewat terminal, contoh:\n"
            f"    export {nama_env}=<api-key-anda>"
        )
    return nilai


# ---------- Pembuat model chat ----------
def _build_ollama(temperature: float):
    from langchain_ollama import ChatOllama

    return ChatOllama(
        model=config.OLLAMA_LLM_MODEL,
        base_url=config.OLLAMA_URL,
        temperature=temperature,
        # False mematikan mode berpikir; tanpa ini qwen3 bisa >1 menit per jawaban.
        reasoning=config.THINKING,
    )


def _build_gemini(temperature: float):
    from langchain_google_genai import ChatGoogleGenerativeAI

    model = config.GEMINI_MODEL
    kwargs = {}
    if not model.lower().startswith("gemini-3"):
        # Gemini 3 memakai fixed sampling: mengirim temperature hanya memunculkan warning.
        kwargs["temperature"] = temperature
    if not config.THINKING and "2.5" in model:
        # 0 = tanpa thinking token (lebih cepat & hemat kuota free tier).
        # Gemini 3 tidak memakai thinking_budget, jadi dibiarkan ke default model.
        kwargs["thinking_budget"] = 0
    return ChatGoogleGenerativeAI(
        model=model,
        google_api_key=_need_key(config.GEMINI_API_KEY, "SECBOT_GEMINI_API_KEY", "gemini"),
        **kwargs,
    )


def _build_deepseek(temperature: float):
    from langchain_deepseek import ChatDeepSeek

    kwargs = {}
    if config.DEEPSEEK_BASE_URL:
        kwargs["api_base"] = config.DEEPSEEK_BASE_URL
    if config.THINKING:
        # DeepSeek: mode berpikir dimatikan secara default, jadi hanya perlu
        # diaktifkan eksplisit bila THINKING=True.
        kwargs["model_kwargs"] = {"extra_body": {"thinking": {"type": "enabled"}}}
    return ChatDeepSeek(
        model=config.DEEPSEEK_MODEL,
        api_key=_need_key(config.DEEPSEEK_API_KEY, "SECBOT_DEEPSEEK_API_KEY", "deepseek"),
        temperature=temperature,
        **kwargs,
    )


_CHAT_BUILDERS = {
    "ollama": _build_ollama,
    "gemini": _build_gemini,
    "deepseek": _build_deepseek,
}


def build_chat_model(temperature: float | None = None):
    """Buat model chat sesuai ``SECBOT_PROVIDER``.

    Kembalikan objek chat model LangChain yang siap dipakai agen (harus mendukung
    tool calling; ketiga provider di atas mendukungnya).
    """
    builder = _CHAT_BUILDERS.get(config.PROVIDER)
    if builder is None:
        raise ProviderError(
            f"Provider '{config.PROVIDER}' tidak dikenal. "
            f"Pilih salah satu: {', '.join(_CHAT_BUILDERS)}."
        )
    return builder(config.TEMPERATURE if temperature is None else temperature)


# ---------- Pembuat embedding ----------
def build_embeddings():
    """Buat model embedding untuk vector DB sesuai ``SECBOT_EMBED_PROVIDER``."""
    provider = config.EMBED_PROVIDER
    if provider == "ollama":
        from langchain_ollama import OllamaEmbeddings

        return OllamaEmbeddings(model=config.OLLAMA_EMBED_MODEL, base_url=config.OLLAMA_URL)
    if provider == "gemini":
        from langchain_google_genai import GoogleGenerativeAIEmbeddings

        return GoogleGenerativeAIEmbeddings(
            model=config.GEMINI_EMBED_MODEL,
            google_api_key=_need_key(config.GEMINI_API_KEY, "SECBOT_GEMINI_API_KEY", "gemini"),
        )
    raise ProviderError(
        f"Provider embedding '{provider}' tidak dikenal. Pilih: ollama, gemini."
    )


# ---------- Informasi untuk ditampilkan ----------
def active_chat_model_name() -> str:
    """Nama model chat yang aktif sekarang."""
    return {
        "ollama": config.OLLAMA_LLM_MODEL,
        "gemini": config.GEMINI_MODEL,
        "deepseek": config.DEEPSEEK_MODEL,
    }.get(config.PROVIDER, "?")


def active_embed_model_name() -> str:
    """Nama model embedding yang aktif sekarang."""
    return {
        "ollama": config.OLLAMA_EMBED_MODEL,
        "gemini": config.GEMINI_EMBED_MODEL,
    }.get(config.EMBED_PROVIDER, "?")


def describe() -> str:
    """Ringkasan satu baris konfigurasi aktif, mis. untuk banner CLI."""
    return (
        f"provider={config.PROVIDER} | llm={active_chat_model_name()} | "
        f"embed={config.EMBED_PROVIDER}:{active_embed_model_name()} | "
        f"thinking={'on' if config.THINKING else 'off'}"
    )


def message_text(message) -> str:
    """Ambil teks dari sebuah pesan/response model, apa pun format ``content``-nya.

    Provider tidak seragam: Ollama dan DeepSeek mengembalikan string, sedangkan
    Gemini 3 mengembalikan daftar blok seperti
    ``[{"type": "text", "text": "..."}]``. Blok non-teks (mis. thinking) dilewati
    supaya yang terpakai hanya jawaban sebenarnya.
    """
    content = getattr(message, "content", message)
    if content is None:
        return ""
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, list):
        bagian: list[str] = []
        for blok in content:
            if isinstance(blok, str):
                bagian.append(blok)
            elif isinstance(blok, dict) and blok.get("type", "text") == "text" and blok.get("text"):
                bagian.append(blok["text"])
        return " ".join(bagian).strip()
    return str(content).strip()
