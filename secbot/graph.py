"""Grafik supervisor: **satu pintu masuk** untuk tanya-jawab dan review akses.

Pola *supervisor router*: satu grafik state, satu node router memilih cabang, lalu
kedua cabang menulis ke riwayat pesan yang sama sehingga memori percakapan tetap
nyambung antar-rute.

    START -> router -+-> chat          (ReAct agent + 5 tool)  -+
                     +-> access_review (pipeline 3 agen)       +-> END
    (riwayat pesan + memori percakapan dibagi ke kedua cabang)
"""
from typing import Annotated, TypedDict

from langchain_core.messages import AIMessage, AnyMessage, HumanMessage
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages

from . import router as router_mod
from .agents.access_agents import review_access
from .chat import build_agent
from .llm import build_chat_model, message_text


class BotState(TypedDict):
    """State yang dibagi seluruh node grafik.

    - ``messages``: riwayat percakapan (digabung dengan ``add_messages``)
    - ``route``: hasil keputusan router (``chat`` / ``access_review``)
    - ``request``: data permintaan akses hasil ekstraksi router
    - ``pending_request``: permintaan akses yang menunggu dilengkapi user
      (hanya diisi bila node review meminta kelengkapan data)
    """

    messages: Annotated[list[AnyMessage], add_messages]
    route: str
    request: dict
    pending_request: dict


# ---------- Pembantu teks pesan ----------
def _text_of(message) -> str:
    """Ambil teks sebuah pesan (aman untuk content string maupun list blok)."""
    return message_text(message)


def _last_user_text(state: BotState) -> str:
    """Teks pesan user terakhir pada state."""
    for m in reversed(state.get("messages", []) or []):
        if isinstance(m, HumanMessage):
            return _text_of(m)
    return ""


# ---------- Node ----------
def make_router_node(llm, verbose: bool = True):
    """Buat node router: jalankan :func:`secbot.router.decide` lalu simpan hasilnya ke state.

    Permintaan yang masih menunggu kelengkapan (``pending_request``) ikut dikirim ke
    router supaya jawaban lanjutan user (mis. hanya menyebut port) bisa melengkapinya.
    Bila rutenya bukan review akses, ``pending_request`` dikosongkan agar permintaan
    lama tidak menggantung dan bocor ke giliran berikutnya.
    """

    def router_node(state: BotState) -> dict:
        text = _last_user_text(state)
        pending = state.get("pending_request") or {}
        route, request = router_mod.decide(text, pending, llm)
        if verbose:
            print(f"  [router] -> {route}")

        hasil = {"route": route, "request": request}
        if route != "access_review":
            hasil["pending_request"] = {}
        return hasil

    return router_node


def make_access_review_node(verbose: bool = True):
    """Buat node review akses.

    Bila data belum lengkap, node mengembalikan pesan permintaan kelengkapan dan
    menyimpan permintaan itu sebagai ``pending_request``. Bila lengkap, pipeline 3
    agen dijalankan dan ``pending_request`` dikosongkan kembali.
    """

    def access_review_node(state: BotState) -> dict:
        request = state.get("request") or {}
        if not router_mod.is_complete(request):
            return {
                "messages": [AIMessage(content=router_mod.clarification_message(request))],
                "pending_request": request,
            }

        if verbose:
            print()
        jawaban = review_access(
            request["src_ip"],
            request["dst_ip"],
            int(request["port"]),
            request.get("protocol") or "tcp",
            verbose=verbose,
        )
        return {"messages": [AIMessage(content=jawaban)], "pending_request": {}}

    return access_review_node


# ---------- Grafik ----------
def build_graph(verbose: bool = True):
    """Susun dan compile grafik supervisor dengan memori percakapan in-memory."""
    llm = build_chat_model()
    graph = StateGraph(BotState)
    graph.add_node("router", make_router_node(llm, verbose))
    graph.add_node("chat", build_agent(llm))
    graph.add_node("access_review", make_access_review_node(verbose))

    graph.add_edge(START, "router")
    graph.add_conditional_edges(
        "router",
        lambda state: state["route"],
        {"chat": "chat", "access_review": "access_review"},
    )
    graph.add_edge("chat", END)
    graph.add_edge("access_review", END)

    return graph.compile(checkpointer=MemorySaver())


# ---------- Menjalankan ----------
def _final_answer(graph, cfg: dict) -> str:
    """Ambil pesan AI terakhir (jawaban akhir) dari state grafik."""
    state = graph.get_state(cfg).values or {}
    for m in reversed(state.get("messages", []) or []):
        if isinstance(m, AIMessage) and not getattr(m, "tool_calls", None):
            teks = _text_of(m)
            if teks:
                return teks
    return ""


def run_once(graph, cfg: dict, question: str) -> str:
    """Jalankan satu pertanyaan, tampilkan jejak tool, lalu cetak jawaban akhir sekali."""
    for step in graph.stream({"messages": [("user", question)]}, cfg, stream_mode="updates"):
        for update in (step or {}).values():
            for m in (update or {}).get("messages", []) or []:
                for tc in getattr(m, "tool_calls", []) or []:
                    print(f"  [tool] {tc['name']}({tc['args']})")
    answer = _final_answer(graph, cfg)
    if answer:
        print(f"\nBot > {answer}\n")
    return answer


def main() -> None:
    """CLI: mode sekali jalan (argumen) atau mode interaktif."""
    import sys

    from .llm import ProviderError, describe

    try:
        graph = build_graph()
    except ProviderError as e:
        raise SystemExit(f"\nKonfigurasi model belum lengkap:\n{e}")

    cfg = {"configurable": {"thread_id": "sesi-1"}}  # memori percakapan

    if len(sys.argv) > 1:
        run_once(graph, cfg, " ".join(sys.argv[1:]))
        return

    print(f"Security Assistant siap. ({describe()})")
    print("Ketik 'exit' untuk keluar.\n")
    print("Contoh: 'IP 10.10.5.21 ada di mana dan bagaimana compliance-nya?'")
    print("        'Buka akses dari 172.16.1.10 ke 10.10.6.30 port 1433'\n")
    while True:
        q = input("Anda > ").strip()
        if q.lower() in {"exit", "quit"}:
            break
        if not q:
            continue
        run_once(graph, cfg, q)
