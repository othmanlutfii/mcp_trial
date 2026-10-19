"""UI web sederhana (Flask) untuk dua pemeriksaan keamanan.

Halaman:
- ``/``          assessment pembukaan akses (source IP, destination IP, port)
- ``/compliance`` cek compliance satu IP

Halaman assessment menjalankan pipeline 3 agen yang sama dengan chatbot
(``review_access``), jadi narasi keputusannya identik dengan perintah CLI
``Buka akses dari ... ke ... port ...``. Halaman compliance tetap deterministik
tanpa LLM. Jalankan dengan ``python app.py``.
"""
import os
import time

from flask import Flask, render_template, request

from secbot import datasource
from secbot.assessment import assess_connection_data
from secbot.compliance import compliance_status

app = Flask(__name__)


def _parse_port(raw: str) -> tuple[int | None, str | None]:
    """Kembalikan ``(port, error)``; salah satu bernilai ``None``."""
    try:
        port = int(raw)
    except (TypeError, ValueError):
        return None, "Port harus berupa angka."
    if not 1 <= port <= 65535:
        return None, "Port harus berada di rentang 1-65535."
    return port, None


def _run_ai_review(src_ip: str, dst_ip: str, port: int, assessment: dict) -> tuple[str, float]:
    """Jalankan pipeline 3 agen yang sama dengan chatbot dan hitung durasinya.

    Hasil assessment deterministik dari halaman web dipakai ulang agar tidak perlu
    satu putaran LLM tambahan.
    """
    from secbot.agents.access_agents import review_access

    started = time.perf_counter()
    answer = review_access(src_ip, dst_ip, port, verbose=False, assessment=assessment)
    return answer, time.perf_counter() - started


@app.route("/", methods=["GET", "POST"])
def assessment():
    form = {"src_ip": "", "dst_ip": "", "port": ""}
    errors: list[str] = []
    result = None
    ai_answer = None
    ai_error = None
    ai_elapsed = None

    if request.method == "POST":
        form = {key: request.form.get(key, "").strip() for key in form}

        for key, label in (("src_ip", "IP source"), ("dst_ip", "IP destination")):
            if not form[key]:
                errors.append(f"{label} wajib diisi.")
            elif not datasource.is_valid_ip(form[key]):
                errors.append(f"{label} '{form[key]}' bukan format IP yang valid.")

        port, port_error = _parse_port(form["port"])
        if port_error:
            errors.append(port_error)

        if not errors:
            result = assess_connection_data(form["src_ip"], form["dst_ip"], port)
            if "error" in result:
                errors.append(result["error"])
                result = None
            else:
                try:
                    ai_answer, ai_elapsed = _run_ai_review(form["src_ip"], form["dst_ip"], port, result)
                except Exception as exc:  # tampilkan kegagalan provider tanpa mematikan halaman
                    app.logger.exception("Analisis AI gagal")
                    ai_error = str(exc) or exc.__class__.__name__

    return render_template(
        "assessment.html",
        active="assessment",
        form=form,
        errors=errors,
        result=result,
        ai_answer=ai_answer,
        ai_error=ai_error,
        ai_elapsed=ai_elapsed,
    )


@app.route("/compliance", methods=["GET", "POST"])
def compliance():
    form = {"ip": ""}
    errors: list[str] = []
    result = None
    asset = None
    terpenuhi = 0

    if request.method == "POST":
        form["ip"] = request.form.get("ip", "").strip()

        if not form["ip"]:
            errors.append("IP wajib diisi.")
        elif not datasource.is_valid_ip(form["ip"]):
            errors.append(f"'{form['ip']}' bukan format IP yang valid.")
        else:
            result = compliance_status(form["ip"])
            if "error" in result:
                errors.append(result["error"])
                result = None
            else:
                asset = datasource.find_asset(form["ip"])
                terpenuhi = len(result["kontrol_wajib"]) - len(result["kontrol_belum_terpenuhi"])

    return render_template(
        "compliance.html",
        active="compliance",
        form=form,
        errors=errors,
        result=result,
        asset=asset,
        terpenuhi=terpenuhi,
    )


if __name__ == "__main__":
    app.run(
        host=os.getenv("WEB_HOST", "127.0.0.1"),
        port=int(os.getenv("WEB_PORT", "5000")),
        debug=os.getenv("WEB_DEBUG", "").lower() in {"1", "true", "yes"},
    )
