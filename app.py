"""UI web sederhana (Flask) untuk dua pemeriksaan keamanan.

Halaman:
- ``/``          assessment pembukaan akses (source IP, destination IP, port)
- ``/compliance`` cek compliance satu IP

Semua perhitungan memakai logika deterministik yang sama dengan CLI; UI hanya
menampilkan hasilnya. Jalankan dengan ``python app.py``.
"""
import os

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


@app.route("/", methods=["GET", "POST"])
def assessment():
    form = {"src_ip": "", "dst_ip": "", "port": ""}
    errors: list[str] = []
    result = None

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

    return render_template(
        "assessment.html",
        active="assessment",
        form=form,
        errors=errors,
        result=result,
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
