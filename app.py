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
import re
import time

from flask import Flask, render_template, request

from secbot import datasource, policies
from secbot.assessment import assess_connection_data
from secbot.compliance import compliance_status
from secbot.splunk_views import splunk_assets_bp

app = Flask(__name__)
app.register_blueprint(splunk_assets_bp)


def _clean_ai_answer(answer: str) -> str:
    """Rapikan Markdown sederhana dari jawaban reviewer sebelum ditampilkan."""
    lines = []
    for line in answer.splitlines():
        line = re.sub(r"^\s{0,3}#{1,6}\s*", "", line)
        bullet = re.match(r"^(\s*)[-*]\s+", line)
        if bullet:
            line = f"{bullet.group(1)}• {line[bullet.end():]}"
        line = re.sub(r"(\*\*|__)(.+?)\1", r"\2", line)
        line = re.sub(r"(?<!\w)(\*|_)(.+?)\1(?!\w)", r"\2", line)
        line = re.sub(r"`([^`]+)`", r"\1", line)
        lines.append(line.rstrip())

    return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()


def _executive_summary(result: dict) -> dict:
    """Susun ringkasan awam hanya dari hasil assessment deterministik."""
    decisions = {
        "DENY": "Akses tidak direkomendasikan untuk dibuka.",
        "REVIEW_REQUIRED": "Akses belum dapat direkomendasikan sebelum ditinjau lebih lanjut.",
        "APPROVE_WITH_CONDITIONS": "Akses dapat diproses setelah persyaratan dipenuhi.",
        "APPROVE": "Akses dapat dilanjutkan berdasarkan pemeriksaan yang tersedia.",
    }
    risk_descriptions = {
        "LOW": "Risiko relatif rendah menurut aturan yang diperiksa.",
        "MEDIUM": "Ada risiko yang perlu diperhatikan sebelum akses dijalankan.",
        "HIGH": "Risiko tinggi; perlu peninjauan dan tindak lanjut sebelum akses.",
        "CRITICAL": "Risiko sangat tinggi; jangan lanjutkan sebelum masalah ditangani.",
    }
    level_descriptions = {
        "ALLOW": "sesuai ketentuan port",
        "RESTRICTED": "memerlukan pemenuhan persyaratan",
        "PROHIBITED": "dilarang oleh aturan port",
    }

    decision = result.get("preliminary_decision", "UNKNOWN")
    risk_level = result.get("risk_level", "UNKNOWN")
    request_data = result.get("request", {})
    port_info = result.get("port_info", {})
    risk_text = risk_descriptions.get(
        risk_level, "Tingkat risiko belum dapat dijelaskan dari hasil yang tersedia."
    )
    overview = (
        f"{decisions.get(decision, 'Keputusan belum dapat ditentukan.')} "
        f"{risk_text} Skor risiko: {result.get('risk_score', 'tidak tersedia')}/100."
    )

    key_points = [
        (
            f"Koneksi yang dinilai: {request_data.get('src_ip', '-')}"
            f" ke {request_data.get('dst_ip', '-')}, "
            f"port {request_data.get('port', '-')}/{request_data.get('protocol', '-')}"
            f" ({port_info.get('service', 'layanan tidak diketahui')})."
        ),
        (
            f"Aturan port: {level_descriptions.get(port_info.get('level'), 'status belum diketahui')}."
        ),
    ]
    concerns: list[str] = []
    source_side = result.get("source", {})
    destination_side = result.get("destination", {})
    if (
        source_side.get("registered")
        and destination_side.get("registered")
        and source_side.get("asset_type") == "server"
        and destination_side.get("asset_type") == "server"
    ):
        source_environment = policies.normalize_environment(
            source_side.get("environment")
        )
        destination_environment = policies.normalize_environment(
            destination_side.get("environment")
        )
        if (
            source_environment
            and destination_environment
            and source_environment != destination_environment
        ):
            environment_result = policies.environment_rule(
                source_environment, destination_environment
            )
            key_points.append(
                f"Koneksi lintas environment {source_environment} → "
                f"{destination_environment}: {environment_result['note']} "
                f"(aturan {environment_result['rule']})."
            )
            if environment_result["level"] == "CONDITIONAL":
                concerns.append(
                    f"Akses lintas environment {source_environment} → "
                    f"{destination_environment} bersyarat: "
                    f"{environment_result['note']}."
                )
            elif environment_result["level"] == "REVIEW":
                concerns.append(
                    f"Pasangan lintas environment {source_environment} → "
                    f"{destination_environment} belum dapat dipastikan; "
                    f"{environment_result['note']}."
                )

    compliance_summaries = []
    for label, side in (
        ("Source", result.get("source", {})),
        ("Destination", result.get("destination", {})),
    ):
        ip = side.get("ip", "-")
        if not side.get("registered"):
            compliance_summaries.append(
                f"{label} {ip}: belum dapat dinilai (aset tidak ditemukan di CMDB)"
            )
            concerns.append(
                f"Lengkapi data aset dan kontrol untuk {label.lower()} {ip} agar compliance dapat dinilai."
            )
            continue

        hostname = side.get("hostname", ip)
        required_controls = [
            str(control).upper()
            for control in side.get("required_controls", [])
        ]
        active_controls = [
            control
            for control in ("EDR", "PAM", "VA")
            if side.get(control.lower()) is True
        ]
        missing_controls = side.get("gate_missing", [])
        if side.get("gate") == "PASS":
            compliance_status = "lengkap"
        elif side.get("gate") == "FAIL":
            compliance_status = (
                "belum lengkap; belum aktif "
                + (", ".join(missing_controls) or "kontrol wajib")
            )
        else:
            compliance_status = "status kewajiban kontrol belum dapat ditentukan"
        required_text = ", ".join(required_controls) or "belum teridentifikasi"
        active_text = ", ".join(active_controls) or "tidak ada yang tercatat aktif"
        compliance_summaries.append(
            f"{label} {hostname} ({ip}): {compliance_status} "
            f"(wajib: {required_text}; aktif: {active_text})"
        )

        if side.get("gate") == "FAIL":
            missing = ", ".join(missing_controls) or "kontrol wajib"
            concerns.append(
                f"Aktifkan/perbaiki kontrol {missing} pada aset {label.lower()} {hostname}."
            )
        elif side.get("gate") == "UNKNOWN":
            concerns.append(
                f"Konfirmasi kontrol wajib untuk aset {label.lower()} {hostname}; "
                "aturan belum menetapkan status kontrolnya."
            )

        vuln = side.get("vuln", {})
        counts = vuln.get("counts", {})
        if vuln.get("scanned"):
            severity_counts = [
                f"{severity} {count}"
                for severity, count in counts.items()
                if count
            ]
            key_points.append(
                f"Data VA lokal {label.lower()}: "
                + (", ".join(severity_counts) if severity_counts else "tidak ada temuan tercatat")
                + "."
            )
        tenable_findings = result.get("finding_va", {})
        tenable_vulnerabilities = (
            tenable_findings.get("vulnerabilities", [])
            if result.get("finding_va_status") == "success"
            and isinstance(tenable_findings, dict)
            else []
        )
        high_va_found = (
            side.get("asset_type") == "server"
            and (
                any(
                    counts.get(severity, 0) > 0
                    for severity in ("High", "Critical")
                )
                or any(
                    isinstance(item.get("cvss"), (int, float))
                    and item["cvss"] > 8
                    for item in vuln.get("top", [])
                    if isinstance(item, dict)
                )
                or any(
                    item.get("ip") == ip
                    and isinstance(item.get("ollama_analysis"), str)
                    and item["ollama_analysis"].strip()
                    and (
                        (
                            isinstance(item.get("vpr_score"), (int, float))
                            and item["vpr_score"] > 8
                        )
                        or (
                            isinstance(item.get("severity"), str)
                            and item["severity"].casefold() in {"high", "critical"}
                        )
                    )
                    for item in tenable_vulnerabilities
                    if isinstance(item, dict)
                )
            )
        )
        if high_va_found:
            concerns.append(
                f"Temuan VA severity High/Critical atau skor VPR/CVSS di atas 8 "
                f"pada server {hostname} wajib ditindaklanjuti oleh tim server "
                "sesuai SLA severity dan environment. Setelah perbaikan, lakukan "
                "VA ulang untuk memastikan temuan tertutup."
            )
        elif side.get("asset_type") != "endpoint":
            key_points.append(
                f"Data VA lokal untuk aset {label.lower()} {hostname} belum tersedia."
            )
            concerns.append(
                f"Lakukan atau lengkapi Vulnerability Assessment untuk aset {label.lower()} {hostname}."
            )

    key_points.append("Compliance kontrol: " + "; ".join(compliance_summaries) + ".")

    for item in result.get("hard_blocks", []):
        concerns.append(f"Aturan memblokir permintaan ini: {item}.")
    for item in result.get("conditions", []):
        concerns.append(f"Persyaratan yang harus dipenuhi: {item}.")
    for item in result.get("review_reasons", []):
        concerns.append(f"Perlu ditinjau: {item}.")

    if not concerns:
        concerns.append(
            "Tidak ada persyaratan tambahan yang tercatat; tetap pastikan detail "
            "koneksi sesuai kebutuhan operasional."
        )

    return {
        "overview": overview,
        "key_points": list(dict.fromkeys(key_points)),
        "concerns": list(dict.fromkeys(concerns)),
    }


def _parse_port(raw: str) -> tuple[int | None, str | None]:
    """Kembalikan ``(port, error)``; salah satu bernilai ``None``."""
    try:
        port = int(raw)
    except (TypeError, ValueError):
        return None, "Port harus berupa angka."
    if not 1 <= port <= 65535:
        return None, "Port harus berada di rentang 1-65535."
    return port, None


def _run_ai_review(
    src_ip: str,
    dst_ip: str,
    port: int,
    assessment: dict,
    protocol: str = "tcp",
) -> tuple[str, float]:
    """Jalankan pipeline 3 agen yang sama dengan chatbot dan hitung durasinya.

    Hasil assessment deterministik dari halaman web dipakai ulang agar tidak perlu
    satu putaran LLM tambahan.
    """
    from secbot.agents.access_agents import review_access

    started = time.perf_counter()
    answer = review_access(
        src_ip,
        dst_ip,
        port,
        protocol=protocol,
        verbose=False,
        assessment=assessment,
    )
    return answer, time.perf_counter() - started


@app.route("/", methods=["GET", "POST"])
def assessment():
    form = {
        "src_ip": "",
        "dst_ip": "",
        "port": "",
        "service": "",
        "protocol": "tcp",
    }
    errors: list[str] = []
    result = None
    ai_answer = None
    ai_error = None
    ai_elapsed = None

    if request.method == "POST":
        form = {
            key: request.form.get(key, "tcp" if key == "protocol" else "").strip()
            for key in form
        }

        for key, label in (("src_ip", "IP source"), ("dst_ip", "IP destination")):
            if not form[key]:
                errors.append(f"{label} wajib diisi.")
            elif not datasource.is_valid_ip(form[key]):
                errors.append(f"{label} '{form[key]}' bukan format IP yang valid.")

        port, port_error = _parse_port(form["port"])
        if port_error:
            errors.append(port_error)
        if not form["service"]:
            errors.append("Service wajib diisi.")
        elif len(form["service"]) > 100:
            errors.append("Service maksimal 100 karakter.")

        if form["protocol"].lower() not in {"tcp", "udp"}:
            errors.append("Protocol harus TCP atau UDP.")
        else:
            form["protocol"] = form["protocol"].lower()

        if not errors:
            result = assess_connection_data(
                form["src_ip"], form["dst_ip"], port, form["protocol"]
            )
            if "error" in result:
                errors.append(result["error"])
                result = None
            else:
                result["executive_summary"] = _executive_summary(result)
                try:
                    ai_answer, ai_elapsed = _run_ai_review(
                        form["src_ip"],
                        form["dst_ip"],
                        port,
                        result,
                        form["protocol"],
                    )
                    ai_answer = _clean_ai_answer(ai_answer)
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
