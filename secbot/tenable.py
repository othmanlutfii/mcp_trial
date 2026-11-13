"""Integrasi REST API Tenable.sc untuk Finding VA pada assessment koneksi."""
import ipaddress
import json
import logging
import math
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import requests

from . import config

logger = logging.getLogger(__name__)

MAX_RESULTS = 3
SEVERITY_BY_ID = {
    4: ("Critical", "critical"),
    3: ("High", "high"),
    2: ("Medium", "medium"),
    1: ("Low", "low"),
}
SEVERITY_BY_NAME = {
    "critical": ("Critical", "critical"),
    "high": ("High", "high"),
    "medium": ("Medium", "medium"),
    "low": ("Low", "low"),
}
SEVERITY_KEYS = ("critical", "high", "medium", "low")


class TenableIntegrationError(Exception):
    """Error integrasi yang aman ditampilkan tanpa membocorkan credential."""


class OllamaAnalysisError(Exception):
    """Analisis Ollama gagal setelah seluruh percobaan ulang."""


_database_lock = threading.Lock()
_database_initialized = False


def _normalize_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except (ValueError, AttributeError) as exc:
        raise TenableIntegrationError("IP source atau destination tidak valid.") from exc


def _analysis_url() -> str:
    base_url = config.TENABLE_BASE_URL.rstrip("/")
    parsed = urlsplit(base_url)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise TenableIntegrationError(
            "TENABLE_BASE_URL harus berupa URL HTTPS Tenable.sc yang valid."
        )
    return f"{base_url}/rest/analysis"


def _build_payload(ip: str) -> dict:
    return {
        "type": "vuln",
        "sourceType": "cumulative",
        "query": {
            "tool": "vulndetails",
            "type": "vuln",
            "startOffset": 0,
            "endOffset": MAX_RESULTS,
            "sortField": "vprScore",
            "sortDir": "DESC",
            "filters": [
                {
                    "filterName": "ip",
                    "operator": "=",
                    "value": ip,
                },
                {
                    "filterName": "vprScore",
                    "operator": "=",
                    "value": "8.1-10",
                },
            ],
        },
    }


def _response_page(payload: object) -> tuple[int, int, list[dict]]:
    if not isinstance(payload, dict):
        raise TenableIntegrationError("Respons Tenable bukan objek JSON yang valid.")

    response_data = payload.get("response")
    error_codes = [payload.get("error_code")]
    if not isinstance(response_data, dict):
        response_data = None
    else:
        error_codes.append(response_data.get("error_code"))
    error_code = next(
        (code for code in error_codes if code not in (None, "", 0, "0")),
        None,
    )
    if error_code is not None:
        raise TenableIntegrationError(
            f"Tenable mengembalikan error API (kode {error_code})."
        )
    if response_data is None:
        raise TenableIntegrationError("Struktur response Tenable tidak valid.")

    try:
        total_records = int(response_data["totalRecords"])
        returned_records = int(response_data["returnedRecords"])
    except (KeyError, TypeError, ValueError) as exc:
        raise TenableIntegrationError(
            "Respons Tenable tidak memuat jumlah record yang valid."
        ) from exc

    results = response_data.get("results")
    if (
        total_records < 0
        or returned_records < 0
        or returned_records > total_records
        or not isinstance(results, list)
        or returned_records != len(results)
    ):
        raise TenableIntegrationError("Pagination response Tenable tidak valid.")

    if any(not isinstance(item, dict) for item in results):
        raise TenableIntegrationError("Item vulnerability Tenable tidak valid.")
    return total_records, returned_records, results


def _request_page(
    session: requests.Session, url: str, headers: dict[str, str], payload: dict
) -> object:
    started = time.perf_counter()
    status_code: int | None = None
    verify_tls: str | bool = config.TENABLE_CA_BUNDLE or config.TENABLE_VERIFY_TLS
    if verify_tls is False:
        logger.warning(
            "Tenable TLS certificate verification is disabled; "
            "connection is vulnerable to interception"
        )
    try:
        response = session.post(
            url,
            json=payload,
            headers=headers,
            timeout=(config.TENABLE_CONNECT_TIMEOUT, config.TENABLE_READ_TIMEOUT),
            allow_redirects=False,
            verify=verify_tls,
        )
        status_code = response.status_code
    except requests.exceptions.SSLError as exc:
        elapsed = time.perf_counter() - started
        cause_type = type(exc.__cause__).__name__ if exc.__cause__ else "none"
        logger.error(
            "Tenable request failed status=%s duration=%.3fs error=tls_error "
            "exception_type=%s cause_type=%s",
            status_code,
            elapsed,
            type(exc).__name__,
            cause_type,
        )
        raise TenableIntegrationError(
            "Verifikasi sertifikat TLS Tenable gagal. Periksa sertifikat server "
            "atau konfigurasi CA tepercaya."
        ) from exc
    except requests.exceptions.ProxyError as exc:
        elapsed = time.perf_counter() - started
        logger.error(
            "Tenable request failed status=%s duration=%.3fs error=proxy_error "
            "exception_type=%s",
            status_code,
            elapsed,
            type(exc).__name__,
        )
        raise TenableIntegrationError(
            "Koneksi proxy ke Tenable gagal. Periksa konfigurasi proxy jaringan."
        ) from exc
    except requests.ConnectTimeout as exc:
        elapsed = time.perf_counter() - started
        logger.error(
            "Tenable request failed status=%s duration=%.3fs error=connection_timeout",
            status_code,
            elapsed,
        )
        raise TenableIntegrationError("Koneksi ke Tenable mengalami timeout.") from exc
    except requests.ReadTimeout as exc:
        elapsed = time.perf_counter() - started
        logger.error(
            "Tenable request failed status=%s duration=%.3fs error=request_timeout",
            status_code,
            elapsed,
        )
        raise TenableIntegrationError("Request ke Tenable mengalami timeout.") from exc
    except requests.ConnectionError as exc:
        elapsed = time.perf_counter() - started
        cause_type = type(exc.__cause__).__name__ if exc.__cause__ else "none"
        logger.error(
            "Tenable request failed status=%s duration=%.3fs error=connection_error "
            "exception_type=%s cause_type=%s",
            status_code,
            elapsed,
            type(exc).__name__,
            cause_type,
        )
        raise TenableIntegrationError(
            "Tidak dapat terhubung ke Tenable. Periksa DNS, routing, firewall, "
            "dan akses jaringan dari komputer yang menjalankan aplikasi."
        ) from exc
    except requests.RequestException as exc:
        elapsed = time.perf_counter() - started
        logger.error(
            "Tenable request failed status=%s duration=%.3fs error=request_failed "
            "exception_type=%s",
            status_code,
            elapsed,
            type(exc).__name__,
        )
        raise TenableIntegrationError("Tidak dapat menghubungi Tenable.") from exc

    elapsed = time.perf_counter() - started
    if not 200 <= response.status_code < 300:
        logger.error(
            "Tenable request failed status=%s duration=%.3fs error=http_error",
            response.status_code,
            elapsed,
        )
        if response.status_code in (401, 403):
            raise TenableIntegrationError(
                "Autentikasi Tenable gagal atau credential tidak memiliki izin."
            )
        raise TenableIntegrationError(
            f"Tenable mengembalikan HTTP {response.status_code}."
        )

    try:
        data = response.json()
    except ValueError as exc:
        logger.error(
            "Tenable request failed status=%s duration=%.3fs error=invalid_json",
            response.status_code,
            elapsed,
        )
        raise TenableIntegrationError("Respons Tenable bukan JSON yang valid.") from exc

    try:
        _response_page(data)
    except TenableIntegrationError:
        logger.error(
            "Tenable request failed status=%s duration=%.3fs error=invalid_api_response",
            response.status_code,
            elapsed,
        )
        raise

    logger.info(
        "Tenable request completed status=%s duration=%.3fs start_offset=%s",
        response.status_code,
        elapsed,
        payload["query"]["startOffset"],
    )
    return data


def _severity_details(raw_severity: object) -> tuple[str | None, str | None]:
    severity_name: str | None = None
    severity_id: object = None
    if isinstance(raw_severity, dict):
        name = raw_severity.get("name")
        severity_name = name if isinstance(name, str) else None
        severity_id = raw_severity.get("id")
    elif isinstance(raw_severity, str):
        severity_name = raw_severity
    elif isinstance(raw_severity, int) and not isinstance(raw_severity, bool):
        severity_id = raw_severity

    try:
        numeric_id = int(severity_id) if severity_id is not None else None
    except (TypeError, ValueError):
        numeric_id = None

    if numeric_id in SEVERITY_BY_ID:
        canonical_name, category = SEVERITY_BY_ID[numeric_id]
        return severity_name or canonical_name, category
    if numeric_id == 0:
        return severity_name, None

    if severity_name:
        mapped = SEVERITY_BY_NAME.get(severity_name.casefold())
        if mapped:
            return severity_name, mapped[1]
    return severity_name, None


def _optional_text(value: object, field: str) -> str | None:
    if value is None:
        return None
    if isinstance(value, (str, int, float)) and not isinstance(value, bool):
        return str(value)
    raise TenableIntegrationError(f"Field {field} pada respons Tenable tidak valid.")


def _cve_text(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return ",".join(value)
    raise TenableIntegrationError("Field cve pada respons Tenable tidak valid.")


def _json_text(value: object, field: str) -> str | None:
    if value is None:
        return None
    try:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise TenableIntegrationError(
            f"Field {field} pada respons Tenable tidak valid."
        ) from exc


def _record_ip(item: dict, queried_ip: str) -> str:
    value = item.get("ip")
    if isinstance(value, str) and value.strip():
        ip = _normalize_ip(value)
    else:
        ips_value = item.get("ips")
        candidates = ips_value if isinstance(ips_value, list) else (
            ips_value.split(",") if isinstance(ips_value, str) else []
        )
        normalized = []
        for candidate in candidates:
            if isinstance(candidate, str) and candidate.strip():
                try:
                    normalized.append(_normalize_ip(candidate))
                except TenableIntegrationError:
                    continue
        ip = (
            queried_ip
            if queried_ip in normalized
            else (normalized[0] if normalized else queried_ip)
        )
    if ip != queried_ip:
        raise TenableIntegrationError(
            "Tenable mengembalikan vulnerability di luar IP yang diminta."
        )
    return ip


def _transform_results(ips: list[str], results: list[dict]) -> dict:
    records: list[tuple[dict, str | None]] = []
    seen: set[tuple[str, str]] = set()
    if len(results) > MAX_RESULTS:
        raise TenableIntegrationError(
            f"Tenable mengembalikan lebih dari {MAX_RESULTS} kerentanan untuk satu IP."
        )

    for item in results:
        if not isinstance(item, dict):
            raise TenableIntegrationError("Item vulnerability Tenable tidak valid.")
        queried_ip = next(
            (ip for ip in ips if item.get("ip") == ip or item.get("ips")),
            ips[0] if ips else "",
        )
        ip = _record_ip(item, queried_ip)
        try:
            vpr_score = float(item["vprScore"])
        except (KeyError, TypeError, ValueError) as exc:
            raise TenableIntegrationError(
                "Field vprScore pada respons Tenable tidak valid."
            ) from exc
        if not math.isfinite(vpr_score):
            raise TenableIntegrationError("Field vprScore pada respons Tenable tidak valid.")
        severity, category = _severity_details(item.get("severity"))
        plugin_id = _optional_text(item.get("pluginID"), "pluginID")
        vuln_uuid = _optional_text(item.get("vulnUUID"), "vulnUUID")
        if not plugin_id:
            plugin_id = vuln_uuid
        if not plugin_id:
            raise TenableIntegrationError(
                "Respons Tenable tidak memuat pluginID atau vulnUUID untuk kunci kerentanan."
            )
        try:
            cvss_score = item.get("cvssV3BaseScore")
            epss_score = item.get("epssScore")
            cvss_score = float(cvss_score) if cvss_score is not None else None
            epss_score = float(epss_score) if epss_score is not None else None
        except (TypeError, ValueError) as exc:
            raise TenableIntegrationError(
                "Field cvssV3BaseScore atau epssScore pada respons Tenable tidak valid."
            ) from exc
        vulnerability = {
            "ip": ip,
            "plugin_id": plugin_id,
            "plugin_name": _optional_text(item.get("pluginName"), "pluginName"),
            "cve": _cve_text(item.get("cve")),
            "vpr_score": vpr_score,
            "severity": severity,
            "risk_factor": _optional_text(item.get("riskFactor"), "riskFactor"),
            "cvss_v3_base_score": cvss_score,
            "epss_score": epss_score,
            "exploit_available": _json_text(item.get("exploitAvailable"), "exploitAvailable"),
            "exploit_frameworks": _json_text(item.get("exploitFrameworks"), "exploitFrameworks"),
            "port": _optional_text(item.get("port"), "port"),
            "protocol": _optional_text(item.get("protocol"), "protocol"),
            "dns_name": _optional_text(item.get("dnsName"), "dnsName"),
            "operating_system": _optional_text(item.get("operatingSystem"), "operatingSystem"),
            "synopsis": _optional_text(item.get("synopsis"), "synopsis"),
            "description": _optional_text(item.get("description"), "description"),
            "solution": _optional_text(item.get("solution"), "solution"),
            "vuln_uuid": vuln_uuid,
        }
        key = (ip, plugin_id)
        if key in seen:
            continue
        seen.add(key)
        records.append((vulnerability, category))

    records.sort(key=lambda record: record[0]["vpr_score"], reverse=True)
    summaries = {
        ip: {
            "ip": ip,
            "total_findings": 0,
            "severity_summary": {key: 0 for key in SEVERITY_KEYS},
        }
        for ip in ips
    }
    overall_severity = {key: 0 for key in SEVERITY_KEYS}

    for vulnerability, category in records:
        summary = summaries[vulnerability["ip"]]
        summary["total_findings"] += 1
        if category is not None:
            summary["severity_summary"][category] += 1
            overall_severity[category] += 1

    return {
        "ip_summary": list(summaries.values()),
        "overall_summary": {
            "total_ips": len(ips),
            "total_findings": len(records),
            "severity_summary": overall_severity,
        },
        "vulnerabilities": [record[0] for record in records],
    }


def _initialize_database() -> None:
    global _database_initialized
    if _database_initialized:
        return
    with _database_lock:
        if _database_initialized:
            return
        database_path = Path(config.TENABLE_DB_PATH)
        database_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(database_path, timeout=30)
        try:
            migration_path = config.PROJECT_ROOT / "migrations" / "002_tenable_vulnerabilities.sql"
            connection.executescript(migration_path.read_text(encoding="utf-8"))
            connection.commit()
        finally:
            connection.close()
        _database_initialized = True


def _persist_vulnerabilities(records: list[dict]) -> None:
    if not records:
        return
    columns = (
        "ip", "plugin_id", "plugin_name", "severity", "risk_factor", "vpr_score",
        "cvss_v3_base_score", "epss_score", "cve", "exploit_available",
        "exploit_frameworks", "port", "protocol", "dns_name", "operating_system",
        "synopsis", "description", "solution", "vuln_uuid",
    )
    updates = ", ".join(
        f"{column}=excluded.{column}" for column in columns if column not in {"ip", "plugin_id"}
    )
    sql = (
        f"INSERT INTO tenable_vulnerabilities ({', '.join(columns)}, updated_at) "
        f"VALUES ({', '.join('?' for _ in columns)}, ?) "
        f"ON CONFLICT(ip, plugin_id) DO UPDATE SET {updates}, updated_at=excluded.updated_at"
    )
    try:
        _initialize_database()
        connection = sqlite3.connect(config.TENABLE_DB_PATH, timeout=30)
        try:
            now = datetime.now(timezone.utc).isoformat()
            with connection:
                connection.executemany(
                    sql,
                    [tuple(record.get(column) for column in columns) + (now,) for record in records],
                )
        finally:
            connection.close()
    except (sqlite3.Error, OSError) as exc:
        logger.exception("Could not save Tenable vulnerability records")
        raise TenableIntegrationError(
            "Gagal menyimpan data kerentanan Tenable ke database."
        ) from exc


def _query_persisted_vulnerabilities(records: list[dict]) -> list[dict]:
    if not records:
        return []
    clauses = " OR ".join("(ip=? AND plugin_id=?)" for _ in records)
    parameters = [value for record in records for value in (record["ip"], record["plugin_id"])]
    try:
        _initialize_database()
        connection = sqlite3.connect(config.TENABLE_DB_PATH, timeout=30)
        connection.row_factory = sqlite3.Row
        try:
            rows = connection.execute(
                "SELECT ip, plugin_id, plugin_name, severity, vpr_score, cve, "
                "synopsis, description, solution, ollama_analysis "
                f"FROM tenable_vulnerabilities WHERE {clauses}",
                parameters,
            ).fetchall()
            return [dict(row) for row in rows]
        finally:
            connection.close()
    except (sqlite3.Error, OSError) as exc:
        logger.exception("Could not read Tenable vulnerability records")
        raise TenableIntegrationError(
            "Gagal membaca kembali data kerentanan Tenable dari database."
        ) from exc


def _save_analysis(ip: str, plugin_id: str, analysis: str) -> None:
    try:
        connection = sqlite3.connect(config.TENABLE_DB_PATH, timeout=30)
        try:
            with connection:
                connection.execute(
                    "UPDATE tenable_vulnerabilities SET ollama_analysis=?, updated_at=? "
                    "WHERE ip=? AND plugin_id=?",
                    (analysis, datetime.now(timezone.utc).isoformat(), ip, plugin_id),
                )
        finally:
            connection.close()
    except (sqlite3.Error, OSError) as exc:
        logger.exception("Could not cache Ollama Tenable analysis")
        raise TenableIntegrationError(
            "Gagal menyimpan hasil analisis Ollama ke database."
        ) from exc


def _analysis_prompt(record: dict) -> str:
    def value(field: str) -> str:
        return "" if record.get(field) is None else str(record[field])

    return (
        "Kamu adalah analis keamanan siber. Analisis kerentanan berikut berdasarkan data Tenable. Gunakan hanya data yang diberikan, jangan mengarang.\n"
        f"- IP: {value('ip')}\n"
        f"- Plugin: {value('plugin_name')}\n"
        f"- VPR Score: {value('vpr_score')} | Severity: {value('severity')}\n"
        f"- CVE: {value('cve')}\n"
        f"- Synopsis: {value('synopsis')}\n"
        f"- Description: {value('description')}\n"
        f"- Solution: {value('solution')}\n"
        "Jawab dalam Bahasa Indonesia dengan format:\n"
        "1. Ringkasan Kerentanan (maks. 2 kalimat)\n"
        "2. Dampak Potensial terhadap sistem\n"
        "3. Tingkat Prioritas (Tinggi/Sedang/Rendah) beserta alasannya\n"
        "4. Rekomendasi Perbaikan (berdasarkan field Solution)"
    )


def _request_ollama_analysis(record: dict) -> str:
    response = requests.post(
        f"{config.OLLAMA_URL.rstrip('/')}/api/chat",
        json={
            "model": config.OLLAMA_LLM_MODEL,
            "messages": [{"role": "user", "content": _analysis_prompt(record)}],
            "stream": False,
        },
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        timeout=(config.OLLAMA_CONNECT_TIMEOUT, config.OLLAMA_READ_TIMEOUT),
    )
    if not 200 <= response.status_code < 300:
        raise OllamaAnalysisError(f"Ollama mengembalikan HTTP {response.status_code}.")
    try:
        body = response.json()
    except ValueError as exc:
        raise OllamaAnalysisError("Ollama mengembalikan JSON yang tidak valid.") from exc
    message = body.get("message") if isinstance(body, dict) else None
    content = message.get("content") if isinstance(message, dict) else None
    if not isinstance(content, str) or not content.strip():
        raise OllamaAnalysisError("Ollama tidak mengembalikan teks analisis.")
    return content.strip()


def _analyze_with_ollama(record: dict) -> str:
    last_error: Exception | None = None
    for attempt in range(3):
        try:
            return _request_ollama_analysis(record)
        except requests.Timeout as exc:
            last_error = exc
            logger.warning("Ollama Tenable analysis timed out; attempt=%s/3", attempt + 1)
        except requests.RequestException as exc:
            last_error = exc
            logger.warning(
                "Ollama Tenable analysis request failed; attempt=%s/3 error=%s",
                attempt + 1,
                type(exc).__name__,
            )
        except OllamaAnalysisError as exc:
            last_error = exc
            logger.warning(
                "Ollama Tenable analysis failed; attempt=%s/3 error=%s",
                attempt + 1,
                str(exc),
            )
    if isinstance(last_error, requests.Timeout):
        raise OllamaAnalysisError(
            "Ollama timeout setelah 3 percobaan (1 request awal dan 2 retry)."
        ) from last_error
    raise OllamaAnalysisError(
        f"Analisis Ollama gagal setelah 3 percobaan: {last_error or 'kesalahan tidak diketahui'}"
    ) from last_error


def _summaries(ips: list[str], vulnerabilities: list[dict]) -> dict:
    summaries = {
        ip: {
            "ip": ip,
            "total_findings": 0,
            "severity_summary": {key: 0 for key in SEVERITY_KEYS},
        }
        for ip in ips
    }
    overall_severity = {key: 0 for key in SEVERITY_KEYS}
    for vulnerability in vulnerabilities:
        summary = summaries[vulnerability["ip"]]
        summary["total_findings"] += 1
        _, category = _severity_details(vulnerability.get("severity"))
        if category is not None:
            summary["severity_summary"][category] += 1
            overall_severity[category] += 1
    return {
        "ip_summary": list(summaries.values()),
        "overall_summary": {
            "total_ips": len(ips),
            "total_findings": len(vulnerabilities),
            "severity_summary": overall_severity,
        },
    }


def get_connection_findings(source_ip: str, destination_ip: str) -> dict:
    """Ambil, persist, dan analisis 3 temuan VPR teratas per IP dengan Ollama."""
    ips = [_normalize_ip(source_ip), _normalize_ip(destination_ip)]
    missing = [
        name
        for name, value in (
            ("TENABLE_BASE_URL", config.TENABLE_BASE_URL),
            ("ACCESS_KEY", config.ACCESS_KEY),
            ("SECRET_KEY", config.SECRET_KEY),
        )
        if not value
    ]
    if missing:
        logger.error("Tenable integration is not configured; missing=%s", ",".join(missing))
        raise TenableIntegrationError(
            "Integrasi Tenable belum dikonfigurasi: " + ", ".join(missing) + "."
        )

    url = _analysis_url()
    headers = {
        "x-apikey": f"accesskey={config.ACCESS_KEY}; secretkey={config.SECRET_KEY}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    records: list[dict] = []

    session = requests.Session()
    try:
        for ip in ips:
            payload = _build_payload(ip)
            page_data = _request_page(session, url, headers, payload)
            _, _, results = _response_page(page_data)
            records.extend(_transform_results([ip], results)["vulnerabilities"])
    finally:
        session.close()

    unique_records = list({
        (record["ip"], record["plugin_id"]): record for record in records
    }.values())
    unique_records.sort(key=lambda record: record["vpr_score"], reverse=True)
    _persist_vulnerabilities(unique_records)

    # Analysis inputs are deliberately read back from SQLite, never reused from the API response.
    persisted = _query_persisted_vulnerabilities(unique_records)
    persisted.sort(
        key=lambda record: record["vpr_score"] if record["vpr_score"] is not None else -1,
        reverse=True,
    )
    reports = []
    for ip in ips:
        ip_records = [record for record in persisted if record["ip"] == ip]
        if not ip_records:
            reports.append({
                "ip": ip,
                "message": "Tidak ada kerentanan VPR 8.1-10 yang ditemukan",
                "vulnerabilities": [],
            })
            continue
        reported_vulnerabilities = []
        for record in ip_records:
            analysis = record["ollama_analysis"]
            error = None
            if not analysis:
                try:
                    analysis = _analyze_with_ollama(record)
                    _save_analysis(record["ip"], record["plugin_id"], analysis)
                except OllamaAnalysisError as exc:
                    error = str(exc)
            reported_vulnerabilities.append({
                **{key: value for key, value in record.items() if key != "ollama_analysis"},
                "ollama_analysis": analysis,
                "ollama_error": error,
            })
        reports.append({
            "ip": ip,
            "vulnerabilities": reported_vulnerabilities,
        })

    summaries = _summaries(ips, unique_records)
    analysis_errors = [
        item["ollama_error"]
        for report in reports
        for item in report.get("vulnerabilities", [])
        if item.get("ollama_error")
    ]
    return {
        **summaries,
        "vulnerabilities": [
            item
            for report in reports
            for item in report.get("vulnerabilities", [])
        ],
        "ip_reports": reports,
        "analysis_status": (
            "failed" if analysis_errors and not any(
                item.get("ollama_analysis")
                for report in reports
                for item in report.get("vulnerabilities", [])
            ) else "partial" if analysis_errors else "success"
        ),
        "analysis_errors": analysis_errors,
    }
