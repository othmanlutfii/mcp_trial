"""Integrasi REST API Tenable.sc untuk Finding VA pada assessment koneksi."""
import ipaddress
import logging
import math
import time
from urllib.parse import urlsplit

import requests

from . import config

logger = logging.getLogger(__name__)

PAGE_SIZE = 500
MIN_VPR_SCORE = 8.0
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


def _build_payload(ips: list[str], start_offset: int) -> dict:
    return {
        "type": "vuln",
        "sourceType": "cumulative",
        "query": {
            "tool": "vulndetails",
            "type": "vuln",
            "startOffset": start_offset,
            "endOffset": start_offset + PAGE_SIZE,
            "sortField": "vprScore",
            "sortDir": "DESC",
            "filters": [
                {
                    "filterName": "ip",
                    "operator": "=",
                    "value": ",".join(ips),
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


def _transform_results(ips: list[str], results: list[dict]) -> dict:
    requested_ips = set(ips)
    records: list[tuple[dict, str | None]] = []
    seen: set[tuple[object, ...]] = set()

    for item in results:
        ip_value = item.get("ip")
        if not isinstance(ip_value, str):
            raise TenableIntegrationError("Field ip pada respons Tenable tidak valid.")
        ip = _normalize_ip(ip_value)
        if ip not in requested_ips:
            raise TenableIntegrationError(
                "Tenable mengembalikan vulnerability di luar IP yang diminta."
            )

        try:
            vpr_score = float(item["vprScore"])
        except (KeyError, TypeError, ValueError) as exc:
            raise TenableIntegrationError(
                "Field vprScore pada respons Tenable tidak valid."
            ) from exc
        if not math.isfinite(vpr_score):
            raise TenableIntegrationError("Field vprScore pada respons Tenable tidak valid.")
        if vpr_score <= MIN_VPR_SCORE:
            continue

        severity, category = _severity_details(item.get("severity"))
        vulnerability = {
            "ip": ip,
            "plugin_id": _optional_text(item.get("pluginID"), "pluginID"),
            "plugin_name": _optional_text(item.get("pluginName"), "pluginName"),
            "cve": _cve_text(item.get("cve")),
            "vpr_score": vpr_score,
            "severity": severity,
            "synopsis": _optional_text(item.get("synopsis"), "synopsis"),
            "solution": _optional_text(item.get("solution"), "solution"),
        }
        # Keep distinct host/port records while removing repeated page records.
        key = (
            tuple(vulnerability[field] for field in vulnerability),
            _optional_text(item.get("id"), "id"),
            _optional_text(item.get("port"), "port"),
            _optional_text(item.get("protocol"), "protocol"),
        )
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


def get_connection_findings(source_ip: str, destination_ip: str) -> dict:
    """Ambil seluruh temuan VPR > 8 untuk IP source dan destination."""
    ips = list(dict.fromkeys(
        (_normalize_ip(source_ip), _normalize_ip(destination_ip))
    ))
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
    all_results: list[dict] = []
    offset = 0

    session = requests.Session()
    try:
        while True:
            payload = _build_payload(ips, offset)
            page_data = _request_page(session, url, headers, payload)
            total_records, returned_records, results = _response_page(page_data)
            all_results.extend(results)

            next_offset = offset + returned_records
            if next_offset >= total_records:
                break
            if returned_records == 0:
                raise TenableIntegrationError(
                    "Pagination Tenable tidak membuat kemajuan; hasil tidak lengkap."
                )
            offset = next_offset
    finally:
        session.close()

    return _transform_results(ips, all_results)
