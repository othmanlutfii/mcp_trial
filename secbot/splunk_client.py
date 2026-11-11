"""Splunk REST search-job client for the asset universe lookup."""
import logging
import time
from urllib.parse import quote, urlsplit

import requests

from . import config

logger = logging.getLogger(__name__)

ASSET_SEARCH = "| inputlookup bni_asset_universe"
RESULT_PAGE_SIZE = 500


class SplunkIntegrationError(Exception):
    """Safe-to-report errors from Splunk connectivity, auth, jobs, or results."""

    def __init__(self, message: str, *, sid: str | None = None):
        super().__init__(message)
        self.sid = sid


def _base_url() -> str:
    host = config.SPLUNK_HOST.rstrip("/")
    if not host:
        raise SplunkIntegrationError("SPLUNK_HOST belum dikonfigurasi.")
    if "://" not in host:
        host = f"https://{host}"
    parsed = urlsplit(host)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise SplunkIntegrationError(
            "SPLUNK_HOST harus berupa hostname atau URL HTTPS tanpa path."
        )
    if not 1 <= config.SPLUNK_PORT <= 65535:
        raise SplunkIntegrationError("SPLUNK_PORT harus berada pada rentang 1-65535.")
    return f"https://{parsed.hostname}:{config.SPLUNK_PORT}"


def _error_detail(response: requests.Response) -> str:
    try:
        body = response.json()
    except ValueError:
        body = None
    if isinstance(body, dict):
        messages = body.get("messages")
        if isinstance(messages, list):
            details = [
                str(item.get("text", ""))
                for item in messages
                if isinstance(item, dict) and item.get("text")
            ]
            if details:
                detail = "; ".join(details)
                if config.SPLUNK_TOKEN:
                    detail = detail.replace(config.SPLUNK_TOKEN, "[REDACTED]")
                return detail[:500]
    return f"HTTP {response.status_code}"


def _raise_for_splunk_messages(payload: dict) -> None:
    messages = payload.get("messages")
    if not isinstance(messages, list):
        return
    errors = [
        str(item.get("text", ""))
        for item in messages
        if isinstance(item, dict)
        and str(item.get("type", "")).casefold() == "error"
    ]
    if errors:
        detail = "; ".join(errors)
        if config.SPLUNK_TOKEN:
            detail = detail.replace(config.SPLUNK_TOKEN, "[REDACTED]")
        raise SplunkIntegrationError(f"Splunk search gagal: {detail[:500]}")


def _request(
    session: requests.Session,
    method: str,
    url: str,
    **kwargs,
) -> dict:
    try:
        response = session.request(
            method,
            url,
            headers={
                "Authorization": f"Splunk {config.SPLUNK_TOKEN}",
                "Accept": "application/json",
            },
            timeout=(config.SPLUNK_CONNECT_TIMEOUT, config.SPLUNK_READ_TIMEOUT),
            verify=config.SPLUNK_CA_BUNDLE or config.SPLUNK_VERIFY_TLS,
            **kwargs,
        )
    except requests.exceptions.SSLError as exc:
        logger.error("Splunk request failed error=tls_error")
        raise SplunkIntegrationError(
            "Verifikasi TLS ke Splunk gagal; periksa sertifikat atau SPLUNK_CA_BUNDLE."
        ) from exc
    except requests.exceptions.ConnectTimeout as exc:
        logger.error("Splunk request failed error=connection_timeout")
        raise SplunkIntegrationError("Koneksi ke Splunk mengalami timeout.") from exc
    except requests.exceptions.ReadTimeout as exc:
        logger.error("Splunk request failed error=request_timeout")
        raise SplunkIntegrationError("Request ke Splunk mengalami timeout.") from exc
    except requests.exceptions.ConnectionError as exc:
        logger.error("Splunk request failed error=connection_error")
        raise SplunkIntegrationError(
            "Tidak dapat terhubung ke Splunk; periksa host, port, DNS, dan firewall."
        ) from exc
    except requests.RequestException as exc:
        logger.error("Splunk request failed error=request_error")
        raise SplunkIntegrationError("Request ke Splunk gagal.") from exc

    logger.info(
        "Splunk request completed method=%s status=%s",
        method,
        response.status_code,
    )
    if not 200 <= response.status_code < 300:
        detail = _error_detail(response)
        if response.status_code in (401, 403):
            message = "Autentikasi Splunk gagal atau token tidak memiliki izin."
        else:
            message = f"Splunk mengembalikan {detail}."
        logger.error(
            "Splunk request failed status=%s error=http_error",
            response.status_code,
        )
        raise SplunkIntegrationError(message)
    try:
        payload = response.json()
    except ValueError as exc:
        logger.error("Splunk request failed status=%s error=invalid_json", response.status_code)
        raise SplunkIntegrationError("Splunk mengembalikan JSON yang tidak valid.") from exc
    if not isinstance(payload, dict):
        raise SplunkIntegrationError("Format respons Splunk tidak valid.")
    _raise_for_splunk_messages(payload)
    return payload


def run_asset_lookup() -> tuple[str, list[dict]]:
    """Run the fixed asset SPL, wait for the SID, and retrieve all result pages."""
    if not config.SPLUNK_TOKEN:
        raise SplunkIntegrationError("SPLUNK_TOKEN belum dikonfigurasi.")
    base_url = _base_url()
    verify = config.SPLUNK_CA_BUNDLE or config.SPLUNK_VERIFY_TLS
    if verify is False:
        logger.warning("Splunk TLS verification is disabled.")

    session = requests.Session()
    started = time.monotonic()
    sid = ""
    try:
        create_payload = _request(
            session,
            "POST",
            f"{base_url}/services/search/jobs",
            data={
                "search": ASSET_SEARCH,
                "output_mode": "json",
                "exec_mode": "normal",
            },
        )
        sid = create_payload.get("sid", "")
        if not isinstance(sid, str) or not sid:
            raise SplunkIntegrationError("Splunk tidak mengembalikan search ID (SID).")
        logger.info("Splunk search job created sid=%s", sid)

        status_url = f"{base_url}/services/search/jobs/{quote(sid, safe='')}"
        while True:
            if time.monotonic() - started >= config.SPLUNK_JOB_TIMEOUT:
                raise SplunkIntegrationError("Waktu tunggu search job Splunk habis.")
            status_payload = _request(
                session,
                "GET",
                status_url,
                params={"output_mode": "json"},
            )
            entries = status_payload.get("entry")
            if not isinstance(entries, list) or not entries or not isinstance(entries[0], dict):
                raise SplunkIntegrationError("Status search job Splunk tidak valid.")
            content = entries[0].get("content", {})
            if not isinstance(content, dict):
                raise SplunkIntegrationError("Status search job Splunk tidak valid.")
            state = str(content.get("dispatchState", "")).upper()
            if content.get("isFailed") is True or state in {
                "FAILED",
                "CANCELED",
                "CANCELLED",
            }:
                raise SplunkIntegrationError(
                    f"Search job Splunk berakhir dengan status {state}."
                )
            if content.get("isDone") is True or state == "DONE":
                break
            time.sleep(max(0.1, config.SPLUNK_POLL_INTERVAL))

        results: list[dict] = []
        offset = 0
        while True:
            result_payload = _request(
                session,
                "GET",
                f"{status_url}/results",
                params={
                    "output_mode": "json",
                    "count": RESULT_PAGE_SIZE,
                    "offset": offset,
                },
            )
            page = result_payload.get("results")
            if not isinstance(page, list) or any(not isinstance(row, dict) for row in page):
                raise SplunkIntegrationError("Hasil asset lookup Splunk tidak valid.")
            results.extend(page)
            if len(page) < RESULT_PAGE_SIZE:
                break
            offset += len(page)
        logger.info("Splunk search job completed sid=%s rows=%s", sid, len(results))
        return sid, results
    except SplunkIntegrationError as exc:
        if exc.sid is None and sid:
            exc.sid = sid
        raise
    finally:
        session.close()
