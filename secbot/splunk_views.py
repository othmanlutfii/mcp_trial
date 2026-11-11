"""Authenticated API and read-only UI for synchronized Splunk assets."""
import hmac
import math
from functools import wraps

from flask import Blueprint, Response, jsonify, render_template, request, url_for

from . import config, splunk_assets

splunk_assets_bp = Blueprint("splunk_assets", __name__)


def _unauthorized(api: bool = False):
    response = jsonify({"error": "Autentikasi diperlukan."}) if api else Response(
        "Autentikasi diperlukan.", status=401
    )
    response.status_code = 401
    response.headers["WWW-Authenticate"] = (
        'Bearer realm="Splunk assets"' if api else 'Basic realm="Splunk assets"'
    )
    return response


def _service_unavailable(api: bool = False):
    message = "Kredensial akses Splunk assets belum dikonfigurasi."
    return (jsonify({"error": message}), 503) if api else (message, 503)


def _public_run(run: dict | None) -> dict | None:
    if run is None:
        return None
    return {key: value for key, value in run.items() if key != "worker_pid"}


def _has_bearer_token(expected: str) -> bool:
    authorization = request.headers.get("Authorization", "")
    scheme, separator, supplied = authorization.partition(" ")
    return bool(
        separator
        and scheme.casefold() == "bearer"
        and supplied
        and hmac.compare_digest(supplied, expected)
    )


def _api_token_required(*, sync: bool = False):
    def decorate(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            expected = (
                config.SPLUNK_ASSETS_SYNC_TOKEN
                if sync
                else config.SPLUNK_ASSETS_READ_TOKEN
            )
            if not expected:
                return _service_unavailable(api=True)
            if not _has_bearer_token(expected):
                return _unauthorized(api=True)
            return view(*args, **kwargs)

        return wrapped

    return decorate


def _ui_auth_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        username = config.SPLUNK_ASSETS_UI_USERNAME
        password = config.SPLUNK_ASSETS_UI_PASSWORD
        if not username or not password:
            return _service_unavailable()
        credentials = request.authorization
        if (
            credentials is None
            or not hmac.compare_digest(credentials.username or "", username)
            or not hmac.compare_digest(credentials.password or "", password)
        ):
            return _unauthorized()
        return view(*args, **kwargs)

    return wrapped


def _pagination_args() -> tuple[int, int]:
    try:
        page = int(request.args.get("page", "1"))
        per_page = int(request.args.get("per_page", "50"))
    except ValueError as exc:
        raise ValueError("page dan per_page harus berupa angka.") from exc
    if page < 1 or per_page < 1:
        raise ValueError("page dan per_page harus lebih besar dari 0.")
    return page, min(per_page, 100)


@splunk_assets_bp.post("/api/splunk/assets/sync")
@_api_token_required(sync=True)
def start_asset_sync():
    try:
        run, created = splunk_assets.enqueue_sync()
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 503
    return (
        jsonify(
            {
                "run_id": run["id"],
                "status": run["status"],
                "reused_active_run": not created,
                "status_url": url_for(
                    "splunk_assets.asset_sync_status", run_id=run["id"], _external=False
                ),
            }
        ),
        202 if created else 200,
    )


@splunk_assets_bp.get("/api/splunk/assets/sync/<int:run_id>")
@_api_token_required()
def asset_sync_status(run_id: int):
    run = splunk_assets.get_sync_run(run_id)
    if run is None:
        return jsonify({"error": "ID sinkronisasi tidak ditemukan."}), 404
    return jsonify(_public_run(run))


@splunk_assets_bp.get("/api/splunk/assets")
@_api_token_required()
def read_assets():
    try:
        page, per_page = _pagination_args()
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    search = request.args.get("q", "").strip()[:200]
    environment = request.args.get("environment", "").strip()[:100]
    assets, total = splunk_assets.list_assets(
        page=page,
        per_page=per_page,
        search=search,
        environment=environment,
    )
    last_sync = splunk_assets.latest_sync_run()
    for asset in assets:
        asset.pop("raw_json", None)
        asset.pop("source_key", None)
    return jsonify(
        {
            "items": assets,
            "total": total,
            "page": page,
            "per_page": per_page,
            "total_pages": math.ceil(total / per_page) if total else 0,
            "last_sync": _public_run(last_sync),
        }
    )


@splunk_assets_bp.get("/splunk/assets")
@_ui_auth_required
def asset_sync_page():
    try:
        page, per_page = _pagination_args()
    except ValueError as exc:
        return str(exc), 400
    search = request.args.get("q", "").strip()[:200]
    environment = request.args.get("environment", "").strip()[:100]
    assets, total = splunk_assets.list_assets(
        page=page,
        per_page=per_page,
        search=search,
        environment=environment,
    )
    run_id = request.args.get("run_id", type=int)
    current_run = splunk_assets.get_sync_run(run_id) if run_id else None
    last_sync = splunk_assets.latest_sync_run()
    return render_template(
        "splunk_assets.html",
        active="splunk_assets",
        assets=assets,
        total=total,
        page=page,
        per_page=per_page,
        total_pages=math.ceil(total / per_page) if total else 0,
        search=search,
        environment=environment,
        current_run=current_run,
        last_sync=last_sync,
    )
