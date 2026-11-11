"""SQLite persistence and process-local background synchronization for Splunk assets."""
import hashlib
import json
import logging
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from . import config
from .splunk_client import run_asset_lookup

logger = logging.getLogger(__name__)

_migration_lock = threading.Lock()
_migration_complete = False

FIELD_ALIASES = {
    "source_id": ("asset_id", "asset id", "assetid", "id"),
    "ip": ("ip",),
    "hostname": ("hostname", "host_name"),
    "asset_type": ("asset_type", "asset type"),
    "edr": ("edr",),
    "pam": ("pam",),
    "splunk": ("splunk",),
    "va": ("va",),
    "segment": ("segment",),
    "category": ("category",),
    "environment": ("environment", "env"),
    "os_version": ("os_version", "os version"),
    "pic": ("pic",),
    "priority": ("priority",),
}
BOOLEAN_FIELDS = {"edr", "pam", "splunk", "va"}
TEXT_FIELDS = {
    "ip",
    "hostname",
    "asset_type",
    "segment",
    "category",
    "environment",
    "os_version",
    "pic",
    "priority",
}


class AssetDataError(ValueError):
    """A Splunk row does not contain usable asset data."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _process_is_alive(pid: int | None) -> bool:
    if pid is None:
        return False
    try:
        os.kill(pid, 0)
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _connect() -> sqlite3.Connection:
    Path(config.SPLUNK_ASSETS_DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(config.SPLUNK_ASSETS_DB_PATH, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout = 30000")
    return connection


@contextmanager
def _database():
    connection = _connect()
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize_database() -> None:
    global _migration_complete
    if _migration_complete:
        return
    with _migration_lock:
        if _migration_complete:
            return
        migration_path = config.PROJECT_ROOT / "migrations" / "001_splunk_assets.sql"
        with _database() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations "
                "(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
            )
            applied = connection.execute(
                "SELECT 1 FROM schema_migrations WHERE version = 1"
            ).fetchone()
            if not applied:
                connection.executescript(migration_path.read_text(encoding="utf-8"))
                connection.execute(
                    "INSERT INTO schema_migrations(version, applied_at) VALUES (1, ?)",
                    (_utc_now(),),
                )
            active_runs = connection.execute(
                "SELECT id, worker_pid FROM splunk_sync_runs "
                "WHERE status IN ('queued', 'running')"
            ).fetchall()
            for run in active_runs:
                if not _process_is_alive(run["worker_pid"]):
                    connection.execute(
                        "UPDATE splunk_sync_runs SET status='failed', finished_at=?, "
                        "error_message=? WHERE id=?",
                        (
                            _utc_now(),
                            "Proses aplikasi sebelumnya berhenti sebelum sync selesai.",
                            run["id"],
                        ),
                    )
        _migration_complete = True


def _normalized_record(row: dict) -> dict:
    if not isinstance(row, dict):
        raise AssetDataError("Hasil lookup memuat baris yang bukan objek.")
    by_name = {str(key).strip().casefold(): value for key, value in row.items()}
    record = {}
    for field, aliases in FIELD_ALIASES.items():
        value = next((by_name[name] for name in aliases if name in by_name), None)
        if field in BOOLEAN_FIELDS:
            record[field] = _boolean_value(value, field)
        elif field in TEXT_FIELDS:
            record[field] = None if value is None else str(value).strip() or None
        else:
            record[field] = None if value is None else str(value).strip() or None

    if not record["ip"]:
        raise AssetDataError("Baris asset lookup tidak memiliki field IP.")
    if record["source_id"]:
        stable_identity = f"id:{record['source_id'].casefold()}"
    elif record["hostname"] and record["asset_type"]:
        stable_identity = "|".join(
            (
                record["ip"].casefold(),
                record["hostname"].casefold(),
                record["asset_type"].casefold(),
            )
        )
    else:
        raise AssetDataError(
            "Baris asset tanpa ID harus memiliki IP, hostname, dan asset_type."
        )
    record["source_key"] = hashlib.sha256(stable_identity.encode("utf-8")).hexdigest()
    record["raw_json"] = json.dumps(row, ensure_ascii=False, sort_keys=True, default=str)
    record["updated_at"] = _utc_now()
    return record


def _boolean_value(value, field: str) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)) and value in (0, 1):
        return int(value)
    normalized = str(value).strip().casefold()
    if normalized in {"1", "true", "yes", "y", "active", "enabled", "on"}:
        return 1
    if normalized in {"0", "false", "no", "n", "inactive", "disabled", "off"}:
        return 0
    raise AssetDataError(f"Nilai kontrol {field} tidak dapat dipetakan ke boolean.")


def upsert_assets(rows: list[dict]) -> tuple[int, int]:
    """Validate all rows, deduplicate within a sync, then atomically upsert."""
    initialize_database()
    by_key = {}
    for row in rows:
        record = _normalized_record(row)
        by_key[record["source_key"]] = record

    columns = [
        "source_key",
        "source_id",
        "ip",
        "hostname",
        "asset_type",
        "edr",
        "pam",
        "splunk",
        "va",
        "segment",
        "category",
        "environment",
        "os_version",
        "pic",
        "priority",
        "raw_json",
        "updated_at",
    ]
    updates = ", ".join(
        f"{column}=excluded.{column}" for column in columns if column != "source_key"
    )
    sql = (
        f"INSERT INTO splunk_assets ({', '.join(columns)}) "
        f"VALUES ({', '.join('?' for _ in columns)}) "
        f"ON CONFLICT(source_key) DO UPDATE SET {updates}"
    )
    inserted = updated = 0
    with _database() as connection:
        connection.execute("BEGIN IMMEDIATE")
        for record in by_key.values():
            exists = connection.execute(
                "SELECT 1 FROM splunk_assets WHERE source_key = ?",
                (record["source_key"],),
            ).fetchone()
            connection.execute(sql, tuple(record[column] for column in columns))
            if exists:
                updated += 1
            else:
                inserted += 1
    return inserted, updated


def _row_dict(row: sqlite3.Row | None) -> dict | None:
    return dict(row) if row is not None else None


def get_sync_run(run_id: int) -> dict | None:
    initialize_database()
    with _database() as connection:
        row = connection.execute(
            "SELECT * FROM splunk_sync_runs WHERE id = ?", (run_id,)
        ).fetchone()
    return _row_dict(row)


def latest_sync_run() -> dict | None:
    initialize_database()
    with _database() as connection:
        row = connection.execute(
            "SELECT * FROM splunk_sync_runs ORDER BY id DESC LIMIT 1"
        ).fetchone()
    return _row_dict(row)


def list_assets(
    *,
    page: int = 1,
    per_page: int = 50,
    search: str = "",
    environment: str = "",
) -> tuple[list[dict], int]:
    initialize_database()
    page = max(page, 1)
    per_page = min(max(per_page, 1), 100)
    filters = []
    parameters: list[object] = []
    if search:
        fields = ("ip", "hostname", "asset_type", "segment", "category", "pic")
        filters.append("(" + " OR ".join(f"{field} LIKE ?" for field in fields) + ")")
        parameters.extend([f"%{search}%" for _ in fields])
    if environment:
        filters.append("environment = ?")
        parameters.append(environment)
    where = f" WHERE {' AND '.join(filters)}" if filters else ""
    with _database() as connection:
        total = connection.execute(
            f"SELECT COUNT(*) FROM splunk_assets{where}", parameters
        ).fetchone()[0]
        rows = connection.execute(
            f"SELECT * FROM splunk_assets{where} "
            "ORDER BY hostname COLLATE NOCASE, ip LIMIT ? OFFSET ?",
            [*parameters, per_page, (page - 1) * per_page],
        ).fetchall()
    return [dict(row) for row in rows], total


def _set_run(run_id: int, **fields) -> None:
    initialize_database()
    if not fields:
        return
    assignments = ", ".join(f"{key} = ?" for key in fields)
    with _database() as connection:
        connection.execute(
            f"UPDATE splunk_sync_runs SET {assignments} WHERE id = ?",
            [*fields.values(), run_id],
        )


def _run_sync(run_id: int) -> None:
    _set_run(run_id, status="running", started_at=_utc_now())
    sid = None
    rows_received = 0
    try:
        sid, rows = run_asset_lookup()
        rows_received = len(rows)
        _set_run(run_id, sid=sid, rows_received=rows_received)
        inserted, updated = upsert_assets(rows)
        _set_run(
            run_id,
            status="succeeded",
            sid=sid,
            finished_at=_utc_now(),
            rows_received=len(rows),
            inserted_count=inserted,
            updated_count=updated,
            error_message=None,
        )
        logger.info(
            "Splunk asset sync completed run_id=%s sid=%s rows=%s inserted=%s updated=%s",
            run_id,
            sid,
            len(rows),
            inserted,
            updated,
        )
    except Exception as exc:
        failed_sid = sid or getattr(exc, "sid", None)
        message = str(exc) or exc.__class__.__name__
        if config.SPLUNK_TOKEN:
            message = message.replace(config.SPLUNK_TOKEN, "[REDACTED]")
        _set_run(
            run_id,
            status="failed",
            sid=failed_sid,
            finished_at=_utc_now(),
            rows_received=rows_received,
            error_message=message[:1000],
        )
        logger.error(
            "Splunk asset sync failed run_id=%s error_type=%s message=%s",
            run_id,
            type(exc).__name__,
            message[:500],
        )


def enqueue_sync() -> tuple[dict, bool]:
    """Create one queued run; return the existing active run if one is in flight."""
    initialize_database()
    with _database() as connection:
        connection.execute("BEGIN IMMEDIATE")
        active = connection.execute(
            "SELECT * FROM splunk_sync_runs "
            "WHERE status IN ('queued', 'running') ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if active:
            return dict(active), False
        cursor = connection.execute(
            "INSERT INTO splunk_sync_runs(status, worker_pid, started_at) "
            "VALUES ('queued', ?, ?)",
            (os.getpid(), _utc_now()),
        )
        run_id = cursor.lastrowid

    try:
        worker = threading.Thread(
            target=_run_sync,
            args=(run_id,),
            name=f"splunk-asset-sync-{run_id}",
            daemon=True,
        )
        worker.start()
    except RuntimeError as exc:
        _set_run(
            run_id,
            status="failed",
            finished_at=_utc_now(),
            error_message="Background sync worker tidak dapat dijalankan.",
        )
        raise RuntimeError("Background sync worker tidak dapat dijalankan.") from exc
    run = get_sync_run(run_id)
    return run, True


if __name__ == "__main__":
    initialize_database()
    print(f"Splunk assets database ready: {config.SPLUNK_ASSETS_DB_PATH}")
