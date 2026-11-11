CREATE TABLE IF NOT EXISTS splunk_assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_key TEXT NOT NULL UNIQUE,
    source_id TEXT,
    ip TEXT,
    hostname TEXT,
    asset_type TEXT,
    edr INTEGER,
    pam INTEGER,
    splunk INTEGER,
    va INTEGER,
    segment TEXT,
    category TEXT,
    environment TEXT,
    os_version TEXT,
    pic TEXT,
    priority TEXT,
    raw_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_splunk_assets_ip ON splunk_assets(ip);
CREATE INDEX IF NOT EXISTS idx_splunk_assets_hostname ON splunk_assets(hostname);
CREATE INDEX IF NOT EXISTS idx_splunk_assets_environment ON splunk_assets(environment);

CREATE TABLE IF NOT EXISTS splunk_sync_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'succeeded', 'failed')),
    worker_pid INTEGER,
    sid TEXT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    rows_received INTEGER NOT NULL DEFAULT 0,
    inserted_count INTEGER NOT NULL DEFAULT 0,
    updated_count INTEGER NOT NULL DEFAULT 0,
    error_message TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_splunk_sync_one_active
ON splunk_sync_runs(status)
WHERE status IN ('queued', 'running');
