CREATE TABLE IF NOT EXISTS tenable_vulnerabilities (
    ip TEXT NOT NULL,
    plugin_id TEXT NOT NULL,
    plugin_name TEXT,
    severity TEXT,
    risk_factor TEXT,
    vpr_score REAL,
    cvss_v3_base_score REAL,
    epss_score REAL,
    cve TEXT,
    exploit_available TEXT,
    exploit_frameworks TEXT,
    port TEXT,
    protocol TEXT,
    dns_name TEXT,
    operating_system TEXT,
    synopsis TEXT,
    description TEXT,
    solution TEXT,
    vuln_uuid TEXT,
    ollama_analysis TEXT,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (ip, plugin_id)
);

CREATE INDEX IF NOT EXISTS idx_tenable_vulnerabilities_ip
ON tenable_vulnerabilities(ip);
