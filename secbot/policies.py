"""Aturan bisnis deterministik yang dipakai kode (bukan ditebak LLM).

Rujukan utama ada di folder ``knowledge/``:

- ``COMP.md``              -> matriks kontrol wajib (EDR/PAM/VA) per environment & segmen
- ``PORT.md``              -> aturan port P-1 s.d. P-12 (default deny)
- ``NET.md``               -> aturan segmen Server Farm/DMZ (SS-1 s.d. SS-10, WS-1 s.d. WS-3)
- ``ENV.md``               -> aturan lintas environment (S-1 s.d. S-4, W-1 s.d. W-5)
- ``remediation_sla.md``   -> SLA remediasi vulnerability

Bila kebijakan berubah, ubah di sini **dan** di file ``.md`` pasangannya agar
penjelasan ke pengguna (dari knowledge base) tetap sinkron dengan hasil hitungan kode.
"""

# =====================================================================
# Compliance — COMP.md
# =====================================================================
# Matriks C-1..C-7. LAN mengecualikan PAM/VA untuk semua environment (C-5);
# Server Farm/DMZ non-produksi tidak mewajibkan PAM (C-6).
COMPLIANCE_MATRIX = {
    "PROD": {"default": ("edr", "pam", "va"), "LAN": ("edr",)},
    "UAT": {"default": ("edr", "va"), "LAN": ("edr",)},
    "DEV": {"default": ("edr",), "LAN": ("edr",)},
}

# Dipertahankan untuk pemanggil lama; nilai default per environment (tanpa pengecualian segmen).
REQUIRED_CONTROLS = {
    env: list(spec["default"]) for env, spec in COMPLIANCE_MATRIX.items()
}


def normalize_environment(environment: str | None) -> str:
    """Normalisasi nama environment (``pre prod``/``pre_prod`` -> ``PRE-PROD``)."""
    env = (environment or "").strip().upper().replace("_", "-").replace(" ", "-")
    return {"PREPROD": "PRE-PROD"}.get(env, env)


def required_controls(
    environment: str | None, segment: str | None = None
) -> list[str] | None:
    """Kontrol wajib menurut ``COMP.md``.

    - Segmen LAN: hanya EDR, untuk semua environment (C-5).
    - Server Farm/DMZ: PROD = EDR+PAM+VA, UAT = EDR+VA, DEV = EDR (C-1..C-3, C-6).
    - Environment yang tidak dinyatakan (mis. Pre-Prod/SIT) -> ``None`` (gate UNKNOWN),
      bukan diasumsikan compliant.
    """
    if segment_kind(segment) == "lan":
        return ["edr"]  # C-5: EDR tetap wajib, PAM/VA tidak wajib
    spec = COMPLIANCE_MATRIX.get(normalize_environment(environment))
    return list(spec["default"]) if spec else None


# =====================================================================
# Port — PORT.md
# =====================================================================
# Port manajemen menurut NET.md; dipakai aturan segmen.
MANAGEMENT_PORTS = {22, 3389, 445, 7001, 7002}
WEB_PORTS = {80, 443, 8080, 8443}

# port -> (service, level, rule, note)
# Level: PROHIBITED (default deny / tanpa exception), RESTRICTED (boleh dengan syarat).
# PORT.md tidak memiliki port yang boleh dibuka tanpa syarat.
PORT_RULES = {
    20: ("FTP", "RESTRICTED", "P-3", "wajib exception form; ganti SFTP"),
    21: ("FTP", "RESTRICTED", "P-3", "wajib exception form; ganti SFTP"),
    22: ("SSH/SFTP", "RESTRICTED", "P-4", "justifikasi server-to-server; DC COLO 20022/30022"),
    23: ("Telnet", "PROHIBITED", "P-8", "default deny; tidak ada exception"),
    25: ("SMTP", "PROHIBITED", "P-10", "wajib redirect ke SMTPS 465"),
    80: ("HTTP", "RESTRICTED", "P-2", "exception form; redirect HTTPS; PROD wajib SSL"),
    110: ("POP3", "PROHIBITED", "P-9", "wajib redirect ke POP3S 995"),
    443: ("HTTPS", "RESTRICTED", "P-2", "HTTPS sebagai target redirect HTTP; PROD wajib SSL"),
    445: ("SMB", "RESTRICTED", "P-6", "wajib SMB 3.0+; SMBv1 diblokir"),
    465: ("SMTPS", "RESTRICTED", "P-10", "pengganti aman SMTP"),
    995: ("POP3S", "RESTRICTED", "P-9", "pengganti aman POP3"),
    1433: ("MSSQL", "RESTRICTED", "P-7", "aturan port database P-7"),
    1521: ("Oracle DB", "RESTRICTED", "P-7", "aturan port database P-7"),
    1522: ("Oracle DB", "RESTRICTED", "P-7", "aturan port database P-7"),
    1530: ("Oracle DB", "RESTRICTED", "P-7", "aturan port database P-7"),
    1540: ("Oracle DB", "RESTRICTED", "P-7", "aturan port database P-7"),
    3306: ("MySQL/MariaDB", "RESTRICTED", "P-7", "aturan port database P-7"),
    3389: ("RDP", "RESTRICTED", "P-5", "endpoint->non-prod atau PAM->prod; DC COLO 103389"),
    5432: ("PostgreSQL", "RESTRICTED", "P-7", "aturan port database P-7"),
    5900: ("VNC", "PROHIBITED", "P-11", "default deny; tidak ada exception"),
    5901: ("VNC", "PROHIBITED", "P-11", "default deny; tidak ada exception"),
    5902: ("VNC", "PROHIBITED", "P-11", "default deny; tidak ada exception"),
    5903: ("VNC", "PROHIBITED", "P-11", "default deny; tidak ada exception"),
    7001: ("HTTP-alt management", "RESTRICTED", "SS-2/SS-5/SS-8", "hanya ke IP Management"),
    7002: ("HTTP-alt management", "RESTRICTED", "SS-2/SS-5/SS-8", "hanya ke IP Management"),
    8080: ("HTTP-alt", "RESTRICTED", "P-2", "exception form; redirect HTTPS"),
    8443: ("HTTPS-alt", "RESTRICTED", "P-2", "HTTPS-alt sebagai target redirect HTTP"),
    20022: ("SSH DC COLO", "RESTRICTED", "P-4", "redirect dari port 22"),
    30022: ("SFTP DC COLO", "RESTRICTED", "P-4", "redirect dari port 22"),
    27017: ("MongoDB", "RESTRICTED", "P-7", "aturan port database P-7"),
    103389: ("RDP DC COLO", "RESTRICTED", "P-5", "redirect dari port 3389"),
}

DB_PORTS = {1433, 1521, 1522, 1530, 1540, 3306, 5432, 27017}


def classify_port(port: int) -> dict:
    """Klasifikasikan port menurut ``PORT.md`` (P-1 default deny).

    Port yang tidak punya aturan eksplisit **tidak** dianggap "perlu review":
    P-1 menyatakan seluruh akses diblokir secara default.
    """
    rule = PORT_RULES.get(port)
    if rule:
        service, level, ref, note = rule
    elif 49152 <= port <= 65535:
        service, level, ref, note = (
            "Dynamic/Ephemeral",
            "RESTRICTED",
            "P-12",
            "wajib justifikasi operasional",
        )
    else:
        service, level, ref, note = (
            "Tidak dikenal",
            "PROHIBITED",
            "P-1",
            "default deny; port tidak memiliki aturan eksplisit",
        )
    return {"service": service, "level": level, "rule": ref, "note": note}


# =====================================================================
# Segmen & environment — NET.md / ENV.md
# =====================================================================
NON_PRODUCTION = {"DEV", "UAT", "SIT"}
PRODUCTION_SIDE = {"PROD", "PRE-PROD"}


def segment_kind(segment: str | None) -> str:
    """Kelompokkan nama segmen dari CMDB."""
    seg = (segment or "").strip().lower()
    if "server" in seg and "farm" in seg:
        return "server-farm"
    if "dmz" in seg:
        return "dmz"
    if seg == "lan" or "lan campus" in seg:
        return "lan"
    return "unknown"


def zone_kind(category: str | None) -> str:
    """Kelompokkan ``ip_category`` menjadi data/management/workstation."""
    cat = (category or "").strip().lower()
    if "management" in cat:
        return "management"
    if any(token in cat for token in ("workstation", "endpoint", "lan campus")):
        return "workstation"
    return "data"


def _rule(level: str, rule: str, points: int, note: str) -> dict:
    return {"level": level, "rule": rule, "points": points, "note": note}


def _workstation_rule(
    dst_segment: str,
    dst_environment: str | None,
    port: int,
) -> dict:
    """Aturan workstation LAN Campus (WS-1..WS-3, W-1..W-5)."""
    dst_env = normalize_environment(dst_environment)
    if segment_kind(dst_segment) == "dmz":
        return _rule(
            "BLOCK",
            "WS-3",
            35,
            "LAN Campus tidak boleh langsung ke DMZ; gunakan F5/forwarding",
        )
    if dst_env in PRODUCTION_SIDE:
        if port in WEB_PORTS:
            return _rule(
                "CONDITIONAL",
                "W-4",
                10,
                "hanya web-based access pada port yang diizinkan",
            )
        return _rule(
            "BLOCK",
            "W-4",
            35,
            "LAN Campus ke PROD/PRE-PROD hanya untuk web-based access",
        )
    if dst_env in NON_PRODUCTION:
        return _rule("ALLOW", "W-1", 0, "LAN Campus ke non-produksi")
    return _rule("REVIEW", "W-1", 10, "environment tujuan tidak dinyatakan")


def _server_segment_rule(
    src_kind: str,
    src_zone: str,
    dst_kind: str,
    dst_zone: str,
    port: int,
) -> dict:
    """Aturan Server Farm/DMZ (SS-1..SS-10)."""
    if src_zone == "management":
        return _rule(
            "BLOCK",
            "SS-3/SS-6/SS-10",
            35,
            "source IP Management diblokir; gunakan IP Data/VS",
        )

    if src_kind == dst_kind:
        if src_kind == "server-farm":
            if src_zone == "data" and dst_zone == "data":
                if port in MANAGEMENT_PORTS:
                    return _rule(
                        "BLOCK",
                        "SS-1",
                        35,
                        "management port tidak boleh Data/VS ke Data/VS",
                    )
                return _rule(
                    "ALLOW", "SS-1", 0, "non-management port sesama Data/VS Server Farm"
                )
            if src_zone == "data" and dst_zone == "management":
                if port in MANAGEMENT_PORTS:
                    return _rule("ALLOW", "SS-2", 0, "management port ke IP Management")
                return _rule(
                    "BLOCK", "SS-2", 35, "hanya management port yang boleh ke IP Management"
                )
            return _rule(
                "REVIEW", "SS-1/SS-2", 10, "kombinasi zona tidak dinyatakan"
            )

        # DMZ
        if src_zone == "data" and dst_zone == "data":
            if port in MANAGEMENT_PORTS:
                return _rule(
                    "BLOCK", "SS-4", 35, "management port tidak boleh Data/VS ke Data/VS"
                )
            return _rule("ALLOW", "SS-4", 0, "non-management port sesama Data/VS DMZ")
        if src_zone == "data" and dst_zone == "management":
            if port in MANAGEMENT_PORTS:
                return _rule("ALLOW", "SS-5", 0, "management port ke IP Management")
            return _rule(
                "BLOCK", "SS-5", 35, "hanya management port yang boleh ke IP Management"
            )
        return _rule("REVIEW", "SS-4/SS-5", 10, "kombinasi zona tidak dinyatakan")

    if src_kind == "server-farm" and dst_kind == "dmz":
        if src_zone != "data":
            return _rule("REVIEW", "SS-7/SS-8", 10, "kombinasi zona tidak dinyatakan")
        if dst_zone == "data":
            if port in MANAGEMENT_PORTS:
                return _rule(
                    "BLOCK",
                    "SS-7/SS-9",
                    35,
                    "management port tidak boleh Server Farm Data -> DMZ Data",
                )
            return _rule(
                "ALLOW", "SS-7/SS-9", 0, "non-management port Server Farm -> DMZ Data/VS"
            )
        if port in MANAGEMENT_PORTS:
            return _rule(
                "ALLOW", "SS-8", 0, "management port Server Farm -> DMZ Management"
            )
        return _rule(
            "BLOCK", "SS-8", 35, "hanya management port ke DMZ Management"
        )

    if src_kind == "dmz" and dst_kind == "server-farm":
        if src_zone == "data":
            if dst_zone == "data" and port in MANAGEMENT_PORTS:
                return _rule(
                    "BLOCK",
                    "NET",
                    35,
                    "management port hanya boleh menuju IP Management",
                )
            return _rule(
                "ALLOW",
                "SS-10",
                0,
                "port spesifik DMZ Data/VS -> Server Farm; verifikasi kebutuhan",
            )
        return _rule(
            "BLOCK", "SS-10", 35, "source IP Management DMZ diblokir"
        )

    return _rule("N/A", "NET", 0, "NET.md hanya mengatur Server Farm dan DMZ")


def segment_rule(
    src_segment: str | None,
    src_category: str | None,
    src_environment: str | None,
    dst_segment: str | None,
    dst_category: str | None,
    dst_environment: str | None,
    port: int,
) -> dict:
    """Aturan segmen NET.md; workstation LAN Campus memakai WS/W."""
    src_kind, dst_kind = segment_kind(src_segment), segment_kind(dst_segment)
    src_zone, dst_zone = zone_kind(src_category), zone_kind(dst_category)
    src_workstation = src_kind == "lan" or src_zone == "workstation"
    dst_workstation = dst_kind == "lan" or dst_zone == "workstation"

    if src_workstation or dst_workstation:
        if src_workstation and dst_workstation:
            if port in {22, 445}:
                return _rule(
                    "ALLOW", "W-3", 0, "LAN Campus ke LAN Campus untuk transfer file"
                )
            return _rule(
                "BLOCK",
                "W-3",
                35,
                "LAN Campus ke LAN Campus hanya untuk transfer file (SMB/SFTP)",
            )
        if src_workstation:
            return _workstation_rule(dst_segment or "", dst_environment, port)
        src_env = normalize_environment(src_environment)
        if src_env in PRODUCTION_SIDE:
            return _rule(
                "CONDITIONAL",
                "W-5",
                20,
                "hanya data downgrade + Production Data Usage Form",
            )
        if src_env in NON_PRODUCTION:
            return _rule("REVIEW", "W-2", 15, "kondisi W-2 belum didefinisikan")
        return _rule("REVIEW", "W-2", 15, "environment sumber tidak dinyatakan")

    if src_kind not in {"server-farm", "dmz"} or dst_kind not in {"server-farm", "dmz"}:
        return _rule("N/A", "NET", 0, "NET.md hanya mengatur Server Farm dan DMZ")

    return _server_segment_rule(src_kind, src_zone, dst_kind, dst_zone, port)


def environment_rule(src_environment: str | None, dst_environment: str | None) -> dict:
    """Aturan lintas environment ENV.md (S-1..S-4)."""
    src = normalize_environment(src_environment)
    dst = normalize_environment(dst_environment)
    if not src or not dst:
        return _rule("REVIEW", "ENV", 10, "environment tidak dikenal")
    if src == dst:
        return _rule("ALLOW", "ENV", 0, f"sesama environment {src}")
    if src in NON_PRODUCTION and dst in NON_PRODUCTION:
        return _rule("ALLOW", "S-1", 0, "non-produksi ke non-produksi")
    if src in PRODUCTION_SIDE and dst in PRODUCTION_SIDE:
        return _rule("ALLOW", "S-2", 0, "PROD/PRE-PROD ke PROD/PRE-PROD")
    if "DEV" in {src, dst} and ({src, dst} & PRODUCTION_SIDE):
        return _rule(
            "CONDITIONAL",
            "S-3",
            15,
            "Exception Form + justifikasi; Production Data Usage Form bila data downgrade",
        )
    if ({src, dst} & {"UAT", "SIT"}) and ({src, dst} & PRODUCTION_SIDE):
        return _rule(
            "CONDITIONAL",
            "S-4",
            15,
            "Exception Form + justifikasi; Production Data Usage Form bila data downgrade",
        )
    return _rule("REVIEW", "ENV", 10, "pasangan environment tidak dinyatakan")


# =====================================================================
# SLA — remediation_sla.md
# =====================================================================
SLA_DAYS = {
    "Critical": {"PROD": 7, "NON-PROD": 14},
    "High": {"PROD": 14, "NON-PROD": 30},
    "Medium": {"PROD": 30, "NON-PROD": 60},
    "Low": {"PROD": 90, "NON-PROD": 90},
}


def sla_for(
    severity: str | None, environment: str | None, public_facing: bool = False
) -> dict | None:
    """SLA remediasi menurut ``remediation_sla.md``.

    Prioritas: (1) Critical PROD public-facing, (2) Critical PROD internal,
    (3) High PROD, (4) sisanya.
    """
    if severity not in SLA_DAYS:
        return None
    prod = normalize_environment(environment) == "PROD"
    target = "PROD" if prod else "NON-PROD"
    if severity == "Critical" and prod:
        priority = 1 if public_facing else 2
    elif severity == "High" and prod:
        priority = 3
    else:
        priority = 4
    return {
        "severity": severity,
        "environment": target,
        "days": SLA_DAYS[severity][target],
        "priority": priority,
        "public_facing": public_facing,
    }


# Urutan severity dari paling berat, dipakai untuk mencari severity tertinggi.
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]
