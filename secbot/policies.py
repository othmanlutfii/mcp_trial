"""Aturan bisnis deterministik yang dipakai kode (bukan ditebak LLM).

Konstanta di sini adalah cerminan file di folder ``knowledge/``:

- :data:`REQUIRED_CONTROLS`       <-> ``knowledge/compliance_policy.md``
- :data:`PORT_RULES` / :data:`DB_PORTS` <-> ``knowledge/port_guideline.md``

Bila kebijakan berubah, ubah di sini **dan** di file ``.md`` pasangannya agar
penjelasan ke pengguna (dari knowledge base) tetap sinkron dengan hasil hitungan kode.
"""

# Kontrol keamanan wajib per environment untuk compliance harian.
REQUIRED_CONTROLS = {
    "PROD": ["edr", "pam", "va"],
    "UAT": ["edr", "va"],
    "DEV": ["edr"],
}

# Kontrol wajib saat pembukaan akses (lebih ketat: selalu ketiganya).
ACCESS_REQUIRED_CONTROLS = ["edr", "pam", "va"]

# Port -> (nama layanan, level). Level: PROHIBITED / RESTRICTED / ALLOWED.
PORT_RULES = {
    21: ("FTP", "PROHIBITED"),
    23: ("Telnet", "PROHIBITED"),
    69: ("TFTP", "PROHIBITED"),
    135: ("RPC", "PROHIBITED"),
    139: ("NetBIOS", "PROHIBITED"),
    22: ("SSH", "RESTRICTED"),
    3389: ("RDP", "RESTRICTED"),
    445: ("SMB", "RESTRICTED"),
    5985: ("WinRM HTTP", "RESTRICTED"),
    5986: ("WinRM HTTPS", "RESTRICTED"),
    1433: ("MSSQL", "RESTRICTED"),
    1521: ("Oracle", "RESTRICTED"),
    3306: ("MySQL", "RESTRICTED"),
    5432: ("PostgreSQL", "RESTRICTED"),
    80: ("HTTP", "ALLOWED"),
    443: ("HTTPS", "ALLOWED"),
    8080: ("HTTP-alt", "ALLOWED"),
    8443: ("HTTPS-alt", "ALLOWED"),
}

# Port database: hanya boleh diakses dari segment APP.
DB_PORTS = {1433, 1521, 3306, 5432}

# Urutan severity dari paling berat, dipakai untuk mencari severity tertinggi.
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]
