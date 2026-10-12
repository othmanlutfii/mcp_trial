"""Tool penilaian permintaan pembukaan koneksi (connection request).

Semua perhitungan DETERMINISTIK (dilakukan kode), bukan tebakan LLM. LLM hanya
bertugas menarasikan hasilnya pada tahap Reviewer.
"""
from langchain_core.tools import tool

from .. import datasource, policies


def _vuln_summary(ip: str) -> dict:
    """Ringkasan vulnerability satu server: apakah pernah discan, jumlah per severity, 5 temuan teratas."""
    data = datasource.find_vulns(ip)
    if data is None:
        return {"scanned": False, "counts": {}, "top": []}
    daftar = sorted(data["vulnerabilities"], key=lambda x: -x["cvss"])[:5]
    counts: dict[str, int] = {}
    for x in data["vulnerabilities"]:
        counts[x["severity"]] = counts.get(x["severity"], 0) + 1
    return {"scanned": True, "counts": counts, "top": daftar}


def _side(ip: str) -> dict:
    """Profil satu sisi koneksi (source atau destination).

    Berisi data aset + gate wajib (EDR/PAM/VA) + ringkasan vulnerability.
    Aset yang tidak terdaftar di CMDB diberi ``registered=False`` dan ``gate="UNKNOWN"``.
    """
    asset = datasource.find_asset(ip)
    if asset is None:
        return {
            "ip": ip,
            "registered": False,
            "gate": "UNKNOWN",
            "gate_missing": [],
            "vuln": _vuln_summary(ip),
        }
    missing = [k.upper() for k in policies.ACCESS_REQUIRED_CONTROLS if not asset.get(k)]
    return {
        "ip": ip,
        "registered": True,
        "hostname": asset["hostname"],
        "application": asset["application"],
        "environment": asset["environment"],
        "segment": asset["segment"],
        "dc": asset["dc"],
        "ip_category": asset["ip_category"],
        "edr": asset["edr"],
        "pam": asset["pam"],
        "va": asset["va"],
        "gate": "PASS" if not missing else "FAIL",
        "gate_missing": missing,
        "vuln": _vuln_summary(ip),
    }


def _highest(side: dict) -> str | None:
    """Severity vulnerability paling berat pada satu sisi, atau ``None`` bila tidak ada temuan."""
    counts = side["vuln"]["counts"]
    for sev in policies.SEVERITY_ORDER:
        if counts.get(sev):
            return sev
    return None


@tool
def assess_connection(src_ip: str, dst_ip: str, port: int, protocol: str = "tcp") -> dict:
    """Nilai permintaan pembukaan koneksi dari server source ke server destination pada port tertentu.
    Mengembalikan: status gate EDR/PAM/VA kedua server, severity vulnerability, level port,
    temuan, skor risiko, dan keputusan awal. Semua dihitung oleh kode."""
    for ip in (src_ip, dst_ip):
        if not datasource.is_valid_ip(ip):
            return {"error": f"'{ip}' bukan format IP yang valid"}
    try:
        port = int(port)
    except (TypeError, ValueError):
        return {"error": f"Port '{port}' tidak valid"}
    if not 1 <= port <= 65535:
        return {"error": f"Port {port} di luar rentang 1-65535"}
    protocol = str(protocol).lower().strip()
    if protocol not in ("tcp", "udp"):
        return {"error": f"Protocol '{protocol}' tidak dikenal (tcp/udp)"}

    src, dst = _side(src_ip.strip()), _side(dst_ip.strip())
    score, findings, blocks = 0, [], []

    def add(points: int, text: str) -> None:
        """Tambah skor risiko dan catat temuan pendukungnya."""
        nonlocal score
        score += points
        findings.append(f"[+{points}] {text}")

    # 1. Registrasi CMDB + gate wajib EDR/PAM/VA
    for label, s, w in (("Source", src, 15), ("Destination", dst, 25)):
        if not s["registered"]:
            add(30, f"{label} {s['ip']} tidak terdaftar di CMDB (kemungkinan shadow asset)")
            blocks.append(f"{label} tidak terdaftar di CMDB")
        elif s["gate"] == "FAIL":
            miss = ", ".join(s["gate_missing"])
            add(w, f"{label} {s['hostname']} belum memenuhi syarat wajib: {miss} belum aktif")
            blocks.append(f"{label} tidak memenuhi syarat EDR/PAM/VA (kurang: {miss})")

    # 2. Port
    svc, level = policies.PORT_RULES.get(port, ("Tidak dikenal", "UNKNOWN"))
    if level == "PROHIBITED":
        add(40, f"Port {port}/{protocol} ({svc}) termasuk port DILARANG")
        blocks.append(f"Port {port} ({svc}) dilarang")
    elif level == "RESTRICTED":
        add(20, f"Port {port}/{protocol} ({svc}) termasuk port TERBATAS")
    elif level == "UNKNOWN":
        add(10, f"Port {port}/{protocol} tidak ada di pedoman, perlu review manual")

    # 3. Zona dan environment (hanya bila kedua aset terdaftar)
    if src["registered"] and dst["registered"]:
        if port in policies.DB_PORTS and src["segment"] != "APP":
            add(20, f"Akses database (port {port}) berasal dari segment {src['segment']}, seharusnya hanya dari APP")
            blocks.append("Akses database hanya boleh dari segment APP")
        src_public = src["ip_category"] == "public-facing" or src["segment"] == "DMZ"
        dst_public = dst["ip_category"] == "public-facing" or dst["segment"] == "DMZ"
        if src_public and not dst_public:
            add(15, "Source berada di zona publik/DMZ dan menuju zona internal")
        if dst["environment"] == "PROD":
            add(10, "Destination berada di environment PROD")
        if src["environment"] != dst["environment"] and "PROD" in (src["environment"], dst["environment"]):
            add(15, f"Akses lintas environment ({src['environment']} ke {dst['environment']})")

    # 4. Severity vulnerability
    for label, s, weights in (("Destination", dst, {"Critical": 25, "High": 15, "Medium": 5}),
                              ("Source", src, {"Critical": 15, "High": 8})):
        if not s["registered"]:
            continue
        if not s["vuln"]["scanned"]:
            add(10, f"{label} {s['hostname']} belum memiliki data VA")
            continue
        top = _highest(s)
        if top in weights:
            cves = [v["cve"] for v in s["vuln"]["top"] if v["severity"] == top]
            add(weights[top], f"{label} {s['hostname']} memiliki vuln {top} "
                              f"({s['vuln']['counts'][top]}): {', '.join(cves)}")

    score = min(score, 100)
    risk = "CRITICAL" if score >= 80 else "HIGH" if score >= 60 else "MEDIUM" if score >= 30 else "LOW"
    dst_critical = dst["registered"] and _highest(dst) == "Critical"
    if blocks:
        decision = "DENY"
    # Skor risiko tinggi ATAU port di luar pedoman (wajib review manual Security).
    elif score >= 60 or level == "UNKNOWN":
        decision = "REVIEW_REQUIRED"
    elif score >= 30 or dst_critical:
        decision = "APPROVE_WITH_CONDITIONS"
    else:
        decision = "APPROVE"

    return {
        "request": {"src_ip": src_ip, "dst_ip": dst_ip, "port": port, "protocol": protocol},
        "port_info": {"service": svc, "level": level},
        "source": src, "destination": dst,
        "findings": findings, "hard_blocks": blocks,
        "risk_score": score, "risk_level": risk, "preliminary_decision": decision,
    }
