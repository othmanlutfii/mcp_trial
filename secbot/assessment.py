"""Penilaian permintaan pembukaan koneksi (connection request).

Semua perhitungan DETERMINISTIK (dilakukan kode), bukan tebakan LLM. Modul ini
tidak memuat LangChain supaya bisa dipakai langsung oleh CLI maupun UI web.
"""
from . import datasource, policies


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

    Kontrol wajib mengikuti matriks ``knowledge/COMP.md``: environment + pengecualian
    segmen (LAN hanya EDR; Server Farm/DMZ non-produksi tanpa PAM). Aset yang tidak
    terdaftar di CMDB diberi ``registered=False`` dan ``gate="UNKNOWN"``.
    """
    asset = datasource.find_asset(ip)
    if asset is None:
        return {
            "ip": ip,
            "registered": False,
            "asset_type": "unknown",
            "gate": "UNKNOWN",
            "gate_missing": [],
            "required_controls": [],
            "vuln": _vuln_summary(ip),
            "sla": None,
        }

    asset_type = "endpoint" if policies.segment_kind(asset["segment"]) == "lan" else "server"
    required = policies.required_controls(asset["environment"], asset["segment"])
    if required is None:
        missing: list[str] = []
        gate = "UNKNOWN"
        required_upper: list[str] = []
    else:
        missing = [k.upper() for k in required if not asset.get(k)]
        gate = "PASS" if not missing else "FAIL"
        required_upper = [k.upper() for k in required]

    return {
        "ip": ip,
        "registered": True,
        "asset_type": asset_type,
        "hostname": asset["hostname"],
        "application": asset["application"],
        "environment": None if asset_type == "endpoint" else asset["environment"],
        "segment": asset["segment"],
        "dc": asset["dc"],
        "ip_category": asset["ip_category"],
        "operating_system": asset.get("operating_system"),
        "zone": policies.zone_kind(asset["ip_category"]),
        "edr": asset["edr"],
        "pam": asset["pam"],
        "va": asset["va"],
        "required_controls": required_upper,
        "gate": gate,
        "gate_missing": missing,
        "vuln": _vuln_summary(ip),
        "sla": None,
    }


def _highest(side: dict) -> str | None:
    """Severity vulnerability paling berat pada satu sisi, atau ``None`` bila tidak ada temuan."""
    counts = side["vuln"]["counts"]
    for sev in policies.SEVERITY_ORDER:
        if counts.get(sev):
            return sev
    return None


def _is_public_facing(side: dict) -> bool:
    """Penanda public-facing untuk prioritas SLA (kategori public atau segmen DMZ)."""
    category = (side.get("ip_category") or "").lower()
    return "public" in category or (side.get("segment") or "").lower() == "dmz"


def assess_connection_data(src_ip: str, dst_ip: str, port: int, protocol: str = "tcp") -> dict:
    """Hitung penilaian koneksi secara deterministik (dipakai tool dan UI web).

    Urutan penilaian mengikuti knowledge:

    1. ``COMP.md``  - registrasi CMDB + kontrol wajib per environment/segmen
    2. ``PORT.md``  - aturan port P-1..P-12 (default deny)
    3. ``NET.md``   - aturan segmen SS-1..SS-10 / WS-1..WS-3
    4. ``ENV.md``   - aturan lintas environment S-1..S-4 / W-1..W-5
    5. ``remediation_sla.md`` - severity vulnerability + SLA + prioritas
    """
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
    score = 0
    findings: list[str] = []
    blocks: list[str] = []
    conditions: list[str] = []
    review_reasons: list[str] = []
    policy_refs: set[str] = set()

    def add(points: int, text: str, rule: str | None = None) -> None:
        """Tambah skor risiko, temuan, dan referensi aturan."""
        nonlocal score
        score += points
        if rule:
            policy_refs.add(rule)
        tag = f"[+{points}]" if points else "[info]"
        suffix = f" ({rule})" if rule else ""
        findings.append(f"{tag} {text}{suffix}")

    def hard_block(points: int, text: str, rule: str | None = None) -> None:
        add(points, text, rule)
        blocks.append(f"{text} ({rule})" if rule else text)

    def conditional(points: int, text: str, rule: str, note: str) -> None:
        add(points, text, rule)
        conditions.append(f"{rule}: {note}")

    def review(points: int, text: str, rule: str, note: str) -> None:
        add(points, text, rule)
        review_reasons.append(f"{rule}: {note}")

    # 1. Registrasi CMDB + kontrol wajib sesuai matriks COMP.md
    for label, side, weight in (("Source", src, 15), ("Destination", dst, 25)):
        if not side["registered"]:
            hard_block(
                30,
                f"{label} {side['ip']} tidak terdaftar di CMDB (kemungkinan shadow asset)",
                "CMDB",
            )
        elif side["gate"] == "FAIL":
            miss = ", ".join(side["gate_missing"])
            context = (
                "segmen LAN (endpoint)"
                if side["asset_type"] == "endpoint"
                else f"{side['environment']}/{side['segment']}"
            )
            hard_block(
                weight,
                f"{label} {side['hostname']} belum memenuhi kontrol wajib "
                f"{context}: {miss}",
                "C-1..C-7",
            )
        elif side["gate"] == "UNKNOWN":
            context = (
                "segmen LAN (endpoint)"
                if side["asset_type"] == "endpoint"
                else f"{side['environment']}/{side['segment']}"
            )
            review(
                10,
                f"Kontrol wajib {label} {side['hostname']} tidak dinyatakan untuk "
                f"{context}",
                "C-4",
                "kewajiban kontrol tidak dinyatakan di COMP.md",
            )
        else:
            add(
                0,
                f"{label} {side['hostname']} memenuhi kontrol wajib "
                f"({', '.join(side['required_controls'])})",
                "C-7",
            )

    # 2. Port sesuai PORT.md (P-1 default deny)
    port_info = policies.classify_port(port)
    if port_info["level"] == "PROHIBITED":
        hard_block(
            40,
            f"Port {port}/{protocol} ({port_info['service']}) dilarang: "
            f"{port_info['note']}",
            port_info["rule"],
        )
    elif port_info["level"] == "RESTRICTED":
        conditional(
            20,
            f"Port {port}/{protocol} ({port_info['service']}) terbatas: "
            f"{port_info['note']}",
            port_info["rule"],
            port_info["note"],
        )

    # P-5: RDP hanya endpoint->non-produksi atau PAM->produksi.
    if port in {3389, 103389}:
        dst_env = dst.get("environment")
        endpoint_to_nonprod = (
            src.get("asset_type") == "endpoint"
            and dst_env is not None
            and policies.normalize_environment(dst_env) in policies.NON_PRODUCTION
        )
        if not endpoint_to_nonprod:
            review(
                0,
                f"RDP {port} hanya untuk endpoint→non-produksi atau PAM→produksi; "
                "verifikasi peran source",
                "P-5",
                "peran source (endpoint/PAM) tidak dapat diverifikasi dari CMDB",
            )

    # 3. Aturan segmen NET.md + lintas environment ENV.md
    if src["registered"] and dst["registered"]:
        seg = policies.segment_rule(
            src["segment"],
            src["ip_category"],
            src["environment"],
            dst["segment"],
            dst["ip_category"],
            dst["environment"],
            port,
        )
        if seg["level"] == "BLOCK":
            hard_block(35, f"Aturan segmen: {seg['note']}", seg["rule"])
        elif seg["level"] == "CONDITIONAL":
            conditional(
                seg["points"],
                f"Aturan segmen: {seg['note']}",
                seg["rule"],
                seg["note"],
            )
        elif seg["level"] == "REVIEW":
            review(
                seg["points"],
                f"Aturan segmen: {seg['note']}",
                seg["rule"],
                seg["note"],
            )
        elif seg["level"] == "ALLOW":
            add(
                0,
                f"Segmen {src['segment']} → {dst['segment']} sesuai aturan",
                seg["rule"],
            )

        if src["asset_type"] != "endpoint" and dst["asset_type"] != "endpoint":
            env = policies.environment_rule(src["environment"], dst["environment"])
            if env["level"] == "CONDITIONAL":
                conditional(
                    env["points"],
                    f"Aturan environment: {env['note']}",
                    env["rule"],
                    env["note"],
                )
            elif env["level"] == "REVIEW":
                review(
                    env["points"],
                    f"Aturan environment: {env['note']}",
                    env["rule"],
                    env["note"],
                )
            elif env["level"] == "ALLOW":
                add(
                    0,
                    f"Environment {src['environment']} → {dst['environment']} "
                    f"sesuai aturan",
                    env["rule"],
                )

    # 4. Vulnerability + SLA remediasi
    for label, side, weights in (
        ("Destination", dst, {"Critical": 25, "High": 15, "Medium": 5}),
        ("Source", src, {"Critical": 15, "High": 8}),
    ):
        if not side["registered"]:
            continue
        if not side["vuln"]["scanned"]:
            if side["asset_type"] != "endpoint":
                add(10, f"{label} {side['hostname']} belum memiliki data VA", "VA")
            continue
        top = _highest(side)
        if not top:
            continue

        sla = (
            policies.sla_for(top, side["environment"], _is_public_facing(side))
            if side["asset_type"] != "endpoint"
            else None
        )
        side["sla"] = sla
        if sla:
            add(
                0,
                f"{label} {side['hostname']} SLA remediasi {top} "
                f"{sla['environment']} {sla['days']} hari (prioritas {sla['priority']})",
                "SLA",
            )
        if top in weights:
            cves = [v["cve"] for v in side["vuln"]["top"] if v["severity"] == top]
            add(
                weights[top],
                f"{label} {side['hostname']} memiliki vuln {top} "
                f"({side['vuln']['counts'][top]}): {', '.join(cves)}",
                "VA",
            )

    score = min(score, 100)
    risk = "CRITICAL" if score >= 80 else "HIGH" if score >= 60 else "MEDIUM" if score >= 30 else "LOW"
    dst_critical = dst["registered"] and _highest(dst) == "Critical"
    if blocks:
        decision = "DENY"
    elif review_reasons or score >= 60:
        decision = "REVIEW_REQUIRED"
    elif score >= 30 or dst_critical or conditions:
        decision = "APPROVE_WITH_CONDITIONS"
    else:
        decision = "APPROVE"

    return {
        "request": {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "port": port,
            "protocol": protocol,
        },
        "port_info": port_info,
        "source": src,
        "destination": dst,
        "findings": findings,
        "hard_blocks": blocks,
        "conditions": list(dict.fromkeys(conditions)),
        "review_reasons": list(dict.fromkeys(review_reasons)),
        "policy_refs": sorted(policy_refs),
        "risk_score": score,
        "risk_level": risk,
        "preliminary_decision": decision,
    }
