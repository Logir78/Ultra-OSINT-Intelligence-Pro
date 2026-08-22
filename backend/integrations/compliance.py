"""Compliance Scorecard — maps scan findings to industry compliance controls.

Frameworks supported:
  - SOC 2 Type II (Trust Services Criteria: Security, Availability, Confidentiality)
  - ISO/IEC 27001:2022 (Annex A controls)
  - GDPR (Articles 25, 32, 33)
  - PCI-DSS v4.0 (Requirements 2, 4, 6, 11)

Each control is scored 0-100 based on presence/absence of related findings.
Aggregate scorecard shows overall compliance % + gaps to remediate.
"""
from typing import Any

# Control → (framework, category, description, weight, matcher)
# matcher is a function that returns (compliant: bool, evidence: str)
CONTROLS = [
    # ─── SOC 2 ────────────────────────────────────────────
    {"id": "CC6.1", "framework": "SOC2",  "category": "Logical Access",
     "desc": "Restrict logical access to production systems.",
     "weight": 10,
     "check": lambda s: (
         not bool(s.get("api_auditor", {}).get("endpoints_without_auth")),
         "API endpoints without authentication found" if s.get("api_auditor", {}).get("endpoints_without_auth")
         else "No unauthenticated API endpoints detected"
     )},
    {"id": "CC6.6", "framework": "SOC2", "category": "Encryption in Transit",
     "desc": "Encrypt data in transit using TLS.",
     "weight": 10,
     "check": lambda s: (
         (s.get("cert_monitor", {}).get("counts", {}).get("expired", 0) == 0),
         f"{s.get('cert_monitor', {}).get('counts', {}).get('expired', 0)} certificados expirados",
     )},
    {"id": "CC7.1", "framework": "SOC2", "category": "System Monitoring",
     "desc": "Detect and respond to security events.",
     "weight": 8,
     "check": lambda s: (
         bool(s.get("takeover", {}).get("scanned")),
         "Subdomain takeover monitoring active" if s.get("takeover") else "No takeover monitoring",
     )},
    {"id": "CC7.4", "framework": "SOC2", "category": "Vulnerability Management",
     "desc": "Identify and remediate known vulnerabilities (CVEs).",
     "weight": 12,
     "check": lambda s: (
         (s.get("cve_correlation", {}).get("summary", {}).get("kev_count", 0) == 0),
         f"{s.get('cve_correlation', {}).get('summary', {}).get('kev_count', 0)} KEV activas",
     )},

    # ─── ISO 27001:2022 ───────────────────────────────────
    {"id": "A.5.7", "framework": "ISO27001", "category": "Threat Intelligence",
     "desc": "Collect and analyse threat intelligence.",
     "weight": 8,
     "check": lambda s: (
         bool(s.get("cve_correlation") or s.get("intel")),
         "AI intelligence + CVE correlation activa" if s.get("cve_correlation") else "Sin threat intel",
     )},
    {"id": "A.8.9", "framework": "ISO27001", "category": "Configuration Management",
     "desc": "Establish, document, and monitor secure configurations.",
     "weight": 10,
     "check": lambda s: (
         not bool(s.get("cloud_config", {}).get("findings")),
         f"{len(s.get('cloud_config', {}).get('findings', []))} config leaks",
     )},
    {"id": "A.8.16", "framework": "ISO27001", "category": "Monitoring Activities",
     "desc": "Monitor networks, systems and applications for anomalies.",
     "weight": 8,
     "check": lambda s: (
         bool(s.get("waf_bypass") or (s.get("result", {}).get("tech_analysis"))),
         "Tech fingerprinting + WAF analysis active",
     )},
    {"id": "A.5.34", "framework": "ISO27001", "category": "Privacy & PII",
     "desc": "Protect personally identifiable information.",
     "weight": 10,
     "check": lambda s: (
         not bool(s.get("github_leak", {}).get("secrets_found")),
         "GitHub secret leaks detected" if s.get("github_leak", {}).get("secrets_found")
         else "No leaked secrets in public repos",
     )},

    # ─── GDPR ─────────────────────────────────────────────
    {"id": "Art25", "framework": "GDPR", "category": "Data Protection by Design",
     "desc": "Implement appropriate technical measures.",
     "weight": 8,
     "check": lambda s: (
         (s.get("cert_monitor", {}).get("counts", {}).get("critical", 0) == 0),
         f"{s.get('cert_monitor', {}).get('counts', {}).get('critical', 0)} certificados expiran <7 días",
     )},
    {"id": "Art32", "framework": "GDPR", "category": "Security of Processing",
     "desc": "Ensure ongoing confidentiality, integrity, availability.",
     "weight": 12,
     "check": lambda s: (
         (s.get("cve_correlation", {}).get("summary", {}).get("critical", 0) == 0),
         f"{s.get('cve_correlation', {}).get('summary', {}).get('critical', 0)} CVEs críticas activas",
     )},
    {"id": "Art33", "framework": "GDPR", "category": "Breach Notification",
     "desc": "Detect and notify personal data breaches within 72h.",
     "weight": 8,
     "check": lambda s: (
         not bool(s.get("breaches") or s.get("paste_search", {}).get("hits")),
         "Datos filtrados detectados" if (s.get("breaches") or s.get("paste_search", {}).get("hits"))
         else "Sin brechas de datos conocidas",
     )},

    # ─── PCI-DSS v4.0 ─────────────────────────────────────
    {"id": "R2", "framework": "PCI-DSS", "category": "Secure Configuration",
     "desc": "Apply secure configurations to system components.",
     "weight": 10,
     "check": lambda s: (
         (len((s.get("result", {}).get("ports") or {}).get("open_ports", [])) < 15),
         f"{len((s.get('result', {}).get('ports') or {}).get('open_ports', []))} puertos abiertos",
     )},
    {"id": "R4", "framework": "PCI-DSS", "category": "Encryption in Transit",
     "desc": "Encrypt cardholder data with strong cryptography.",
     "weight": 10,
     "check": lambda s: (
         (s.get("cert_monitor", {}).get("counts", {}).get("expired", 0) == 0),
         "TLS certificates health check",
     )},
    {"id": "R6", "framework": "PCI-DSS", "category": "Vulnerability Management",
     "desc": "Develop and maintain secure systems.",
     "weight": 12,
     "check": lambda s: (
         (s.get("cve_correlation", {}).get("summary", {}).get("kev_count", 0) == 0),
         f"{s.get('cve_correlation', {}).get('summary', {}).get('kev_count', 0)} KEV en tu stack",
     )},
    {"id": "R11", "framework": "PCI-DSS", "category": "Regular Testing",
     "desc": "Regularly test security systems and processes.",
     "weight": 8,
     "check": lambda s: (
         bool(s.get("takeover") and s.get("api_auditor") and s.get("cve_correlation")),
         "Multiple security modules executed",
     )},
]


def compute_scorecard(scan_doc: dict) -> dict[str, Any]:
    """Return compliance scorecard per framework + overall summary."""
    by_framework: dict[str, dict] = {}
    for ctrl in CONTROLS:
        try:
            compliant, evidence = ctrl["check"](scan_doc)
        except Exception:
            compliant, evidence = False, "Evaluation error"
        fw = ctrl["framework"]
        if fw not in by_framework:
            by_framework[fw] = {"framework": fw, "controls": [],
                                 "score": 0, "max": 0, "gaps": []}
        by_framework[fw]["controls"].append({
            "id": ctrl["id"],
            "category": ctrl["category"],
            "desc": ctrl["desc"],
            "compliant": compliant,
            "evidence": evidence,
            "weight": ctrl["weight"],
        })
        by_framework[fw]["max"] += ctrl["weight"]
        if compliant:
            by_framework[fw]["score"] += ctrl["weight"]
        else:
            by_framework[fw]["gaps"].append({"id": ctrl["id"], "category": ctrl["category"],
                                              "evidence": evidence})

    # Compute percentages + grade
    frameworks = []
    total_score = 0
    total_max = 0
    for fw, data in by_framework.items():
        pct = int((data["score"] / data["max"]) * 100) if data["max"] > 0 else 0
        grade = "A+" if pct >= 95 else "A" if pct >= 85 else "B" if pct >= 70 else "C" if pct >= 50 else "D" if pct >= 30 else "F"
        frameworks.append({**data, "percentage": pct, "grade": grade})
        total_score += data["score"]
        total_max += data["max"]

    overall_pct = int((total_score / total_max) * 100) if total_max > 0 else 0
    overall_grade = "A+" if overall_pct >= 95 else "A" if overall_pct >= 85 else "B" if overall_pct >= 70 else "C" if overall_pct >= 50 else "D" if overall_pct >= 30 else "F"

    # Prioritized remediation (worst-scoring gaps by weight)
    all_gaps = []
    for fw_data in frameworks:
        for gap in fw_data["gaps"]:
            ctrl = next((c for c in CONTROLS if c["id"] == gap["id"]), None)
            if ctrl:
                all_gaps.append({"framework": fw_data["framework"], **gap,
                                  "weight": ctrl["weight"]})
    all_gaps.sort(key=lambda g: g["weight"], reverse=True)

    return {
        "overall": {
            "score": total_score, "max": total_max,
            "percentage": overall_pct, "grade": overall_grade,
        },
        "frameworks": frameworks,
        "top_gaps": all_gaps[:10],
    }
