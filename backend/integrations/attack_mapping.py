"""MITRE ATT&CK Mapping.

Maps NOCTUA scan findings to MITRE ATT&CK techniques (Enterprise matrix).
Enables SOC teams to consume our output in Splunk/Sentinel/QRadar workflows.

Reference: https://attack.mitre.org/techniques/enterprise/
"""
from typing import Iterable

# Curated mapping — finding keyword → ATT&CK technique
FINDING_MAPPINGS = [
    # RECON (TA0043)
    {"match": ["subdomains", "found", "assets"],       "tactic": "TA0043", "tactic_name": "Reconnaissance",
     "techniques": [("T1590", "Gather Victim Network Information"),
                    ("T1590.005", "IP Addresses")]},
    {"match": ["ct_logs", "certificate"],              "tactic": "TA0043", "tactic_name": "Reconnaissance",
     "techniques": [("T1596.002", "DNS/Passive DNS")]},
    {"match": ["metadata", "documents", "leaked"],     "tactic": "TA0043", "tactic_name": "Reconnaissance",
     "techniques": [("T1592.001", "Hardware"),
                    ("T1592.002", "Software")]},
    {"match": ["github", "leaked_secrets", "github_leak"], "tactic": "TA0043", "tactic_name": "Reconnaissance",
     "techniques": [("T1593.003", "Code Repositories")]},

    # RESOURCE DEV (TA0042)
    {"match": ["typosquat", "phishing_domain"],        "tactic": "TA0042", "tactic_name": "Resource Development",
     "techniques": [("T1583.001", "Domains"),
                    ("T1587.003", "Digital Certificates")]},

    # INITIAL ACCESS (TA0001)
    {"match": ["takeover", "subdomain_takeover"],      "tactic": "TA0001", "tactic_name": "Initial Access",
     "techniques": [("T1189", "Drive-by Compromise")]},
    {"match": ["exposed_login", "credentials_exposed"], "tactic": "TA0001", "tactic_name": "Initial Access",
     "techniques": [("T1078", "Valid Accounts"),
                    ("T1078.004", "Cloud Accounts")]},
    {"match": ["exposed_api", "api_leak"],             "tactic": "TA0001", "tactic_name": "Initial Access",
     "techniques": [("T1190", "Exploit Public-Facing Application")]},

    # EXECUTION (TA0002)
    {"match": ["poc", "exploit_available", "kev"],     "tactic": "TA0002", "tactic_name": "Execution",
     "techniques": [("T1203", "Exploitation for Client Execution")]},

    # CREDENTIAL ACCESS (TA0006)
    {"match": ["breach", "hibp", "leaked_password", "paste"], "tactic": "TA0006", "tactic_name": "Credential Access",
     "techniques": [("T1589.001", "Credentials"),
                    ("T1552", "Unsecured Credentials"),
                    ("T1552.001", "Credentials In Files")]},
    {"match": ["jwt", "exposed_secret", "api_key"],    "tactic": "TA0006", "tactic_name": "Credential Access",
     "techniques": [("T1552.001", "Credentials In Files")]},

    # DISCOVERY (TA0007)
    {"match": ["open_ports", "shodan", "port"],        "tactic": "TA0007", "tactic_name": "Discovery",
     "techniques": [("T1046", "Network Service Discovery")]},
    {"match": ["cloud_config", "s3", "bucket", "env"], "tactic": "TA0007", "tactic_name": "Discovery",
     "techniques": [("T1526", "Cloud Service Discovery")]},

    # DEFENSE EVASION (TA0005)
    {"match": ["waf_bypass", "waf"],                   "tactic": "TA0005", "tactic_name": "Defense Evasion",
     "techniques": [("T1600", "Weaken Encryption")]},

    # IMPACT (TA0040)
    {"match": ["idor", "logic_flow"],                  "tactic": "TA0040", "tactic_name": "Impact",
     "techniques": [("T1499", "Endpoint Denial of Service")]},
]


def _matches(finding_kind: str, keywords: Iterable[str]) -> bool:
    fk = (finding_kind or "").lower()
    return any(k in fk for k in keywords)


def map_scan_to_attack(scan_doc: dict) -> dict:
    """Analyze a scan document and return an ATT&CK mapping matrix.

    Returns:
      {
        "tactics": [{"tactic", "tactic_name", "techniques": [{tid, name, sources: [...]}]}],
        "coverage": int,  # techniques mapped
      }
    """
    result = scan_doc.get("result", {}) or {}
    findings_present: list[tuple[str, str]] = []  # (finding_kind, source)

    # Detect what findings exist in the scan
    if result.get("subdomains", {}).get("found"):
        findings_present.append(("subdomains", "OSINT: subdomains found"))
    if (result.get("ports") or {}).get("open_ports"):
        findings_present.append(("open_ports", "Port scan: open_ports"))
    if result.get("ct_logs"):
        findings_present.append(("ct_logs", "CT logs enumeration"))
    if scan_doc.get("takeover"):
        findings_present.append(("takeover", "Subdomain takeover fingerprints"))
    if scan_doc.get("cloud_config", {}).get("findings"):
        findings_present.append(("cloud_config", "Cloud config exposure"))
    if scan_doc.get("api_auditor", {}).get("endpoints"):
        findings_present.append(("exposed_api", "API endpoint discovery"))
    if scan_doc.get("github_leak"):
        findings_present.append(("github_leak", "GitHub secret leak"))
    if scan_doc.get("param_miner", {}).get("params"):
        findings_present.append(("exposed_api", "Param miner"))
    if scan_doc.get("waf_bypass", {}).get("waf_detected"):
        findings_present.append(("waf_bypass", "WAF bypass suggestions"))
    if scan_doc.get("idor"):
        findings_present.append(("idor", "IDOR analyzer"))
    if scan_doc.get("logic_flow"):
        findings_present.append(("logic_flow", "Logic flow analysis"))
    if scan_doc.get("cve_correlation", {}).get("kev_hits"):
        findings_present.append(("kev", "CISA KEV hit"))
    if scan_doc.get("typosquat", {}).get("registered_count", 0) > 0:
        findings_present.append(("typosquat", "Typosquatting variants registered"))
    if scan_doc.get("breaches") or scan_doc.get("paste_search"):
        findings_present.append(("breach", "Breach/paste hit"))
    if scan_doc.get("metadata_leak", {}).get("documents"):
        findings_present.append(("metadata", "Document metadata leaks"))

    # Now map findings to ATT&CK techniques
    tactic_bag: dict[str, dict] = {}
    for finding_kind, source in findings_present:
        for m in FINDING_MAPPINGS:
            if _matches(finding_kind, m["match"]):
                tactic_key = m["tactic"]
                if tactic_key not in tactic_bag:
                    tactic_bag[tactic_key] = {
                        "tactic": tactic_key,
                        "tactic_name": m["tactic_name"],
                        "techniques": {},
                    }
                for tid, tname in m["techniques"]:
                    tech_slot = tactic_bag[tactic_key]["techniques"].setdefault(
                        tid, {"id": tid, "name": tname, "sources": set()},
                    )
                    tech_slot["sources"].add(source)

    # Flatten
    tactics_out = []
    total_techs = 0
    for _, t in tactic_bag.items():
        techs = []
        for _, tech in t["techniques"].items():
            techs.append({"id": tech["id"], "name": tech["name"],
                          "sources": sorted(tech["sources"])})
        techs.sort(key=lambda x: x["id"])
        total_techs += len(techs)
        tactics_out.append({"tactic": t["tactic"],
                            "tactic_name": t["tactic_name"],
                            "techniques": techs})
    # Order by ATT&CK phase (Recon → Impact)
    ORDER = ["TA0043", "TA0042", "TA0001", "TA0002", "TA0005",
             "TA0006", "TA0007", "TA0040"]
    tactics_out.sort(key=lambda t: ORDER.index(t["tactic"]) if t["tactic"] in ORDER else 99)

    return {
        "coverage": total_techs,
        "findings_matched": len(findings_present),
        "tactics": tactics_out,
    }


def to_stix_layer(mapping: dict, target: str) -> dict:
    """Emit an ATT&CK Navigator-compatible layer (JSON)."""
    techniques = []
    for t in mapping.get("tactics", []):
        for tech in t.get("techniques", []):
            techniques.append({
                "techniqueID": tech["id"],
                "score": len(tech["sources"]),
                "color": "",
                "comment": " · ".join(tech["sources"][:2]),
                "enabled": True,
            })
    return {
        "name": f"NOCTUA · {target}",
        "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.4"},
        "domain": "enterprise-attack",
        "description": f"MITRE ATT&CK mapping of OSINT findings for {target}",
        "techniques": techniques,
        "gradient": {
            "colors": ["#8ec843ff", "#ffe766ff", "#ff6666ff"],
            "minValue": 0, "maxValue": 5,
        },
        "legendItems": [{"label": "Techniques mapped from NOCTUA findings", "color": "#00E5FF"}],
    }
