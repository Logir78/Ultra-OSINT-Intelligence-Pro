"""Platform-ready bug-bounty report generator (Diferenciador #3).

Turns a finding into a submittable Markdown report for HackerOne / Bugcrowd,
weaving in NOCTUA's unique assets: the exploitability verdict (#1) and the
notarized, timestamped evidence hash (#2). No competitor hands you this.
"""
from __future__ import annotations

from datetime import datetime, timezone

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

_TYPE_TITLES = {
    "subdomain_takeover": "Subdomain Takeover",
    "open_cloud_bucket": "Publicly Readable Cloud Bucket",
    "config_leak": "Sensitive Configuration File Exposed",
    "leaked_secret": "Hardcoded Secret Leaked in Source",
    "vulnerable_library": "Known-Vulnerable Dependency",
    "unauth_service_exposed": "Unauthenticated Service Exposed",
}

_REMEDIATION = {
    "subdomain_takeover": "Elimina el registro DNS colgante o reclama el recurso en el proveedor antes que un atacante.",
    "open_cloud_bucket": "Restringe la política del bucket a privado y revoca el listado público.",
    "config_leak": "Bloquea el acceso web a archivos de configuración (`.git`, `.env`) y rota cualqu​ier secreto expuesto.",
    "leaked_secret": "Revoca y rota la credencial inmediatamente y purga el secreto del historial de código.",
    "vulnerable_library": "Actualiza la dependencia a una versión sin CVEs conocidos.",
    "unauth_service_exposed": "Exige autenticación o restringe el acceso por red al servicio.",
}


def _target(finding: dict) -> str:
    return (finding.get("subdomain") or finding.get("url") or finding.get("name")
            or finding.get("ip") or finding.get("library") or "—")


def build_report(finding: dict, scan_doc: dict, *, exploitability: dict | None = None,
                 notarization: dict | None = None, platform: str = "hackerone") -> dict:
    ftype = finding.get("type", "finding")
    domain = (scan_doc.get("result") or {}).get("domain") or "—"
    title = _TYPE_TITLES.get(ftype, ftype.replace("_", " ").title())
    severity = (finding.get("severity") or "medium").lower()
    target = _target(finding)

    # Verdict from the exploitability engine (#1), if available for this target.
    verdict = None
    if exploitability:
        for r in exploitability.get("findings", []):
            if _target(r) == target and r.get("type") == ftype:
                verdict = r
                break

    lines = []
    lines.append(f"# {title} — {target}")
    lines.append("")
    lines.append(f"**Programa/Dominio:** {domain}  ")
    lines.append(f"**Severidad:** {severity.capitalize()}  ")
    lines.append(f"**Activo afectado:** `{target}`  ")
    if verdict:
        lines.append(f"**Estado de explotabilidad (NOCTUA):** `{verdict.get('verdict','').upper()}` "
                     f"— {verdict.get('detail') or verdict.get('method')}  ")
    lines.append("")
    lines.append("## Resumen")
    lines.append(_summary_for(ftype, target, finding))
    lines.append("")
    lines.append("## Pasos para reproducir")
    for i, step in enumerate(_steps_for(ftype, target, finding), 1):
        lines.append(f"{i}. {step}")
    lines.append("")
    lines.append("## Impacto")
    lines.append(_impact_for(ftype))
    lines.append("")
    lines.append("## Evidencia")
    if finding.get("evidence"):
        lines.append(f"> {finding.get('evidence')}")
    lines.append(_evidence_block(finding, notarization))
    lines.append("")
    lines.append("## Remediación")
    lines.append(_REMEDIATION.get(ftype, "Mitiga la exposición descrita arriba."))
    lines.append("")
    lines.append("---")
    lines.append(f"_Reporte generado por NOCTUA.osint · {datetime.now(timezone.utc).strftime('%Y-%m-%d')} "
                 f"· formato {platform}_")

    return {
        "platform": platform,
        "title": f"{title} on {target}",
        "severity": severity,
        "target": target,
        "verdict": (verdict or {}).get("verdict"),
        "markdown": "\n".join(lines),
    }


def _summary_for(ftype, target, f):
    return {
        "subdomain_takeover":
            f"El subdominio `{target}` apunta (CNAME) a un servicio de terceros cuyo recurso ya no existe, "
            f"lo que permite reclamarlo y servir contenido bajo el dominio de la organización.",
        "open_cloud_bucket":
            f"El bucket `{target}` permite el listado y lectura de objetos sin autenticación.",
        "config_leak":
            f"El archivo sensible en `{target}` se sirve públicamente, exponiendo configuración interna.",
        "leaked_secret":
            f"Se encontró una credencial embebida (`{f.get('kind')}`) en el código servido del objetivo.",
    }.get(ftype, f"Se detectó `{ftype}` en `{target}`.")


def _steps_for(ftype, target, f):
    return {
        "subdomain_takeover": [
            f"Resuelve el CNAME de `{target}`.",
            "Observa que el proveedor destino devuelve la firma de 'recurso inexistente'.",
            "Reclama el recurso en el proveedor para tomar control del subdominio (no ejecutado — solo verificado).",
        ],
        "open_cloud_bucket": [
            f"Solicita `GET {f.get('url') or target}`.",
            "Observa el listado XML de objetos devuelto sin autenticación.",
        ],
        "config_leak": [
            f"Solicita `GET {f.get('url') or target}`.",
            "Observa que el contenido sensible se devuelve con estado 200.",
        ],
    }.get(ftype, [f"Accede a `{target}` y observa la exposición descrita."])


def _impact_for(ftype):
    return {
        "subdomain_takeover": "Un atacante puede servir phishing, robar cookies o dañar la marca bajo un subdominio legítimo.",
        "open_cloud_bucket": "Exposición/filtración de datos almacenados en el bucket.",
        "config_leak": "Filtración de secretos y detalles internos que facilitan ataques posteriores.",
        "leaked_secret": "Acceso no autorizado a servicios usando la credencial filtrada.",
    }.get(ftype, "Compromiso potencial de confidencialidad, integridad o disponibilidad.")


def _evidence_block(finding, notarization):
    if not notarization:
        return "\n_(Notariza este escaneo para adjuntar un hash con sello de tiempo RFC3161.)_"
    return (f"\n**Evidencia notarizada (NOCTUA):** chain hash `{notarization.get('chain_hash','')[:32]}…` "
            f"sellado con timestamp RFC3161 ({(notarization.get('rfc3161_timestamp') or {}).get('authority','FreeTSA')}), "
            f"notary_id `{notarization.get('notary_id')}`. Prueba de descubrimiento con fecha verificable.")
