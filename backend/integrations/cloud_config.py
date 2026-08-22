"""Cloud & Dev Config Hunter — probe for exposed .env, .git, docker-compose, etc."""
import asyncio
import httpx
import logging
import re

from integrations.stealth import stealth_httpx_client

log = logging.getLogger("cloud_config")

# path → (severity, description)
DANGEROUS_PATHS = {
    ".env":                 ("critical", "Fichero de variables de entorno con secretos"),
    ".env.local":           ("critical", ".env local con secretos"),
    ".env.production":      ("critical", ".env producción con secretos"),
    ".env.backup":          ("critical", "Backup de .env con secretos"),
    ".git/config":          ("critical", "Repositorio Git expuesto (código completo descargable)"),
    ".git/HEAD":            ("critical", "Repositorio Git expuesto"),
    ".gitignore":           ("low",      ".gitignore expuesto (informativo)"),
    ".DS_Store":            ("medium",   "Fichero macOS expuesto — puede revelar estructura de directorios"),
    ".htaccess":            ("medium",   "Fichero de configuración Apache expuesto"),
    ".htpasswd":            ("critical", "Fichero de contraseñas Apache expuesto"),
    "docker-compose.yml":   ("high",     "Configuración Docker Compose expuesta"),
    "docker-compose.yaml":  ("high",     "Configuración Docker Compose expuesta"),
    "Dockerfile":           ("medium",   "Dockerfile expuesto"),
    "wp-config.php.bak":    ("critical", "Backup de wp-config con credenciales"),
    "wp-config.php~":       ("critical", "Backup de wp-config con credenciales"),
    "config.yml.bak":       ("high",     "Backup de configuración"),
    "config.php.bak":       ("high",     "Backup de configuración PHP"),
    "web.config":           ("medium",   "Configuración IIS expuesta"),
    "phpinfo.php":          ("high",     "phpinfo.php revela versiones y rutas internas"),
    "info.php":             ("high",     "info.php puede revelar phpinfo"),
    "server-status":        ("medium",   "Apache server-status expuesto"),
    "server-info":          ("medium",   "Apache server-info expuesto"),
    "backup.sql":           ("critical", "Dump SQL expuesto"),
    "database.sql":         ("critical", "Dump SQL expuesto"),
    "dump.sql":             ("critical", "Dump SQL expuesto"),
    "config.json":          ("medium",   "config.json — revisar contenido"),
    "firebase.json":        ("medium",   "Firebase config expuesta"),
    ".firebaserc":          ("medium",   "Config Firebase expuesta"),
    "kubeconfig":           ("critical", "Kubernetes config expuesto"),
    ".kube/config":         ("critical", "Kubernetes config expuesto"),
    "id_rsa":               ("critical", "Clave privada SSH RSA expuesta"),
    "id_ed25519":           ("critical", "Clave privada SSH Ed25519 expuesta"),
    ".ssh/authorized_keys": ("critical", "Claves SSH autorizadas expuestas"),
    ".aws/credentials":     ("critical", "Credenciales AWS expuestas"),
    ".npmrc":               ("high",     ".npmrc puede contener tokens de registry"),
    ".pypirc":              ("high",     ".pypirc puede contener credenciales PyPI"),
    "package.json":         ("low",      "package.json expuesto (informativo)"),
    "yarn.lock":            ("low",      "yarn.lock expuesto (informativo)"),
    "composer.json":        ("low",      "composer.json expuesto (informativo)"),
    "composer.lock":        ("low",      "composer.lock expuesto (informativo)"),
    "sitemap.xml":          ("info",     "sitemap.xml (informativo)"),
    "robots.txt":           ("info",     "robots.txt (informativo — a veces revela rutas internas)"),
    "crossdomain.xml":      ("low",      "crossdomain.xml (revisar policy)"),
}


CONTENT_HINTS = {
    ".env": [b"APP_KEY=", b"DB_PASSWORD=", b"SECRET_KEY", b"AWS_"],
    ".git/config": [b"[core]", b"repositoryformatversion"],
    "docker-compose.yml": [b"services:", b"version:"],
    "wp-config.php.bak": [b"DB_PASSWORD", b"AUTH_KEY"],
    "id_rsa": [b"BEGIN RSA PRIVATE KEY", b"BEGIN OPENSSH PRIVATE KEY"],
    "firebase.json": [b"\"hosting\"", b"\"database\""],
}


async def _probe(client: httpx.AsyncClient, base: str, path: str) -> dict | None:
    url = f"{base}/{path}"
    try:
        # GET first 4KB only
        r = await client.get(url, timeout=5.0, follow_redirects=False,
                              headers={"User-Agent": "Mozilla/5.0 NOCTUA-osint",
                                       "Range": "bytes=0-4095"})
        # Accept 200 + 206 (Partial Content)
        if r.status_code not in (200, 206):
            return None
        content = r.content[:4096]
        # Heuristic: strip if it's obviously the homepage / 404 template
        if b"<!DOCTYPE" in content[:100] or b"<html" in content[:200]:
            # Only accept HTML if the file legitimately is HTML-formatted
            if path not in ("phpinfo.php", "info.php", "server-status", "server-info"):
                return None
        # Content confirmation
        confirmed = False
        for hint in CONTENT_HINTS.get(path, []):
            if hint.lower() in content.lower():
                confirmed = True
                break
        # If we don't have hint match, still keep only for the higher-severity files
        sev, desc = DANGEROUS_PATHS[path]
        return {
            "url": url, "path": path, "status": r.status_code,
            "severity": sev, "description": desc,
            "content_length": int(r.headers.get("content-length") or len(content)),
            "content_type": r.headers.get("content-type", "unknown"),
            "content_preview": content[:200].decode("utf-8", errors="replace"),
            "confirmed": confirmed,
        }
    except Exception:
        return None


async def hunt_configs(domain: str, subdomains: list[str] | None = None,
                       max_subs: int = 3) -> dict:
    """Probe root + top N subdomains for exposed config files."""
    targets = [f"https://{domain}", f"http://{domain}"]
    for sub in (subdomains or [])[:max_subs]:
        targets.append(f"https://{sub}")

    async with stealth_httpx_client(domain, timeout=6.0) as client:
        tasks = []
        for base in targets:
            for path in DANGEROUS_PATHS.keys():
                tasks.append(_probe(client, base, path))
        results = await asyncio.gather(*tasks, return_exceptions=False)

    findings = [r for r in results if r]
    # Dedupe by (path)
    seen = set()
    unique = []
    for f in findings:
        key = (f["path"], f["url"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)

    counts = {}
    for f in unique:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    return {
        "domain": domain,
        "targets_probed": len(targets),
        "paths_probed": len(DANGEROUS_PATHS),
        "total_findings": len(unique),
        "counts_by_severity": counts,
        "findings": sorted(unique, key=lambda x: {"critical":0,"high":1,"medium":2,"low":3,"info":4}.get(x["severity"], 5)),
    }
