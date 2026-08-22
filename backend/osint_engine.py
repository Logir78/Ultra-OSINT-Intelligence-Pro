"""OSINT analysis engine using native Python libraries."""
import asyncio
import socket
import ssl
import re
from datetime import datetime, timezone
from typing import Any
import httpx
import whois
import dns.resolver
import dns.exception

from tech_stack import analyze_tech_for_hosts
from integrations.stealth import stealth_httpx_client


COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8000: "HTTP-Alt", 8080: "HTTP-Proxy",
    8443: "HTTPS-Alt", 8888: "HTTP-Alt", 9200: "Elasticsearch",
    27017: "MongoDB",
}

EXTENDED_PORTS = {
    **COMMON_PORTS,
    20: "FTP-Data", 69: "TFTP", 111: "RPC", 135: "MSRPC",
    137: "NetBIOS", 139: "NetBIOS-SSN", 161: "SNMP", 389: "LDAP",
    465: "SMTPS", 514: "Syslog", 587: "SMTP-Sub", 636: "LDAPS",
    873: "Rsync", 990: "FTPS", 1080: "SOCKS", 1194: "OpenVPN",
    1723: "PPTP", 2049: "NFS", 2082: "cPanel", 2083: "cPanel-SSL",
    2222: "SSH-Alt", 3000: "Node/React", 3001: "Node-Alt",
    4444: "Metasploit", 5000: "UPnP/Flask", 5001: "Node-Alt",
    5060: "SIP", 5222: "XMPP", 5672: "RabbitMQ", 5984: "CouchDB",
    6000: "X11", 7000: "AFS", 7001: "AFS", 7777: "Game/Alt",
    8081: "HTTP-Alt", 8181: "HTTP-Alt", 8834: "Nessus",
    9000: "SonarQube", 9090: "Prometheus", 9091: "Trans",
    9418: "Git", 11211: "Memcached", 25565: "Minecraft",
    50000: "SAP", 50070: "Hadoop",
}

COMMON_SUBDOMAINS = [
    # web
    "www", "www1", "www2", "web", "m", "mobile", "app", "apps", "portal",
    # mail
    "mail", "webmail", "smtp", "smtp2", "pop", "pop3", "imap", "mx", "mx1", "mx2",
    "email", "exchange", "autodiscover", "mta",
    # DNS / infra
    "ns", "ns1", "ns2", "ns3", "ns4", "dns", "dns1", "dns2",
    # dev/qa
    "dev", "development", "test", "testing", "qa", "uat", "staging", "stage",
    "preprod", "sandbox", "demo", "beta", "alpha", "canary",
    # admin
    "admin", "administrator", "manage", "manager", "dashboard", "cpanel",
    "webdisk", "whm", "backup", "backups",
    # api / services
    "api", "api1", "api2", "apis", "graphql", "gateway", "auth", "sso", "oauth",
    "identity", "id", "login", "signin", "signup",
    # content
    "blog", "news", "docs", "help", "support", "kb", "faq", "forum", "wiki",
    "community", "learn", "academy", "training",
    # commerce
    "shop", "store", "cart", "checkout", "pay", "payments", "billing",
    # cdn / media
    "cdn", "cdn1", "cdn2", "static", "assets", "media", "images", "img",
    "video", "videos", "download", "downloads", "files",
    # devops
    "git", "gitlab", "github", "jenkins", "ci", "build", "deploy", "docker",
    "kubernetes", "k8s", "monitor", "monitoring", "grafana", "prometheus",
    "kibana", "elk", "logs", "logging", "status", "health", "metrics",
    # network
    "vpn", "ssh", "ftp", "sftp", "proxy", "remote", "rdp", "gate",
    "internal", "intranet", "extranet", "corp", "office",
    # security
    "secure", "security", "waf", "mfa",
    # crm / bi
    "crm", "erp", "hr", "hrms", "jira", "confluence", "slack", "teams",
    "analytics", "bi", "data", "warehouse", "reports",
    # misc
    "old", "legacy", "new", "test1", "test2", "temp", "hidden", "private",
    "public", "external", "partner", "partners", "customer", "customers",
    "client", "clients", "affiliate", "affiliates",
]


def _normalize_domain(domain: str) -> str:
    domain = domain.strip().lower()
    domain = re.sub(r"^https?://", "", domain)
    domain = domain.split("/")[0].split(":")[0]
    return domain


async def get_whois(domain: str) -> dict[str, Any]:
    def _lookup():
        try:
            w = whois.whois(domain)
            data = {}
            for k, v in dict(w).items():
                if v is None:
                    continue
                if isinstance(v, list):
                    v = [str(x) for x in v]
                elif isinstance(v, datetime):
                    v = v.isoformat()
                else:
                    v = str(v)
                data[k] = v
            return {"success": True, "data": data}
        except Exception as e:
            return {"success": False, "error": str(e), "data": {}}
    return await asyncio.to_thread(_lookup)


async def get_dns_records(domain: str) -> dict[str, Any]:
    def _lookup():
        result = {}
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 4
        for rtype in record_types:
            try:
                answers = resolver.resolve(domain, rtype)
                result[rtype] = [str(r) for r in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                    dns.resolver.NoNameservers, dns.exception.Timeout):
                result[rtype] = []
            except Exception:
                result[rtype] = []
        return result
    return await asyncio.to_thread(_lookup)


async def get_ip(domain: str) -> dict[str, Any]:
    def _lookup():
        try:
            ip = socket.gethostbyname(domain)
            try:
                reverse = socket.gethostbyaddr(ip)[0]
            except Exception:
                reverse = None
            return {"ip": ip, "reverse_dns": reverse}
        except Exception as e:
            return {"ip": None, "error": str(e)}
    return await asyncio.to_thread(_lookup)


async def get_ssl_cert(domain: str) -> dict[str, Any]:
    def _lookup():
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    version = ssock.version()
                    cipher = ssock.cipher()
            def _fmt_field(field):
                return {k: v for tup in field for k, v in [tup]}
            return {
                "success": True,
                "subject": _fmt_field(cert.get("subject", [])),
                "issuer": _fmt_field(cert.get("issuer", [])),
                "version": cert.get("version"),
                "serial_number": cert.get("serialNumber"),
                "not_before": cert.get("notBefore"),
                "not_after": cert.get("notAfter"),
                "san": [n[1] for n in cert.get("subjectAltName", [])],
                "tls_version": version,
                "cipher": list(cipher) if cipher else None,
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    return await asyncio.to_thread(_lookup)


async def get_http_headers(domain: str, scheme: str = "http") -> dict[str, Any]:
    url = f"{scheme}://{domain}"
    try:
        async with stealth_httpx_client(domain, follow_redirects=True, timeout=8.0, verify=False) as c:
            r = await c.get(url)
        return {
            "success": True,
            "status_code": r.status_code,
            "final_url": str(r.url),
            "headers": dict(r.headers),
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


async def scan_port(host: str, port: int) -> tuple[int, bool]:
    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=1.5)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return port, True
    except Exception:
        return port, False


async def scan_ports(host: str, extended: bool = False) -> dict[str, Any]:
    ports = EXTENDED_PORTS if extended else COMMON_PORTS
    tasks = [scan_port(host, p) for p in ports.keys()]
    results = await asyncio.gather(*tasks)
    open_ports = [
        {"port": p, "service": ports[p]}
        for p, is_open in results if is_open
    ]
    return {"open_ports": open_ports, "total_scanned": len(ports)}


async def find_subdomains(domain: str) -> dict[str, Any]:
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 3

    def _check(sub):
        target = f"{sub}.{domain}"
        try:
            answers = resolver.resolve(target, "A")
            return {"subdomain": target, "ips": [str(r) for r in answers]}
        except Exception:
            return None

    results = await asyncio.gather(*[asyncio.to_thread(_check, s) for s in COMMON_SUBDOMAINS])
    found = [r for r in results if r]
    return {"found": found, "total_checked": len(COMMON_SUBDOMAINS)}


def _analyze_security(headers_https: dict, ssl_cert: dict, headers_http: dict,
                     dns_records: dict, open_ports: list) -> dict[str, Any]:
    basic = []
    medium = []
    advanced = []

    https_ok = headers_https.get("success", False)
    hdrs = {k.lower(): v for k, v in (headers_https.get("headers") or {}).items()}
    http_hdrs = {k.lower(): v for k, v in (headers_http.get("headers") or {}).items()}

    # BASIC
    basic.append({
        "check": "HTTPS disponible",
        "status": "pass" if https_ok else "fail",
        "detail": "El sitio responde por HTTPS" if https_ok else "El sitio no responde por HTTPS",
    })
    ssl_valid = ssl_cert.get("success", False)
    basic.append({
        "check": "Certificado SSL válido",
        "status": "pass" if ssl_valid else "fail",
        "detail": f"Emisor: {ssl_cert.get('issuer', {}).get('organizationName', 'N/A')}" if ssl_valid else ssl_cert.get("error", "Sin SSL"),
    })
    basic.append({
        "check": "Redirección HTTP → HTTPS",
        "status": "pass" if str(headers_http.get("final_url", "")).startswith("https://") else "warn",
        "detail": f"URL final: {headers_http.get('final_url', 'N/A')}",
    })
    basic.append({
        "check": "Registros DNS presentes",
        "status": "pass" if dns_records.get("A") else "fail",
        "detail": f"{len(dns_records.get('A', []))} A records",
    })

    # MEDIUM - security headers
    sec_headers = {
        "strict-transport-security": "HSTS",
        "content-security-policy": "CSP",
        "x-frame-options": "X-Frame-Options",
        "x-content-type-options": "X-Content-Type-Options",
        "referrer-policy": "Referrer-Policy",
        "permissions-policy": "Permissions-Policy",
    }
    for hkey, label in sec_headers.items():
        present = hkey in hdrs
        medium.append({
            "check": f"Cabecera {label}",
            "status": "pass" if present else "warn",
            "detail": hdrs.get(hkey, "No presente"),
        })

    # ADVANCED
    server = hdrs.get("server") or http_hdrs.get("server")
    advanced.append({
        "check": "Banner del servidor oculto",
        "status": "warn" if server else "pass",
        "detail": f"Server: {server}" if server else "No expone banner",
    })
    powered = hdrs.get("x-powered-by") or http_hdrs.get("x-powered-by")
    advanced.append({
        "check": "X-Powered-By oculto",
        "status": "warn" if powered else "pass",
        "detail": f"X-Powered-By: {powered}" if powered else "No expone tecnología",
    })
    # TLS version
    tls_ver = ssl_cert.get("tls_version") or ""
    tls_ok = tls_ver.startswith("TLSv1.2") or tls_ver.startswith("TLSv1.3")
    advanced.append({
        "check": "TLS moderno (1.2+)",
        "status": "pass" if tls_ok else "fail",
        "detail": f"Versión: {tls_ver or 'N/A'}",
    })
    # DNSSEC / CAA
    advanced.append({
        "check": "Registro CAA configurado",
        "status": "pass" if dns_records.get("CAA") else "warn",
        "detail": f"{len(dns_records.get('CAA', []))} CAA records",
    })
    # Ports risky
    risky_ports = [21, 23, 3389, 3306, 5432, 6379, 27017, 5900, 445]
    exposed = [p for p in open_ports if p["port"] in risky_ports]
    advanced.append({
        "check": "Puertos sensibles cerrados",
        "status": "fail" if exposed else "pass",
        "detail": f"Expuestos: {', '.join(str(p['port']) for p in exposed)}" if exposed else "Ninguno expuesto",
    })

    def _score(items):
        if not items:
            return 0
        total = len(items)
        passed = sum(1 for i in items if i["status"] == "pass")
        return round(passed / total * 100)

    return {
        "basic": {"items": basic, "score": _score(basic)},
        "medium": {"items": medium, "score": _score(medium)},
        "advanced": {"items": advanced, "score": _score(advanced)},
    }


async def analyze_domain(raw_domain: str, extended_ports: bool = False) -> dict[str, Any]:
    domain = _normalize_domain(raw_domain)
    started = datetime.now(timezone.utc)

    ip_task = get_ip(domain)
    whois_task = get_whois(domain)
    dns_task = get_dns_records(domain)
    ssl_task = get_ssl_cert(domain)
    http_task = get_http_headers(domain, "http")
    https_task = get_http_headers(domain, "https")
    subs_task = find_subdomains(domain)

    ip_info, whois_info, dns_info, ssl_info, http_info, https_info, subs_info = await asyncio.gather(
        ip_task, whois_task, dns_task, ssl_task, http_task, https_task, subs_task
    )

    scan_host = ip_info.get("ip") or domain
    ports_info = await scan_ports(scan_host, extended=extended_ports)

    security = _analyze_security(
        headers_https=https_info,
        ssl_cert=ssl_info,
        headers_http=http_info,
        dns_records=dns_info,
        open_ports=ports_info["open_ports"],
    )

    # Tech stack analysis for main domain + each subdomain
    hosts = [domain]
    for sub in subs_info.get("found", []):
        hosts.append(sub["subdomain"])
    # preload main-domain headers to avoid a redundant fetch
    preloaded = {}
    if https_info.get("success"):
        preloaded[domain] = https_info.get("headers")
    tech_analysis = await analyze_tech_for_hosts(hosts, preloaded=preloaded)
    # Attach IP list to each entry so the frontend can display it
    ip_by_host = {domain: [ip_info.get("ip")] if ip_info.get("ip") else []}
    for sub in subs_info.get("found", []):
        ip_by_host[sub["subdomain"]] = sub.get("ips", [])
    for t in tech_analysis:
        t["ips"] = ip_by_host.get(t["hostname"], [])

    finished = datetime.now(timezone.utc)
    return {
        "domain": domain,
        "started_at": started.isoformat(),
        "finished_at": finished.isoformat(),
        "duration_seconds": (finished - started).total_seconds(),
        "ip": ip_info,
        "whois": whois_info,
        "dns": dns_info,
        "ssl": ssl_info,
        "http_headers": http_info,
        "https_headers": https_info,
        "subdomains": subs_info,
        "ports": ports_info,
        "security": security,
        "tech_analysis": tech_analysis,
    }
