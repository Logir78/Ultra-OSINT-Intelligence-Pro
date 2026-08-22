"""Subdomain Takeover / Dangling DNS scanner.

For each subdomain, resolves CNAME chain and matches the target against known
fingerprints of external services that leave DNS pointing to unclaimed resources.

Fingerprint database inspired by can-i-take-over-xyz and public bug-bounty work.
"""
import asyncio
import re
import httpx
import dns.resolver
import dns.exception
import logging

from integrations.stealth import stealth_httpx_client

log = logging.getLogger("takeover")


# Fingerprints: (service, cname_pattern_regex, http_body_signature_regex, risk)
FINGERPRINTS = [
    ("GitHub Pages",   r"\.github\.io$",                r"There isn'?t a GitHub Pages site here|For root URLs",         "critical"),
    ("Heroku",         r"\.herokuapp\.com$",            r"No such app|herokucdn\.com/error-pages/no-such-app",           "critical"),
    ("AWS S3",         r"\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com$", r"NoSuchBucket|The specified bucket does not exist", "critical"),
    ("AWS S3 Website", r"\.s3-website[.-][a-z0-9-]+\.amazonaws\.com$", r"NoSuchBucket",                                  "critical"),
    ("Azure Web App",  r"\.azurewebsites\.net$",        r"404 Web Site not found|Error 404 - Web app not found",         "critical"),
    ("Azure TrafficMgr", r"\.trafficmanager\.net$",     r"",                                                              "high"),
    ("Azure CloudApp", r"\.cloudapp\.(net|azure\.com)$", r"",                                                             "high"),
    ("Shopify",        r"\.myshopify\.com$",            r"Sorry, this shop is currently unavailable",                    "critical"),
    ("Zendesk",        r"\.zendesk\.com$",              r"Help Center Closed",                                            "critical"),
    ("Fastly",         r"\.fastly\.net$",               r"Fastly error: unknown domain",                                  "critical"),
    ("Ghost",          r"\.ghost\.io$",                 r"The thing you were looking for is no longer here",              "critical"),
    ("Tumblr",         r"\.tumblr\.com$",               r"Whatever you were looking for doesn'?t currently exist",       "critical"),
    ("Bitbucket",      r"\.bitbucket\.io$",             r"Repository not found",                                          "critical"),
    ("Cargo",          r"\.cargocollective\.com$",      r"404 Not Found",                                                 "high"),
    ("Squarespace",    r"\.squarespace\.com$",          r"No Such Account|We couldn'?t find the page",                    "critical"),
    ("Surge.sh",       r"\.surge\.sh$",                 r"project not found",                                             "critical"),
    ("Netlify",        r"\.netlify\.app$",              r"Not Found - Request ID",                                        "high"),
    ("Vercel",         r"\.vercel\.app$",               r"DEPLOYMENT_NOT_FOUND",                                          "high"),
    ("Readme.io",      r"\.readme\.io$",                r"Project doesnt exist",                                          "critical"),
    ("Statuspage",     r"\.statuspage\.io$",            r"You are being redirected",                                      "high"),
    ("Unbounce",       r"\.unbouncepages\.com$",        r"The requested URL was not found",                               "critical"),
    ("Uservoice",      r"\.uservoice\.com$",            r"This UserVoice subdomain is currently available",               "critical"),
    ("WPengine",       r"\.wpengine\.com$",             r"The site you were looking for couldn'?t be found",              "high"),
    ("Pantheon",       r"\.pantheonsite\.io$",          r"The gods are wise",                                             "critical"),
    ("Kinsta",         r"\.kinsta\.cloud$",             r"No Site For Domain",                                            "critical"),
    ("HelpJuice",      r"\.helpjuice\.com$",            r"We could not find what you'?re looking for",                    "high"),
    ("Intercom",       r"\.custom\.intercom\.help$",    r"This page is reserved for artistic \(no, actually inventors\)", "critical"),
    ("Tilda",          r"\.tilda\.ws$",                 r"Please renew your subscription",                                "critical"),
    ("Webflow",        r"\.webflow\.io$",               r"The page you are looking for doesn'?t exist",                   "high"),
    ("Wordpress.com",  r"\.wordpress\.com$",            r"Do you want to register",                                       "critical"),
    ("Cloudfront",     r"\.cloudfront\.net$",           r"Bad request|The request could not be satisfied|ERR_TOO_MANY_REDIRECTS", "high"),
    # ─────────── extra 20 fingerprints ───────────
    ("Wistia",         r"\.wistia\.com$",               r"Wistia project not found|We couldn'?t find",                   "high"),
    ("Feedpress",      r"\.feedpress\.me$",             r"The feed has not been found",                                    "critical"),
    ("Instapage",      r"\.pageserve\.co$|\.instapage\.com$", r"Looks like you'?re lost",                                 "critical"),
    ("Teamwork",       r"\.teamwork\.com$",             r"Oops - We didn'?t find your site",                              "critical"),
    ("Aha",            r"\.aha\.io$",                   r"There is no portal here|Try again",                             "critical"),
    ("Airee",          r"\.airee\.(ru|com)$",           r"",                                                                "high"),
    ("Anima",          r"\.animaapp\.io$",              r"If this is your website and you'?ve just created",              "high"),
    ("Announcekit",    r"\.announcekit\.app$",          r"Announcekit App|Page not found",                                 "high"),
    ("Bigcartel",      r"\.bigcartel\.com$",            r"<h1>Oops! We couldn.?t find that page",                          "critical"),
    ("Brightcove",     r"\.brightcovegallery\.com$|\.gallery\.video$|\.bcvp0rtal\.com$", r"",                              "high"),
    ("Campaign Mon.",  r"createsend\.com$",             r"Double check the URL",                                            "high"),
    ("Canny",          r"\.canny\.io$",                 r"Company Not Found",                                              "critical"),
    ("HatenaBlog",     r"\.hatenablog\.com$",           r"404 Blog is not found",                                          "critical"),
    ("Helpscout",      r"\.helpscoutdocs\.com$",        r"No settings were found for this company",                       "critical"),
    ("LaunchRock",     r"\.launchrock\.com$",           r"HTTP 404 Not Found",                                             "high"),
    ("Ngrok",          r"\.ngrok\.io$",                 r"Tunnel .* not found",                                            "critical"),
    ("Pingdom",        r"stats\.pingdom\.com$",         r"pingdom",                                                        "high"),
    ("Proposify",      r"\.proposify\.biz$",            r"If you need immediate assistance",                               "high"),
    ("Simplebooklet",  r"\.simplebooklet\.com$",        r"We can'?t find this <a",                                          "critical"),
    ("Smugmug",        r"\.smugmug\.com$",              r"",                                                                "high"),
    ("Strikingly",     r"\.strikinglydns\.com$",        r"But if you'?re looking to build your own website|PAGE NOT FOUND", "critical"),
    ("Thinkific",      r"\.thinkific\.com$",            r"You may have mistyped the address",                              "critical"),
    ("Uberflip",       r"\.uberflip\.com$",             r"The URL you'?ve accessed does not provide a hub",                 "critical"),
    ("Worksites.net",  r"\.worksites\.net$",            r"Hello! Sorry, but this website is either unavailable",           "high"),
    # ─────────── expansion batch 3 (25 more services) ───────────
    ("Acquia",         r"\.acquia-sites\.com$",         r"Web Site Not Found",                                            "critical"),
    ("ActiveCampaign", r"\.activehosted\.com$",         r"cannot be found",                                                "high"),
    ("Aftership",      r"\.aftership\.com$",            r"Oops\.\s*The page you'?re looking for does not exist",           "high"),
    ("Agile CRM",      r"\.agilecrm\.com$",             r"Sorry, this page is no longer available",                        "high"),
    ("Akamai",         r"\.edgekey\.net$|\.edgesuite\.net$", r"Reference #\d+|the server encountered an internal error",   "medium"),
    ("Bitly",          r"\.bitly\.com$|bit\.ly$",       r"Bitly \|",                                                        "high"),
    ("Brightcove",     r"\.brightcove\.com$",           r"BC Player",                                                       "medium"),
    ("Cloud Foundry",  r"\.cfapps\.io$",                r"404 Not Found: Requested route",                                  "critical"),
    ("Fly.io",         r"\.fly\.dev$",                  r"unknown app|not found|Unknown application",                      "high"),
    ("Github Pages 2", r"\.io$",                        r"Site not found \\u00b7 GitHub Pages",                             "critical"),
    ("Google Cloud",   r"\.googleapis\.com$",           r"The specified bucket does not exist|NoSuchBucket",               "high"),
    ("Hubspot",        r"\.hs-sites\.com$|\.hubspot\.com$", r"Domain not found|invalid page",                              "high"),
    ("JetBrains",      r"\.myjetbrains\.com$",          r"is not a registered InCloud YouTrack",                            "high"),
    ("Kajabi",         r"\.mykajabi\.com$",             r"The page you were looking for doesn'?t exist",                   "high"),
    ("Mashery",        r"\.mashery\.com$",              r"Unrecognized domain",                                             "critical"),
    ("Mediumsub",      r"\.medium\.com$",               r"Medium is a place to write",                                     "medium"),
    ("Ngrok Free",     r"\.ngrok-free\.app$",           r"tunnel [^ ]+ not found",                                          "critical"),
    ("Notion",         r"\.notion\.site$",              r"This page was not found",                                        "high"),
    ("Pardot",         r"go\.pardot\.com$",             r"Domain not found",                                                "high"),
    ("Salesforce",     r"\.desk\.com$",                 r"Please try again or try Desk\.com",                              "high"),
    ("SmartJobBoard",  r"\.smartjobboard\.com$",        r"This job board website is either expired",                       "critical"),
    ("Sprintful",      r"\.sprintful\.com$",            r"page not found",                                                  "high"),
    ("Tave",           r"\.tave\.com$",                 r"<h1>Error 404: Page Not Found</h1>",                              "high"),
    ("Uptimerobot",    r"stats\.uptimerobot\.com$",     r"page not found",                                                  "medium"),
    ("Zoho",           r"\.zohodesk\.com$|\.zohoshop\.com$", r"The specified domain has expired|does not exist",           "high"),
]


def _match_cname(cname: str) -> tuple[str, str, str] | None:
    for service, cpat, bpat, risk in FINGERPRINTS:
        if re.search(cpat, cname, re.IGNORECASE):
            return service, bpat, risk
    return None


async def _resolve_cname_chain(hostname: str) -> list[str]:
    """Return the CNAME target chain (may be empty)."""
    def _do():
        chain = []
        current = hostname
        for _ in range(6):
            try:
                answers = dns.resolver.resolve(current, "CNAME", lifetime=3.0)
                target = str(answers[0].target).rstrip(".")
                if not target or target == current:
                    break
                chain.append(target)
                current = target
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                    dns.resolver.NoNameservers, dns.exception.Timeout):
                break
            except Exception:
                break
        return chain
    return await asyncio.to_thread(_do)


async def _fetch_body(client: httpx.AsyncClient, hostname: str) -> tuple[int | None, str]:
    for scheme in ("https", "http"):
        try:
            r = await client.get(f"{scheme}://{hostname}", timeout=8.0,
                                 follow_redirects=True)
            return r.status_code, r.text[:2500]
        except Exception:
            continue
    return None, ""


async def _check_subdomain(client: httpx.AsyncClient, hostname: str) -> dict:
    """Analyze one subdomain for takeover potential."""
    result = {
        "subdomain": hostname,
        "cname_chain": [],
        "risk": "safe",
        "service": None,
        "evidence": None,
        "status_code": None,
        "vulnerable": False,
    }
    chain = await _resolve_cname_chain(hostname)
    result["cname_chain"] = chain
    if not chain:
        return result

    # Check every CNAME in the chain against fingerprints
    matched = None
    for cn in chain:
        m = _match_cname(cn)
        if m:
            matched = (cn, *m)
            break
    if not matched:
        return result

    cn_target, service, body_pattern, risk_level = matched
    result["service"] = service
    result["risk"] = "possibly_vulnerable"

    status, body = await _fetch_body(client, hostname)
    result["status_code"] = status

    # Verify with body signature
    if body_pattern and re.search(body_pattern, body, re.IGNORECASE):
        result["vulnerable"] = True
        result["risk"] = risk_level  # critical / high
        result["evidence"] = re.search(body_pattern, body, re.IGNORECASE).group(0)[:180]
    elif status == 404 and body_pattern == "":
        # Some services have no reliable body but 404 is enough
        result["vulnerable"] = True
        result["risk"] = risk_level
        result["evidence"] = f"HTTP 404 en servicio {service}"
    elif status is None:
        # DNS resolves but nothing responds — classic dangling
        result["vulnerable"] = True
        result["risk"] = "critical"
        result["evidence"] = f"CNAME apunta a {service} pero el servicio no responde"

    return result


async def scan_takeovers(subdomains: list[str], main_domain: str) -> dict:
    """Scan a list of subdomains for takeover / dangling DNS risks."""
    # Always include the root domain too
    targets = list({main_domain, *subdomains})
    limits = httpx.Limits(max_connections=20, max_keepalive_connections=10)
    async with stealth_httpx_client(main_domain, limits=limits, verify=False) as client:
        results = await asyncio.gather(*[_check_subdomain(client, h) for h in targets])

    vulnerable = [r for r in results if r["vulnerable"]]
    with_cname = [r for r in results if r["cname_chain"]]

    return {
        "domain": main_domain,
        "checked": len(targets),
        "with_cname": len(with_cname),
        "vulnerable_count": len(vulnerable),
        "results": sorted(results, key=lambda r: (not r["vulnerable"], r["subdomain"])),
        "explanation": (
            "Un secuestro de subdominio (subdomain takeover) ocurre cuando un registro DNS "
            "(típicamente un CNAME) apunta a un servicio externo que ha sido eliminado o "
            "nunca fue reclamado. Un atacante puede reclamar ese servicio y tomar el control "
            "total del subdominio, permitiéndole realizar ataques de phishing, robo de cookies "
            "de sesión o distribuir malware bajo el nombre de su empresa. Verifique inmediatamente "
            "los subdominios marcados y elimine el registro DNS o reclame el servicio."
        ),
    }
