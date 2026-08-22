"""Bot Resistance Evaluator — detect captcha, rate-limit and login form protections."""
import httpx
import re
import logging
import asyncio

from integrations.stealth import stealth_httpx_client

log = logging.getLogger("bot_resistance")


CAPTCHA_SIGNATURES = {
    "reCAPTCHA v2": [r"google\.com/recaptcha", r"g-recaptcha", r"grecaptcha\.render"],
    "reCAPTCHA v3": [r"grecaptcha\.execute", r"recaptcha/api\.js\?render="],
    "hCaptcha":     [r"hcaptcha\.com", r"h-captcha", r"js\.hcaptcha\.com"],
    "Cloudflare Turnstile": [r"cf-turnstile", r"challenges\.cloudflare\.com/turnstile"],
    "Arkose Labs (FunCaptcha)": [r"funcaptcha", r"arkoselabs\.com"],
    "GeeTest":      [r"geetest\.com", r"gt_captcha"],
    "AWS WAF Captcha": [r"aws-waf-token", r"awswaf.*captcha"],
    "Simple honeypot": [r'<input[^>]+type=["\']hidden["\'][^>]+name=["\'](honeypot|website|url|hp_field)'],
    "Custom challenge": [r"prove\s*you.*human", r"captcha\.php", r"security\s*question"],
}

LOGIN_FORM_HINT = re.compile(
    r"<form[^>]*action=[\"']([^\"']*(?:login|signin|auth|session)[^\"']*)[\"'][^>]*>",
    re.IGNORECASE,
)
INPUT_PASSWORD = re.compile(r"""<input[^>]+type=["']password["']""", re.IGNORECASE)


async def _probe(client: httpx.AsyncClient, url: str) -> httpx.Response | None:
    try:
        r = await client.get(url, timeout=7.0, follow_redirects=True)
        return r
    except Exception:
        return None


async def _test_rate_limit(url: str, host: str) -> dict:
    """Send 8 rapid GETs (with rotating UA per request) and check for 429/403/challenge.
    Rate-limit detection intentionally uses distinct UAs to look like distributed bots."""
    async with stealth_httpx_client(host, timeout=6.0) as client:
        try:
            responses = await asyncio.gather(
                *[client.get(url, headers={"User-Agent": f"NOCTUA-probe/{i}"})
                  for i in range(8)],
                return_exceptions=True,
            )
        except Exception:
            return {"tested": False, "sample_size": 0}
    statuses = []
    rate_limited = False
    challenge = False
    for r in responses:
        if isinstance(r, Exception):
            statuses.append("err")
            continue
        statuses.append(r.status_code)
        if r.status_code == 429:
            rate_limited = True
        if r.status_code == 403 and any(k in r.text.lower() for k in ("captcha", "challenge", "cf-", "block")):
            challenge = True
    return {
        "tested": True,
        "sample_size": len(statuses),
        "statuses": statuses,
        "rate_limited_seen": rate_limited,
        "challenge_seen": challenge,
    }


async def evaluate(domain: str) -> dict:
    """Fetch homepage + /login (if any) and evaluate bot protections."""
    findings = {
        "domain": domain,
        "homepage": {"analyzed": False},
        "login_page": None,
        "captchas_detected": [],
        "waf_hint": None,
        "rate_limit": None,
        "risk": "unknown",
        "score": 0,
        "verdict": "",
    }

    async with stealth_httpx_client(domain, timeout=8.0, follow_redirects=True) as client:
        home_r = None
        for scheme in ("https", "http"):
            r = await _probe(client, f"{scheme}://{domain}")
            if r and r.status_code == 200:
                home_r = r
                break

        if home_r:
            html = home_r.text[:200 * 1024]
            findings["homepage"]["analyzed"] = True
            findings["homepage"]["status"] = home_r.status_code

            # Detect captchas
            for name, patterns in CAPTCHA_SIGNATURES.items():
                for p in patterns:
                    if re.search(p, html, re.IGNORECASE):
                        if name not in findings["captchas_detected"]:
                            findings["captchas_detected"].append(name)
                        break

            # WAF hint from headers
            server_hdr = (home_r.headers.get("server", "") + " " + home_r.headers.get("cf-ray", "")).lower()
            if "cloudflare" in server_hdr or home_r.headers.get("cf-ray"):
                findings["waf_hint"] = "Cloudflare"
            elif "sucuri" in server_hdr:
                findings["waf_hint"] = "Sucuri"
            elif "akamai" in server_hdr:
                findings["waf_hint"] = "Akamai"
            elif "aws" in server_hdr or home_r.headers.get("x-amzn-requestid"):
                findings["waf_hint"] = "AWS WAF"

            # Locate login form
            login_match = LOGIN_FORM_HINT.search(html)
            if login_match:
                login_action = login_match.group(1)
                if login_action.startswith("/"):
                    login_url = f"https://{domain}{login_action}"
                elif login_action.startswith("http"):
                    login_url = login_action
                else:
                    login_url = f"https://{domain}/{login_action.lstrip('/')}"
                # Fetch login page
                lr = await _probe(client, login_url)
                if lr and lr.status_code == 200:
                    lhtml = lr.text[:100 * 1024]
                    login_captchas = []
                    for name, patterns in CAPTCHA_SIGNATURES.items():
                        for p in patterns:
                            if re.search(p, lhtml, re.IGNORECASE):
                                login_captchas.append(name)
                                break
                    findings["login_page"] = {
                        "url": login_url,
                        "has_password_input": bool(INPUT_PASSWORD.search(lhtml)),
                        "captchas_on_login": sorted(set(login_captchas)),
                        "status": lr.status_code,
                    }
                    # Update main captcha list
                    for c in login_captchas:
                        if c not in findings["captchas_detected"]:
                            findings["captchas_detected"].append(c)

    # Rate-limit probe (on login page if found, else homepage)
    target = (findings.get("login_page") or {}).get("url") or f"https://{domain}"
    findings["rate_limit"] = await _test_rate_limit(target, domain)

    # Scoring: lower is weaker
    score = 0
    if findings["captchas_detected"]: score += 40
    if findings["login_page"] and (findings["login_page"] or {}).get("captchas_on_login"):
        score += 30
    if findings.get("waf_hint"): score += 15
    if (findings["rate_limit"] or {}).get("rate_limited_seen"): score += 15
    findings["score"] = min(100, score)

    if score >= 70:
        risk = "low"
        verdict = "Protecciones robustas contra bots detectadas."
    elif score >= 40:
        risk = "medium"
        verdict = "Protecciones parciales. Un ataque de credential-stuffing dirigido podría avanzar."
    else:
        risk = "high"
        verdict = "Protecciones débiles o ausentes. Alta susceptibilidad a fuerza bruta y bots."
        if not findings["captchas_detected"] and not (findings["rate_limit"] or {}).get("rate_limited_seen"):
            risk = "critical"
            verdict = "Sin captcha ni rate-limit efectivo detectado — el formulario de login es vulnerable a ataques automatizados."

    findings["risk"] = risk
    findings["verdict"] = verdict
    findings["captchas_count"] = len(findings["captchas_detected"])
    return findings
