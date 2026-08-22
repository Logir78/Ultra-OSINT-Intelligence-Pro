"""Per-user API key management, connection tests, and AI provider abstraction."""
import os
import httpx
import stripe  # noqa: F401 (import kept if needed elsewhere)


PROVIDERS = ("shodan", "abuseipdb", "hibp", "rapidapi", "github")
AI_PROVIDERS = ("emergent", "openai", "anthropic", "gemini", "ollama")
AI_MODES = ("precision", "investigative")


def get_user_key(user: dict, provider: str) -> str | None:
    """Return the user-provided key if set, else fall back to env var."""
    if not user:
        return _env_key(provider)
    keys = (user.get("api_keys") or {})
    val = (keys.get(provider) or "").strip()
    if val:
        return val
    return _env_key(provider)


def _env_key(provider: str) -> str | None:
    m = {
        "shodan":     "SHODAN_KEY",
        "abuseipdb":  "ABUSEIPDB_KEY",
        "hibp":       "HIBP_KEY",
        "rapidapi":   "RAPIDAPI_KEY",
    }
    v = os.environ.get(m.get(provider, ""), "")
    return v.strip() or None


def get_ai_config(user: dict) -> dict:
    ai = (user or {}).get("ai_config") or {}
    provider = ai.get("provider") or "emergent"
    key = (ai.get("key") or "").strip() or None
    mode = ai.get("mode") or "precision"
    if provider not in AI_PROVIDERS:
        provider = "emergent"
    if mode not in AI_MODES:
        mode = "precision"
    # Ollama-specific extras
    ollama_url = (ai.get("ollama_url") or "").strip() or None
    ollama_model = (ai.get("ollama_model") or "").strip() or None
    return {"provider": provider, "key": key, "mode": mode,
            "ollama_url": ollama_url, "ollama_model": ollama_model}


# ---------------- CONNECTION TESTS ---------------- #

async def test_shodan(key: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=8.0) as c:
            r = await c.get("https://api.shodan.io/api-info", params={"key": key})
        if r.status_code == 200:
            d = r.json()
            return {
                "ok": True,
                "detail": f"Plan: {d.get('plan', '?')} · {d.get('query_credits', 0)} query credits",
                "usage": {
                    "plan": d.get("plan"),
                    "query_credits": d.get("query_credits", 0),
                    "scan_credits": d.get("scan_credits", 0),
                    "monitored_ips": d.get("monitored_ips"),
                    "unlocked_left": d.get("unlocked_left"),
                },
            }
        return {"ok": False, "detail": f"HTTP {r.status_code}: {r.text[:100]}"}
    except Exception as e:
        return {"ok": False, "detail": str(e)}


async def test_abuseipdb(key: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=8.0) as c:
            r = await c.get("https://api.abuseipdb.com/api/v2/check",
                            headers={"Key": key, "Accept": "application/json"},
                            params={"ipAddress": "8.8.8.8", "maxAgeInDays": 30})
        if r.status_code == 200:
            usage = {
                "remaining": r.headers.get("X-RateLimit-Remaining"),
                "limit": r.headers.get("X-RateLimit-Limit"),
                "reset": r.headers.get("X-RateLimit-Reset"),
            }
            return {"ok": True, "detail": f"Key OK · {usage['remaining']}/{usage['limit']} restantes hoy", "usage": usage}
        return {"ok": False, "detail": f"HTTP {r.status_code}: {r.text[:100]}"}
    except Exception as e:
        return {"ok": False, "detail": str(e)}


async def test_hibp(key: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=8.0) as c:
            r = await c.get("https://haveibeenpwned.com/api/v3/subscription/status",
                            headers={"hibp-api-key": key, "user-agent": "NOCTUA-osint"})
        if r.status_code == 200:
            d = r.json()
            return {
                "ok": True,
                "detail": f"Suscripción: {d.get('SubscriptionName', 'activa')}",
                "usage": {
                    "plan": d.get("SubscriptionName"),
                    "rpm": d.get("Rpm"),
                    "domain_search_max": d.get("DomainSearchMaxBreachedAccounts"),
                    "renews": d.get("SubscribedUntil"),
                },
            }
        return {"ok": False, "detail": f"HTTP {r.status_code}: {r.text[:120]}"}
    except Exception as e:
        return {"ok": False, "detail": str(e)}


async def test_rapidapi(key: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=10.0) as c:
            r = await c.get("https://breachdirectory.p.rapidapi.com/",
                            headers={"X-RapidAPI-Key": key,
                                     "X-RapidAPI-Host": "breachdirectory.p.rapidapi.com"},
                            params={"func": "auto", "term": "test@example.com"})
        if r.status_code == 200:
            return {"ok": True, "detail": "BreachDirectory alcanzable"}
        if r.status_code == 401:
            return {"ok": False, "detail": "Key inválida (401)"}
        if r.status_code == 429:
            return {"ok": True, "detail": "Alcanzable (rate limit al probar — key OK)"}
        return {"ok": False, "detail": f"HTTP {r.status_code}: {r.text[:100]}"}
    except Exception as e:
        return {"ok": False, "detail": str(e)}


async def test_telegram(bot_token: str, chat_id: str) -> dict:
    """Send a silent 'NOCTUA connection test' message via Telegram Bot API."""
    try:
        async with httpx.AsyncClient(timeout=8.0) as c:
            # 1) Validate the bot itself
            r0 = await c.get(f"https://api.telegram.org/bot{bot_token}/getMe")
            if r0.status_code != 200:
                return {"ok": False, "detail": f"Bot token inválido (HTTP {r0.status_code})"}
            bot = (r0.json() or {}).get("result") or {}
            # 2) Send test message
            r = await c.post(
                f"https://api.telegram.org/bot{bot_token}/sendMessage",
                json={
                    "chat_id": chat_id,
                    "text": "*NOCTUA.osint*\n_Canal de alertas conectado correctamente._ ✅",
                    "parse_mode": "Markdown",
                    "disable_notification": True,
                },
            )
        if r.status_code == 200:
            return {
                "ok": True,
                "detail": f"Bot @{bot.get('username', '?')} · mensaje enviado a chat {chat_id}",
                "usage": {"bot_username": bot.get("username"), "bot_id": bot.get("id")},
            }
        try:
            err = r.json().get("description", "")
        except Exception:
            err = r.text[:120]
        return {"ok": False, "detail": f"HTTP {r.status_code}: {err}"}
    except Exception as e:
        return {"ok": False, "detail": str(e)}


async def test_ai_provider(provider: str, key: str) -> dict:
    """Ping the AI provider with a minimal request."""
    if provider == "emergent":
        return {"ok": True, "detail": "Motor Emergent (integrado)"}
    if provider == "openai":
        try:
            async with httpx.AsyncClient(timeout=10.0) as c:
                r = await c.get("https://api.openai.com/v1/models",
                                headers={"Authorization": f"Bearer {key}"})
            if r.status_code == 200:
                d = r.json()
                n = len(d.get("data", []))
                return {"ok": True, "detail": f"OpenAI · {n} modelos disponibles"}
            return {"ok": False, "detail": f"HTTP {r.status_code}: {r.text[:120]}"}
        except Exception as e:
            return {"ok": False, "detail": str(e)}
    if provider == "anthropic":
        try:
            async with httpx.AsyncClient(timeout=10.0) as c:
                r = await c.post("https://api.anthropic.com/v1/messages",
                                 headers={"x-api-key": key,
                                          "anthropic-version": "2023-06-01",
                                          "content-type": "application/json"},
                                 json={"model": "claude-haiku-4-5-20251001", "max_tokens": 5,
                                       "messages": [{"role": "user", "content": "hi"}]})
            if r.status_code == 200:
                return {"ok": True, "detail": "Anthropic · Haiku 4.5 · ping OK"}
            return {"ok": False, "detail": f"HTTP {r.status_code}: {r.text[:120]}"}
        except Exception as e:
            return {"ok": False, "detail": str(e)}
    if provider == "gemini":
        try:
            async with httpx.AsyncClient(timeout=10.0) as c:
                r = await c.get(
                    "https://generativelanguage.googleapis.com/v1beta/models",
                    params={"key": key},
                )
            if r.status_code == 200:
                d = r.json()
                n = len(d.get("models", []))
                return {"ok": True, "detail": f"Gemini · {n} modelos disponibles"}
            return {"ok": False, "detail": f"HTTP {r.status_code}: {r.text[:120]}"}
        except Exception as e:
            return {"ok": False, "detail": str(e)}
    if provider == "ollama":
        # For ollama, `key` field holds the base URL (e.g., https://xxx.ngrok.app)
        base = (key or "").strip().rstrip("/")
        if not base.startswith("http"):
            return {"ok": False, "detail": "URL de Ollama debe empezar por http:// o https://"}
        try:
            async with httpx.AsyncClient(timeout=8.0) as c:
                r = await c.get(f"{base}/api/tags")
            if r.status_code == 200:
                models = [m.get("name") for m in (r.json() or {}).get("models", [])]
                n = len(models)
                sample = ", ".join(models[:5]) if models else "(sin modelos descargados)"
                return {"ok": True,
                        "detail": f"Ollama · {n} modelo(s) local(es): {sample}",
                        "usage": {"models": models}}
            return {"ok": False, "detail": f"HTTP {r.status_code}: {r.text[:120]}"}
        except httpx.ConnectError:
            return {"ok": False,
                    "detail": "No se pudo conectar. Verifica que la URL sea pública y accesible desde Internet (ngrok/cloudflared)."}
        except Exception as e:
            return {"ok": False, "detail": str(e)}
    return {"ok": False, "detail": "Provider desconocido"}


async def test_github(key: str) -> dict:
    """Validate a GitHub Personal Access Token via /user endpoint."""
    try:
        async with httpx.AsyncClient(timeout=6.0) as c:
            r = await c.get("https://api.github.com/user",
                            headers={"Authorization": f"token {key}",
                                     "Accept": "application/vnd.github+json",
                                     "User-Agent": "NOCTUA-osint"})
        if r.status_code == 200:
            d = r.json()
            return {"ok": True,
                    "detail": f"Autenticado como @{d.get('login', '?')}",
                    "usage": {"login": d.get("login"), "public_repos": d.get("public_repos")}}
        return {"ok": False, "detail": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"ok": False, "detail": str(e)}


TEST_FUNCS = {
    "shodan": test_shodan, "abuseipdb": test_abuseipdb,
    "hibp": test_hibp, "rapidapi": test_rapidapi,
    "github": test_github,
}


def mask_key(k: str | None) -> str:
    if not k:
        return ""
    if len(k) <= 8:
        return "*" * len(k)
    return k[:4] + "•" * (len(k) - 8) + k[-4:]
