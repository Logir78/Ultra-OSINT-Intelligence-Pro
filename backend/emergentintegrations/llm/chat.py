"""Local drop-in replacement for `emergentintegrations.llm.chat`.

The original was a private Emergent package (not on PyPI), so we couldn't deploy
with it. This shim keeps the SAME interface used across the code
(`LlmChat(...).with_model(provider, model)` + `await send_message(UserMessage(...))`)
but talks **directly** to Anthropic / OpenAI via httpx — no Emergent, no heavy deps.

Provider + key resolution (first match wins):
  1. env DEFAULT_LLM_PROVIDER / DEFAULT_LLM_KEY / DEFAULT_LLM_MODEL
  2. what the calling code passed (provider via with_model, api_key via LlmChat)
If no usable key is found, `send_message` returns a clear, non-crashing message.
"""
from __future__ import annotations

import os
import logging

import httpx

log = logging.getLogger("noctua.llm.shim")

_DEFAULT_MODELS = {
    "anthropic": "claude-3-5-sonnet-latest",
    "openai": "gpt-4o-mini",
}
_NOT_CONFIGURED = (
    "⚠️ IA no configurada. Define DEFAULT_LLM_PROVIDER (anthropic|openai) y "
    "DEFAULT_LLM_KEY en el servidor para activar los resúmenes con IA."
)


class UserMessage:
    def __init__(self, text: str = "", **_):
        self.text = text


class LlmChat:
    def __init__(self, api_key: str = "", session_id: str = "", system_message: str = "", **_):
        self._api_key = api_key or ""
        self._system = system_message or "Eres un asistente experto en ciberseguridad."
        self._provider = None
        self._model = None

    def with_model(self, provider: str = None, model: str = None):
        self._provider = provider
        self._model = model
        return self

    def _resolve(self):
        provider = (os.environ.get("DEFAULT_LLM_PROVIDER") or self._provider or "anthropic").lower()
        key = os.environ.get("DEFAULT_LLM_KEY") or self._api_key or ""
        model = os.environ.get("DEFAULT_LLM_MODEL") or _DEFAULT_MODELS.get(provider)
        return provider, key, model

    async def send_message(self, message) -> str:
        text = getattr(message, "text", str(message))
        provider, key, model = self._resolve()
        if not key:
            return _NOT_CONFIGURED
        try:
            if provider == "anthropic":
                return await self._anthropic(text, key, model)
            if provider in ("openai", "ollama"):
                return await self._openai(text, key, model)
            # Unknown provider → try OpenAI-compatible as a best effort
            return await self._openai(text, key, model or "gpt-4o-mini")
        except Exception as e:  # noqa: BLE001 — never crash the caller
            log.warning("LLM call failed: %s", e)
            return f"⚠️ No se pudo generar la respuesta de IA ({provider}): {e}"

    async def _anthropic(self, text: str, key: str, model: str) -> str:
        async with httpx.AsyncClient(timeout=60.0) as c:
            r = await c.post(
                "https://api.anthropic.com/v1/messages",
                headers={"x-api-key": key, "anthropic-version": "2023-06-01",
                         "content-type": "application/json"},
                json={"model": model or "claude-3-5-sonnet-latest", "max_tokens": 1500,
                      "system": self._system,
                      "messages": [{"role": "user", "content": text}]},
            )
        r.raise_for_status()
        data = r.json()
        parts = [b.get("text", "") for b in data.get("content", []) if b.get("type") == "text"]
        return "\n".join(parts).strip() or "(respuesta vacía)"

    async def _openai(self, text: str, key: str, model: str) -> str:
        base = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
        async with httpx.AsyncClient(timeout=60.0) as c:
            r = await c.post(
                f"{base}/chat/completions",
                headers={"Authorization": f"Bearer {key}", "content-type": "application/json"},
                json={"model": model or "gpt-4o-mini",
                      "messages": [{"role": "system", "content": self._system},
                                   {"role": "user", "content": text}]},
            )
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"].strip()
