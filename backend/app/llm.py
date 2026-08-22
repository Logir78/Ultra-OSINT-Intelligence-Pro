"""LLM abstraction (Fase 4 — decoupling from Emergent).

Prefers a *direct* provider via the official `litellm` (Anthropic / OpenAI /
Gemini with your own key), and falls back to the existing Emergent integration
when no direct provider is configured. This keeps today's behavior intact while
giving you a path off the Emergent dependency.

Configure the direct path with env:
    DEFAULT_LLM_PROVIDER = anthropic | openai | gemini
    DEFAULT_LLM_KEY      = <your api key>
    DEFAULT_LLM_MODEL    = <optional override, else a sensible default>
"""
from __future__ import annotations

import logging
import os
import uuid

log = logging.getLogger("noctua.llm")

_DEFAULT_MODELS = {
    "anthropic": "anthropic/claude-3-5-sonnet-latest",
    "openai": "gpt-4o",
    "gemini": "gemini/gemini-1.5-pro",
}


def _direct_config() -> tuple[str, str, str] | None:
    provider = os.environ.get("DEFAULT_LLM_PROVIDER", "").strip().lower()
    key = os.environ.get("DEFAULT_LLM_KEY", "").strip()
    if not provider or not key:
        return None
    model = os.environ.get("DEFAULT_LLM_MODEL", "").strip() or _DEFAULT_MODELS.get(provider)
    if not model:
        return None
    return provider, key, model


async def _complete_direct(prompt: str, system: str, cfg: tuple[str, str, str]) -> str:
    provider, key, model = cfg
    import litellm  # imported lazily so the dependency is optional

    resp = await litellm.acompletion(
        model=model,
        api_key=key,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ],
    )
    return resp["choices"][0]["message"]["content"]


async def _complete_emergent(prompt: str, system: str) -> str:
    from app.core import EMERGENT_LLM_KEY
    if not EMERGENT_LLM_KEY:
        return "AI summary no disponible (configura DEFAULT_LLM_* o EMERGENT_LLM_KEY)."
    from emergentintegrations.llm.chat import LlmChat, UserMessage
    from claude_models import resolve_claude_model

    chat = LlmChat(
        api_key=EMERGENT_LLM_KEY,
        session_id=f"osint-{uuid.uuid4().hex[:8]}",
        system_message=system,
    ).with_model("anthropic", resolve_claude_model())
    return str(await chat.send_message(UserMessage(text=prompt)))


async def complete(prompt: str, system: str) -> str:
    """Run a completion via the direct provider if configured, else Emergent."""
    cfg = _direct_config()
    if cfg is not None:
        try:
            return await _complete_direct(prompt, system, cfg)
        except Exception:
            log.exception("Direct LLM provider failed; falling back to Emergent")
    try:
        return await _complete_emergent(prompt, system)
    except Exception as e:
        logging.getLogger("noctua").exception("AI summary failed")
        return f"Error generando resumen IA: {e}"
