"""Thin wrapper around the model provider — with call logging."""

import logging

import requests

from config import OPENAI_API_KEY

logger = logging.getLogger("clinic.llm")


def complete(prompt_token_count: int, prompt: str, max_tokens: int = 800) -> str:
    """Call the chat-completions endpoint, logging the invocation metadata.

    We log metadata about the call (not raw PHI): the model, token counts, and
    a correlation id would be attached by the caller. The orchestrator adds the
    full audit-trail entry (see rag/assistant.py).
    """
    logger.info("llm.call model=gpt-4o prompt_tokens=%d max_tokens=%d", prompt_token_count, max_tokens)
    resp = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers={"Authorization": f"Bearer {OPENAI_API_KEY}"},
        json={
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": max_tokens,
        },
    )
    return resp.json()["choices"][0]["message"]["content"]
