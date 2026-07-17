"""Thin wrapper around the model provider."""

import requests

from config import OPENAI_API_KEY


def complete(prompt: str, max_tokens: int = 800) -> str:
    """Call the chat-completions endpoint and return the text.

    AUDIT-02: the LLM call is not logged anywhere. There is no audit record that a
    model invocation happened, what was sent, or what came back. (Distinct from
    AI-RAG-04, which is about the RAG orchestrator never feeding the audit trail with
    inputs/outputs/sources/user — here the wrapper itself has no logging hook.)
    """
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
