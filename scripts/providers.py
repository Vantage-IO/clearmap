#!/usr/bin/env python3
"""OpenAI-compatible reasoning provider client. Stdlib only (urllib), no
requests / openai SDK / pydantic. Enforces the loopback boundary under
local-only privacy mode, never logs or echoes the API key, times out, and maps
transport/HTTP/JSON failures to a single ProviderError. Works with any
/v1/chat/completions endpoint: a local model (Ollama, LM Studio) or a remote one
(OpenRouter and similar)."""
from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request

import config

LOCAL_ENDPOINTS = (
    "http://127.0.0.1:11434/v1",   # Ollama
    "http://127.0.0.1:1234/v1",    # LM Studio
)


class ProviderError(Exception):
    pass


def _enforce_privacy(cfg: dict) -> None:
    if cfg.get("privacy_mode", "local-only") == "local-only" \
            and not config.is_loopback(cfg.get("base_url")):
        raise ProviderError(
            "privacy_mode local-only allows only loopback endpoints; refusing to "
            "send code to a non-loopback provider. Set privacy_mode=provider-managed "
            "to use a remote provider.")


def _request(url: str, payload: dict | None, headers: dict, timeout: float) -> dict:
    method = "POST" if payload is not None else "GET"
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={**headers, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode(errors="ignore")[:200]
        except OSError:
            pass
        raise ProviderError(f"provider returned HTTP {e.code}: {body}") from None
    except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError) as e:
        reason = getattr(e, "reason", e)
        raise ProviderError(f"could not reach provider: {reason}") from None
    except json.JSONDecodeError:
        raise ProviderError("provider returned invalid JSON") from None


def chat_completion(cfg: dict, messages: list[dict], timeout: float = 120) -> dict:
    """Call /chat/completions. Returns {content, model, usage}."""
    _enforce_privacy(cfg)
    url = cfg["base_url"].rstrip("/") + "/chat/completions"
    headers = {}
    key = config.resolve_api_key(cfg)
    if key:
        headers["Authorization"] = f"Bearer {key}"  # never logged
    payload = {
        "model": cfg["model"],
        "messages": messages,
        "temperature": cfg.get("temperature", 0.0),
        "max_tokens": cfg.get("max_tokens", 4096),
    }
    data = _request(url, payload, headers, timeout)
    try:
        content = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        raise ProviderError("provider response missing choices[0].message.content") from None
    return {"content": content, "model": data.get("model", cfg.get("model")),
            "usage": data.get("usage", {})}


def list_models(cfg: dict, timeout: float = 10) -> list[str]:
    """GET /models -> list of model ids. Empty list if the endpoint has none."""
    _enforce_privacy(cfg)
    url = cfg["base_url"].rstrip("/") + "/models"
    headers = {}
    key = config.resolve_api_key(cfg)
    if key:
        headers["Authorization"] = f"Bearer {key}"
    data = _request(url, None, headers, timeout)
    return [m.get("id") for m in data.get("data", []) if isinstance(m, dict) and m.get("id")]


def probe_local(timeout: float = 1.5) -> list[tuple[str, list[str]]]:
    """Probe common local endpoints; return [(base_url, model_ids)] for reachable ones."""
    found = []
    for base in LOCAL_ENDPOINTS:
        try:
            models = list_models({"base_url": base, "privacy_mode": "local-only"}, timeout=timeout)
            found.append((base, models))
        except ProviderError:
            pass
    return found


def extract_json(text: str):
    """Strictly pull a JSON object/array out of a model response (tolerating
    Markdown code fences and surrounding prose)."""
    t = (text or "").strip()
    if t.startswith("```"):
        parts = t.split("```")
        if len(parts) >= 3:
            t = parts[1]
        if t.lstrip().lower().startswith("json"):
            t = t.lstrip()[4:]
        t = t.strip()
    try:
        return json.loads(t)
    except json.JSONDecodeError:
        pass
    for open_c, close_c in (("{", "}"), ("[", "]")):
        i, j = t.find(open_c), t.rfind(close_c)
        if 0 <= i < j:
            try:
                return json.loads(t[i:j + 1])
            except json.JSONDecodeError:
                continue
    raise ProviderError("could not extract JSON from the provider output")
