---
description: Configure ClearMap (engines + optional AI reasoning provider)
argument-hint: ""
allowed-tools: Bash, Read
---

# ClearMap setup

Configure ClearMap for this environment:

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/setup.py"
```

This checks the scanner engines and sets how the AI-assisted reasoning review runs. The default is the **host agent** (this coding agent), which needs no API key and makes no extra network calls. You may optionally configure an **OpenAI-compatible** provider instead: a local model (Ollama, LM Studio) or a remote one (OpenRouter and similar) by giving a base URL, a model, and the name of an environment variable that holds the API key. ClearMap stores the endpoint, model, and the env-var name, never the key itself. A remote provider sends the files under review to the endpoint you configure; a local-only provider is restricted to loopback addresses.

Then verify everything is ready:

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/doctor.py" .
```

Show the results and, if anything is missing, relay the exact next action. ClearMap is a technical-risk signal, not a compliance certification.
