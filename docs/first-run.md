# First run: configuring the AI-assisted review

ClearMap's audit has two layers: a deterministic scan (Semgrep + Gitleaks, always local) and an AI-assisted reasoning review of the checks pattern matching cannot judge. This page covers how the reasoning review runs.

Run `clearmap setup` (or `python3 scripts/setup.py`) to choose one of:

## Host agent (default, recommended)

The coding agent running ClearMap performs the reasoning review itself. No API key, and ClearMap makes no extra network calls. This is the default and needs no configuration.

## Local OpenAI-compatible model

Run a model on your machine and point ClearMap at it. Nothing leaves your machine.

**Ollama:**
```bash
ollama serve            # exposes http://127.0.0.1:11434
clearmap setup          # choose openai-compatible, base URL http://127.0.0.1:11434/v1
```

**LM Studio:** start its local server (default `http://127.0.0.1:1234/v1`), then `clearmap setup`.

A capable local coding model (for example a Qwen Coder, Llama, or Mistral variant) works well; pick one your hardware supports.

## Remote OpenAI-compatible provider (OpenRouter and similar)

An explicit opt-in. The files under review are sent to the endpoint you configure.

```bash
export OPENROUTER_KEY=sk-...
clearmap setup
#   provider: openai-compatible
#   base URL: https://openrouter.ai/api/v1
#   model:    <a model id>
#   confirm remote, env var: OPENROUTER_KEY
```

ClearMap stores the endpoint, the model, and the *name* of the env var holding the key, never the key value.

## Environment variables

Override any setting without editing config:

```
CLEARMAP_REASONING_PROVIDER   host-agent | openai-compatible | manual
CLEARMAP_MODEL_BASE_URL       e.g. http://127.0.0.1:11434/v1
CLEARMAP_MODEL_NAME           model id
CLEARMAP_MODEL_API_KEY_ENV    name of the env var holding the key
CLEARMAP_MODEL_API_KEY        the key itself (read only, never stored)
CLEARMAP_PRIVACY_MODE         local-only | provider-managed
```

## Precedence

Highest first: **CLI flags > environment variables > repository config (`<repo>/.clearmap/config.json`) > user config (`~/.config/clearmap/config.json`) > safe defaults.**

## What `local-only` guarantees

Under the default `local-only` privacy mode, an OpenAI-compatible endpoint may only be a loopback address (`127.0.0.0/8`, `::1`, `localhost`). A non-loopback endpoint is refused before any request is made. To use a remote provider you must set `provider-managed` explicitly, which is a clear statement that repository content will be sent to that provider.

## What data is sent to a reasoning provider

- **host-agent / manual:** ClearMap sends nothing itself; the review happens in your agent or is supplied by you.
- **openai-compatible (local):** the files under review are sent only to your local model; nothing leaves the machine.
- **openai-compatible (remote):** the files under review are sent to the remote endpoint you configured. ClearMap never sends its own answer-key fixtures, and never sends raw PHI back into its output (all snippets are redacted).

## Troubleshooting

```bash
clearmap doctor .        # engines, config, endpoint reachability, model availability
clearmap config show     # effective config (secrets redacted) and where it came from
clearmap config validate # confirm the config is usable
```

If `doctor` reports the endpoint unreachable, confirm the local server is running or the base URL is correct. If it reports the API key env is unset, export it. If a required engine is missing, install `semgrep` 1.164.x and `gitleaks` 8.30.x.
