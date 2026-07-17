---
description: Implement a healthcare feature with ClearMap HIPAA-aware guidance
argument-hint: "[task]"
allowed-tools: Read, Write, Edit, Bash, Glob, Grep
---

# ClearMap develop

Implement: `$ARGUMENTS` (if empty, ask what to build).

Follow the `clearmap-development` skill. Build the feature, but apply the minimum-necessary principle, keep raw PHI and secrets out of logs, analytics, URLs, browser storage, prompts, tests, and error messages, and add authentication, authorization, audit events, input validation, encryption in transit, and retention behavior where they apply, plus tests for that behavior. If the request is unsafe, briefly say why, determine the real goal, and implement the safer design. ClearMap is a technical-risk signal, not a compliance certification; do not claim the result is HIPAA compliant.
