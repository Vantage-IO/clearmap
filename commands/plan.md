---
description: HIPAA-aware planning questions before writing healthcare code
argument-hint: "[feature description]"
allowed-tools: Read, Glob, Grep
---

# ClearMap plan

The user is about to build: `$ARGUMENTS` (if empty, ask what they are planning to build).

Follow the `clearmap-development` skill and its planning reference. Ask only the HIPAA technical-safeguard questions that materially change the architecture or risk profile for the stack and feature in play, then fold the answers into the implementation plan as a short "HIPAA technical-risk plan" (per applicable category: the decision and the safeguard that will be implemented). Do not turn a small or obvious change into a questionnaire. ClearMap is a technical-risk signal, not a compliance certification.
