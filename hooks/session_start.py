#!/usr/bin/env python3
"""ClearMap SessionStart hook: a small routing reminder.

Adds one short line of context so the agent knows to load the ClearMap
development skill for healthcare work and to offer an audit. It makes no network
calls, writes no files, runs no scan, and does not activate ClearMap for
unrelated code. Safe to disable: the clearmap-development skill still
auto-activates from its own description.
"""
import json

MSG = (
    "ClearMap is installed. If this session involves healthcare or PHI code "
    "(patient data, symptoms, diagnoses, medications, lab results, medical "
    "records, clinical AI/RAG, healthcare APIs, or the auth/audit/storage/"
    "transmission of health information), load the clearmap-development skill to "
    "build it safely, and offer /clearmap:audit to check a repository. ClearMap "
    "is a technical-risk signal, not a HIPAA certification."
)

print(json.dumps({"hookSpecificOutput": {
    "hookEventName": "SessionStart", "additionalContext": MSG}}))
