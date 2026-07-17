---
name: clearmap-companion
description: Compatibility alias for clearmap-development. Loads while writing or modifying code that touches PHI, patient records, medical APIs, health-data storage, clinical AI/LLM/RAG features, healthcare frontends, or analytics on patient-facing surfaces, and biases generation toward the safe pattern for each risky one. ClearMap is a technical-risk signal, not a HIPAA certification.
---

# ClearMap companion (compatibility alias)

The healthcare-aware development guidance now lives in the **clearmap-development** skill. Follow that skill: while generating healthcare code, prefer the safe form for each risky pattern (authentication on PHI routes, audit events, TLS in transit, redaction before prompts, no PHI in browser storage or analytics, no untrusted input in SQL/shell/paths), and note the category code briefly. After a substantial healthcare feature lands, suggest an audit with `clearmap-audit`. ClearMap is a technical-risk signal, not a HIPAA certification.
