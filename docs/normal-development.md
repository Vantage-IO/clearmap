# Normal development with ClearMap

ClearMap is meant to be part of ordinary healthcare development, not a gate you invoke separately. Below are real workflows.

## Build a patient API

```
/clearmap:plan Build an endpoint that returns patient lab results
/clearmap:develop Implement the approved design
```

Planning asks only the questions that change the design (who may call it, which fields are PHI, what audit events are needed, does anything reach an LLM). Development then implements it with authentication, resource-level authorization, audit events that omit patient content, and tests, and keeps lab values out of logs and URLs.

## Add clinical AI

```
/clearmap:plan Add an LLM-generated patient summary
```

ClearMap reasons about the AI-RAG category: redact PHI before the prompt, abstain on weak retrieval, return citations and confidence, audit the model call, treat retrieved text as data (not instructions), bound the answer to sources, and store the output as an unverified draft with a review state.

## Fix an existing unsafe pattern

```
Use ClearMap to modify this logger so request bodies containing PHI are never recorded.
```

ClearMap changes the logger to redact or drop PHI-bearing fields and adds a test proving PHI does not reach the log.

## Ordinary natural language

```
Add symptoms and an identity-verification field to the patient database.
```

ClearMap completes the legitimate feature and challenges the unsafe part: it stores symptoms as clinical observations with provenance and access control, and for the identity field it questions whether a full value is needed, isolates it behind stricter storage and access, and never returns or logs it. It does not refuse the work, and it does not claim the result is compliant.

## When ClearMap should not activate

ClearMap stays out of the way for generic, non-healthcare work: adding pagination to a product catalog, refactoring a CSS component, renaming an internal utility, or adding a test to a math helper. If it activates when it should not, say so and it will step back.
