# ClearMap scoring methodology

How `scripts/scoring.py` turns findings into the 0-100 HIPAA Risk Score. The
topline is the **blended** score (deterministic + agent-identified). It is
deliberately cautious and **never reaches 100**.

## Two layers

1. **Weighted category composite.** Each category starts at 100 and deducts by
   severity (critical −25, high −15, medium −8, low −3), floored at 0. The
   composite is the weight-sum of category scores (weights in `scoring.py`,
   AI/RAG and Audit highest). Reasoning ("agent-identified, verify") deductions
   are capped per category so they can't dominate the verify-required number.

2. **Severity ceiling (the score is the *lower* of the two).** The worst finding
   present caps the score, and criticals compound:

   | Worst severity present | Ceiling |
   |---|---|
   | none | 95 |
   | medium | 90 |
   | high | 85 |
   | critical | `critical_ceiling(n)` (see below) |

   `final_score = min(weighted_composite, severity_ceiling)`.

## Why a ceiling, and why criticals compound

Research on aggregating severities into one score converges on two principles,
and **explicitly rejects averaging** (averaging lets many low findings dilute a
critical: "the average of 1000×0.3 is still 0.3"):

- **Worst dominates (weakest-link).** The most severe open finding sets the
  ceiling: a system is only as safe as its worst exposure.
- **Diminishing returns on count.** Additional findings should lower the score,
  but with saturation: the 2nd critical matters more than the 7th. This is the
  **noisy-OR** shape used to combine independent risks: `risk = 1−(1−p)^n`.

### Critical-count curve

```
critical_ceiling(n) = FLOOR + (CAP_ONE − FLOOR) · DECAY^(n−1)
CAP_ONE = 75   FLOOR = 40   DECAY = 0.55   (≡ noisy-OR p = 0.45 per critical)
```

| # criticals | 1 | 2 | 3 | 4 | 5 | 6 | 7 | … |
|---|---|---|---|---|---|---|---|---|
| ceiling | 75 | 59 | 51 | 46 | 43 | 42 | 41 | → 40 |

So **one critical caps the score at 75** ("Elevated"); more criticals push it
toward the 40 floor ("High"), with each additional one mattering less.

## Posture bands (number and words agree)

| Score | Posture |
|---|---|
| ≥ 90 | Low technical risk in the areas ClearMap checks |
| 76-89 | Moderate: some gaps to address |
| 50-75 | Elevated: multiple significant gaps |
| < 50 | High: substantial gaps; prioritize remediation |

Bands are aligned to the ceilings: a single critical (75) reads **Elevated**, a
high (85) reads **Moderate**, and a critical/high can never read "Low".

## Tuning

All parameters are named constants in `scripts/scoring.py`
(`CRIT_CAP_ONE`, `CRIT_FLOOR`, `CRIT_DECAY`, `HIGH_CEILING`, `MEDIUM_CEILING`,
`SCORE_CEILING`, `WEIGHTS`, `DEDUCTION`, `REASONING_CAP`). Calibrate against the
fixtures and real-repo runs.

## Sources / grounding

- No standardized CVSS aggregation exists; averaging is widely rejected as
  dilutive: *Gotta Catch 'em All: Aggregating CVSS Scores* (arXiv:2310.02062);
  *Multi-target Risk Score Aggregation* (Carleton, CloudCom 2024).
- Worst-dominates / weakest-link is standard in posture rating (e.g. Panorays
  cyber-posture).
- Noisy-OR aggregation of independent risks: *A Generalization of the Noisy-Or
  Model* (arXiv:1303.1479); standard in fault-tree → Bayesian-network risk models.

These are an engineering basis for a risk *signal*, not a validated actuarial
model; calibrate before external use, and counsel confirms regulatory mapping.
