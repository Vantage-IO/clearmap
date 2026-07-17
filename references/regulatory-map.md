# ClearMap regulatory map

Maps every ClearMap category to the authority it is grounded in. The HIPAA
Security Rule **Technical Safeguards** live at **45 CFR 164.312**; categories
beyond it are extensions grounded in OCR guidance, the ONC HTI-1 rule, or
general secure-engineering practice.

## Versioning (read first)

Regulations change: rules are amended, new ones are added, NPRMs finalize. So
the **requirement set itself is versioned**. The machine-readable source of
truth is [`regulatory-baseline.json`](./regulatory-baseline.json):

- It carries a `baseline_version` (e.g. **`2026.1`**) and an `as_of` date.
- It records, per citation, the framework, R/A status, **last-amended date**,
  retrieval date, and source URL: plus a `pending_changes` list (e.g. the 2024
  encryption NPRM) so we can show what's coming.
- Every finding's `hipaa_ref` **must** resolve to a citation in the baseline;
  `examples/build_manifest.py` fails the build otherwise.
- Both manifests and every generated report stamp the
  `regulatory_baseline` version. That makes any assessment **traceable to the
  exact requirement set in force when it was produced.**

When a regulation is amended or a pending change finalizes: bump
`baseline_version`, update the affected entries, regenerate, and keep the prior
version for diffing. **Finding IDs never change**: only the citations they
point at.

> ClearMap is a **technical risk signal, not a legal HIPAA compliance
> certification.** These citations are an engineering target. Counsel must
> confirm any regulatory claim before it appears in an external artifact.

## Source of the regulation text

45 CFR 164.312: Technical safeguards. Standards are **Required**;
implementation specifications are either **Required (R)** or **Addressable (A)**.

| Citation | Title | R/A |
|---|---|---|
| 164.312(a)(1) | **Access control** (standard) | Required |
| 164.312(a)(2)(i) | Unique user identification | R |
| 164.312(a)(2)(ii) | Emergency access procedure | R |
| 164.312(a)(2)(iii) | Automatic logoff | A |
| 164.312(a)(2)(iv) | Encryption and decryption | A |
| 164.312(b) | **Audit controls** (standard) | Required |
| 164.312(c)(1) | **Integrity** (standard) | Required |
| 164.312(c)(2) | Mechanism to authenticate ePHI | A |
| 164.312(d) | **Person or entity authentication** (standard) | Required |
| 164.312(e)(1) | **Transmission security** (standard) | Required |
| 164.312(e)(2)(i) | Integrity controls | A |
| 164.312(e)(2)(ii) | Encryption | A |

### Encryption status: read carefully ("Addressable" ≠ optional)

This trips people up. Two different layers:

- **The transmission-security *standard*: `164.312(e)(1)`: is `Required`.**
  Guarding ePHI in transit is mandatory, no exceptions.
- Encryption is an *implementation specification* labelled **`Addressable`**
  (`(e)(2)(ii)` in transit, `(a)(2)(iv)` at rest).

**`Addressable` does not mean optional.** Per **`164.306(d)(3)`**, a covered
entity must either implement the spec, **or** document why it is not reasonable
and appropriate **and implement an equivalent alternative**. For ePHI crossing
an open/public network there is no reasonable equivalent to encryption, and OCR
treats unencrypted transmission over open networks as a violation.

**ClearMap therefore treats encryption-in-transit as a hard requirement** and
anchors `TRANSIT-*` findings to the **Required** standard `164.312(e)(1)` (not
the addressable encryption spec). The `clearmap_treatment: "required"` field on
the encryption entries in `regulatory-baseline.json` records this stance with
its rationale.

Direction of travel: the **Dec 27, 2024 NPRM** (90 FR 898, Jan 6 2025) would
promote encryption to a **Required standalone standard** and remove the
Required/Addressable distinction entirely. No final rule as of mid-2026: so
this is reinforcement, not the basis, for treating it as required.

#### External vs internal (how `TRANSIT` severity-splits)

The flexibility in §164.306(d)(3) matters most *inside a trusted boundary*. A
blanket "any `http://` = critical" rule would false-positive on normal backends
(TLS terminates at the edge; plaintext hop-by-hop within a VPC / service mesh is
a common, defensible pattern). So ClearMap classifies the destination host and
splits severity:

| Destination | + PHI | ClearMap |
|---|---|---|
| External / open network (internet, partners, third parties) | yes | **hard finding** (severity by sensitivity) |
| Internal: `localhost`, RFC-1918 `10./172.16-31./192.168.`, `*.internal`, `*.svc.cluster.local` | yes | **low / advisory**: verify trusted boundary + compensating controls; zero-trust = encrypt internally too |
| Internal | no | **not reported** |

The deterministic layer does the host classification heuristically; the
reasoning layer confirms whether the boundary is genuinely trusted. Corpus seeds:
`TRANSIT-01/02/03` (external, hard), `TRANSIT-04` (internal, advisory),
safe-fixture `http://localhost` near-miss (internal + no PHI, silent).

Sources:
- [eCFR: 45 CFR 164.312](https://www.ecfr.gov/current/title-45/section-164.312)
- [Cornell LII: 45 CFR 164.312](https://www.law.cornell.edu/cfr/text/45/164.312)
- [Federal Register: HIPAA Security Rule NPRM (2024-30983)](https://www.federalregister.gov/documents/2025/01/06/2024-30983/hipaa-security-rule-to-strengthen-the-cybersecurity-of-electronic-protected-health-information)
- [HHS: HIPAA Security Rule NPRM](https://www.hhs.gov/hipaa/for-professionals/security/hipaa-security-rule-nprm/index.html)

## Category → authority

| Code | Name | Primary citation | Notes |
|------|------|------------------|-------|
| `ACCESS` | Access Control | 164.312(a)(1); (a)(2)(i),(iii),(iv) | Authorization, role checks, automatic logoff, unique user id, credential mgmt |
| `AUTH` | Person/Entity Authentication | 164.312(d) | Verifying *who* a caller is: missing/weak auth on PHI access |
| `AUDIT` | Audit Controls | 164.312(b) | Recording activity on systems that contain/use ePHI |
| `INTEGRITY` | Integrity | 164.312(c)(1),(c)(2) | Protect ePHI from improper alteration/destruction; corroborate it wasn't altered |
| `TRANSIT` | Transmission Security | 164.312(e)(1),(e)(2)(i),(ii) | Guard ePHI in transit on **any** network path; encrypt; detect tampering |
| `SESSION` | Frontend / Session Exposure | 164.312(a)(2)(iv); (a)(2)(iii) | *Extension.* Client-side persistence of ePHI; relates to encryption + logoff |
| `TRACKING` | Tracking / Analytics | HHS OCR online-tracking guidance | *Extension.* OCR bulletin on tracking technologies in patient-facing surfaces |
| `AI-RAG` | AI / LLM / RAG Risk | ONC HTI-1: 45 CFR 170.315(b)(11) | *Extension.* Decision-support intervention transparency; clinical-AI reliability |
| `SECRETS` | Secrets / Config | 164.312(a)(1) | *Extension.* Credential/secret material in source supports access control |

## Why ACCESS and AUTH are separate

The regulation distinguishes **(a) Access control** (authorization: *what* an
authenticated principal may do) from **(d) Person or entity authentication**
(*who* the principal is). ClearMap mirrors that:

- `AUTH-01`: a PHI **read** with no authentication at all → 164.312(d).
- `INTEGRITY-01`: a PHI **write** with no authentication → improper alteration,
  164.312(c)(1) (also implicates (d)).
- `ACCESS-02`: an authenticated caller with **no role check** → 164.312(a)(1).
- `ACCESS-03`: sessions that never expire / can't be revoked → 164.312(a)(2)(iii)
  automatic logoff.

## Maintenance

When a finding's regulatory basis changes (e.g. the NPRM finalizes), update the
`hipaa_ref` values in `examples/build_manifest.py`, regenerate the manifests,
and update this table: not the finding IDs, which are intentionally decoupled
from citations.
