# AgenID v1.1.1 — Final Protocol Specification
### Protocol Closure Sprint (Pre-Code Gate)

```
SPECIFICATION:         v1.1.1 FINAL (closure sprint applied; Erratum E1 applied to §5)
APPLICATION CODE:       BLOCKED (no implementation code in this document, by directive)
CRYPTOGRAPHIC AUDIT:    COMPLETE — all vectors in §8 computed and verified in-session, not illustrative
BUILD AUTHORIZATION:    NOT GRANTED — see §21 Build-Ready Matrix and §22 residual items
```

**Scope of this revision.** This document supersedes the v1.1.1 Hardening draft in full. It applies the two P0 corrections received in the closure directive (§0), carries forward everything else unchanged unless stated, and closes several items the hardening draft had left BLOCKED (trust-anchor bootstrap, adversarial canonicalization vectors, number-domain rules). Only corrections **A** and **B** were received in the directive; if the directive contained further items (C onward) they did not arrive and are not addressed here.

---

## 0. P0 Corrections Applied

### A. Key identifier URI fragment bug — FIXED

**Defect confirmed.** The hardening draft defined `key_id` as `agenid:key:<agent-ULID>#z1`. A `#fragment` is client-side only under RFC 3986 §3.5 — it is never transmitted in an HTTP request path — so `GET /v1/keys/agenid:key:01J8...#z1` reaches the server as `GET /v1/keys/agenid:key:01J8...` and every key would collide on its first fragment-less prefix. The draft's key identifier was unresolvable as specified.

**Fix (normative):**
1. A key has its **own ULID**. `key_id` is `agenid:key:<key-ULID>` — no fragment, no relationship to the agent's ULID encoded in the identifier. Which agent/operator/authority controls the key is stated in the key document's `controller` field (§9), not in the identifier.
2. Two representations are defined and both are normative:
   - **Logical form** (appears inside signed payloads): `agenid:key:01J8Z3M9Q4XK2P7VBN6TDR8HWE`
   - **Wire form** (appears in HTTP paths): the bare key-ULID, `01J8Z3M9Q4XK2P7VBN6TDR8HWE`, which is path-safe by construction (Crockford Base32, no reserved characters).
   - `GET /v1/keys/{key-ULID}` is the canonical resolver path. `GET /v1/keys?key_id=agenid%3Akey%3A01J8Z3M9Q4XK2P7VBN6TDR8HWE` (percent-encoded logical form) MUST also be accepted and MUST return the identical document. Servers MUST reject a `key_id` containing `#` with `400 invalid_key_id`; they never silently truncate.
3. **Operator-hosted discovery URI (normative):** `https://<operator_domain>/.well-known/agenid/keys.json` — one document listing every key the operator controls (§9.3). Per-key files are not used; a single document avoids a second class of path-encoding problems and lets a verifier fetch one URL.
4. **Authority-hosted discovery URI (normative):** `https://<authority_domain>/.well-known/agenid/keys.json`, same schema, for authority keys (§9.4).

### B. `Manifest` proof vs `VerificationAssertion` conflation — FIXED

**Defect confirmed.** The hardening draft's single `ProofPayload` carried a `verification_level` field, which made one signed object do two incompatible jobs: an operator's self-declaration over a manifest, and a verification authority's attestation over evidence. That let one key role speak for the other.

**Fix (normative):** two distinct signed objects, two distinct key roles, one shared signing construction (§7):

| Object | Signer | Key role | Asserts |
|---|---|---|---|
| `ManifestProof` (§6.2) | the **Operator** | `operator` | "I, the operator, declare this manifest (by digest) for this agent." DECLARED only. |
| `VerificationAssertion` (§6.3) | a **Verification Authority** | `authority` | "I, the authority, verified this specific claim against this evidence, at this level, in this scope, for this window." VERIFIED only. |

A verifier MUST reject a `ManifestProof` signed by an `authority`-role key and MUST reject a `VerificationAssertion` signed by an `operator`-role key, even if the Ed25519 math validates (§7.3 step 6, vectors §8.6). The `VerificationAssertion` schema required by the directive is adopted verbatim in §6.3 with two additions the directive's own model needs to be cryptographically closed: `key_id` (which authority key signed it) and `manifest_digest` (which manifest version the assertion is bound to).

**Domain note flagged for owner decision:** the directive's required schema uses `https://agenid.org/schemas/...` while the product domain is `agenid.com`. This document follows the directive's value verbatim (`agenid.org` as the open-standard namespace) and flags the split as a decision to confirm (§22 item 1) — it is a sensible open-spec/commercial split, but it must be deliberate, not inherited.

---

## 1. Normative Terminology

Unchanged from the hardening draft except for the additions marked **(new)**.

| Term | Definition |
|---|---|
| **Agent** | Persistent logical AI identity, `agenid:<ULID>`. Never re-keyed by platform, configuration, or deployment change. |
| **Deployment** | One concrete execution of an Agent on a platform/channel. Platform-scoped identifier, distinct from `agent_id`. |
| **Operator** | The legal/operational entity accountable for an Agent. Never the hosting platform. |
| **Verification Authority** | A named party that performs verification and signs `VerificationAssertion`s with an `authority`-role key. AgenID's own nodes are `agenid:authority:<node>`; the model admits other authorities without protocol change. |
| **Key Role (new)** | Every key document declares exactly one role: `operator` or `authority`. Role is enforced at verification time, not merely documented. |
| **Manifest** | Operator's canonical-JSON self-declaration (§6.1). DECLARED content only. Plain JSON, not JSON-LD. |
| **ManifestProof (new)** | Operator-signed binding of an `agent_id` to a manifest digest (§6.2). |
| **VerificationAssertion (new)** | Authority-signed attestation over one claim, one evidence item, one level, one scope, one validity window (§6.3). |
| **DECLARED / VERIFIED / AUTHORIZED** | Three non-inferable claim states. `ManifestProof` can only produce DECLARED. `VerificationAssertion` can only produce VERIFIED. AUTHORIZED is reserved for v1.2 and has no signed object in v1.1.1. |
| **Verification Level / Status** | Orthogonal. Level is a property of an assertion; status is a property of an Agent or Deployment (§12). |
| **Resolver / Adapter** | As in the hardening draft (§15, §18). |

```
DECLARED            does NOT imply       VERIFIED
VERIFIED            does NOT imply       AUTHORIZED
PLATFORM_CONFIGURED does NOT imply       AUTHORIZED
operator-signed     does NOT produce     VERIFIED      (new, enforced by key role)
authority-signed    does NOT produce     DECLARED      (new, enforced by key role)
```

---

## 2. Identity Model

- `agenid:<ULID>`; ULID per the ULID spec (128-bit, Crockford Base32, 26 chars). Regex: `^agenid:[0-9A-HJKMNP-TV-Z]{26}$`.
- Immutable for the life of the record, including through `REVOKED`. Never reissued.
- Non-semantic. A platform-native ID MUST NOT be used as, encoded into, or derived into an `agenid:` identifier.
- Registration MUST perform a uniqueness check before commit regardless of ULID's collision resistance.

**Identifier namespaces in v1.1.1 (complete list):**

| Prefix | Meaning | Example |
|---|---|---|
| `agenid:` | Agent | `agenid:01J8Z3K3F2QZ9X6V7R4T8N2W5Y` |
| `agenid:key:` | Key (own ULID) | `agenid:key:01J8Z3M9Q4XK2P7VBN6TDR8HWE` |
| `agenid:authority:` | Verification authority | `agenid:authority:node-01` |
| `assertion:` | VerificationAssertion | `assertion:01J8Z3P2K8VW4RN7XTQ6MYD5HC` |
| `dep_` | Deployment (platform-scoped, opaque) | `dep_a1b2c3` |

Reserved, not shipped: `agenid:operator:<ULID>` (operator-level keys spanning many agents — v1.2; in v1.1.1 an operator key's `controller` is an `agenid:` agent identifier).

---

## 3. Agent ≠ Deployment

Unchanged from the hardening draft. Summary of the binding rules:
1. Creating/changing/deleting a Deployment MUST NOT alter `agent_id`, `manifest_version`, or any existing `ManifestProof` / `VerificationAssertion`.
2. A Deployment carries its own status (§12) and its own L4 assertion (§11); the parent Agent's L1–L3 assertions are unaffected.
3. Platform migration = retire Deployment A (Deployment-level `REVOKED`), create Deployment B under the same `agent_id`.
4. A manifest change touching a claim already covered by an L2/L3 assertion sets Agent status `CHANGED` (§12); it does not invalidate the old assertion's signature — it makes it *not applicable to the new manifest version*, which is exactly why every assertion carries `manifest_digest` (§6.3).

---

## 4. Claim Semantics — Structural Enforcement

In v1.1.1 the three states are separated by *object*, not by a field value:

| State | Only produced by | Object |
|---|---|---|
| DECLARED | Operator | `Manifest` + `ManifestProof` |
| VERIFIED | Authority | `VerificationAssertion` |
| AUTHORIZED | — | none in v1.1.1 (reserved: v1.2 `AuthorizationGrant`) |

There is no field anywhere in v1.1.1 whose value alone flips a claim from DECLARED to VERIFIED. The transition is the existence of a valid, in-window, role-correct `VerificationAssertion` whose `manifest_digest` matches the current manifest.

---

## 5. Canonicalization — RFC 8785 (JCS)

Normative and unchanged: every object that is hashed or signed is canonicalized with RFC 8785, from a parsed data structure, never by "fixing up" pre-serialized text. Reference implementation used for all vectors here: the `rfc8785` Python package (a direct RFC 8785 implementation).

**Number-domain rules — NEW, normative, derived from executed vectors (§8.7):**
- **(Erratum E1, applied Sept 13, 2026 — supersedes the earlier "integer" wording.)** The rule is defined on the **RFC 8785 canonical token**, not on the host language's number type: a number MUST be rejected at validation (`invalid_number_domain`) if it is non-finite, or if its canonical token is an *integer literal* (contains neither `.` nor `e`) with magnitude > 2⁵³−1 (9007199254740991). Exponent-form tokens (`1e+21`, `1e+100`) are unambiguously floating-point in every JSON implementation and are accepted. Rationale: an integer-literal token above 2⁵³ is not guaranteed to round-trip through implementations that parse integer literals into 64-bit or arbitrary-precision integers, so it cannot be part of a portable signature; the earlier wording ("integers of 2⁵³ or larger") was implicitly tied to Python's `int`/`float` distinction and was not implementable language-neutrally (JavaScript cannot tell `1e20` from `100000000000000000000`). Consequences: `9007199254740991` ok; `9007199254740992` rejected; `1e20` (token `100000000000000000000`) rejected; `1e21` (token `1e+21`) ok. No §8 vector changes under this wording.
- `NaN` and `±Infinity` MUST be rejected.
- Consequences implementers must expect: `1.0` canonicalizes to `1`; `-0.0` canonicalizes to `0`; `1e21` to `1e+21`; `1e-7` to `1e-7`; `0.000001` to `0.000001`. Vectors in §8.7.
- **Design rule:** AgenID schemas avoid large integers entirely — timestamps are RFC 3339 strings, digests are hex strings, ULIDs are strings. No v1.1.1 schema field is a number. This rule exists so the number-domain edge cases above can never be reached by conformant documents.

**String/Unicode rules (executed, §8.7):** JCS emits raw UTF-8 for non-ASCII (no `\uXXXX` escaping of `検証`, `🔐`, `é`); escapes only `"`, `\`, and control characters U+0000–U+001F using the RFC 8785 short forms (`\n`, `\t`) or `\u00XX`; U+007F (DEL) and U+00A0 (NBSP) are emitted raw. Key sort order is by UTF-16 code units (`"10" < "9" < "B" < "a" < "aa" < "ab" < "b" < "é"`), not locale or codepoint-of-first-byte order. Implementations MUST reproduce §8.7 byte-for-byte.

---

## 6. Normative Objects

### 6.1 `Manifest` (Operator self-declaration content)

Schema unchanged from the hardening draft (five core fields; `additionalProperties: false`; reserved keys rejected; prohibited-content rule enforced at validation). Restated compactly:

```json
{
  "manifest_version": "1.0",
  "agent_id": "agenid:<ULID>",
  "identity":   { "name": "...", "description": "..." },
  "ownership":  { "operator": "...", "operator_domain": "hostname", "contact": "email" },
  "purpose":    { "summary": "...", "channels": ["voice"|"sms"|"chat"|"email"|"api", ...] },
  "disclosure": { "is_ai": bool, "discloses_to_user": bool, "human_escalation": bool }
}
```
The `Manifest` itself is **never signed directly**. It is bound by digest from the two signed objects below. This keeps the manifest freely readable/cacheable and lets many assertions reference one manifest version without re-signing it.

### 6.2 `ManifestProof` (Operator-signed)

```json
{
  "$schema": "https://agenid.org/schemas/v1.1.1/manifest-proof.json",
  "proof_type": "manifest_self_declaration",
  "agent_id": "agenid:01J8Z3K3F2QZ9X6V7R4T8N2W5Y",
  "manifest_version": "1.0",
  "manifest_digest": { "alg": "sha-256", "value": "<64 hex>" },
  "key_id": "agenid:key:<key-ULID>",
  "created_at": "RFC3339 UTC",
  "expires_at": "RFC3339 UTC",
  "signature": "<base64url, no padding, 64 bytes>"
}
```
Rules: `key_id` MUST resolve to a key document with `role: "operator"` and `controller == agent_id`. `proof_type` is a fixed enum (`manifest_self_declaration` only in v1.1.1). All members except `signature` are signing input (§7).

### 6.3 `VerificationAssertion` (Authority-signed) — directive schema, adopted

```json
{
  "$schema": "https://agenid.org/schemas/v1.1.1/assertion.json",
  "assertion_id": "assertion:01J8Z3P2K8VW4RN7XTQ6MYD5HC",
  "subject": "agenid:01J8Z3K3F2QZ9X6V7R4T8N2W5Y",
  "subject_type": "agent",
  "level": "L2_DOMAIN_VERIFIED",
  "claim": { "type": "domain_control", "domain": "acmemedical.com" },
  "authority": "agenid:authority:node-01",
  "evidence": { "type": "dns_txt_challenge", "reference": "_agenid-challenge.acmemedical.com" },
  "verified_at": "2026-09-13T06:00:00Z",
  "expires_at": "2026-10-13T06:00:00Z",
  "scope": "domain_control_only",
  "manifest_digest": { "alg": "sha-256", "value": "<64 hex>" },
  "key_id": "agenid:key:<key-ULID>",
  "signature": "<base64url, no padding, 64 bytes>"
}
```
Fields exactly as required by the directive, plus `manifest_digest` and `key_id` (rationale in §0.B). Enumerations:

| Field | Allowed values (v1.1.1) |
|---|---|
| `subject_type` | `agent`, `deployment` |
| `level` | `L1_REGISTERED`, `L2_DOMAIN_VERIFIED`, `L3_ORGANIZATION_VERIFIED`, `L4_DEPLOYMENT_VERIFIED` (`L5_CONTINUOUSLY_MONITORED` is defined as a name only and MUST NOT be issued in v1.1.1) |
| `claim.type` | `registration`, `domain_control`, `organization_identity`, `deployment_conformance` |
| `evidence.type` | `schema_validation`, `dns_txt_challenge`, `http_wellknown_challenge`, `business_registry_match`, `document_review`, `deployment_sample_review` |
| `scope` | free string, but MUST be one of the authority's published scope identifiers; the vector uses `domain_control_only` |

Rules: `key_id` MUST resolve to a key document with `role: "authority"` and `controller == authority`. `evidence.reference` is a *pointer*, never content (a DNS name, a registry ID, an opaque review ID) — §17 privacy rule. `subject_type: "deployment"` requires `subject` to be a `dep_` identifier and `level` to be `L4_DEPLOYMENT_VERIFIED`.

### 6.4 Key document (§9) and Deployment record (§3) are the other normative objects; neither is signed in v1.1.1 (key documents are trusted via their discovery path, §9; deployment records are DECLARED metadata bound to L4 assertions by digest — full L4 evidence model remains open, §22).

---

## 7. The ONE Signing Construction (applies to both signed objects)

```
 Signed object S  (ManifestProof or VerificationAssertion, as a parsed JSON object)
        │
        ▼
 1. Remove the "signature" member if present  →  P  (the payload)
        │
        ▼
 2. RFC 8785 JCS canonicalize P  →  signing_input (UTF-8 bytes)
        │
        ▼
 3. Ed25519.Sign(private_key_for(P.key_id), signing_input)  →  sig (64 bytes)
        │
        ▼
 4. S = P + { "signature": base64url_nopad(sig) }
```

- **Pure Ed25519 (RFC 8032 PureEdDSA).** The bytes passed to Ed25519 are exactly `signing_input`. No Ed25519ph, no external SHA-512/SHA-256 pre-hash of the payload. The only SHA-256 in the protocol is the `manifest_digest` *data value* inside payloads, computed over the canonical `Manifest` bytes (§6.1) — it is bound *by* the signature, it is not *what is* signed.
- The `$schema` member **is** part of the signing input (it is not stripped). Changing the schema URI invalidates the signature by design.
- Only `signature` is excluded. Including it in the canonicalized input is a verification failure (vector §8.6e).

### 7.1 Verification procedure — `ManifestProof`
1. Parse S; require `signature`; set P = S minus `signature`.
2. Fetch `Manifest` M for (`agent_id`, `manifest_version`); compute `sha256(JCS(M))`; require equality with `P.manifest_digest.value`. Mismatch → `manifest_digest_mismatch`. (No signature math yet.)
3. Resolve `P.key_id` via §9 two-path discovery; require both paths agree; require `role == "operator"` and `controller == P.agent_id`. Failure → `key_role_mismatch` / `key_discovery_mismatch`.
4. Require key `status == "active"` at `P.created_at` (i.e. `created_at < retired_at/revoked_at` if those are set).
5. Require `P.created_at ≤ now ≤ P.expires_at`.
6. `Ed25519.Verify(public_key, JCS(P), base64url_decode(signature))`. Failure → `signature_invalid`.
7. Result: DECLARED manifest, operator-bound. **Never** more than DECLARED.

### 7.2 Verification procedure — `VerificationAssertion`
Steps 1, 4, 5, 6 as above, plus:
- Step 2': compute `sha256(JCS(M))` for the manifest version the verifier is evaluating; require equality with `P.manifest_digest.value`. An assertion whose digest matches an *older* manifest version is valid *for that version* and not applicable to the current one — the verifier reports `assertion_not_applicable_to_current_manifest`, not `invalid`.
- Step 3': `role == "authority"` and `controller == P.authority`. Additionally the verifier MUST decide whether it trusts `P.authority` at all (§9.5 trust anchors) — a valid signature from an untrusted authority is `authority_untrusted`, not VERIFIED.
- Step 5': window is `verified_at ≤ now ≤ expires_at`.
- Result: VERIFIED for exactly `claim` at `level` within `scope`. Nothing outside `scope` is implied.

### 7.3 Role enforcement (both procedures)
Signature validity is necessary, not sufficient. A signature that validates under a key of the wrong role MUST be rejected. §8.6 proves the two cross-role cases reject on the math alone for these vectors (different keys), but implementations MUST additionally check `role`, because a future authority that was also an operator would otherwise be able to self-verify.

---

## 8. Deterministic Test Vectors (computed, reproducible)

Generated in-session with `rfc8785` (RFC 8785) and pyca `cryptography` 46.0.7 (Ed25519). Seeds are `SHA-256(label)`; anyone can regenerate every value below from the labels and the exact JSON shown. **TEST KEYS ONLY.**

### 8.1 Keys

| | Operator key | Authority key |
|---|---|---|
| Seed label | `AgenID v1.1.1 operator test key seed` | `AgenID v1.1.1 authority test key seed` |
| `key_id` | `agenid:key:01J8Z3M9Q4XK2P7VBN6TDR8HWE` | `agenid:key:01J8Z3NC5R7YT3W9KM2XQ4VJHB` |
| role | `operator` | `authority` |
| controller | `agenid:01J8Z3K3F2QZ9X6V7R4T8N2W5Y` | `agenid:authority:node-01` |
| private (32 B, hex) | `eb775bd120e9b13accc73ce6c869f88c2e03beb327be2c2582be031a27297c0d` | `68ab5520f6de62c073760132437f8b6f3e841ad69bc742f18795d235c022b21b` |
| public (32 B, hex) | `0b65c2690e35219a05ba6fb83db349d5a5027af499c02952ce3c99fb1f394f78` | `806b130924dbb3096bd974ae6d99d14b218cf57e291ffa62373553674ae64fe0` |
| public (base64url) | `C2XCaQ41IZoFum-4PbNJ1aUCevSZwClSzjyZ-x85T3g` | `gGsTCSTbswlr2XSubZnRSyGM9X4pH_piNzVTZ0rmT-A` |

All hex values above are exactly 64 characters (32 bytes). Signatures below are exactly 128 hex characters (64 bytes). Line-wrapping is the most common way vectors get corrupted in transcription — count before use.

### 8.2 Manifest → canonical bytes → digest

Input (as authored; member order is irrelevant):
```json
{
  "manifest_version": "1.0",
  "agent_id": "agenid:01J8Z3K3F2QZ9X6V7R4T8N2W5Y",
  "identity": { "name": "Sarah", "description": "Inbound appointment scheduling assistant" },
  "ownership": { "operator": "Acme Medical LLC", "operator_domain": "acmemedical.com", "contact": "trust@acmemedical.com" },
  "purpose": { "summary": "Schedules and reschedules patient appointments by phone and SMS", "channels": ["voice", "sms"] },
  "disclosure": { "is_ai": true, "discloses_to_user": true, "human_escalation": true }
}
```
RFC 8785 canonical UTF-8:
```
{"agent_id":"agenid:01J8Z3K3F2QZ9X6V7R4T8N2W5Y","disclosure":{"discloses_to_user":true,"human_escalation":true,"is_ai":true},"identity":{"description":"Inbound appointment scheduling assistant","name":"Sarah"},"manifest_version":"1.0","ownership":{"contact":"trust@acmemedical.com","operator":"Acme Medical LLC","operator_domain":"acmemedical.com"},"purpose":{"channels":["voice","sms"],"summary":"Schedules and reschedules patient appointments by phone and SMS"}}
```
```
manifest_digest (sha-256) = 81ba268016595373a12091598403eb1d099b214faed04fdabb5bdb47b473ab5d
```
(Identical to the hardening-draft vector — the manifest and its digest did not change; only what is signed over it did.)

### 8.3 `ManifestProof` — signing input and signature (Operator key)

Payload P (before signature):
```json
{
  "$schema": "https://agenid.org/schemas/v1.1.1/manifest-proof.json",
  "proof_type": "manifest_self_declaration",
  "agent_id": "agenid:01J8Z3K3F2QZ9X6V7R4T8N2W5Y",
  "manifest_version": "1.0",
  "manifest_digest": { "alg": "sha-256", "value": "81ba268016595373a12091598403eb1d099b214faed04fdabb5bdb47b473ab5d" },
  "key_id": "agenid:key:01J8Z3M9Q4XK2P7VBN6TDR8HWE",
  "created_at": "2026-09-13T00:00:00Z",
  "expires_at": "2026-12-12T00:00:00Z"
}
```
`signing_input` = RFC 8785 canonical UTF-8 of P — **these exact bytes go to Ed25519:**
```
{"$schema":"https://agenid.org/schemas/v1.1.1/manifest-proof.json","agent_id":"agenid:01J8Z3K3F2QZ9X6V7R4T8N2W5Y","created_at":"2026-09-13T00:00:00Z","expires_at":"2026-12-12T00:00:00Z","key_id":"agenid:key:01J8Z3M9Q4XK2P7VBN6TDR8HWE","manifest_digest":{"alg":"sha-256","value":"81ba268016595373a12091598403eb1d099b214faed04fdabb5bdb47b473ab5d"},"manifest_version":"1.0","proof_type":"manifest_self_declaration"}
```
Signature (Ed25519, operator private key), hex:
```
f1b9a81101db1d327d2ef0921b5682cd02013e8314e543c7592c1a85eda916c16253aa193e079e60eb383634e0ce588662d0e4e2796f4bfe39fb03095806260c
```
base64url (as carried in the `signature` member):
```
8bmoEQHbHTJ9LvCSG1aCzQIBPoMU5UPHWSwahe2pFsFiU6oZPgeeYOs4NjTgzliGYtDk4nlvS_45-wMJWAYmDA
```

### 8.4 `VerificationAssertion` — signing input and signature (Authority key)

Payload P (before signature) — the directive's schema plus `manifest_digest` and `key_id`:
```json
{
  "$schema": "https://agenid.org/schemas/v1.1.1/assertion.json",
  "assertion_id": "assertion:01J8Z3P2K8VW4RN7XTQ6MYD5HC",
  "subject": "agenid:01J8Z3K3F2QZ9X6V7R4T8N2W5Y",
  "subject_type": "agent",
  "level": "L2_DOMAIN_VERIFIED",
  "claim": { "type": "domain_control", "domain": "acmemedical.com" },
  "authority": "agenid:authority:node-01",
  "evidence": { "type": "dns_txt_challenge", "reference": "_agenid-challenge.acmemedical.com" },
  "verified_at": "2026-09-13T06:00:00Z",
  "expires_at": "2026-10-13T06:00:00Z",
  "scope": "domain_control_only",
  "manifest_digest": { "alg": "sha-256", "value": "81ba268016595373a12091598403eb1d099b214faed04fdabb5bdb47b473ab5d" },
  "key_id": "agenid:key:01J8Z3NC5R7YT3W9KM2XQ4VJHB"
}
```
`signing_input` (RFC 8785 canonical UTF-8 — exact Ed25519 message):
```
{"$schema":"https://agenid.org/schemas/v1.1.1/assertion.json","assertion_id":"assertion:01J8Z3P2K8VW4RN7XTQ6MYD5HC","authority":"agenid:authority:node-01","claim":{"domain":"acmemedical.com","type":"domain_control"},"evidence":{"reference":"_agenid-challenge.acmemedical.com","type":"dns_txt_challenge"},"expires_at":"2026-10-13T06:00:00Z","key_id":"agenid:key:01J8Z3NC5R7YT3W9KM2XQ4VJHB","level":"L2_DOMAIN_VERIFIED","manifest_digest":{"alg":"sha-256","value":"81ba268016595373a12091598403eb1d099b214faed04fdabb5bdb47b473ab5d"},"scope":"domain_control_only","subject":"agenid:01J8Z3K3F2QZ9X6V7R4T8N2W5Y","subject_type":"agent","verified_at":"2026-09-13T06:00:00Z"}
```
Signature (Ed25519, authority private key), hex:
```
80a0e77a3d1df3fc68fb5b82d0ebeb26394b5faae854a21096cd283d2e1802862b8bf15d2b644927bc02dd979b5f0fe825265fba593c6ed5d3995c55f871230e
```
base64url:
```
gKDnej0d8_xo-1uC0OvrJjlLX6roVKIQls0oPS4YAoYri_FdK2RJJ7wC3ZebXw_oJSZfulk8btXTmVxV-HEjDg
```

### 8.5 Positive results (executed)

| Check | Result |
|---|---|
| `ManifestProof` signature verifies under operator public key over §8.3 signing input | **VALID** |
| `VerificationAssertion` signature verifies under authority public key over §8.4 signing input | **VALID** |
| Stripping `signature` from each *signed object* and re-canonicalizing reproduces the exact signing input byte-for-byte (verifier-side reconstruction, §7 step 1–2) | **IDENTICAL** |

### 8.6 Negative results (executed)

| # | Case | Result |
|---|---|---|
| a | Assertion `level` changed `L2_DOMAIN_VERIFIED` → `L3_ORGANIZATION_VERIFIED`, re-canonicalized, original signature | **REJECTED** |
| b | Assertion signature verified under the **operator** public key (role substitution) | **REJECTED** |
| c | `ManifestProof` signature verified under the **authority** public key (role substitution) | **REJECTED** |
| d | Manifest `disclosure.human_escalation` flipped to `false`; recomputed digest vs the digest in both payloads | **MISMATCH DETECTED** (fails at §7.1 step 2, before any signature math) |
| e | Verifier mistakenly includes the `signature` member in the canonicalized signing input | **REJECTED** |
| f | Manifest members supplied in a different order → canonical bytes | **IDENTICAL** (order-independence holds) |

### 8.7 Adversarial canonicalization vectors (executed) — NEW

| Case | Input (JSON) | RFC 8785 canonical UTF-8 | SHA-256 |
|---|---|---|---|
| numbers | `{"a":1,"b":1.0,"c":1e21,"d":0.000001,"e":1e-7,"f":-0.0,"g":9007199254740991,"h":1.5,"i":100,"j":1e100}` | `{"a":1,"b":1,"c":1e+21,"d":0.000001,"e":1e-7,"f":0,"g":9007199254740991,"h":1.5,"i":100,"j":1e+100}` | `c90806482c2f6ca448cf6b4334edd43373d8aa7f2352e626e8a006ecea660d27` |
| unicode | `{"emoji":"🔐","cjk":"検証","combining":"é","control":"line\nbreak\ttab","quote":"say \"hi\"","slash":"a/b\\c","del":"","nbsp":" "}` | `{"cjk":"検証","combining":"é","control":"line\nbreak\ttab","del":"<U+007F raw>","emoji":"🔐","nbsp":"<U+00A0 raw>","quote":"say \"hi\"","slash":"a/b\\c"}` — hex: `7b22636a6b223a22e6a49ce8a8bc222c22636f6d62696e696e67223a2265cc81222c22636f6e74726f6c223a226c696e655c6e627265616b5c74746162222c2264656c223a227f222c22656d6f6a69223a22f09f9490222c226e627370223a22c2a0222c2271756f7465223a22736179205c2268695c22222c22736c617368223a22612f625c5c63227d` | `df23e8ef35dc7c3934311edbcdd7d31b8248f6488fac982dcc9df86e1f691995` |
| sort_order | `{"b":1,"a":2,"aa":3,"B":4,"é":5,"ab":6,"10":7,"9":8}` | `{"10":7,"9":8,"B":4,"a":2,"aa":3,"ab":6,"b":1,"é":5}` | `72eda6bc50ecb8b507940d26a19f6507ef284d99fa246c2275fabc8e8a7409b5` |
| empty_and_null | `{"z":null,"empty_obj":{},"empty_arr":[],"nested":{"k":[null,true,false,""]}}` | `{"empty_arr":[],"empty_obj":{},"nested":{"k":[null,true,false,""]},"z":null}` | `8715fe3470ad104b498353e84f3112e2bf729d4d2de1a55fcc60e91b33c3ed37` |

Rejections (executed; a conformant implementation MUST refuse these at validation):

| Input | Result |
|---|---|
| `{"x": 9007199254740992}` (2⁵³) | **REJECTED** — outside safe integer domain |
| `{"x": 9007199254740993}` | **REJECTED** |
| `{"x": 100000000000000000000}` | **REJECTED** |
| `{"x": NaN}` | **REJECTED** — not representable in JCS |
| `{"x": Infinity}` | **REJECTED** |

Note on the unicode row: the DEL (`0x7f`) and NBSP (`0xc2a0`) bytes are present in the hex and are invisible in the rendered text — use the hex, not the rendered string, when reproducing.

---

## 9. Key Management — Discovery, Roles, Trust Anchors

### 9.1 Key document (normative)
```json
{
  "key_id": "agenid:key:01J8Z3M9Q4XK2P7VBN6TDR8HWE",
  "key_type": "Ed25519",
  "public_key_b64u": "C2XCaQ41IZoFum-4PbNJ1aUCevSZwClSzjyZ-x85T3g",
  "role": "operator",
  "controller": "agenid:01J8Z3K3F2QZ9X6V7R4T8N2W5Y",
  "created_at": "2026-09-13T00:00:00Z",
  "status": "active",
  "retired_at": null,
  "revoked_at": null
}
```
`role` ∈ {`operator`, `authority`}. `status` ∈ {`active`, `retired`, `revoked`}. `retired`/`revoked` keys remain resolvable forever so historical proofs stay verifiable.

### 9.2 Wire resolution (fixes §0.A)
- `GET https://api.agenid.com/v1/keys/{key-ULID}` → key document (`application/json`).
- `GET https://api.agenid.com/v1/keys?key_id={percent-encoded logical id}` → identical document.
- A request whose `key_id` contains `#` → `400 invalid_key_id`.

### 9.3 Operator-hosted discovery (normative URI and schema)
`https://<ownership.operator_domain>/.well-known/agenid/keys.json`:
```json
{
  "$schema": "https://agenid.org/schemas/v1.1.1/keys.json",
  "controller_domain": "acmemedical.com",
  "keys": [ { ...key document... }, { ...key document... } ]
}
```
Served over HTTPS with a valid certificate for `operator_domain`. This document is what makes an operator key *domain-bound*: an L2 assertion says the operator controls the domain; the well-known file says which keys that domain vouches for.

### 9.4 Authority-hosted discovery
`https://<authority_domain>/.well-known/agenid/keys.json`, same schema, `controller_domain` = the authority's domain. For `agenid:authority:node-01` the authority domain is published in the authority registry (§9.5).

### 9.5 Trust anchors — bootstrap now specified (closes hardening-draft BLOCKED item)
A verifier needs two things it cannot derive from a signature: (1) which domain an `agenid:authority:*` identifier maps to, and (2) an initial reason to trust that domain's well-known key file.

- **Authority registry document:** `https://agenid.org/.well-known/agenid/authorities.json` lists `{ authority_id, authority_domain, root_key_id, root_public_key_b64u }` for every recognized authority. This file is itself signed (as a `VerificationAssertion` with `claim.type: "authority_registry"`, reserved value) by the **AgenID root authority key**.
- **Root key pinning (out-of-band anchor):** the AgenID root authority key's public value and `key_id` are published in this specification's repository (the spec is the out-of-band channel) and MUST be pinned by verifiers. TLS on `agenid.org` is the *online* path; the pinned root key is the *offline* anchor. A verifier that trusts only TLS is doing "trust AgenID's infrastructure"; a verifier that also checks the pin is doing independent verification. Both paths are normative; disagreement is `trust_anchor_mismatch` (hard fail).
- **What is and isn't done:** the *mechanism* is now fully specified and testable (an `authorities.json` + pinned root key can be verified with the exact §7.2 procedure). The *production root key* does not exist yet — generating it, storing it in an HSM, and publishing the pin is an operational ceremony recorded in §22 as a pre-launch task, not a protocol gap. §21 scores Gate 4 accordingly.

### 9.6 Rotation / revocation / expiry
Unchanged: rotation = new key ULID, old key `retired` with `retired_at`; proofs created before `retired_at` remain valid; `revoked_at` invalidates proofs created after it regardless of signature; `expires_at` inside every signed payload is checked independently of key status; re-attestation issues a new signed object, never mutates an old one.

---

## 10. Manifest Schema — unchanged from the hardening draft (§9 there), with one clarification
`additionalProperties: false` remains; reserved keys (`platform`, `permissions`, `jurisdictions`, `status`, `change_history`, `authorizations`, `configuration_fingerprint`) are rejected by a v1.1.1 validator. The configuration-fingerprint boundary language (fingerprint ≠ behavioral/safety/compliance proof) carries forward verbatim and applies to any future `VerificationAssertion` with `evidence.type` referencing a fingerprint.

## 11. Verification Levels — restated as assertion enumerations
Each level below is issued **only** as a `VerificationAssertion` (§6.3). The hardening draft's table of subject/evidence/method/authority is unchanged; the mapping to enumerated values is:

| Level enum | `subject_type` | `claim.type` | Typical `evidence.type` |
|---|---|---|---|
| `L1_REGISTERED` | agent | `registration` | `schema_validation` |
| `L2_DOMAIN_VERIFIED` | agent | `domain_control` | `dns_txt_challenge` / `http_wellknown_challenge` |
| `L3_ORGANIZATION_VERIFIED` | agent | `organization_identity` | `business_registry_match` / `document_review` |
| `L4_DEPLOYMENT_VERIFIED` | deployment | `deployment_conformance` | `deployment_sample_review` |
| `L5_CONTINUOUSLY_MONITORED` | — | — | **NOT ISSUABLE in v1.1.1.** Name reserved. No continuous-integrity claim is made. |

Verification ≠ compliance: unchanged, hard rule.

## 12. Status Model — unchanged
`ACTIVE / CHANGED / STALE / SUSPENDED / REVOKED`, Agent-level and Deployment-level tracked independently; `REVOKED` identities are permanent and publicly resolvable. One clarification: `CHANGED` is now precisely defined as "the current manifest digest differs from the `manifest_digest` of at least one otherwise-valid L2+ assertion" — a mechanical, testable condition rather than a judgment.

## 13. Event Ledger — unchanged, one addition
Append-only; hashes/references only. New event types: `assertion.issued`, `assertion.expired`, `key.retired` (in addition to `key.rotated`, `key.revoked`). Every `assertion.issued` event carries `assertion_id` and the assertion's `manifest_digest`, never the evidence.

## 14. API — unchanged except key endpoints (§9.2) and two additions
- `GET /v1/agents/{agent_id}/proof` returns the current `ManifestProof`.
- `GET /v1/agents/{agent_id}/assertions` returns all `VerificationAssertion`s (current and expired, flagged), each a complete signed object.
- `GET /v1/assertions/{assertion-ULID}` returns one assertion by its own identifier (wire form = bare ULID, same rule as keys).
Single `/v1` prefix; content negotiation unchanged.

## 15. Resolver — unchanged
`agenid:<ULID>` → HTML / JSON / (proof + assertions + key-discovery pointers sufficient for §7 verification without further resolver trust).

## 16. Security Model — hardening-draft table carried forward; rows updated by this revision

| Threat | Change in this revision |
|---|---|
| Signature substitution / role confusion | **Closed.** Separate objects + key `role` enforced at verify time; vectors §8.6b/c. |
| Key resolution failure (fragment bug) | **Closed.** §0.A / §9.2; `#` is a hard 400. |
| Trust-anchor circularity | **Mechanism closed** (§9.5); production ceremony pending (§22). |
| Serialization divergence (numbers/unicode) | **Covered by executed vectors** (§8.7) and a number-domain validation rule (§5). |
| Assertion reuse against a newer manifest | **Closed.** `manifest_digest` in every assertion; §7.2 reports `not_applicable_to_current_manifest`. |
| Replay / expiry / key revocation | Unchanged; §7 steps 4–5. |
| Malicious adapter | Unchanged; adapter output is DECLARED-equivalent only (§18). |

## 17. Privacy Model — unchanged
Public: manifest, proof, assertions (with evidence *references*), status. Never public: evidence content, secrets, prohibited content. `evidence.reference` MUST be a pointer.

## 18. Adapter Contracts — unchanged
Generic contract as in the hardening draft. Retell: AgenID-side interface normative; Retell-side field mapping remains **BLOCKED** pending verification against current official Retell documentation (no Retell endpoint, webhook, or dashboard hook is asserted to exist by this document).

## 19. Test Requirements — hardening-draft table carried forward, with these now **satisfied by executed vectors**
Cryptography: valid signature ✓ (×2 objects), tampered payload ✓, wrong key ✓, wrong *role* ✓ (×2), digest mismatch ✓, signature-in-input error ✓, key-order independence ✓, canonicalization adversarial cases ✓ (numbers, unicode, sort order, null/empty), number-domain rejections ✓. Still pending implementation: expired proof, revoked/retired key timing, ULID collision insert, resolver content negotiation, L2/L3/L4 flows, status transitions, adapter fuzzing.

## 20. Normative Schemas — locations
`https://agenid.org/schemas/v1.1.1/manifest.json`, `.../manifest-proof.json`, `.../assertion.json`, `.../keys.json`, `.../authorities.json`. The `manifest.json` schema is the hardening draft's §9 verbatim; `manifest-proof.json` and `assertion.json` are the structures in §6.2/§6.3 with the enumerations in §6.3 and `additionalProperties: false`. (Schema documents are specification artifacts, not application code, and are the next spec deliverable if the owner wants them as standalone files.)

---

## 21. Build-Ready Verification Matrix (re-scored)

| Gate | Requirement | Status | Concrete evidence (not prose) |
|---|---|---|---|
| 1. Cryptographic Reproducibility | Independent developer reproduces the exact result from published vectors | **PASS** | §8.1–8.6: two keys, two signed objects, signing inputs shown byte-exact, signatures shown hex + base64url, 3 positive and 6 negative checks executed. §8.7: 4 canonicalization vectors + 5 domain rejections executed. Seeds are label-derived; nothing is illustrative. |
| 2. Identity Permanence | Deployment changes cannot mutate/re-key the Agent | **SPEC-DEFINED, IMPLEMENTATION-PENDING** | §2/§3 normative; `manifest_digest` binding (§6.3) makes "assertion survives deployment change" mechanically true by construction. No registration code exists to execute the §19 identity tests against — cannot be PASS under the directive's own rule. |
| 3. Verification Semantics | Every verification claim identifies evidence, authority, scope, time | **PASS (schema-level)** | §6.3 `VerificationAssertion` is a normative schema in which `evidence`, `authority`, `scope`, `verified_at`, `expires_at`, `level`, `subject` are all **required** members, and §8.4 is an executed instance of it. A claim without these fields cannot be a valid assertion. This is a concrete normative schema + deterministic vector, which is the PASS bar the directive sets. |
| 4. Third-Party Verification | Validator verifies without trusting AgenID's app/DB | **PASS (protocol) / CEREMONY-PENDING (operations)** | §7.1/§7.2 are executable procedures needing only: the signed object, the manifest, a key document from either discovery path, and (for assertions) the pinned root anchor. §8.5 demonstrates verifier-side reconstruction from the signed object alone. The remaining dependency is that the *production* root key has not been generated/pinned (§22.2) — an operational precondition, not a protocol hole. |
| 5. Protocol Independence | Survives replacement of AgenID's infrastructure/integrations | **SPEC-DEFINED, IMPLEMENTATION-PENDING** | No storage-specific construct appears in any normative object (§6, §9, §13). Empirical proof (second backend / second language re-running §8) requires an implementation that does not exist yet. |

**Build authorization: NOT GRANTED.** Gates 1, 3 and (protocol-level) 4 are now PASS on concrete evidence. Gates 2 and 5 cannot honestly move past spec-defined without code to test, which is the expected state at a pre-code gate, not a defect. The remaining *protocol* blocker count is zero; the remaining blockers are operational and external (§22).

---

## 22. Residual Items (post-closure)

1. **`agenid.org` vs `agenid.com` namespace split** — confirm the directive's `agenid.org` schema/authority namespace is intentional (open standard on .org, product on .com). Followed verbatim here; needs an explicit yes.
2. **Root authority key ceremony** — generate the production root key (HSM), publish `authorities.json`, publish the pin in the spec repo. Operational, pre-launch, not a spec gap.
3. **Retell-side adapter field verification** — unchanged; do not implement against unverified Retell API shapes.
4. **L4 deployment-evidence methodology** — sampling method/size/pass criteria for `deployment_sample_review` still to be specified before L4 can be *issued*; the assertion format for L4 is already closed.
5. **Standalone JSON Schema files** (§20) — next specification artifact if wanted as files rather than inline definitions.
6. **Directive items beyond A and B** — not received; if the closure directive had further P0 corrections, resend them and they will be applied against this baseline.

---

*AgenID — a venture of AI Venture Holdings LLC. All rights reserved by AIVH LLC.*
