# AgenID Protocol

**AI Agent Identity Infrastructure — the open specification.**

AgenID gives an AI agent a persistent, portable, independently verifiable identity: a permanent `agenid:<ULID>`, an accountable operator, declared attributes, and cryptographically verifiable records that a person, a program, an auditor, or another agent can check **without trusting AgenID's own database**.

This repository is the standard. The reference implementation lives at [`AgenID-protocol/agenid`](https://github.com/AgenID-protocol/agenid) (`@agenid/core`).

## Contents

| Path | What |
|---|---|
| [`spec/agenid-v1.1.1.md`](spec/agenid-v1.1.1.md) | **AgenID v1.1.1 Final Protocol Specification** — normative. |
| [`schemas/`](schemas/) | JSON Schema (draft 2020-12) for every normative object: `manifest`, `manifest-proof`, `assertion`, `keys`, `authorities`. Served at `https://agenid.org/schemas/v1.1.1/<name>.json`. |
| [`vectors/`](vectors/) | Deterministic test vectors (§8) — real Ed25519 signatures and RFC 8785 canonical bytes — plus the generator that produced them. |
| [`ERRATA.md`](ERRATA.md) | Corrections applied after publication. |

## The protocol in one screen

```
Manifest  (operator's DECLARED self-description; plain canonical JSON; never signed directly)
   │  SHA-256( RFC 8785 canonical bytes )
   ▼
ManifestProof           signed by an OPERATOR key      → produces DECLARED only
VerificationAssertion   signed by an AUTHORITY key     → produces VERIFIED only
                        (one claim, one evidence pointer, one level L1–L4, one scope, one window,
                         bound to one manifest version by digest)

Signing construction (the only one):
   signing_input = RFC 8785 JCS( object minus "signature" )   — "$schema" IS included
   signature     = Ed25519.Sign( private_key, signing_input )  — pure EdDSA, no pre-hash

Keys:   agenid:key:<ULID>  — a key has its own ULID; no URI fragments; role ∈ {operator, authority}
        discovery: GET /v1/keys/{key-ULID}  AND  https://<controller-domain>/.well-known/agenid/keys.json — both must agree
```

Three claim states that are never inferred from one another:

```
DECLARED            does NOT imply   VERIFIED
VERIFIED            does NOT imply   AUTHORIZED
PLATFORM_CONFIGURED does NOT imply   AUTHORIZED
```

## Reproduce the test vectors

```bash
pip install rfc8785 cryptography
python3 vectors/generate_vectors.py > my-vectors.json
diff <(python3 -m json.tool my-vectors.json) <(python3 -m json.tool vectors/v1.1.1-vectors.json)
```

Seeds are `SHA-256(label)`; every signature is deterministic. An implementation in any language that does not reproduce these bytes exactly is non-conformant — that is what the vectors are for.

## Status

- **Specification:** v1.1.1 Final (Erratum E1 applied).
- **Verification levels issuable:** L1–L4. **L5 is a reserved name only** and is not issuable.
- **Authorization (`permissions` / AUTHORIZED):** reserved for v1.2; no signed object exists in v1.1.1.
- **Root authority key:** not yet generated. Until the key ceremony is complete and the pin is published here, no production `VerificationAssertion` can be trusted end-to-end. The vectors use test keys only.

## Governance

Maintained by AI Venture Holdings LLC. The specification, schemas, and vectors are MIT-licensed so that any platform can implement the standard without a relationship with AgenID; AgenID's own registry and verification services are separate products built on this standard.

Issues and proposals: open a GitHub issue. Changes to identity, cryptography, serialization, verification semantics, or schemas require an erratum or a new version — the specification is the source of truth, code follows it.
