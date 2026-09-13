"""AgenID v1.1.1 FINAL — deterministic test vector generator.
Two distinct signed objects, two distinct keys:
  ManifestProof          signed by the OPERATOR key
  VerificationAssertion  signed by the AUTHORITY key
Reproduce: seeds are SHA-256 of the labels below. Never use these keys in production.
"""
import json, hashlib, base64
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

def b64u(b): return base64.urlsafe_b64encode(b).decode().rstrip("=")
def raw_pub(k): return k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
def raw_priv(k): return k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())

OP_SEED  = hashlib.sha256(b"AgenID v1.1.1 operator test key seed").digest()
AU_SEED  = hashlib.sha256(b"AgenID v1.1.1 authority test key seed").digest()
op_key = Ed25519PrivateKey.from_private_bytes(OP_SEED)
au_key = Ed25519PrivateKey.from_private_bytes(AU_SEED)

AGENT_ID     = "agenid:01J8Z3K3F2QZ9X6V7R4T8N2W5Y"
OP_KEY_ID    = "agenid:key:01J8Z3M9Q4XK2P7VBN6TDR8HWE"   # key has its OWN ULID; no fragment
AU_KEY_ID    = "agenid:key:01J8Z3NC5R7YT3W9KM2XQ4VJHB"
AUTHORITY_ID = "agenid:authority:node-01"

# ---------- 1. Manifest (operator self-declaration content) ----------
manifest = {
    "manifest_version": "1.0",
    "agent_id": AGENT_ID,
    "identity": {"name": "Sarah", "description": "Inbound appointment scheduling assistant"},
    "ownership": {"operator": "Acme Medical LLC", "operator_domain": "acmemedical.com", "contact": "trust@acmemedical.com"},
    "purpose": {"summary": "Schedules and reschedules patient appointments by phone and SMS", "channels": ["voice", "sms"]},
    "disclosure": {"is_ai": True, "discloses_to_user": True, "human_escalation": True},
}
manifest_bytes = rfc8785.dumps(manifest)
manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()

# ---------- 2. ManifestProof (signed by OPERATOR key) ----------
manifest_proof_payload = {
    "$schema": "https://agenid.org/schemas/v1.1.1/manifest-proof.json",
    "proof_type": "manifest_self_declaration",
    "agent_id": AGENT_ID,
    "manifest_version": "1.0",
    "manifest_digest": {"alg": "sha-256", "value": manifest_digest},
    "key_id": OP_KEY_ID,
    "created_at": "2026-09-13T00:00:00Z",
    "expires_at": "2026-12-12T00:00:00Z",
}
mp_bytes = rfc8785.dumps(manifest_proof_payload)
mp_sig = op_key.sign(mp_bytes)
manifest_proof = dict(manifest_proof_payload); manifest_proof["signature"] = b64u(mp_sig)

# ---------- 3. VerificationAssertion (signed by AUTHORITY key) ----------
assertion_payload = {
    "$schema": "https://agenid.org/schemas/v1.1.1/assertion.json",
    "assertion_id": "assertion:01J8Z3P2K8VW4RN7XTQ6MYD5HC",
    "subject": AGENT_ID,
    "subject_type": "agent",
    "level": "L2_DOMAIN_VERIFIED",
    "claim": {"type": "domain_control", "domain": "acmemedical.com"},
    "authority": AUTHORITY_ID,
    "evidence": {"type": "dns_txt_challenge", "reference": "_agenid-challenge.acmemedical.com"},
    "verified_at": "2026-09-13T06:00:00Z",
    "expires_at": "2026-10-13T06:00:00Z",
    "scope": "domain_control_only",
    "manifest_digest": {"alg": "sha-256", "value": manifest_digest},
    "key_id": AU_KEY_ID,
}
va_bytes = rfc8785.dumps(assertion_payload)
va_sig = au_key.sign(va_bytes)
assertion = dict(assertion_payload); assertion["signature"] = b64u(va_sig)

# ---------- 4. Verification (positive) ----------
op_key.public_key().verify(mp_sig, mp_bytes)
au_key.public_key().verify(va_sig, va_bytes)

def strip_sig(obj):
    o = dict(obj); o.pop("signature", None); return o

# re-derive signing input from the *signed object* (what a verifier actually holds)
assert rfc8785.dumps(strip_sig(manifest_proof)) == mp_bytes
assert rfc8785.dumps(strip_sig(assertion)) == va_bytes

# ---------- 5. Negative vectors ----------
def rejects(pub, sig, msg):
    try: pub.verify(sig, msg); return False
    except InvalidSignature: return True

neg = {}
# 5a. assertion tampered: level upgraded
t = dict(assertion_payload); t["level"] = "L3_ORGANIZATION_VERIFIED"
neg["assertion_level_tampered_rejected"] = rejects(au_key.public_key(), va_sig, rfc8785.dumps(t))
# 5b. role substitution: operator key presented as if it signed the assertion
neg["assertion_verified_with_operator_key_rejected"] = rejects(op_key.public_key(), va_sig, va_bytes)
# 5c. manifest proof verified with authority key (wrong role)
neg["manifest_proof_verified_with_authority_key_rejected"] = rejects(au_key.public_key(), mp_sig, mp_bytes)
# 5d. manifest content changed -> digest mismatch (checked BEFORE signature, no sig involved)
m2 = json.loads(json.dumps(manifest)); m2["disclosure"]["human_escalation"] = False
neg["manifest_digest_mismatch_detected"] = hashlib.sha256(rfc8785.dumps(m2)).hexdigest() != manifest_digest
# 5e. signature field included in canonicalization by mistake -> must NOT verify
neg["including_signature_field_in_signing_input_rejected"] = rejects(au_key.public_key(), va_sig, rfc8785.dumps(assertion))
# 5f. key-order independence: same manifest, shuffled key order -> identical bytes
shuffled = {"disclosure": manifest["disclosure"], "purpose": manifest["purpose"], "agent_id": AGENT_ID,
            "ownership": manifest["ownership"], "identity": manifest["identity"], "manifest_version": "1.0"}
neg["key_order_independence_holds"] = rfc8785.dumps(shuffled) == manifest_bytes

# ---------- 6. Adversarial canonicalization vectors (RFC 8785 §3.2.2.3 numbers, unicode) ----------
adv_cases = {
    "numbers": {"a": 1, "b": 1.0, "c": 1e21, "d": 0.000001, "e": 1e-7, "f": -0.0, "g": 100000000000000000000, "h": 9007199254740992},
    "unicode": {"emoji": "🔐", "cjk": "検証", "combining": "é", "control": "line\nbreak\ttab", "quote": "say \"hi\"", "slash": "a/b\\c", "del": "", "nbsp": " "},
    "sort_order": {"b": 1, "a": 2, "aa": 3, "B": 4, "é": 5, "ab": 6, "10": 7, "9": 8},
    "empty_and_null": {"z": None, "empty_obj": {}, "empty_arr": [], "nested": {"k": [None, True, False, ""]}},
}
adv = {}
for name, obj in adv_cases.items():
    try:
        cb = rfc8785.dumps(obj)
        adv[name] = {"input": obj, "canonical_utf8": cb.decode("utf-8"), "canonical_hex": cb.hex(), "sha256": hashlib.sha256(cb).hexdigest()}
    except Exception as e:
        adv[name] = {"input": obj, "error": type(e).__name__ + ": " + str(e)}

out = {
    "operator_key": {"seed_label": "AgenID v1.1.1 operator test key seed", "private_hex": raw_priv(op_key).hex(), "public_hex": raw_pub(op_key).hex(), "public_b64u": b64u(raw_pub(op_key)), "key_id": OP_KEY_ID},
    "authority_key": {"seed_label": "AgenID v1.1.1 authority test key seed", "private_hex": raw_priv(au_key).hex(), "public_hex": raw_pub(au_key).hex(), "public_b64u": b64u(raw_pub(au_key)), "key_id": AU_KEY_ID},
    "manifest": {"input": manifest, "canonical_utf8": manifest_bytes.decode(), "canonical_hex": manifest_bytes.hex(), "sha256": manifest_digest},
    "manifest_proof": {"payload_input": manifest_proof_payload, "signing_input_utf8": mp_bytes.decode(), "signing_input_hex": mp_bytes.hex(), "signature_hex": mp_sig.hex(), "signature_b64u": b64u(mp_sig), "signed_object": manifest_proof},
    "verification_assertion": {"payload_input": assertion_payload, "signing_input_utf8": va_bytes.decode(), "signing_input_hex": va_bytes.hex(), "signature_hex": va_sig.hex(), "signature_b64u": b64u(va_sig), "signed_object": assertion},
    "positive": {"manifest_proof_verifies_with_operator_key": True, "assertion_verifies_with_authority_key": True, "signing_input_rederivable_from_signed_object": True},
    "negative": neg,
    "adversarial_canonicalization": adv,
}
print(json.dumps(out, indent=2, ensure_ascii=False))
