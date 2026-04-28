# Receipt schema

Receipts are signed records of executed actions.

## Goals

- prove what action was approved/executed
- make tampering detectable
- avoid raw secret exposure
- work offline
- support future hosted publication

## Candidate v1 shape

```json
{
  "receipt_version": "authority.receipt.v1",
  "receipt_id": "rcpt_demo",
  "principal": "local",
  "agent": "demo",
  "action": "email.send",
  "resource": "fake-mailgun",
  "payload_hash": "sha256:...",
  "policy_hash": "sha256:...",
  "approval": {
    "required": true,
    "approved_by": "local-human",
    "approved_at": "2026-04-28T18:02:00Z"
  },
  "execution": {
    "status": "succeeded",
    "provider": "fake-mailgun",
    "provider_request_id": "fake-request-1"
  },
  "issued_at": "2026-04-28T18:03:00Z",
  "signature": {
    "alg": "ed25519",
    "kid": "local-test-key",
    "sig": "..."
  }
}
```

## Must not include

- raw secrets
- OAuth refresh tokens
- passwords
- provider API keys
- unredacted provider response bodies unless explicitly safe

## Open decision

Choose signing envelope:

- JWS
- COSE
- custom canonical JSON + Ed25519

Current recommendation: canonical JSON plus Ed25519 for v1.

Why:

- simple to implement and inspect in Rust
- easy to verify offline
- no dependency on JWT semantics that may imply auth tokens rather than records
- no COSE/CBOR complexity for the first release
- maps cleanly to JSONL local audit/export

The design should keep an envelope version so the hosted product can later move
to JWS, COSE, or W3C-verifiable-credential-compatible formats without breaking
v1 receipts.

## Action hash

The v1 field name is `payload_hash`, but the value must bind the canonical
action envelope, not only the free-form payload body. The hash includes the
action id, agent id, task id, capability, resource, operation, payload,
idempotency key, and request timestamp. This prevents approvals and receipts
from being reused across different URLs, recipients, resources, or action ids
that happen to share the same payload body.

## Local verification

`ctxa receipts verify receipt.json` verifies the Ed25519 signature against the
current local broker key and rejects receipts signed by another key id. It must
fail closed if the local signing key is missing, the key id differs, the
signature cannot be decoded, the receipt contains unknown fields, or the receipt
body was modified after signing.
