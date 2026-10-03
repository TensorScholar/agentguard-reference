# Evidence model

This document describes the standalone `agentguard-reference` 0.1.0 audit evidence. It is not a publisher attestation, not a business-effect proof, and not a production certification.

## What a record is

Each audit record is an in-memory dictionary with exactly these fields:

| Field | Meaning |
|---|---|
| `sequence` | 1-based position in this log instance |
| `previous` | SHA256 chain head of the prior record, or 64 zero hex digits for the first record |
| `event` | One of `decision.allowed`, `decision.denied`, `execution.admitted`, `execution.denied`, `execution.succeeded`, `execution.unknown` |
| `authorization_id` | Authorization identifier, or empty when no identifier was established |
| `action_digest` | SHA256 of the canonical action snapshot, or 64 zero hex digits when no valid action was established |
| `reason` | Stable reason code, not exception text |
| `mac` | HMAC-SHA256 of the record payload under the audit domain separator |

Records do not contain principal labels, argument values, executor return values, exception strings, HMAC keys, or provider payloads. The action digest is a binding handle, not a reconstruction of the action.

## How authenticity is computed

Domain-separated MAC input:

```text
HMAC-SHA256(key, "agentguard-reference:audit:v1\0" || canonical(payload_without_mac))
```

Chain head:

```text
SHA256("agentguard-reference:chain:v1\0" || canonical(record_including_mac))
```

Authorization signatures use a different domain (`agentguard-reference:authorization:v1`). An authorization MAC is not a valid audit MAC.

Verification (`verify_records`) answers one of two questions, selected by whether `expected_head` is supplied.

### Integrity of the presented prefix — no `expected_head`

`verify_records(records, key)`, and its explicitly-named alias `verify_prefix(records, key)`, check that each presented record has the exact schema, that sequence runs from 1, that `previous` links from the zero head, and that every MAC is valid under the key.

What this establishes is the integrity of the records **presented**. It establishes nothing about completeness. A shorter authentic chain verifies just as well as the full one, so removing records from the end is invisible. `verify_prefix` is the honest name for this mode and is provided so the weaker question is visible at the call site.

### Integrity and completeness — with `expected_head`

`verify_records(records, key, expected_head=HEX)` additionally requires the final computed head to equal `HEX`. A chain truncated to an earlier valid prefix then fails. This is the only way trailing-record removal is detected.

`HEX` must come from a channel the verifier trusts. A head copied from the document being verified, or from any source the artifact controls, anchors nothing: an attacker who can choose the head can supply the head of the shorter chain they left behind.

In short: **integrity without a head, completeness with a trusted one.** Neither mode says anything about whether records from another process, host, or store are absent.

A valid prefix under the key is not completeness. Truncation to an earlier authentic prefix verifies unless the expected head is supplied and matches the intended endpoint. Anyone who holds the HMAC key can forge records. HMAC is shared-secret authentication, not a public signature and not non-repudiation.

## What evidence can support

Under a secret key and a trusted expected head, a verified chain supports:

- that these records were produced by a holder of that key;
- that the sequence was not reordered, internally tampered, or prefix-stripped;
- that the recorded events, authorization identifiers, action digests, and reason codes match what that log instance emitted.

The CLI verifier must be given the key as a separate file. A key embedded in the JSON document is ignored as authority.

## What evidence cannot support

A verified chain does not prove:

- that an external business operation completed;
- that a principal was authenticated;
- that a prompt or document expressed genuine human intent;
- that the key holder was honest;
- that records from another process, host, or store are absent;
- that consumed authorization cannot be replayed after restart or against a different store;
- that records are retained for any particular period. The log is an in-memory list with no bound and no eviction, so it ends with the process, and trailing records can be lost without any record of the loss inside the chain itself.

A verified chain says nothing about the executor. `executor` is trusted process code with full host authority; what is bound and recorded is the argument value that was dispatched, not the behaviour of the code that received it. See [limitations](limitations.md).

`ExecutionResult.status == "succeeded"` means the local callback returned and the success audit record was appended. It is not provider confirmation. `unknown` means dispatch occurred and the guarded outcome could not be confirmed; it is not evidence that no effect occurred and not permission to retry the same authorization.

## Demo output

The CLI demo uses a public illustrative in-memory key and a fixed clock. Its JSON contains `records`, `head`, and `results` for inspection. Demo output is internally consistent under that public key and is not trusted evidence.

See [architecture](architecture.md), [threat model](threat-model.md), and [limitations](limitations.md).
