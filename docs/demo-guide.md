# Demo guide

The standalone 1.0.1 CLI requires Python >=3.11, without provider credentials or integrations.

## Install

From the package root, use an isolated environment:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
python -m agentguard_reference demo
```

The distribution and CLI are named `agentguard-reference`; the distinct `agentguard_reference` import namespace avoids collisions with other `agentguard` packages.

## Read the output

The demo fixes time at 1000 and uses a fixed synthetic nonce, a public illustrative in-memory HMAC key, and a callback that appends arguments to a list. Repeated runs produce the same JSON. It does not issue a real refund or contact a provider.

| Field | Interpretation |
|---|---|
| `schema` | `agentguard-reference-demo-v1` |
| `package_version` | Import-package version string |
| `key_warning` | Labels the public illustrative key; does not export a verification secret |
| `decision` | Authorization decision and synthetic authorization |
| `records`, `head` | Audit records and chain endpoint |
| `results` | First dispatch and replay-denial results |
| `executor_calls` | Callback invocation count |
| `verified` | Internal consistency under the public demo key |

The demo returns status 0 only when verification is true and the callback count is one; otherwise it returns 1. Its first result is `succeeded`/`executor.returned`; replay is `denied`/`authorization.replayed`. This describes the code and assertions in `tests/unit/test_cli.py`, not an independent release attestation.

`denied` means no callback dispatch. `succeeded` requires callback return and successful outcome auditing. `unknown` means dispatch occurred but the guarded outcome could not be confirmed; it must not trigger reuse of consumed authorization.

## Verify an audit file

In the activated environment, for separately provisioned inputs:

```sh
python -m agentguard_reference verify audit.json --key-file verification.key --expected-head HEX
```

The paths are examples, not supplied fixtures. The audit input is UTF-8 JSON: either a record array or an object whose `records` value is that array. The key file supplies raw bytes, not decoded hex or base64; it needs at least 32 bytes. The file-size checks accept audit files up to 10485760 bytes (10 MiB) and key files up to 4096 bytes, inclusive, based on `stat()` before reads. These checks are not race-free streaming limits.

Replace `HEX` with a trusted, independently obtained 64-character lowercase hexadecimal head. The CLI ignores embedded keys and document head metadata as authority; only the external key and `--expected-head` control verification. A key-holding verifier can forge HMAC records, and a head copied only from untrusted input does not establish completeness.

## Failure behavior and exit status

- Successful verification prints `{"verified": true}` and exits 0.
- A wrong key/head, tampered record, or missing record field prints `{"verified": false}` and exits 1.
- Malformed JSON, missing/non-array `records`, unreadable files, or excessive reported size prints `verification failed: invalid or unreadable input` to stderr and exits 1.
- Missing `--key-file` or `--expected-head` is an argparse error with exit status 2, before file reads.

The policy is a refund demonstration, not identity authentication. Principal and provenance are asserted by the trusted caller; there is no prompt classification. Action arguments are canonical ASCII JSON limited to 65536 characters, depth 16 (root 0), and 1024 entries per container; nonempty identities are at most 256 characters and reject surrounding whitespace and ASCII control characters. Policy limits are strict integers in `1..2**53`; authorization is valid only for `issued_at <= now < expires_at`, excluding exact expiry. Exact expiry does not consume the ticket.

See [reproducibility](reproducibility.md) for checks and [security properties](security-properties.md) for actual test paths and methods.
