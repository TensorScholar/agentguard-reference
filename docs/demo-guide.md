# Demo guide

The standalone 0.1.0 CLI requires Python >=3.11, without provider credentials or integrations.

## Install

From the package root, use an isolated environment:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
python -m agentguard_reference
```

`python -m agentguard_reference demo` is equivalent; `--json` switches to machine output.

The distribution and CLI are named `agentguard-reference`; the distinct `agentguard_reference` import namespace avoids collisions with the separate AgentGuard Core distribution.

## Read the output

With no arguments the CLI runs the guided demo. It fixes time, uses fixed synthetic nonces, a public illustrative in-memory HMAC key, and callbacks that record their arguments. Repeated runs produce identical output. It does not issue a real refund or contact a provider.

The demo writes one key warning to stderr on every run, before any result:

> The HMAC key used by this demo is published in the package source. It is not a secret. Any verification result shown here is a self-check under that public key and is not evidence about anything.

### Scenarios shown

| # | Scenario | What it demonstrates |
|---|---|---|
| 1 | mutation | A changed argument after approval gives `denied`/`authorization.action_mismatch`; the callback is never invoked |
| 2 | expiry | At exactly `expires_at` the ticket gives `denied`/`authorization.invalid_time` with zero callback invocations, then succeeds once the clock is inside the window, proving the refusal did not consume it |
| 3 | replay | The consumed ticket gives `denied`/`authorization.replayed` on every later presentation, with one callback invocation in total |
| 4 | unknown | A callback that raises after dispatch gives `unknown`/`executor.raised` with `executor_called` true; replaying it is refused, so unknown is not a retry licence |
| 5 | tamper | An edited record and a wrong key are rejected; a valid prefix without a trusted expected head still verifies, and the same prefix against the trusted head does not |

All five run against one shared audit chain, so the emitted records are the actual evidence for the sequence narrated above.

### Narrative output

Each scenario prints its claim, what happened, and `-> property HELD` or `-> property NOT HELD`. The run ends with the audit chain's event sequence.

### `--json` output

| Field | Interpretation |
|---|---|
| `schema` | `agentguard-reference-demo-v2` |
| `package_version` | Import-package version string |
| `identity` | States that this is not AgentGuard Core and not a newer version of Core |
| `key` | States that the key is published in source and is not a secret |
| `scenarios` | Per scenario: `id`, `title`, `claim`, `lines`, `observed`, `property_held` |
| `all_properties_held` | True only when every scenario's expectation held |
| `audit.record_count`, `audit.head` | Chain length and endpoint |
| `audit.self_check_under_public_demo_key` | Internal consistency under the published key. Not evidence |
| `audit.records` | The full record chain |

There is deliberately no field named `verified`. The self-check is named for what it is.

The demo exits 0 only when every scenario property held and the self-check passed; otherwise it exits 1. This describes the code and the assertions in `tests/unit/test_cli.py`, not an independent release attestation.

`denied` means no callback dispatch. `succeeded` requires callback return and successful outcome auditing. `unknown` means dispatch occurred but the guarded outcome could not be confirmed; it must not trigger reuse of consumed authorization.

## Verify an audit file

In the activated environment, for separately provisioned inputs:

```sh
python -m agentguard_reference verify audit.json --key-file verification.key --expected-head HEX
```

The paths are examples, not supplied fixtures. The audit input is UTF-8 JSON: either a record array or an object whose `records` value is that array. The key file supplies raw bytes, not decoded hex or base64; it needs at least 32 bytes. The file-size checks accept audit files up to 10485760 bytes (10 MiB) and key files up to 4096 bytes, inclusive, based on `stat()` before reads. These checks are not race-free streaming limits.

Replace `HEX` with a trusted, independently obtained 64-character lowercase hexadecimal head. The CLI ignores embedded keys and document head metadata as authority; only the external key and `--expected-head` control verification. A key-holding verifier can forge HMAC records, and a head copied only from untrusted input does not establish completeness.

## Failure behavior and exit status

- The guided demo exits 0 when all five demonstrated properties held and the self-check passed; otherwise 1.
- Successful verification prints `{"verified": true}` and exits 0.
- A wrong key/head, tampered record, or missing record field prints `{"verified": false}` and exits 1.
- Malformed JSON, missing/non-array `records`, unreadable files, or excessive reported size prints `verification failed: invalid or unreadable input` to stderr and exits 1.
- Missing `--key-file` or `--expected-head` is an argparse error with exit status 2, before file reads.
- `verify --help` is the only path that still exits 2 by design; the demo no longer requires a subcommand.

The policy is a refund demonstration, not identity authentication. Principal and provenance are asserted by the trusted caller; there is no prompt classification. Action arguments are canonical ASCII JSON limited to 65536 characters, depth 16 (root 0), and 1024 entries per container; nonempty identities are at most 256 characters and reject surrounding whitespace and ASCII control characters. Policy limits are strict integers in `1..2**53`; authorization is valid only for `issued_at <= now < expires_at`, excluding exact expiry. Exact expiry does not consume the ticket.

See [reproducibility](reproducibility.md) for checks and [security properties](security-properties.md) for actual test paths and methods.
