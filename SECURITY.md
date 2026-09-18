# Security

AgentGuard Reference 1.0.0 is a bounded, standalone reference implementation, not a production-certified security system. Its implementation contract and assumptions are in [the threat model](docs/threat-model.md), [security properties](docs/security-properties.md), and [limitations](docs/limitations.md).

## Reporting

Report suspected vulnerabilities privately to the repository maintainers through an available private reporting channel. If none is advertised, request a private contact without publishing sensitive details. Include the package version, a minimal synthetic reproducer, expected versus observed behavior, and relevant sanitized logs. Do not include real keys, credentials, customer data, or sensitive audit records. No response-time or support-window commitment is made here.

## Key and audit boundaries

- Supply `Guard` a bytes key of at least 32 bytes. Length validation alone does not establish entropy or secrecy.
- The CLI demo key is synthetic, public, illustrative, and held in memory. Never use it to protect real actions or authenticate trusted evidence.
- `agentguard-reference verify FILE --key-file FILE --expected-head HEX` requires an external key. A key embedded in the untrusted audit input must never be used as verification authority.
- Obtain the expected head independently through a trusted channel, not solely from the file being verified.
- HMAC uses a shared secret. Every verifier holding that secret can forge authorizations or audit records; verification is not a digital signature or non-repudiation proof.
- Audit authentication does not encrypt record contents or establish external business truth.

## Execution boundaries

Authorization and dispatch audit failures must prevent callback dispatch. Callback exceptions or outcome audit failure after dispatch must not be reported as success: the outcome is `unknown`. Consumed authorization is never released for retry.

Single-use locking covers only the same in-memory store within the same process. Restarts, independent stores, multiple processes, direct callback invocation, compromised hosts, and malicious executors are outside that guarantee. Invalid inputs, floats, and values exceeding bounded JSON limits must be rejected.

Actual test paths and methods are listed in the security-property map; their presence is not an assertion that a particular run passed. The current policy is a refund demonstration, not identity authentication: principal and provenance are asserted by the trusted caller, with no prompt classification.
