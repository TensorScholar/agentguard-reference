# Limitations

These limits apply to the standalone `agentguard-reference` 1.0.0 implementation. The package is a reference for a guarded callback boundary, not a production certification or a complete deployment security system.

## Local state only

Single-use consumption is protected by an in-memory lock for the same store in the same process. There is no persistence, crash recovery, cross-process coordination, or protection across independent stores. Authorization consumed before a callback is never released, even after a callback or audit failure. This is not exactly-once business execution or a retry protocol.

## Callback outcome is not business truth

`succeeded` requires the callback to return and outcome audit recording to succeed. It does not prove an external service completed an operation. A callback may perform an effect and then raise; outcome audit may fail after a returned callback. Both must be treated as `unknown`, not as evidence that no effect occurred. No provider reconciliation, rollback, or automatic retry is included.

## HMAC and audit trust

HMAC is shared-secret authentication. Every verifier with the key can forge authorizations or records. It does not provide non-repudiation, public verification, encryption, or independent proof of events.

The demo key is synthetic, public, illustrative, and in memory. It must never protect real operations. An external verification key and independently trusted expected head are required for meaningful file verification; an embedded key or untrusted head cannot establish authority or completeness. A SHA256 release manifest detects byte changes only relative to a trusted manifest; it does not authenticate a publisher.

## Trusted environment and callers

Host integrity, Python runtime integrity, key confidentiality, suitable nonce generation, and trustworthy time are assumptions. Principal labels are not authenticated identities. A lock does not isolate malicious code within the same process. A caller can bypass the guard by invoking an executor directly unless a separate integration prevents that route.

## Narrow policy and data model

The current policy is a refund demonstration covering the action allowlist, audience, integer amount ceiling, and caller-asserted `untrusted` flag; lifetime and configuration binding are rechecked at execution. Principal and provenance are asserted by the trusted caller, not authenticated by this package. There is no prompt classification. A malicious but policy-compliant proposal may be allowed; prompt injection is not solved as a class.

Actions use immutable bounded JSON. Floats, unsupported objects, and values beyond validation limits are rejected. Integer minor units avoid floating-point currency ambiguity but do not establish currency conversion, accounting correctness, or arbitrary resource safety. Bounds constrain accepted input, not every possible denial-of-service risk.

## No integrations or operational guarantees

No provider adapters, network mediation, secret manager, durable replay service, distributed coordinator, or external business-effect verification is included. No performance, scalability, availability, platform-coverage, or production-readiness claims are made here. Unfinished experiments and legacy harnesses are outside the release scope.

## Validation status

Documentation and synthetic output are not test evidence. [Security properties](security-properties.md) maps properties to actual test paths and method names; outcomes require a recorded run. No benchmark results or historical validation are implied.
