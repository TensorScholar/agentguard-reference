# Limitations

These limits apply to the standalone `agentguard-reference` 0.1.0 implementation. The package is a reference for a guarded callback boundary, not a production certification or a complete deployment security system.

## Non-goals

This package is none of the following, by design:

- **Not durable.** No persistence, no crash recovery, no retention policy.
- **Not cross-process.** Single-use state is an in-memory store in one process.
- **Not non-repudiable.** HMAC is shared-secret authentication; any key holder can forge.
- **Not an effect oracle.** A local `succeeded` never means a provider completed anything.
- **Not a credential broker.** No credential issuance, secret handling, or late secret resolution.
- **Not AgentGuard Core,** and not a newer version of it. See the Relationship to AgentGuard Core section below.
- Not an MCP mediation layer, not a distributed coordinator, and not a production service.

## The executor is trusted code

`executor` is a caller-supplied callable running with the full authority of the host process. The guard binds and records the arguments it dispatches; it does not constrain what the callable does with them, and it is not an operating-system enforcement boundary.

Argument binding is therefore a **record** property, not a containment property. What it guarantees is that the authorized and dispatched arguments cannot be altered after approval and that a mismatch is refused before dispatch. It does not guarantee that the callback performs the authorized action, performs only that action, or is reached through the guard at all. A caller that invokes its executor directly bypasses every guarantee in this document.

## Named hazards

Stated here with what fails, what holds, and why it is acceptable. Full detail is in [the threat model](threat-model.md).

| Hazard | What fails | What still holds |
|---|---|---|
| **H1 cross-store replay** | A ticket consumed in one store can be dispatched through a second `Guard` with its own store | Exactly-once within one store in one process |
| **H2 fork before consumption** | Parent and child can each dispatch the same ticket once | A fork taken after consumption is still refused |
| **H3 re-entrant clock** | The guard deadlocks permanently if the clock calls back into the store | Sampling under the lock, which is what makes the expiry boundary non-racy |
| **H4 unbounded growth** | `ReplayStore` and `AuditLog` grow for process lifetime; denied `authorize` traffic grows the log | Every individual operation stays correct and fail-closed |

## Local state only

Single-use consumption is protected by an in-memory lock for the same store in the same process. The clock used at reservation is sampled while that lock is held. There is no persistence, crash recovery, cross-process coordination, or protection across independent stores. Authorization consumed before a callback is never released, even after a callback, interruption, or audit failure. Expired tickets are not consumed. This is not exactly-once business execution or a retry protocol.

## Callback outcome is not business truth

`succeeded` requires the callback to return and outcome audit recording to succeed. It does not prove an external service completed an operation. A callback may perform an effect and then raise; a `BaseException` may interrupt after dispatch; outcome audit may fail after a returned callback. These must be treated as `unknown` (or as an interrupted dispatch with an `execution.unknown` record), not as evidence that no effect occurred. No provider reconciliation, rollback, or automatic retry is included.

## HMAC and audit trust

HMAC is shared-secret authentication. Every verifier with the key can forge authorizations or records. It does not provide non-repudiation, public verification, encryption, or independent proof of events.

The demo key is synthetic, public, illustrative, and in memory. It must never protect real operations. An external verification key and independently trusted expected head are required for meaningful file verification; an embedded key or untrusted head cannot establish authority or completeness. A SHA256 release manifest detects byte changes only relative to a trusted manifest; it does not authenticate a publisher.

## Trusted environment and callers

Host integrity, Python runtime integrity, key confidentiality, suitable nonce generation, and trustworthy time are assumptions. Principal labels are not authenticated identities. A lock does not isolate malicious code within the same process. A caller can bypass the guard by invoking an executor directly unless a separate integration prevents that route.

## Narrow policy and data model

The current policy is a refund demonstration covering the action allowlist, audience, integer amount ceiling, and a caller-asserted `untrusted` flag; lifetime and configuration binding are rechecked at execution. Principal and provenance are asserted by the trusted caller, not authenticated by this package. There is no prompt classification. A malicious but policy-compliant proposal may be allowed; prompt injection is not solved as a class.

The `untrusted` flag is **defeatable by omission**. It is a field inside the arguments the caller supplies, so a caller that never sets it is treated as trusted. Its only effect is to force a caller to state provenance explicitly rather than by default. It is a convention, not a control against a caller that wants to bypass it, and no documentation in this package should be read as claiming provenance enforcement.

Actions use immutable bounded JSON. Identity strings reject surrounding whitespace and ASCII control characters. Floats, unsupported objects, and values beyond validation limits are rejected. Integer minor units avoid floating-point currency ambiguity but do not establish currency conversion, accounting correctness, or arbitrary resource safety. Bounds constrain accepted input, not every possible denial-of-service risk; see H4 for the unbounded growth that remains.

## Relationship to AgentGuard Core

Core is a separate, private distribution. This package is a public reference for one boundary and is deliberately narrower. The following ideas belong to Core and are **absent here by design** — their absence is not an oversight and not a roadmap item for this package:

- **Decision-bound credential ceilings and late secret resolution.** Here the amount ceiling is a policy field evaluated twice; there is no credential authority and no late binding.
- **Durable evidence.** Here the audit chain is an in-memory list for the life of the process.
- **Reconcile-before-retry after `UNKNOWN`.** Here `unknown` is terminal and has no reconciliation path.
- **MCP mediation.** Here there is no transport, no protocol handling, and no credential broker.

## No integrations or operational guarantees

No provider adapters, network mediation, secret manager, credential issuance, durable replay service, distributed coordinator, or external business-effect verification is included. No performance, scalability, availability, platform-coverage, or production-readiness claims are made here. Unfinished experiments and legacy harnesses are outside the release scope.

## Validation status

Documentation and synthetic output are not test evidence. [Security properties](security-properties.md) maps properties to actual test paths and method names; outcomes require a recorded run. No benchmark results or historical validation are implied.
