# Threat model

This threat model describes the standalone 1.0.0 reference package. Controls below map to the current tests, not reported test results.

## Assets and boundary

The protected assets are the integrity of a structured authorization, the single guarded callback dispatch it permits, and the authenticated audit sequence. Untrusted proposals enter through `Action.create`; enforcement occurs in `Guard.authorize` and `Guard.execute`.

The trusted caller supplies principal and provenance assertions, policy, key, clock, nonce factory, and executor. The current policy is a refund demonstration, not identity authentication. It rejects `untrusted` unless absent or boolean false; it does not infer provenance from text and performs no prompt classification. If an untrusted caller can freely assert a trusted principal or omit provenance, this package does not authenticate or correct that assertion.

## In-scope attempts and controls

| Attempt | Control | Boundary |
|---|---|---|
| Change principal, name, audience, or arguments after approval | Immutable JSON snapshot and authorization binding of every field | Only guarded execution is checked |
| Change policy while retaining the revision label | Fingerprint of current policy configuration | Policy source remains trusted |
| Request a disallowed action, wrong audience, or excessive refund | Explicit policy denial | Policy expresses only the supplied constraints |
| Present expired or tampered authorization | Lifetime and HMAC validation before dispatch | Trusted key and clock required |
| Replay authorization, including concurrent reuse | Atomic consume before callback; never release | Same store, same process only |
| Use malformed, floating-point, oversized, or deeply nested inputs | Strict bounded input validation | Not a general host-level denial-of-service defense |
| Proceed when authorization or dispatch auditing fails | Fail closed before callback | No claim of durable audit storage |
| Treat callback exception or outcome audit failure as success | Return `unknown` after dispatch | No automatic retry or effect reconciliation |
| Modify, reorder, or truncate audit records | Chain verification against external key and trusted expected head | Shared-secret holders can forge; an untrusted head is not an anchor |
| Supply an embedded verification key | Require an external key file | Verifier must protect its independent trust inputs |

## Trusted assumptions

- The Python process, runtime, host, and implementation have not been compromised.
- Policy and principal labels are supplied by an appropriate trusted caller.
- Non-demo HMAC keys remain secret and have suitable entropy; the verifier's key and expected head are authentic.
- The clock and nonce factory satisfy their intended roles.
- The caller routes protected operations through the guard and does not expose a parallel unguarded executor route.
- The executor is responsible for interpreting the dispatched action; callback return is only a local observation.

## Outside the boundary

No protection is claimed against compromised hosts, malicious key holders, direct provider calls, malicious executors, restart replay, cross-process replay, or independent in-memory stores. There are no provider adapters, external identity integrations, persistent coordination, or business-effect reconciliation.

Prompt injection is not solved as a class. A malicious proposal that satisfies the configured policy can still be allowed; policy compliance is not proof that the proposal matches a person's intent.

See [limitations](limitations.md) and [the test map](security-properties.md). This reference is not a production certification.
