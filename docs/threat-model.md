# Threat model

This threat model describes the standalone 0.1.0 reference package. Controls below map to the current tests, not reported test results.

## Assets and boundary

The protected assets are the integrity of a structured authorization, the single guarded callback dispatch it permits, and the authenticated audit sequence. Untrusted proposals enter through `Action.create`; enforcement occurs in `Guard.authorize` and `Guard.execute`.

## The first assumption: the executor is trusted process code

Read this before any other row in this document, because every other guarantee rests on it.

`executor` is a caller-supplied Python callable running with the full authority of the host process. `Guard` binds the *arguments* it hands to that callable and records what was dispatched. It does **not** constrain what the callable does with them, and it is not an operating-system enforcement boundary. Nothing in this package stops an executor from ignoring its arguments, dispatching a different action, calling a provider directly, or simply never being called through the guard at all.

What argument binding actually buys is narrower and still worth having: the *record* of what was authorized and dispatched cannot be altered after approval, and a mismatch is refused before dispatch. It is an integrity property over a structured value, not containment of the code that receives it. Any statement in these documents that sounds like the guard constrains the executor should be read as a statement about the recorded intent only.

## Caller-asserted provenance

The trusted caller supplies principal and provenance assertions, policy, key, clock, nonce factory, and executor. The current policy is a refund demonstration, not identity authentication. It rejects `untrusted` unless absent or boolean false; it does not infer provenance from text and performs no prompt classification.

The `untrusted` field lives inside the arguments the caller supplies, so it is an assertion the caller makes about itself. **It is defeatable by omission:** a caller that never sets the field is treated as trusted. It is a structural convention that forces provenance to be stated explicitly, not a control against a caller who wants to bypass it. See [limitations](limitations.md) for the full statement.

## In-scope attempts and controls

| Attempt | Control | Boundary |
|---|---|---|
| Change principal, name, audience, or arguments after approval | Immutable JSON snapshot and authorization binding of every field | Only guarded execution is checked |
| Change policy while retaining the revision label | Fingerprint of current policy configuration | Policy source remains trusted |
| Request a disallowed action, wrong audience, or excessive refund | Explicit policy denial | Policy expresses only the supplied constraints |
| Present expired or tampered authorization | Lifetime and HMAC validation before dispatch | Trusted key and clock required |
| Replay authorization, including concurrent reuse | Atomic `claim` before callback; clock sampled while the store lock is held; never release | Same store, same process only |
| Use an expired ticket at the reservation boundary | Lifetime predicate evaluated inside `claim`; failure does not consume the identifier | Trusted clock required |
| Use malformed, floating-point, oversized, or deeply nested inputs | Strict bounded input validation | Not a general host-level denial-of-service defense |
| Proceed when authorization or dispatch auditing fails | Fail closed before callback | No claim of durable audit storage |
| Treat callback exception or outcome audit failure as success | Return `unknown` after dispatch | No automatic retry or effect reconciliation |
| Modify, reorder, or truncate audit records | Chain verification against external key and trusted expected head | Shared-secret holders can forge; an untrusted head is not an anchor |
| Supply an embedded verification key | Require an external key file | Verifier must protect its independent trust inputs |

## Named hazards

These are properties of this implementation, stated as hazards rather than as soft caveats. Each says what fails, what still holds, and why it is acceptable for a single-process reference. They are properties of the code, not configuration mistakes.

### H1 — Cross-store and fresh-`Guard` replay

A consumed identifier is remembered only in the `ReplayStore` instance that consumed it. A ticket consumed through one guard can be dispatched again through a second `Guard` built with the same key and policy but its own store, because the new store has never seen the identifier.

- **What fails:** single-use semantics do not cross a store boundary. A second dispatch of the same ticket succeeds.
- **What still holds:** within one store, in one process, the ticket is spent exactly once, including under concurrency.
- **Why acceptable:** the guarantee was never about the ticket; it is about the store. A reference that claimed cross-store single-use would need durable shared state, which is out of scope by design.

### H2 — `fork()` before consumption can double-dispatch

Process creation copies memory. If a process forks after authorization but before the ticket is consumed, parent and child hold identical pre-consumption state. Each can then claim the identifier once, and both can dispatch it.

- **What fails:** single-use semantics across the fork boundary. One ticket can produce two dispatches.
- **What still holds:** a fork taken *after* consumption inherits the consumed set, so the child is still refused. The hazard is specifically fork-before-consumption.
- **Why acceptable:** the same root cause as H1 — an independent copy of the store is an independent store. Forks are not a supported deployment shape for this reference.

### H3 — Re-entrant clock deadlock under the store lock

The clock callable is invoked while the `ReplayStore` lock is held, by design, so the lifetime predicate and the claim are serialized. `threading.Lock` is not reentrant. A clock implementation that calls back into the same store — for example to probe or reset it — deadlocks permanently, and the thread does not recover.

- **What fails:** the guard hangs. There is no timeout and no recovery path.
- **What still holds:** nothing else changes; the store is not left in a partially updated state, because the deadlock occurs before the identifier is added.
- **Why acceptable:** sampling the clock under the lock is the correct behaviour and is what makes the expiry boundary non-racy. The requirement is simply that the injected clock does not re-enter the store.

### H4 — Unbounded `ReplayStore` and `AuditLog` growth

Neither store evicts. `ReplayStore._consumed` grows by one entry per successful dispatch, and `AuditLog._records` grows by one entry per audit event, for the lifetime of the process. Both are driven by caller traffic: **denied authorizations grow the audit log too**, so an unauthenticated caller who can reach `authorize` can force unbounded record growth without ever obtaining a ticket.

- **What fails:** memory grows without bound over a long-lived process. There is no cap, no rotation, no flush, and no persistence.
- **What still holds:** every individual operation is still correct and fail-closed. Growth is an availability and resource concern, not an integrity one.
- **Why acceptable:** a reference must not imply a durable audit service. A deployment that needs bounded retention needs storage this package deliberately does not provide.

## Trusted assumptions

- The Python process, runtime, host, and implementation have not been compromised.
- The executor is trusted code whose behaviour the guard does not constrain. See the first section.
- Policy and principal labels are supplied by an appropriate trusted caller, and provenance assertions in arguments are believed rather than verified.
- Non-demo HMAC keys remain secret and have suitable entropy; the verifier's key and expected head are authentic.
- The clock and nonce factory satisfy their intended roles, and the clock does not re-enter the store it is sampled under (H3).
- The caller routes protected operations through the guard and does not expose a parallel unguarded executor route.
- The process is short-lived or its caller accounts for unbounded store growth (H4).

## Outside the boundary

No protection is claimed against compromised hosts, malicious key holders, direct provider calls, malicious executors, restart replay, cross-process replay, cross-store replay (H1), fork-before-consumption double dispatch (H2), a re-entrant clock (H3), or unbounded growth under sustained traffic (H4). There are no provider adapters, external identity integrations, persistent coordination, credential issuance, or business-effect reconciliation.

Prompt injection is not solved as a class. A malicious proposal that satisfies the configured policy can still be allowed; policy compliance is not proof that the proposal matches a person's intent.

See [limitations](limitations.md) and [the test map](security-properties.md). This reference is not a production certification.
