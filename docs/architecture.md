# Architecture

This document describes the `agentguard-reference` 1.0.0 implementation. It is not a test report or production certification.

## Package boundary

The standalone import package is `agentguard_reference`, under `src/agentguard_reference`, with four responsibilities:

| Component | Responsibility |
|---|---|
| `domain` | Action snapshots, policy configuration, decisions, execution results, and input validation |
| `engine` | Authorization, execution-time binding checks, expiry checks, and single-use dispatch |
| `audit` | Authenticated record chaining and verification against an external key and expected head |
| `cli` | Synthetic demo and file verification |

Runtime code uses only the Python >=3.11 standard library. There are no provider integrations, credential brokers, private package dependencies, persistent replay services, or distributed coordination components.

## Public interface

```python
Action.create(principal=principal, name=name, audience=audience, arguments=arguments)
Policy(
    allowed_actions=('refund.create',),
    audience='refund-demo',
    max_amount_minor=10000,
    ttl_seconds=60,
    revision='reference-v1',
)
Guard(policy=policy, key=key, clock=clock, nonce_factory=nonce_factory)
```

`key` is bytes of length at least 32. `clock` and `nonce_factory` are caller-supplied callables. Controlled implementations support deterministic tests; trusted time and suitable nonce generation remain caller responsibilities outside synthetic tests.

`guard.authorize(action)` returns a `Decision` exposing `allowed`, `reason`, and `authorization`. Only an allowed decision supplies authority for guarded execution.

`guard.execute(action, authorization, executor)` returns an `ExecutionResult` exposing `status`, `reason`, and `executor_called`. Authorization does not call the executor. Consumers must check these fields rather than treating possession of an authorization as successful execution. The executor receives a fresh decoded arguments dictionary; its return value is ignored. Successful execution reports `executor.returned`; replay denial reports `authorization.replayed`.

## Immutable action and policy binding

`Action.create` takes an immutable JSON snapshot of the principal, action name, audience, and all arguments. Mutating a caller-owned nested object later must not mutate the authorized snapshot. A different value in any bound field must not reuse the original authorization.

Arguments must be a JSON object serialized with sorted keys, compact separators, and ASCII escaping (`ensure_ascii=True`), with at most 65536 canonical characters. JSON values are strings, integers, booleans, null, lists, and string-keyed dictionaries; floats and unsupported objects are rejected. Maximum nesting depth is 16 with the root at depth 0; each list or dictionary has at most 1024 entries. Principal, name, audience, policy revision, and authorization identifier are nonblank strings of at most 256 characters. `amount_minor` cannot be boolean. Constructor validation rejects these inputs; malformed or excessively nested JSON may raise parsing exceptions including `ValueError` or `RecursionError`. Bound incoming payloads before constructing actions; these limits are not a resource-isolation sandbox.

The current policy is a refund demonstration, not identity authentication. It checks action allowlist, audience, a strict integer amount in `1..max_amount_minor`, and `untrusted` being boolean false (default false when absent). Principal and provenance are asserted by a trusted caller; arbitrary text is not classified and no prompt classification occurs. Both `max_amount_minor` and `ttl_seconds` are strict integers in `1..2**53`, defaulting to 10000 and 60. Other integer arguments have no separate policy numeric range.

Lifetime is bound to issuance: `expires_at = issued_at + ttl_seconds`, and execution requires `issued_at <= now < expires_at`. Exactly at expiry, before issuance, or after expiry, dispatch is denied with `authorization.invalid_time`.

The policy fingerprint binds the current configuration: `allowed_actions`, `audience`, `max_amount_minor`, `ttl_seconds`, and `revision`. Execution checks the authorization against the action snapshot and the current policy, not merely the revision label.

## Guarded flow

```text
Structured proposal
  -> Validate and snapshot
  -> Evaluate policy and record authorization audit
  -> Return decision
  -> Validate authorization, action, current policy, and lifetime
  -> Atomically claim single-use authority and record dispatch audit
  -> Invoke callback
  -> Record outcome
  -> Return execution result
```

Both the single-use claim and dispatch audit must succeed before callback invocation. Authorization audit failure must not issue usable authority. Dispatch audit failure must not call the executor. Once consumed, authorization is never released, including when dispatch auditing fails or the callback does not return normally.

The injected audit and replay stores are trusted components. Audit adapters must raise an ordinary `Exception` on failure; silent data loss is not detected. Process termination and `BaseException` interruptions may leave admission without an outcome record. `snapshot()` and `head` are individually locked, not an atomic pair; capture them after writers quiesce.

A lock makes the claim atomic only for callers using the same in-memory store in the same process. It is not a durable reservation and provides no guarantee across restarts, separate stores, or processes.

## Outcome semantics

| Status | Meaning |
|---|---|
| `denied` | Dispatch was refused; the executor was not called |
| `succeeded` | The callback returned and outcome auditing succeeded |
| `unknown` | Dispatch occurred but a callback exception or outcome audit failure prevents a confirmed guarded outcome |

`executor_called` distinguishes admission failure from attempted execution. A returned callback is not evidence that an external service completed a business operation. `unknown` is not permission to retry consumed authorization.

## Audit trust

The audit chain authenticates records using HMAC. The CLI verifier requires an external key file and a trusted expected head. It must not derive verification authority from an embedded key. The expected head anchors the intended chain endpoint; a valid prefix alone does not establish completeness.

HMAC is shared-secret authentication, not public-key signing: a verifier with the key can forge records. Neither an authenticated chain nor callback return proves external effects. The demo's public illustrative key offers no adversarial authenticity.
