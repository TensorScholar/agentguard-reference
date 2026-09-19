# Architecture

This document describes the `agentguard-reference` 1.0.1 implementation. It is not a test report or production certification.

## Package boundary

The standalone import package is `agentguard_reference`, under `src/agentguard_reference`, with four responsibilities:

| Component | Responsibility |
|---|---|
| `domain` | Action snapshots, policy configuration, decisions, execution results, and input validation |
| `engine` | Authorization issuance, execution-time binding checks, and serialized single-use dispatch |
| `audit` | Authenticated record chaining and verification against an external key and expected head |
| `cli` | Synthetic demo and file verification |

Runtime code uses only the Python >=3.11 standard library. There are no provider integrations, credential brokers, private package dependencies, persistent replay services, distributed coordinators, or reconciliation workers.

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

`key` is bytes of length at least 32. `clock` and `nonce_factory` are caller-supplied callables. Controlled implementations support deterministic tests; trusted time and suitable nonce generation remain caller responsibilities outside synthetic tests. Identity strings (principal, name, audience, policy revision, authorization identifier) are nonempty, at most 256 characters, without surrounding whitespace or ASCII control characters.

`guard.authorize(action)` returns a `Decision` exposing `allowed`, `reason`, and `authorization`. Authorization is an admission ticket: it does not call the executor and does not consume single-use state.

`guard.execute(action, authorization, executor)` returns an `ExecutionResult` exposing `status`, `reason`, and `executor_called`. Consumers must check these fields rather than treating possession of an authorization as successful execution. The executor receives a fresh decoded arguments dictionary; its return value is ignored. Successful execution reports `executor.returned`; replay denial reports `authorization.replayed`.

## Immutable action and policy binding

`Action.create` takes an immutable JSON snapshot of the principal, action name, audience, and all arguments. Mutating a caller-owned nested object later must not mutate the authorized snapshot. A different value in any bound field, including principal, must not reuse the original authorization; that mismatch is reported as `authorization.action_mismatch`.

Arguments must be a JSON object serialized with sorted keys, compact separators, and ASCII escaping (`ensure_ascii=True`), with at most 65536 canonical characters. JSON values are strings, integers, booleans, null, lists, and string-keyed dictionaries; floats and unsupported objects are rejected. Maximum nesting depth is 16 with the root at depth 0; each list or dictionary has at most 1024 entries. `amount_minor` cannot be boolean. Constructor validation rejects these inputs; malformed or excessively nested JSON may raise parsing exceptions including `ValueError` or `RecursionError`. Bound incoming payloads before constructing actions; these limits are not a resource-isolation sandbox.

The current policy is a refund demonstration, not identity authentication. It is default-deny: it allows only when the action name is in the allowlist, the audience matches, `amount_minor` is a strict integer in `1..max_amount_minor`, and `untrusted` is boolean false (default false when absent). Principal and provenance are asserted by a trusted caller; arbitrary text is not classified and no prompt classification occurs. Both `max_amount_minor` and `ttl_seconds` are strict integers in `1..2**53`, defaulting to 10000 and 60. Other integer arguments have no separate policy numeric range.

Lifetime is bound to issuance: `expires_at = issued_at + ttl_seconds`, and execution requires `issued_at <= now < expires_at` with a duration no longer than the current policy TTL. Exactly at expiry, before issuance, or after expiry, dispatch is denied with `authorization.invalid_time` and the authorization is not consumed.

The policy fingerprint binds the current configuration: `allowed_actions`, `audience`, `max_amount_minor`, `ttl_seconds`, and `revision`. Execution checks the authorization against the action snapshot and the current policy, not merely the revision label.

## Guarded flow

```text
Structured proposal
  -> Validate and snapshot
  -> Evaluate policy and record authorization audit
  -> Return admission ticket (no executor, no consumption)
  -> Validate signature, action digest, current policy, and executor
  -> Atomically sample time and claim single-use authority
  -> Record dispatch audit
  -> Invoke callback
  -> Record outcome
  -> Return execution result
```

Authorization is not a reservation. The reservation boundary is `ReplayStore.claim`: the store lock is held while the clock is sampled and the identifier is either consumed or left unconsumed. Both the single-use claim and dispatch audit must succeed before callback invocation. Authorization audit failure must not issue usable authority. Dispatch audit failure must not call the executor. Once consumed, authorization is never released, including when dispatch auditing fails, the callback raises, the callback is interrupted by `BaseException`, or the outcome audit fails.

Expiry and other `claim` predicate failures do not consume the identifier. Replay of a consumed identifier reports `authorization.replayed`.

The injected audit and replay stores are trusted components. Audit adapters must raise an ordinary `Exception` on failure; silent data loss is not detected. The clock callable used during `claim` must not re-enter the same store (the lock is not reentrant). Process termination after admission may still lose an in-flight outcome record if the process is killed before the handler runs. `snapshot()` and `head` are individually locked, not an atomic pair; capture them after writers quiesce.

A lock makes the claim atomic only for callers using the same in-memory store in the same process. It is not a durable reservation and provides no guarantee across restarts, separate stores, or processes.

## Reason codes

| Code | Typical path |
|---|---|
| `policy.allowed` | Authorize succeeded |
| `policy.unknown_action` | Action name not in the allowlist |
| `policy.audience_mismatch` | Audience does not match policy |
| `policy.invalid_amount` | Missing, non-integer, non-positive, or over-ceiling amount |
| `policy.untrusted_input` | `untrusted` present and not boolean false |
| `policy.invalid_action` | Authorize received a non-`Action` or evaluation raised |
| `authorization.issuance_failed` | Clock, nonce, or signing failed after policy allow |
| `authorization.invalid_signature` | Missing, malformed, or wrong-key HMAC |
| `authorization.policy_changed` | Current fingerprint or revision does not match the ticket |
| `authorization.action_mismatch` | Current action digest does not match the ticket, including principal |
| `authorization.invalid_time` | Before issuance, at/after expiry, or duration longer than current TTL |
| `authorization.replayed` | Identifier already consumed in this store |
| `execution.invalid_input` | Non-`Action`/`Authorization`, or an unexpected execution exception |
| `execution.invalid_executor` | Executor is not callable; identifier is not consumed |
| `audit.unavailable` | Required audit append failed |
| `executor.returned` | Callback returned; success audit appended |
| `executor.raised` | Callback raised `Exception` after admission |
| `executor.interrupted` | Callback raised `BaseException` after admission; the exception is re-raised |

## Outcome semantics

| Status | Meaning |
|---|---|
| `denied` | Dispatch was refused; the executor was not called |
| `succeeded` | The callback returned and outcome auditing succeeded |
| `unknown` | Dispatch occurred but a callback exception or outcome audit failure prevents a confirmed guarded outcome |

`executor_called` distinguishes admission failure from attempted execution. A returned callback is not evidence that an external service completed a business operation. `unknown` is not permission to retry consumed authorization. This package has no reconciliation, retry, or provider-effect verification path.

## Audit trust

The audit chain authenticates records using HMAC. The chain head is advanced only after the record has been appended. The CLI verifier requires an external key file and a trusted expected head. It must not derive verification authority from an embedded key. The expected head anchors the intended chain endpoint; a valid prefix alone does not establish completeness.

HMAC is shared-secret authentication, not public-key signing: a verifier with the key can forge records. Neither an authenticated chain nor callback return proves external effects. The demo's public illustrative key offers no adversarial authenticity.

See [the evidence model](evidence-model.md).
