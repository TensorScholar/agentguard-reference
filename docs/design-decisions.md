# Design decisions

These decisions describe the standalone 1.0.0 implementation, not additional architecture or validation results. The `agentguard_reference` namespace avoids collisions with other `agentguard` imports; an isolated `.venv` keeps dependencies separate without relying on another checkout.

## A small standalone package

`agentguard-reference` exposes `agentguard_reference` with `domain`, `engine`, `audit`, and `cli` responsibilities. Python >=3.11 and a standard-library runtime keep inspection independent of private packages. Development dependencies are separate. Provider integrations and experimental harnesses are not part of this package.

## Structured authority, not model judgment

An agent supplies a proposal. The current `Policy` is a refund demonstration, not identity authentication. Principal and provenance are asserted by a trusted caller. The `untrusted` flag is checked structurally; there is no prompt classification or inference of provenance from text. Natural-language approval is not execution authority, and policy compliance does not establish genuine human intent.

## Snapshot all action fields

`Action.create(principal=..., name=..., audience=..., arguments=...)` captures immutable JSON. Principal, name, audience, and all arguments are bound together so that an authorization cannot be transferred to a different structured action. Caller-owned nested mutations must not affect the snapshot.

Bounded JSON and explicit validation avoid silent coercion. Floats are disallowed; refund values use integer minor units. Invalid values are rejected rather than normalized into new authority. Canonical ASCII arguments are capped at 65536 characters, nesting at depth 16 (root 0), containers at 1024 entries, and nonblank identity strings at 256 characters. Policy numeric limits are strict integers in `1..2**53`.

## Bind current policy, not just a label

The policy fingerprint covers the current configuration, including the allowlist, audience, amount ceiling, lifetime, and revision. Keeping the same revision string must not preserve authority after a material configuration change.

## Separate authorization from dispatch

`authorize` returns `Decision(allowed, reason, authorization)` conceptually; `execute` returns `ExecutionResult(status, reason, executor_called)`. These field summaries do not specify positional constructors. Issuing authorization does not call the executor, and possession of authorization is not a success result.

The execution path rechecks bindings and lifetime, then consumes single-use authority before calling the callback. Consumption is never undone. This favors preventing repeated dispatch through the same store over transparent retries after uncertain outcomes.

## Explicitly local replay state

The in-memory lock protects only the same store in the same process. It is intentionally not described as crash-safe, persistent, distributed, or exactly-once execution. A new process or independent store is outside this guarantee.

## Audit gates admission, not external truth

Authorization audit failure prevents usable authority. Dispatch audit failure prevents callback invocation. After dispatch, callback exception or outcome audit failure returns `unknown`, not a fabricated success or a claim that nothing happened.

`succeeded` requires a returned callback and successful outcome audit. It does not certify a provider-side effect. There is no automatic retry, rollback, or reconciliation contract.

## HMAC with explicit trust inputs

HMAC uses the standard library but gives every key-holding verifier forging capability. It is shared-secret authentication, not a public signature or non-repudiation mechanism.

The verifier takes an external key and a trusted expected head. Accepting a key embedded in an audit artifact would let that artifact choose its own authority. Accepting its head as the sole anchor would not establish completeness. The synthetic demo's public in-memory key is illustrative only.

## Claims follow tests, not examples

The [security-property map](security-properties.md) lists actual test paths and methods. A demo is not a test report, and neither documentation nor generated output alone establishes security. Publication excludes historical validation claims and production certification.
