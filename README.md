# AgentGuard Reference

> **This is a reference implementation. It is not AgentGuard Core, and it is not a
> newer version of Core.** Core is a separate, private distribution. Package `0.1.0`
> names this reference artifact only. Nothing here is production software, a
> certification, or a release attestation, and it is not a credential broker, an MCP
> mediation layer, or a durable execution service.

`agentguard-reference` 0.1.0 is a standalone Python reference package for binding an
authorized structured action to a single guarded callback dispatch. The import package
is `agentguard_reference`; runtime requirements are Python >=3.11 and the standard
library only. No private dependencies or provider integrations are included. The
namespace differs from the Core distribution to avoid an import collision.

## Install and run

From the package root, use an isolated environment:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
python -m agentguard_reference
```

With no arguments the CLI runs a guided demo that executes and narrates five
properties — mutation blocked, exact expiry denied without consuming the ticket,
replay blocked, `unknown` after dispatch, and audit tampering detected. Add `--json`
for the raw machine-readable document. Every field is deterministic and synthetic; no
refund is issued and no provider is contacted. The demo's HMAC key is published in
this source file, so its own verification result is a self-check, not evidence.

For development in that environment:

```sh
python -m pip install '.[dev]'
make verify PYTHON=.venv/bin/python
```

`make verify` runs `python -m pytest`, `ruff check`, `mypy src`, and the CLI demo. Development tools are not runtime dependencies. `make release` builds the public archive after verification and then validates the artifact it produced; a missing, stale, or non-publishable archive fails that step. See [reproducibility](docs/reproducibility.md) for individual commands and release packaging.

The source distribution ships `docs/`, `tests/`, and `examples/`, so it can be reviewed
and executed without cloning: unpack it, `python -m pip install '.[dev]'`, `make verify`.

## Public API

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
guard.authorize(action)
guard.execute(action, authorization, executor)
```

This is a signature sketch, not a complete executable example. `key` must be bytes of at least 32 bytes; `clock` and `nonce_factory` must be callables.

- `authorize` returns a `Decision` with `allowed`, `reason`, and `authorization`. Authorization is not execution.
- `execute` returns an `ExecutionResult` with `status`, `reason`, and `executor_called`. Status is `denied`, `succeeded`, or `unknown`.
- `succeeded` requires the callback to have returned and outcome audit recording to have succeeded; it does not prove an external business effect.
- Authorization and dispatch audit failures fail closed. Outcome audit failure after dispatch produces `unknown`.
- Single-use authorization is claimed under the in-memory store lock, with the clock sampled inside that claim. Failure of the lifetime predicate does not consume the ticket. Locking protects only the same in-memory store in the same process.

#### Snapshot limits

The action snapshot binds the principal, action name, audience, and every argument into immutable canonical ASCII JSON. Arguments are capped at 65536 characters, nesting at depth 16 with the root at depth 0, and containers at 1024 entries. Identity strings are nonempty, at most 256 characters, and reject surrounding whitespace and ASCII control characters. Floats are disallowed and refund amounts use integer minor units. These bounds constrain accepted input; they are not a resource-isolation sandbox.

#### Policy scope

The bundled policy is a refund demonstration, not identity authentication. It is default-deny over a name allowlist, an audience, and an integer amount ceiling bounded at `2**53`. Principal and provenance are asserted by a trusted caller; there is no prompt classification, and a policy-compliant malicious proposal can still be allowed. The `untrusted` flag is a caller assertion inside the caller's own arguments and is defeated by omitting it.

#### Lifetime semantics

Authorization is valid only while `issued_at <= now < expires_at`, with `expires_at` bound to issuance time. Exactly at the boundary, dispatch is denied **without consuming the ticket**, so an expired ticket still works if it is presented inside a valid window.

See [architecture](docs/architecture.md) for the full contract and [limitations](docs/limitations.md) for what is not guaranteed.

## Audit verification

The demo uses a synthetic, public, illustrative HMAC key in memory. Its JSON reports each scenario's observations and, for the audit chain, `records`, `head`, and `self_check_under_public_demo_key`. That field is a self-check under a published key and is not trusted evidence; there is deliberately no field named `verified`.

For an independently produced audit file:

```sh
python -m agentguard_reference verify audit.json --key-file verification.key --expected-head HEX
```

Replace `HEX` with the expected head obtained through a trusted channel. Verification requires an external key file; it must never accept an embedded key as authority. HMAC is shared-secret authentication: anyone who can verify with the key can also forge records. A trusted expected head is needed to detect substitution or truncation to a valid earlier chain.

## Documentation

- [Architecture and API contract](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [Security properties and test mapping](docs/security-properties.md)
- [Evidence model](docs/evidence-model.md)
- [Limitations](docs/limitations.md)
- [Demo guide](docs/demo-guide.md)
- [Design decisions](docs/design-decisions.md)
- [Reproducibility and release](docs/reproducibility.md)
- [Examples](examples/README.md)
- [Security reporting](SECURITY.md)

Tests are in `tests/unit`, `tests/security`, and `tests/adversarial`, with unittest discovery and pytest support. The test map lists actual paths and methods separately from observed run results. `make release` runs verification, then builds the public archive, then validates the produced artifact; a missing, stale, or non-publishable archive fails that final step rather than being skipped. Release outputs are described in [reproducibility](docs/reproducibility.md).
