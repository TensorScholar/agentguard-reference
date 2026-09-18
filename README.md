# AgentGuard Reference

`agentguard-reference` 1.0.0 is a standalone Python reference package for binding an authorized structured action to a single guarded callback dispatch. The import package is `agentguard_reference`; runtime requirements are Python >=3.11 and the standard library only. No private dependencies or provider integrations are included.

The `agentguard_reference` namespace avoids import collisions with other `agentguard` packages and keeps the reference independent. These documents describe the implementation, not a release attestation or production certification.

## Install and run

From the package root, use an isolated environment:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
python -m agentguard_reference demo
```

For development in that environment:

```sh
python -m pip install '.[dev]'
make verify PYTHON=.venv/bin/python
```

`make verify` runs `python -m pytest`, `ruff check`, `mypy src`, and the CLI demo. Development tools are not runtime dependencies. See [reproducibility](docs/reproducibility.md) for individual commands and release packaging.

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
- Single-use authorization is consumed before the callback and never released, including after failure. Locking protects only the same in-memory store in the same process.

The immutable JSON action snapshot binds the principal, action name, audience, and every argument. Canonical ASCII arguments are limited to 65536 characters, nesting depth 16 (root depth 0), and 1024 entries per container; identity strings are nonblank and at most 256 characters. Floats are disallowed; refund amounts use integer minor units. Policy limits are strict positive integers at most `2**53`. The current policy is a refund demonstration, not identity authentication: principal and provenance are asserted by a trusted caller, and there is no prompt classification. Authorization is valid only while `issued_at <= now < expires_at`; the exact expiry boundary denies dispatch. See [architecture](docs/architecture.md).

## Audit verification

The demo uses a synthetic, public, illustrative HMAC key in memory and emits JSON containing `records`, `head`, and `results`. Demo output is not trusted evidence.

For an independently produced audit file:

```sh
python -m agentguard_reference verify audit.json --key-file verification.key --expected-head HEX
```

Replace `HEX` with the expected head obtained through a trusted channel. Verification requires an external key file; it must never accept an embedded key as authority. HMAC is shared-secret authentication: anyone who can verify with the key can also forge records. A trusted expected head is needed to detect substitution or truncation to a valid earlier chain.

## Documentation

- [Architecture and API contract](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [Security properties and test mapping](docs/security-properties.md)
- [Limitations](docs/limitations.md)
- [Demo guide](docs/demo-guide.md)
- [Design decisions](docs/design-decisions.md)
- [Reproducibility and release](docs/reproducibility.md)
- [Publication review](docs/publication-review.md)
- [Examples](examples/README.md)
- [Security reporting](SECURITY.md)

Tests are in `tests/unit`, `tests/security`, and `tests/adversarial`, with unittest discovery and pytest support. The test map lists actual paths and methods separately from observed run results. `make release` runs verification and then `scripts/build_release.py`; release outputs are described in [reproducibility](docs/reproducibility.md).
