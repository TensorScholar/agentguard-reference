# Examples

From the package root with Python >=3.11, run the synthetic CLI demo in an isolated environment:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
python -m agentguard_reference demo
```

The demo uses an in-memory callback and a public illustrative HMAC key. JSON contains `records`, `head`, and `results`; it is not trusted evidence or a real refund. No provider credentials or framework adapters are needed or included.

The API uses keyword-only `Action.create(principal=..., name=..., audience=..., arguments=...)` and `Guard(policy=..., key=..., clock=..., nonce_factory=...)`. `authorize` returns a decision; `execute` passes a fresh arguments dictionary to the callback and returns status, reason, and whether the executor was called. See the [API contract](../docs/architecture.md).

The policy is a refund demonstration, not identity authentication. Principal and provenance are asserted by a trusted caller, with no prompt classification. Only callback return plus successful outcome audit permits `succeeded`; callback failure or outcome audit failure produces `unknown`. Consumed authorization is never released, and replay protection covers only the same in-memory store in one process.

In the activated environment, verify separately supplied inputs with `python -m agentguard_reference verify FILE --key-file KEY_FILE --expected-head HEX`. Use raw external key bytes and an independently trusted expected head, never embedded key material. HMAC key holders can forge records.

See the [demo guide](../docs/demo-guide.md) and [reproducibility instructions](../docs/reproducibility.md).
