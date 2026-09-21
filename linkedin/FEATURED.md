# Featured capsule — AgentGuard reference

**Pin:** `267e755` · **v1.0.1**

## One-line

Bind an authorized structured action to a single guarded callback dispatch. Authorize ≠ execute. Stdlib only.

## Proof moment

```bash
python -m pip install '.[dev]'
make verify
python -m agentguard_reference demo
```

## Invariant

Immutable action snapshot re-checked at execute. Single-use ticket in-process. Status: denied · succeeded · unknown.

## Non-claims

Not production certification. Not identity provider. HMAC verify capability implies forge capability—use external key + trusted head.
