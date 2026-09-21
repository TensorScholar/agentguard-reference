# Featured capsule — AgentGuard reference

**Pin:** `267e755` · **v1.0.1**

## One-line

Immutable action snapshot bound to a single guarded callback. Authorize ≠ execute. Stdlib only.

## Proof path

```bash
python -m pip install '.[dev]'
make verify
```

## Invariant

Execute re-binds the authorized snapshot. Single-use in-process. denied · succeeded · unknown.

## Non-claims

Not production certification. Not cross-process tickets. Not business-effect proof. Demo HMAC key is not evidence.
