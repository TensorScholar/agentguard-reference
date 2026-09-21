# Claims summary — agentguard-reference @267e755 (v1.0.1)

Supported:

- Authorize returns a decision; execute re-binds the immutable snapshot before callback.
- Single-use ticket claim under in-process store lock; lifetime failure does not consume.
- Auth/dispatch audit failures fail closed; post-dispatch outcome audit failure → unknown.
- Stdlib-only runtime; `make verify` runs pytest, ruff, mypy, demo.

Not claimed:

- Production certification or release attestation
- Distributed multi-node ticket authority
- Identity authentication or prompt classification
- External business-effect proof on status=succeeded
- Trust in demo/synthetic HMAC keys
