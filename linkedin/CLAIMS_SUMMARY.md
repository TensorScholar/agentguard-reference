# Claims summary — agentguard-reference 0.1.0

Claims map to the property-to-test table in `docs/security-properties.md`. This
file is not AgentGuard Core and does not describe a release of it.

Supported:

- Snapshot equality at execute; mutation denies without calling executor
- Single-use in-process claim; lifetime failure does not consume
- Auth/dispatch audit fail-closed; post-dispatch outcome audit fail → unknown
- `make verify`: pytest · ruff · mypy · demo

Not claimed:

- Production certification
- Cross-process / persistent tickets
- External business-effect proof on succeeded
- Identity authentication
- Trust in demo HMAC keys
