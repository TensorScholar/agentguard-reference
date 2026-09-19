# Changelog

## 1.0.1

This entry describes the standalone implementation and release workflow, not test results or a packaging attestation.

- Serialized single-use `ReplayStore.claim`: the clock is sampled while the store lock is held. Lifetime predicate failure does not consume the authorization identifier.
- Identity strings reject surrounding whitespace and ASCII control characters.
- Audit chain head advances only after the record is appended.
- Callback `BaseException` after admission appends `execution.unknown` with `executor.interrupted` and re-raises.
- Evidence model document; authorization treated as an admission ticket distinct from reservation and from callback return.
- Tests for non-consuming expiry, policy revision change, admission clock sampling, invalid guard configuration, and interruption.

## 1.0.0

This entry describes the standalone implementation and release workflow, not test results or a packaging attestation.

- Distribution: `agentguard-reference`; import package: `agentguard_reference`.
- Python >=3.11, standard-library runtime, no private dependencies.
- Source boundaries: `domain`, `engine`, `audit`, and `cli` under `src/agentguard_reference`.
- Immutable bounded JSON actions, explicit policy configuration, HMAC-bound authorization, and same-process single-use execution.
- Explicit `denied`, `succeeded`, and `unknown` execution outcomes with fail-closed authorization and dispatch auditing.
- Synthetic JSON demo and audit verification using an external key and trusted expected head.
- Unit, CLI, security, and adversarial tests with actual path/method mapping; `make verify` runs pytest, Ruff, mypy, and the demo.
- `make release` runs verification, then `scripts/build_release.py`; its output contract is `release/agentguard-reference-final.zip`, `release/agentguard-reference-final.zip.sha256`, and `release/manifest.sha256`, with `MANIFEST.sha256` inside the ZIP. See [reproducibility](docs/reproducibility.md) for prerequisites and validation.
- Documentation replaces legacy harness instructions with the standalone package contract; provider integrations and unfinished experiments are excluded from release scope.

No historical validation results, generated evidence claims, or production certification are carried forward. Test outcomes and release artifacts must be established by an actual run.
