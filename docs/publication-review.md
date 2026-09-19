# Publication review

This review defines general inclusion decisions for the standalone `agentguard-reference` 1.0.1 package. It is not an assertion that cleanup, testing, or release review has completed. It contains no private implementation details.

## KEEP

- The small public `agentguard_reference` package and its `domain`, `engine`, `audit`, and `cli` responsibilities.
- Standard-library runtime code for Python >=3.11 and explicit public development dependencies.
- Immutable action binding, current-policy fingerprints, strict bounded JSON, and integer minor-unit amounts.
- Single-use same-store, same-process dispatch, serialized admission-time sampling, and explicit outcome semantics.
- Synthetic examples, public test fixtures, unittest/pytest suites, and reproducible verification commands.
- Architecture, threat model, limitations, evidence model, security-property mapping, security reporting guidance, and release integrity inventory.

## REFINE

- Describe security properties as bounded invariants with named assumptions, not broad guarantees.
- Maintain the [test map](security-properties.md) with actual paths, classes, and methods for unit, CLI, security-boundary, and adversarial assertions.
- Distinguish authorization, callback dispatch, callback return, audit recording, and external business effects.
- State fail-closed authorization and dispatch auditing, `unknown` outcome behavior, and irreversible consumption precisely.
- Label the demo's synthetic public in-memory HMAC key as illustrative; require external verification keys and trusted expected heads.
- Explain shared-secret forgery capability, lack of non-repudiation, and the limits of SHA256 manifests.
- Check API names, CLI options, accepted input bounds, file schemas, and commands against the public source.
- Report only observed test and packaging outcomes, with source and environment metadata. Expected behavior must remain labeled as expected.

## EXCLUDE

- Private dependencies, internal architecture details, credentials, secrets, customer data, and sensitive audit artifacts.
- Legacy harnesses, sibling-checkout workflows, unfinished experiments, placeholders, and unsupported integrations.
- Generated or historical artifacts presented as evidence of current behavior.
- Fabricated test results, benchmark numbers, validation levels, or release attestations.
- Provider integration claims, durable or distributed replay claims, credential issuance, and exactly-once business-effect guarantees.
- Claims of universal prompt-injection protection, non-repudiation from HMAC, or production certification.

## Publication gate

Inspect only public release contents, reconcile documentation with the final API and actual tests, and record real verification outcomes. Confirm that the final archive and SHA256 manifest contain only intended files. Inclusion decisions do not prove that excluded files have already been removed, and an artifact's existence does not prove that its tests passed.
