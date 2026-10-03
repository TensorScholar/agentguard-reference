# Changelog

## 0.1.0

This is the first externally visible identity for this package. It is an honesty
correction, not a feature release: the implementation, tests, and documented
semantics are unchanged from the pre-release tree.

### Withdrawn pre-release numbering

Earlier internal trees carried the number `1.0.1`, and one carried `1.0.0`. Both
numbers are **withdrawn**. They were never published to an external package index
and must not be read as a release history for this artifact. `1.0.1` was an
internal mis-numbering: it sat above the maturity of the artifact it named and
would have been read as "newer than AgentGuard Core", which this package is not.
The corrected identity is `0.1.0`, matching this package's actual state: an
in-memory, single-process, stdlib-only reference with no persistence, no
cross-process coordination, and no reconciliation path.

No tag, archive filename, distribution metadata, or document heading carries the
withdrawn numbers. A test asserts that no published archive member contains them
outside the withdrawal record above.

### Release integrity corrections

- The public archive is now built *before* it is validated. Previously verification
  ran first and the archive-membership test skipped when the archive was absent, so
  a stale archive could be recorded as a pass.
- A missing public archive is now a test failure on the release path, not a skip.
- Archive members are compared byte-for-byte against the working tree, so a stale
  archive fails.
- The archive is rejected if it contains any non-public package-family reference,
  a version-control remote, a user home path, a parent-directory traversal outside
  Markdown link targets, a private-key header, or a credential-shaped token.
- The self-exempting publication scanner and its private denylist were deleted. The
  replacement rules are written against generic properties of a publishable file
  and name no private identifier.
- The public README is asserted to carry the AgentGuard Core relationship statement
  and the current version.

### Metadata corrections

- Version corrected to `0.1.0` and sourced from `agentguard_reference.__version__`,
  so packaging metadata cannot drift from the package.
- Package description states that this is not AgentGuard Core and not production
  software.
- Added authors, keywords, classifiers, project URLs, and a `py.typed` marker.
- `LICENSE` names TensorScholar as copyright holder.
- Deleted the unused `ReplayStore.consume()`, which bypassed the lifetime predicate
  and had no callers.

### First-run experience

These are teaching and packaging changes. No property in `engine`, `domain`, or `audit`
changed behaviour.

- The default `python -m agentguard_reference` invocation now runs a guided demo
  instead of failing with an argparse error. `demo` remains valid and `--json` emits
  the raw document.
- The demo now executes and narrates five properties: argument mutation blocked, exact
  expiry denied without consuming the ticket, replay blocked, `unknown` after a
  dispatched callback failure, and audit tampering rejected. All five share one audit
  chain, so the emitted records are the evidence for the narrated sequence.
- The demo reports `self_check_under_public_demo_key` and no longer emits any field
  named `verified`. The key is published in the package source, so a bare
  `verified: true` was a self-congratulatory tautology. A key warning is written to
  stderr on every run.
- Scenario narration reports the callback invocation count observed at the moment of
  each step, so the exact-expiry step shows zero invocations rather than a later total.
- Demo exit status is 0 only when every scenario property held and the self-check
  passed.

### Reviewability

- The source distribution now ships `docs/`, `tests/`, `examples/`, `CHANGELOG.md`,
  `SECURITY.md`, and `Makefile` via an explicit `MANIFEST.in`. Unpacking it and
  running `make verify` works. There is no `graft .`, so nothing is swept in by
  accident, and `.release/` is pruned.
- Added `tests/unit/test_canonical.py`, which asserts that distinct accepted scalar
  and nested values never share a canonical form or an action digest, that key order
  is the one difference that does collapse, and that float-bearing text is rejected
  before a snapshot exists.
- The README states on its first screen that this is not AgentGuard Core and not a
  newer version of Core.
- The release collector no longer requires `.gitignore`, which a source distribution
  and an unpacked archive do not carry. Only files that are part of the artifact
  contract are mandatory.

### Documentation hardening

These entries change documentation and naming. `engine`, `domain`, and `audit` behaviour is unchanged apart from the additive `verify_prefix` alias, which is exactly `verify_records` with no `expected_head`.

- The executor-trust assumption is now stated first, in the threat model, the
  limitations, the architecture contract, and the property map, rather than as a
  buried clause. Argument binding is described as a **record** property, not an
  operating-system enforcement boundary.
- Four limits are promoted from soft caveats to named hazards, each with what fails,
  what still holds, and why it is acceptable for a single-process reference:
  cross-store and fresh-`Guard` replay, `fork()` before consumption double-dispatching
  a ticket, deadlock from a clock that re-enters the store under its lock, and
  unbounded `ReplayStore`/`AuditLog` growth including growth driven by denied
  `authorize` traffic.
- `verify_records` now documents its two modes at the definition: integrity of the
  presented prefix without an expected head, integrity plus completeness with one. A
  `verify_prefix` alias gives the weaker mode an honest name at the call site; it is
  exactly the same call and can never be stronger.
- The `untrusted` field is documented as a caller assertion **defeatable by
  omission** wherever it is described. Two adversarial tests were renamed off
  "provenance enforcement" wording, and a new test locks the omission bypass so the
  documentation cannot drift back.
- Non-goals are now a compact list in both the architecture contract and the
  limitations: not durable, not cross-process, not non-repudiable, not an effect
  oracle, not a credential broker, not an MCP mediation layer, not AgentGuard Core.
- A short Relationship to AgentGuard Core note records which ideas belong to Core and
  are absent here by design, so their absence reads as scope rather than oversight.
- The property-to-test map now covers every test method in the suite.

### Release tooling note

The publication guard is optional and untracked by necessity. `make release` prints
`exact private-marker layer NOT RUN` when `.release/guard.py` is absent, which is the
expected result on any machine that is not the maintainer's. The tracked layer is
sufficient to produce a correct artifact; the guard is defence in depth. This is now
documented in [reproducibility](docs/reproducibility.md).

### Documentation sculpture

Documentation and packaging only. No runtime behaviour changed, and no test method was added or removed.

- Deleted `docs/publication-review.md`. It was an internal inclusion-decision memo with
  no technical fact an external reader needs, and it duplicated exclusions that
  [limitations](docs/limitations.md) already states.
- Deleted `linkedin/`. Marketing collateral does not belong inside a security artifact,
  and its claims duplicated the README and the property map.
- The repeated load-bearing statements are now stated in full in exactly the three
  places a reader must not miss them — the README first screen, the threat model's
  first section, and the limitations — and cross-referenced elsewhere.
- The README's Public API section is split into three labelled subsections: snapshot
  limits, policy scope, and lifetime semantics.
- The property-to-test map is grouped into nine property classes. Coverage is
  unchanged and still complete: every test method appears in exactly one row.
- Repaired two table rows whose property-name cell had been duplicated by an earlier
  scripted edit, and removed a paragraph describing a pytest marker that no longer
  exists.

## What 0.1.0 contains

- Distribution `agentguard-reference`; import package `agentguard_reference`;
  Python >=3.11; standard-library runtime; no private dependencies.
- Source boundaries `domain`, `engine`, `audit`, `cli` under `src/agentguard_reference`.
- Immutable bounded JSON actions, explicit policy configuration, HMAC-bound
  authorization, and same-process single-use execution.
- Explicit `denied`, `succeeded`, and `unknown` outcomes with fail-closed
  authorization and dispatch auditing.
- Serialized `ReplayStore.claim`: the clock is sampled while the store lock is held.
  Lifetime predicate failure does not consume the authorization identifier.
- Identity strings reject surrounding whitespace and ASCII control characters.
- The audit chain head advances only after the record is appended.
- Callback `BaseException` after admission appends `execution.unknown` with
  `executor.interrupted` and re-raises.
- Synthetic JSON demo and audit verification using an external key and a trusted
  expected head.
- Unit, security-boundary, and adversarial tests with an actual path/method map.

No historical validation results, generated evidence claims, or production
certification are carried forward. Test outcomes and release artifacts must be
established by an actual run.