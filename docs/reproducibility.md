# Reproducibility

Commands describe the standalone 0.1.0 verification and packaging workflow, not evidence that a release has passed. No sibling checkout or provider account is required.

## Environment and installation

Use Python >=3.11 from the package root in an isolated `.venv`. The `agentguard_reference` namespace avoids collisions with the separate AgentGuard Core distribution; do not use another checkout's environment. Runtime code uses only the standard library; installation and development tools may need public package sources.

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install '.[dev]'
```

For runtime-only installation, replace the last command with `python -m pip install .`. Record Python/platform versions, installed public dependency versions, and the exact source revision when reporting a run.

## Tests and checks

The suites support standard-library discovery in the activated environment:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests/unit -p 'test_*.py'
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests/security -p 'test_*.py'
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests/adversarial -p 'test_*.py'
```

`make verify` runs the whole suite. Validating a built public archive is separate and
lives outside the package, in `scripts/validate_archive.py`, which `make release` runs
after building. Nothing in the test suite requires an archive to be present, so all
three discovery commands above work in a clean checkout.

Run only CLI tests with:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests/unit -p test_cli.py -v
```

The combined gate is:

```sh
make verify PYTHON=.venv/bin/python
```

`make verify` runs pytest, Ruff, mypy, and the demo, in that order. Its equivalent individual commands are:

```sh
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH=src
python -m pytest -q
python -m ruff check --no-cache src tests examples scripts
python -m mypy --cache-dir=/dev/null src
python -m agentguard_reference
```

Tests use controlled clocks, synthetic keys, and callback counters. CLI file inputs use mocked `Path.stat`, `Path.read_text`, and `Path.read_bytes`, with captured stdout/stderr; no input files are created. The [test map](security-properties.md) lists actual paths, classes, and methods. Record actual exit statuses and discovered tests; an empty suite is not validation. Demo output authenticated with a public key is not trusted evidence.

## Audit verification

```sh
python -m agentguard_reference verify audit.json --key-file verification.key --expected-head HEX
```

Input is a UTF-8 JSON record array or object with a `records` array. The external key file contains raw bytes (minimum 32); no hex/base64 decoding occurs. Reported audit/key sizes must not exceed 10485760/4096 bytes respectively. Replace `HEX` with an independently trusted lowercase 64-character hexadecimal head. Embedded keys and document head metadata do not supply verification authority.

Successful verification exits 0; invalid verification or unreadable/malformed input exits 1; missing required options exits 2. HMAC key holders can forge records. Verification establishes consistency under supplied trust inputs, not non-repudiation or external business effects.

## Release packaging

```sh
make release PYTHON=.venv/bin/python
```

The Makefile declares `release: verify build archive-check`. Release runs the verification gate, then builds the archive, then validates the archive that was just produced:

```sh
python scripts/build_release.py [output-directory]
python scripts/validate_archive.py
```

`archive-check` has two layers. The first is mandatory and tracked; the second is optional, local, and its absence is expected.

**Layer 1 — tracked and mandatory.** `scripts/validate_archive.py` fails closed on a missing archive, an archive whose members differ from the working tree, a broken manifest, an archive whose README lacks the AgentGuard Core relationship statement, a changelog that presents a superseded `1.x` heading, and a non-reproducible build. None of those rules requires naming a private identifier, so this file is safe to track and to read. This layer alone is sufficient to produce a correct public artifact.

**Layer 2 — local, optional, never committed.** `.release/guard.py` additionally checks for *exact* forbidden markers. It holds those markers itself, so it is gitignored, is not tracked in any commit, is not in the archive, the sdist, or the wheel, and is not required for a fresh clone to build, verify, or release.

**Seeing `archive-check: exact private-marker layer NOT RUN (.release/guard.py absent)` is the expected result for anyone who has not cloned a maintainer workstation.** It is a notice, not a failure: `make release` still exits 0. The reason for the split is structural. A denylist that is itself published defeats its purpose, so the exact markers cannot live in any tracked or shipped file. The tracked policy in `scripts/build_release.py` covers the same leak *shapes* without naming them, by deriving the package-family stem from this package's own declared distribution name. Layer 2 is defence in depth for whoever holds the private remote, not a prerequisite for correctness.

If you maintain this package and want layer 2 active, recreate `.release/guard.py` locally; it is deliberately not recoverable from the repository.

No check in either layer skips. A missing archive is a failure, not a skip.

The release artifact contract is:

- `release/agentguard-reference-final.zip`: source archive.
- `release/agentguard-reference-final.zip.sha256`: archive SHA256 checksum.
- `release/manifest.sha256`: SHA256 inventory of packaged files.
- `release/agentguard-reference-final.manifest.txt`: the same inventory under an explicit name.
- `MANIFEST.sha256` inside the ZIP: the packaged-file inventory, excluding itself.

The release collector includes the license, package configuration, source, tests, examples, and documentation. It excludes Git history, virtual environments, bytecode, caches, generated package metadata, release outputs, and the release tooling itself: archiving the collector would ship the collector's own policy. It rejects symlinks, unapproved file types in source directories, private-key headers, user home paths, credential-shaped tokens, version-control remotes, parent-directory traversal outside Markdown link targets, and any package-family reference that is not one of this artifact's own public names.

An optional output directory argument writes the archive outside the package tree. The ZIP contains only the public artifact under `agentguard-reference/`. External siblings `agentguard-reference-final.zip.sha256` and `agentguard-reference-final.manifest.txt` are not ZIP members.

Release evidence is the command transcript and the archive checksum. The package issues no pass certificate, no validation JSON, and no attestation of its own release. Before publication, compare manifest digests with archive members and the external inventory, verify the archive checksum, and inspect membership for unintended secrets or excluded material. Test installation and the CLI from the packaged source in a fresh isolated environment. A SHA256 inventory is not a publisher signature; byte-identical archives across environments are not promised. Keep actual run results separate from workflow descriptions: this document describes the workflow, and it is not a record that any run passed.
