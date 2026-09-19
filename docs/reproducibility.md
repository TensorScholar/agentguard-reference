# Reproducibility

Commands describe the standalone 1.0.1 verification and packaging workflow, not evidence that a release has passed. No sibling checkout or provider account is required.

## Environment and installation

Use Python >=3.11 from the package root in an isolated `.venv`. The `agentguard_reference` namespace avoids collisions with other `agentguard` packages; do not use another checkout's environment. Runtime code uses only the standard library; installation and development tools may need public package sources.

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
python -m agentguard_reference demo
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

The Makefile declares `release: verify`, so release first runs the entire verification gate, then executes:

```sh
python scripts/build_release.py [output-directory]
```

The release artifact contract is:

- `release/agentguard-reference-final.zip`: source archive.
- `release/agentguard-reference-final.zip.sha256`: archive SHA256 checksum.
- `release/manifest.sha256`: SHA256 inventory of packaged files.
- `MANIFEST.sha256` inside the ZIP: the packaged-file inventory, excluding itself.

The release collector includes the license, package configuration, source, tests, examples, documentation, and release script. It excludes Git history, virtual environments, bytecode, caches, generated package metadata, and release outputs. It rejects symlinks, unapproved file types in source directories, and selected private-path or credential markers. These checks complement manual review; they are not an exhaustive secret scanner. Entries use fixed timestamps, permissions, ordering, and uncompressed storage to make repeated builds from identical source byte-identical.

An optional output directory argument writes the archive outside the package tree. The ZIP contains only the public artifact under `agentguard-reference/`. External siblings `agentguard-reference-final.zip.sha256` and `agentguard-reference-final.manifest.txt` are not ZIP members.

Before publication, compare manifest digests with archive members and the external inventory, verify the archive checksum, and inspect membership for unintended secrets or excluded material. Test installation and the CLI from the packaged source in a fresh isolated environment. A SHA256 inventory is not a publisher signature; byte-identical archives across environments are not promised. Keep actual run results separate from workflow descriptions and apply the [publication review](publication-review.md).
