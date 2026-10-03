"""Fail-closed validation of the built public archive.

Run after `scripts/build_release.py`, never instead of it. Every check raises on a
defect and is silent otherwise. This module issues no verdict, certificate, or
attestation; evidence is the command transcript and the archive checksum.

Every rule here is expressible without naming a private identifier, so this file is
safe to track and to read. The additional exact layer that checks for specific
forbidden markers lives outside version control in `.release/guard.py`, because a
marker that must be kept out of every public file cannot be written into one.
"""

import hashlib
import importlib.util
import shutil
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = ROOT / "release/agentguard-reference-final.zip"
PREFIX = "agentguard-reference/"

_spec = importlib.util.spec_from_file_location(
    "release_builder", ROOT / "scripts/build_release.py")
assert _spec is not None and _spec.loader is not None
BUILDER = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(BUILDER)


class ContentPolicyTests(unittest.TestCase):
    """Negative probes for the publication content policy.

    Probe data necessarily contains the shapes it rejects, so it lives here rather
    than in the shipped suite: `scripts/` is not in DIRECTORIES, so this file is
    never archived. Family-specific shapes are built from the stem this package
    declares for itself, so no private identifier is written down here either.
    """

    def setUp(self) -> None:
        self.stem = BUILDER.family_stem()

    def test_policy_catches_every_leak_shape(self) -> None:
        upper = self.stem.upper()
        cases = {
            "concatenated-private-remote":
                b"github.com/TensorScholar/" + self.stem + b".git\n",
            "split-literal-private-remote":
                b"github.com/TensorScholar/\"" + b"\" b\"" + self.stem + b".git\n",
            "sibling-checkout-path": b"open('../" + self.stem + b"/x')\n",
            "family-marker-token": upper + b"_CORE\n",
            "bare-family-name": b"the " + self.stem + b" project\n",
            "user-home-path": b"/home/someone/x\n",
            "private-key-header": b"-----BEGIN PRIVATE KEY-----\n",
            "vcs-remote": b"clone repo.git\n",
            "traversal-in-source": b'x = "../../etc"\n',
            "credential-token": b"ghp_" + b"a" * 36 + b"\n",
        }
        for label, data in sorted(cases.items()):
            with self.subTest(case=label):
                self.assertNotEqual(BUILDER.public_artifact_violations("src/x.py", data), [])

    def test_markdown_link_targets_may_use_parent_traversal(self) -> None:
        data = b"see [architecture](../docs/architecture.md)\n"
        self.assertEqual(BUILDER.public_artifact_violations("examples/README.md", data), [])

    def test_every_publishable_file_satisfies_the_policy(self) -> None:
        files = BUILDER.collect(ROOT)
        self.assertGreater(len(files), 20)
        for relative, data in sorted(files.items()):
            with self.subTest(file=relative):
                self.assertEqual(BUILDER.public_artifact_violations(relative, data), [])

    def test_collector_never_archives_the_release_tooling(self) -> None:
        names = set(BUILDER.collect(ROOT))
        self.assertFalse([name for name in names if name.startswith("scripts/")])
        self.assertFalse([name for name in names if name.startswith(".release/")])


class ArchiveTests(unittest.TestCase):
    """Validate the artifact `make release` just produced. Never skips."""

    def open_archive(self) -> zipfile.ZipFile:
        if not ARCHIVE.exists():
            self.fail(f"public archive missing: {ARCHIVE}. `make release` builds the "
                      "archive and then validates it; an absent artifact is a defect.")
        return zipfile.ZipFile(ARCHIVE)

    def test_archive_manifest_matches_members(self) -> None:
        with self.open_archive() as bundle:
            self.assertIsNone(bundle.testzip())
            manifest = bundle.read(PREFIX + "MANIFEST.sha256").decode("utf-8")
            entries = dict(line.split("  ", 1)[::-1] for line in manifest.splitlines())
            self.assertEqual(
                set(bundle.namelist()),
                {PREFIX + name for name in entries} | {PREFIX + "MANIFEST.sha256"},
            )
            for name, expected in entries.items():
                self.assertEqual(hashlib.sha256(bundle.read(PREFIX + name)).hexdigest(), expected)
        self.assertEqual(manifest, (ROOT / "release/manifest.sha256").read_text())

    def test_archive_matches_working_tree(self) -> None:
        """A stale archive is a defect: every member must equal the source it claims."""
        for name, expected in sorted(BUILDER.collect(ROOT).items()):
            with self.subTest(file=name):
                with self.open_archive() as bundle:
                    self.assertEqual(bundle.read(PREFIX + name), expected)

    def test_archive_carries_the_core_disclaimer_and_current_version(self) -> None:
        """Asserted by intent and by first-screen position, not by one exact sentence."""
        with self.open_archive() as bundle:
            readme = bundle.read(PREFIX + "README.md").decode("utf-8")
        first_screen = "\n".join(readme.splitlines()[:12])
        for marker in ("not AgentGuard Core", "newer version of Core"):
            with self.subTest(marker=marker):
                self.assertIn(marker, first_screen)
        self.assertIn("0.1.0", first_screen)
        self.assertIn(BUILDER.family_stem().decode("ascii"), readme)

    def test_archive_declares_no_superseded_major_minor_version(self) -> None:
        """A changelog must not present a 1.x heading as this artifact's release."""
        with self.open_archive() as bundle:
            changelog = bundle.read(PREFIX + "CHANGELOG.md").decode("utf-8")
        self.assertRegex(changelog, r"(?m)^## 0\.")
        self.assertNotRegex(changelog, r"(?m)^## 1\.")

    def test_archive_is_byte_reproducible(self) -> None:
        """Rebuild into a temporary directory.

        The rebuild must never write to `release/`. A test that regenerates the
        artifact it is validating destroys the evidence of staleness and turns the
        freshness check into a tautology.
        """
        canonical = ARCHIVE.read_bytes()
        with tempfile.TemporaryDirectory() as scratch:
            archive, checksum, _ = BUILDER.build(ROOT, Path(scratch))
            self.assertEqual(archive.read_bytes(), canonical)
            self.assertEqual(checksum, hashlib.sha256(canonical).hexdigest())
        self.assertEqual(ARCHIVE.read_bytes(), canonical)

    def test_stale_archive_would_be_detected(self) -> None:
        """Positive control for the freshness rule.

        Builds an archive from a drifted copy of the tree in a scratch directory and
        asserts it differs from the canonical artifact. If this ever passes, the
        freshness check has stopped having teeth.
        """
        canonical = ARCHIVE.read_bytes()
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch) / "tree"
            shutil.copytree(ROOT, root, ignore=shutil.ignore_patterns(
                ".git", "release", "build", "__pycache__", "*.egg-info", ".release"))
            target = root / "docs/architecture.md"
            target.write_text(target.read_text(encoding="utf-8") + "\ndrifted\n",
                              encoding="utf-8")
            drifted, _, _ = BUILDER.build(root, Path(scratch) / "out")
            self.assertNotEqual(drifted.read_bytes(), canonical)
        self.assertEqual(ARCHIVE.read_bytes(), canonical)


if __name__ == "__main__":
    unittest.main(verbosity=2, argv=[sys.argv[0], *sys.argv[1:]])