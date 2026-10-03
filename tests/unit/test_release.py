import importlib.util
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("release_builder", ROOT / "scripts/build_release.py")
assert SPEC is not None and SPEC.loader is not None
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)


class ReleaseCollectorTests(unittest.TestCase):
    """Membership of the publishable file set.

    These cases run in a clean checkout with no archive present. Validation of a
    built archive is release policy, not package behaviour: it lives outside the
    package, in the gitignored `.release/guard.py`, so that no file shipped to a
    public index has to contain a leakage marker in order to check for one.
    """

    def test_source_inventory_excludes_generated_and_private_material(self) -> None:
        files = BUILDER.collect(ROOT)
        self.assertIn("docs/evidence-model.md", files)
        self.assertIn("LICENSE", files)
        self.assertIn("pyproject.toml", files)
        self.assertIn("examples/quickstart.py", files)
        self.assertIn("src/agentguard_reference/engine/__init__.py", files)
        self.assertIn("src/agentguard_reference/py.typed", files)
        self.assertFalse(any(".egg-info" in name or "__pycache__" in name for name in files))
        self.assertFalse(any(name.startswith(("release/", ".git/", "demos/", ".release/"))
                             for name in files))

    def test_collector_does_not_archive_its_own_exclusion_logic(self) -> None:
        names = set(BUILDER.collect(ROOT))
        self.assertNotIn("scripts/build_release.py", names)
        self.assertFalse([name for name in names if name.startswith("scripts/")])

    def test_collector_rejects_unapproved_file_types(self) -> None:
        self.assertEqual(BUILDER.DIRECTORIES["src"], {".py", ".typed"})
        self.assertNotIn("scripts", BUILDER.DIRECTORIES)

    def test_build_writes_the_declared_artifact_set(self) -> None:
        archive, checksum, count = BUILDER.build(ROOT, ROOT / "release")
        self.assertTrue(archive.is_file())
        self.assertEqual(len(checksum), 64)
        self.assertGreater(count, 20)
        for name in ("agentguard-reference-final.zip.sha256", "manifest.sha256",
                     "agentguard-reference-final.manifest.txt"):
            self.assertTrue((ROOT / "release" / name).is_file(), name)


class PublicArtifactPolicyTests(unittest.TestCase):
    """Every shippable file must satisfy the publication content policy.

    The rules are expressed against generic shapes and against the package-family
    stem this package declares for itself, so this file ships to a public index
    without containing a single private identifier.

    The negative probes for these rules live in `scripts/validate_archive.py`:
    probe data necessarily contains the shapes being rejected, and that data must
    not ship.
    """

    def test_every_publishable_file_satisfies_the_policy(self) -> None:
        files = BUILDER.collect(ROOT)
        self.assertGreater(len(files), 20)
        for relative, data in sorted(files.items()):
            with self.subTest(file=relative):
                self.assertEqual(BUILDER.public_artifact_violations(relative, data), [])

    def test_policy_accepts_this_packages_public_names(self) -> None:
        stem = BUILDER.family_stem()
        allowed = [
            stem + b"_reference\n",
            stem + b"-reference/docs\n",
            b"src/" + stem + b"_reference/engine/__init__.py\n",
            b"# AgentGuard Reference\n",
            b"separate from the canonical AgentGuard Core implementation\n",
            b"." + stem + b"/\n",
        ]
        for data in allowed:
            with self.subTest(data=data):
                self.assertEqual(BUILDER.public_artifact_violations("README.md", data), [])

    def test_stem_is_derived_from_the_declared_distribution_name(self) -> None:
        """The stem comes from this package's own name, so no private name is written."""
        declared = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        name = declared["project"]["name"]
        self.assertEqual(BUILDER.family_stem(), name.split("-")[0].encode("ascii"))
        self.assertEqual(BUILDER.family_stem(), BUILDER.family_stem(ROOT))


if __name__ == "__main__":
    unittest.main()