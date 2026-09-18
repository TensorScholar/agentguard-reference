import hashlib
import importlib.util
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("release_builder", ROOT / "scripts/build_release.py")
assert SPEC is not None and SPEC.loader is not None
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)


class ReleaseTests(unittest.TestCase):
    def test_source_inventory_excludes_generated_and_private_material(self):
        files = BUILDER.collect(ROOT)
        self.assertIn("LICENSE", files)
        self.assertIn("pyproject.toml", files)
        self.assertIn("examples/quickstart.py", files)
        self.assertIn("src/agentguard_reference/engine/__init__.py", files)
        self.assertFalse(any(".egg-info" in name or "__pycache__" in name for name in files))
        self.assertFalse(any(name.startswith(("release/", ".git/", "demos/")) for name in files))

    def test_checked_archive_matches_inventory_when_present(self):
        archive = ROOT / "release/agentguard-reference-final.zip"
        if not archive.exists():
            self.skipTest("archive is checked after release generation")
        with zipfile.ZipFile(archive) as bundle:
            self.assertIsNone(bundle.testzip())
            prefix = "agentguard-reference/"
            manifest = bundle.read(prefix + "MANIFEST.sha256").decode("utf-8")
            entries = dict(line.split("  ", 1)[::-1] for line in manifest.splitlines())
            self.assertEqual(set(bundle.namelist()),
                             {prefix + name for name in entries} | {prefix + "MANIFEST.sha256"})
            for name, expected in entries.items():
                self.assertEqual(hashlib.sha256(bundle.read(prefix + name)).hexdigest(), expected)
            self.assertEqual(manifest, (ROOT / "release/manifest.sha256").read_text())


if __name__ == "__main__":
    unittest.main()
