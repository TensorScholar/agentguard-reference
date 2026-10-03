import re
import tomllib
import unittest
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as installed_version
from pathlib import Path

import agentguard_reference

ROOT = Path(__file__).resolve().parents[2]
DISTRIBUTION = "agentguard-reference"
CURRENT_VERSION = "0.1.0"


class VersionIdentityTests(unittest.TestCase):
    """Single source of truth for the version, and honest identity metadata.

    This module intentionally contains no withdrawn version number and no leakage
    marker, because it ships inside the public archive. The sweep for withdrawn
    numbers is release policy and lives in the non-shipped `.release/guard.py`.
    """

    def load_pyproject(self) -> dict[str, object]:
        return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    def test_package_version_is_the_declared_value(self) -> None:
        self.assertEqual(agentguard_reference.__version__, CURRENT_VERSION)

    def test_pyproject_version_is_not_hardcoded(self) -> None:
        project = self.load_pyproject()["project"]
        self.assertNotIn("version", project)
        self.assertIn("version", project["dynamic"])

    def test_pyproject_reads_version_from_the_package(self) -> None:
        """Packaging metadata cannot drift: it is derived from __version__."""
        dynamic = self.load_pyproject()["tool"]["setuptools"]["dynamic"]
        self.assertEqual(dynamic["version"], {"attr": "agentguard_reference.__version__"})

    def test_installed_distribution_metadata_matches_the_package(self) -> None:
        try:
            observed = installed_version(DISTRIBUTION)
        except PackageNotFoundError:
            self.skipTest(f"{DISTRIBUTION} is not installed in this interpreter")
        self.assertEqual(observed, agentguard_reference.__version__)

    def test_public_metadata_states_the_package_is_not_core(self) -> None:
        description = self.load_pyproject()["project"]["description"]
        self.assertIn("Not AgentGuard Core", description)
        self.assertIn("Not production software", description)

    def test_public_metadata_declares_typing_and_licence_terms(self) -> None:
        project = self.load_pyproject()["project"]
        self.assertIn("Typing :: Typed", project["classifiers"])
        self.assertIn("Development Status :: 3 - Alpha", project["classifiers"])
        self.assertIn("Topic :: Security", project["classifiers"])
        self.assertEqual(project["license"], "MIT")
        self.assertTrue(project["urls"])
        self.assertTrue(project["authors"])

    def test_package_ships_a_typing_marker(self) -> None:
        self.assertTrue((ROOT / "src/agentguard_reference/py.typed").is_file())

    def test_readme_states_the_core_relationship_on_the_first_screen(self) -> None:
        """The Core disclaimer must be visible before a reader scrolls, not buried.

        Asserted by intent and by position rather than by one exact sentence, so
        rewording cannot quietly drop it and rewording cannot quietly weaken it.
        """
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        first_screen = "\n".join(readme.splitlines()[:12])
        for marker in ("not AgentGuard Core", "not a", "newer version of Core"):
            with self.subTest(marker=marker):
                self.assertIn(marker, first_screen)
        self.assertIn(CURRENT_VERSION, first_screen)
        # A withdrawn 1.x number must not appear as a standalone version token. The
        # lookbehind keeps the current "0.1.0" from matching on its own "1.0" substring.
        self.assertIsNone(re.search(r"(?<![\d.])1\.0\.[01](?![\d])", readme))

    def test_security_policy_states_the_core_relationship(self) -> None:
        text = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
        self.assertIn("not AgentGuard Core", text)
        self.assertIn("not a newer version of it", text)

    def test_changelog_records_the_withdrawn_numbering(self) -> None:
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertRegex(changelog, r"(?m)^## 0\.1\.0$")
        self.assertIn("withdrawn", changelog.lower())
        self.assertIn("never published", changelog.lower())
        self.assertNotRegex(changelog, r"(?m)^## 1\.")

    def test_license_names_a_real_copyright_holder(self) -> None:
        text = (ROOT / "LICENSE").read_text(encoding="utf-8")
        match = re.search(r"Copyright \(c\) \d{4} (.+)", text)
        self.assertIsNotNone(match)
        holder = match.group(1)
        self.assertNotIn("showcase", holder.lower())
        self.assertTrue(holder.strip())

    def test_no_dead_public_api_remains(self) -> None:
        self.assertFalse(hasattr(agentguard_reference.ReplayStore, "consume"))


if __name__ == "__main__":
    unittest.main()