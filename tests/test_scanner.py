import tempfile
import unittest
from pathlib import Path

from repo_security_check import scan_repository
from repo_security_check.cli import main


_PINNED_SHA = "a" * 40


class ScanRepositoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def write_file(self, relative_path: str, content: str = "") -> None:
        path = self.root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def make_hardened_repository(self) -> None:
        self.write_file("LICENSE", "MIT")
        self.write_file("SECURITY.md", "Report vulnerabilities privately.")
        self.write_file(".github/dependabot.yml", "version: 2")
        self.write_file(
            ".github/workflows/codeql.yml",
            "uses: actions/checkout@" + _PINNED_SHA + "\n"
            "uses: github/codeql-action/init@" + _PINNED_SHA,
        )
        self.write_file(".gitignore", ".env\n*.pem\n*.key\n")

    def test_hardened_repository_scores_100(self) -> None:
        self.make_hardened_repository()

        result = scan_repository(self.root)

        self.assertEqual(result.score, 100)
        self.assertTrue(all(finding.status == "pass" for finding in result.findings))

    def test_reports_missing_controls_and_sensitive_files(self) -> None:
        self.write_file(".github/workflows/build.yml", "uses: actions/checkout@v4")
        self.write_file("private.key", "not-a-real-key")

        result = scan_repository(self.root)

        self.assertLess(result.score, 100)
        findings = {finding.key: finding for finding in result.findings}
        self.assertEqual(findings["sensitive_files"].status, "warn")
        self.assertIn("private.key", findings["sensitive_files"].message)
        self.assertEqual(findings["pinned_actions"].status, "warn")

    def test_rejects_missing_directory(self) -> None:
        with self.assertRaises(ValueError):
            scan_repository(self.root / "missing")


class CommandLineTests(unittest.TestCase):
    def test_json_output_succeeds(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            exit_code = main([temporary_directory, "--format", "json"])

        self.assertEqual(exit_code, 0)


if __name__ == "__main__":
    unittest.main()
