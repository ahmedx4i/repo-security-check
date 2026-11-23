"""Local checks for common repository security hygiene."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import re
from typing import Iterable

_ACTION_REFERENCE = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)", re.MULTILINE)
_SHA_REFERENCE = re.compile(r"@[0-9a-fA-F]{40}$")
_SENSITIVE_NAMES = {
    ".env",
    ".env.local",
    ".env.production",
    "credentials.json",
    "id_rsa",
    "id_dsa",
}
_SENSITIVE_SUFFIXES = {".pem", ".key", ".p12", ".pfx"}
_IGNORED_DIRECTORIES = {".git", ".venv", "node_modules", "dist", "build"}


@dataclass(frozen=True)
class Finding:
    """One result from a repository security hygiene check."""

    key: str
    status: str
    message: str
    points: int


@dataclass(frozen=True)
class ScanResult:
    """The aggregate result of a repository scan."""

    path: str
    score: int
    findings: list[Finding]

    def as_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "score": self.score,
            "findings": [asdict(finding) for finding in self.findings],
        }


def _iter_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if any(part in _IGNORED_DIRECTORIES for part in path.parts):
            continue
        if path.is_file():
            yield path


def _exists_any(root: Path, paths: Iterable[str]) -> bool:
    return any((root / path).is_file() for path in paths)


def _workflow_files(root: Path) -> list[Path]:
    workflow_directory = root / ".github" / "workflows"
    if not workflow_directory.is_dir():
        return []
    return [
        path
        for path in workflow_directory.iterdir()
        if path.is_file() and path.suffix in {".yml", ".yaml"}
    ]


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _sensitive_files(root: Path) -> list[Path]:
    matches = []
    for path in _iter_files(root):
        if path.name in _SENSITIVE_NAMES or path.suffix.lower() in _SENSITIVE_SUFFIXES:
            matches.append(path.relative_to(root))
    return matches


def _unpinned_actions(workflows: Iterable[Path]) -> list[str]:
    unpinned = []
    for workflow in workflows:
        for reference in _ACTION_REFERENCE.findall(_read_text(workflow)):
            if not _SHA_REFERENCE.search(reference):
                unpinned.append(reference)
    return sorted(set(unpinned))


def _has_codeql(workflows: Iterable[Path]) -> bool:
    return any("github/codeql-action" in _read_text(workflow) for workflow in workflows)


def _gitignore_covers_sensitive_files(root: Path) -> bool:
    gitignore = root / ".gitignore"
    if not gitignore.is_file():
        return False

    entries = {
        line.strip()
        for line in _read_text(gitignore).splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    expected = {".env", "*.pem", "*.key"}
    return expected.issubset(entries)


def scan_repository(path: str | Path) -> ScanResult:
    """Scan a local repository directory and return a hygiene score out of 100."""
    root = Path(path).resolve()
    if not root.is_dir():
        raise ValueError(f"Repository path does not exist or is not a directory: {root}")

    workflows = _workflow_files(root)
    sensitive_files = _sensitive_files(root)
    unpinned_actions = _unpinned_actions(workflows)

    checks = [
        (
            "license",
            _exists_any(root, ("LICENSE", "LICENSE.md", "LICENSE.txt")),
            "License file found.",
            "License file is missing.",
            15,
        ),
        (
            "security_policy",
            _exists_any(root, ("SECURITY.md", ".github/SECURITY.md")),
            "Security policy found.",
            "Security policy is missing.",
            15,
        ),
        (
            "dependabot",
            _exists_any(root, (".github/dependabot.yml", ".github/dependabot.yaml")),
            "Dependabot configuration found.",
            "Dependabot configuration is missing.",
            15,
        ),
        (
            "codeql",
            _has_codeql(workflows),
            "CodeQL workflow found.",
            "CodeQL workflow is missing.",
            20,
        ),
        (
            "pinned_actions",
            not unpinned_actions,
            "GitHub Actions are pinned to commit SHAs.",
            "Some GitHub Actions use mutable version tags.",
            10,
        ),
        (
            "sensitive_files",
            not sensitive_files,
            "No sensitive-looking files were found.",
            "Sensitive-looking files were found: " + ", ".join(map(str, sensitive_files)),
            15,
        ),
        (
            "gitignore",
            _gitignore_covers_sensitive_files(root),
            "The .gitignore covers common sensitive file patterns.",
            "The .gitignore does not cover .env, *.pem, and *.key.",
            10,
        ),
    ]

    findings = [
        Finding(
            key=key,
            status="pass" if passed else "warn",
            message=passed_message if passed else warning_message,
            points=points if passed else 0,
        )
        for key, passed, passed_message, warning_message, points in checks
    ]
    return ScanResult(
        path=str(root),
        score=sum(finding.points for finding in findings),
        findings=findings,
    )
