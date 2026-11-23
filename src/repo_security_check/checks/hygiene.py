"""Optional maintainer hygiene checks with a 0-100 score (the original v0.1 checks)."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, List

from ..models import Finding, HygieneCheck


def _exists_any(root: Path, paths: Iterable[str]) -> bool:
    return any((root / path).is_file() for path in paths)


def _workflow_texts(root: Path) -> List[str]:
    directory = root / ".github" / "workflows"
    if not directory.is_dir():
        return []
    texts = []
    for path in sorted(directory.iterdir()):
        if path.is_file() and not path.is_symlink() and path.suffix in {".yml", ".yaml"}:
            texts.append(path.read_text(encoding="utf-8", errors="replace"))
    return texts


def _gitignore_entries(root: Path) -> set:
    gitignore = root / ".gitignore"
    if not gitignore.is_file() or gitignore.is_symlink():
        return set()
    return {
        line.strip()
        for line in gitignore.read_text(encoding="utf-8", errors="replace").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }


def run_hygiene(root: Path, findings: List[Finding]) -> List[HygieneCheck]:
    workflows = _workflow_texts(root)
    rule_ids = {finding.rule_id for finding in findings}
    entries = _gitignore_entries(root)
    checks = [
        ("license", _exists_any(root, ("LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING")),
         "License file found.", "License file is missing.", 15),
        ("security_policy", _exists_any(root, ("SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md")),
         "Security policy found.", "Security policy (SECURITY.md) is missing.", 15),
        ("dependency_updates", _exists_any(root, (".github/dependabot.yml", ".github/dependabot.yaml",
                                                   "renovate.json", ".github/renovate.json", "renovate.json5")),
         "Automated dependency updates are configured.", "Dependabot or Renovate is not configured.", 15),
        ("code_scanning", any("github/codeql-action" in text for text in workflows),
         "CodeQL / code scanning workflow found.", "No CodeQL / code scanning workflow found.", 20),
        ("pinned_actions", "RSC403" not in rule_ids,
         "GitHub Actions are pinned to commit SHAs.", "Some GitHub Actions use mutable tags.", 10),
        ("no_committed_secrets", not ({"RSC501", "RSC502"} & rule_ids),
         "No committed secrets or sensitive files were found.", "Secrets or sensitive files are committed.", 15),
        ("gitignore", {".env", "*.pem", "*.key"}.issubset(entries),
         ".gitignore covers .env, *.pem and *.key.", ".gitignore does not cover .env, *.pem and *.key.", 10),
    ]
    return [
        HygieneCheck(key, passed, good if passed else bad, points if passed else 0, points)
        for key, passed, good, bad, points in checks
    ]
