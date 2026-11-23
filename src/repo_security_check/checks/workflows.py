"""GitHub Actions workflow checks (RSC401-RSC405).

Workflows are analysed line by line rather than with a YAML library so the
scanner keeps zero runtime dependencies. The parser only needs to find
triggers, `uses:` references and the bodies of `run:` / `script:` blocks.
"""

from __future__ import annotations

import re
from typing import List, Tuple

from ..models import Finding, Severity
from ..textutil import safe_display
from .context import FileContext

_UNTRUSTED_CONTEXT = re.compile(
    r"github\.head_ref"
    r"|github\.event\.(?:issue|pull_request|discussion)\.(?:title|body)"
    r"|github\.event\.(?:comment|review|review_comment)\.body"
    r"|github\.event\.pages\.[^}]*\.page_name"
    r"|github\.event\.commits\.[^}]*\.(?:message|author\.(?:email|name))"
    r"|github\.event\.head_commit\.(?:message|author\.(?:email|name))"
    r"|github\.event\.pull_request\.head\.(?:ref|label|repo\.default_branch)"
    r"|github\.event\.workflow_run\.(?:head_branch|display_title|head_commit\.(?:message|author\.(?:email|name)))"
    r"|github\.event\.workflow_run\.pull_requests\[[^\]]*\]\.head\.ref"
)
_EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)
_PRIVILEGED_TRIGGER = re.compile(r"\b(pull_request_target|workflow_run)\b")
_UNTRUSTED_REF = re.compile(
    r"github\.event\.pull_request\.head\.(?:sha|ref)|github\.head_ref|refs/pull/|"
    r"github\.event\.workflow_run\.head_(?:sha|branch)|"
    r"github\.event\.pull_request\.merge_commit_sha"
)
_UNTRUSTED_CHECKOUT_CMD = re.compile(
    r"\bgh\s+pr\s+checkout\b|\bgit\s+(?:fetch|checkout|pull)\b[^\n]*(?:pull/|refs/pull|head\.(?:sha|ref)|head_ref)"
)
_USES = re.compile(r"^\s*(?:-\s+)?uses:\s*['\"]?([^\s'\"#]+)")
_SHA = re.compile(r"@[0-9a-fA-F]{40}$")
_DOCKER_DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")
_BLOCK_KEY = re.compile(r"^(\s*)(?:-\s+)?(run|script):\s*(.*)$")
_TRUSTED_OWNERS = ("actions/", "github/")


def _strip_comment(line: str) -> str:
    in_single = in_double = False
    for index, character in enumerate(line):
        if character == "'" and not in_double:
            in_single = not in_single
        elif character == '"' and not in_single:
            in_double = not in_double
        elif character == "#" and not in_single and not in_double:
            if index == 0 or line[index - 1] in " \t":
                return line[:index]
    return line


def _script_blocks(lines: List[str]) -> List[Tuple[int, str, str]]:
    """Return (line_number, key, content_line) for every line inside run:/script: blocks."""
    entries = []
    index = 0
    while index < len(lines):
        match = _BLOCK_KEY.match(lines[index])
        if not match:
            index += 1
            continue
        indent = len(match.group(1))
        key = match.group(2)
        value = match.group(3).strip()
        if value and value[0] not in "|>":
            entries.append((index + 1, key, value))
            index += 1
            continue
        index += 1
        while index < len(lines):
            line = lines[index]
            if line.strip() and (len(line) - len(line.lstrip())) <= indent:
                break
            if line.strip():
                entries.append((index + 1, key, line))
            index += 1
    return entries


def is_workflow_file(rel: str) -> bool:
    lower = rel.lower()
    if lower.startswith(".github/workflows/") and lower.endswith((".yml", ".yaml")):
        return True
    return lower.endswith(("/action.yml", "/action.yaml")) or lower in {"action.yml", "action.yaml"}


def check_workflow(context: FileContext) -> List[Finding]:
    if context.text is None or not is_workflow_file(context.rel):
        return []
    text = context.text
    lines = text.split("\n")
    code_lines = [_strip_comment(line) for line in lines]
    findings: List[Finding] = []

    # RSC402: untrusted data interpolated into scripts.
    reported = 0
    for number, key, content in _script_blocks(code_lines):
        for expression in _EXPRESSION.finditer(content):
            inner = expression.group(1)
            hit = _UNTRUSTED_CONTEXT.search(inner)
            if hit and reported < 10:
                reported += 1
                language = "JavaScript" if key == "script" else "shell"
                findings.append(
                    Finding(
                        "RSC402",
                        Severity.HIGH,
                        context.rel,
                        f"`{hit.group(0)}` is attacker-controlled and is pasted directly into "
                        f"{language} code; pass it through an env: variable instead.",
                        number,
                        safe_display(content.strip()),
                    )
                )

    # RSC401: privileged trigger + checkout of untrusted code.
    trigger_lines = [
        number
        for number, line in enumerate(code_lines, start=1)
        if _PRIVILEGED_TRIGGER.search(line) and "github.event" not in line
    ]
    if trigger_lines:
        for number, line in enumerate(code_lines, start=1):
            ref_line = re.match(r"^\s*(?:-\s+)?ref:\s*(.+)$", line)
            risky = (ref_line and _UNTRUSTED_REF.search(ref_line.group(1))) or _UNTRUSTED_CHECKOUT_CMD.search(line)
            if risky:
                trigger = _PRIVILEGED_TRIGGER.search(code_lines[trigger_lines[0] - 1]).group(1)
                findings.append(
                    Finding(
                        "RSC401",
                        Severity.CRITICAL,
                        context.rel,
                        f"Workflow runs on `{trigger}` (with secrets and a write token) and checks "
                        "out code from the pull request, so a fork can run code in a privileged context.",
                        number,
                        safe_display(line.strip()),
                    )
                )
                break

    # RSC403 / RSC404 / RSC405
    for number, line in enumerate(code_lines, start=1):
        uses = _USES.match(line)
        if uses:
            reference = uses.group(1)
            if reference.startswith("./") or reference.startswith(".\\"):
                continue
            if reference.startswith("docker://"):
                if not _DOCKER_DIGEST.search(reference):
                    findings.append(Finding("RSC403", Severity.LOW, context.rel,
                                            "Container image is referenced by tag instead of digest.",
                                            number, safe_display(reference)))
                continue
            if "@" not in reference or not _SHA.search(reference):
                first_party = reference.lower().startswith(_TRUSTED_OWNERS)
                findings.append(
                    Finding(
                        "RSC403",
                        Severity.LOW if first_party else Severity.MEDIUM,
                        context.rel,
                        f"`{safe_display(reference, 80)}` uses a mutable reference; pin it to a commit SHA.",
                        number,
                        safe_display(line.strip()),
                    )
                )
        if re.match(r"^\s*permissions:\s*write-all\s*$", line):
            findings.append(Finding("RSC404", Severity.MEDIUM, context.rel,
                                    "permissions: write-all grants every scope to the job token.",
                                    number, safe_display(line.strip())))
        if re.search(r"ACTIONS_ALLOW_UNSECURE_COMMANDS\s*:\s*['\"]?true", line, re.I):
            findings.append(Finding("RSC405", Severity.HIGH, context.rel,
                                    "Insecure set-env/add-path workflow commands are re-enabled.",
                                    number, safe_display(line.strip())))
    return findings
