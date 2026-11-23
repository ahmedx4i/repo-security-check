"""Prompt-injection heuristics for files AI agents read (RSC201-RSC204, RSC312)."""

from __future__ import annotations

import re
from typing import List

from ..models import Finding, Severity
from ..textutil import line_number, safe_display
from . import commands
from .context import FileContext


def _p(expression: str) -> "re.Pattern[str]":
    return re.compile(expression, re.IGNORECASE)


_OVERRIDE_PATTERNS = (
    _p(
        r"\b(?:ignore|disregard|forget|override|bypass|skip)\s+(?:all\s+|any\s+|the\s+|your\s+|"
        r"my\s+|of\s+)*(?:previous|prior|above|earlier|preceding|existing|system|safety|original|"
        r"initial)\s+(?:instructions?|prompts?|rules?|directions?|guidelines?|messages?|"
        r"constraints?|directives?)"
    ),
    _p(r"\bnew\s+system\s+(?:prompt|instructions?)\s*:"),
    _p(r"\byou\s+are\s+now\s+(?:in\s+)?(?:developer|dan|jailbreak|unrestricted|god|admin)\s+mode"),
    _p(r"\b(?:system|admin|developer)\s+override\b"),
    _p(r"<\|?\s*im_start\s*\|?>\s*system|<\|\s*(?:system|endoftext)\s*\|>"),
    _p(r"^\s*\[(?:system|SYSTEM)\s*(?:message|prompt)?\]\s*:"),
)

_CONCEALMENT_PATTERNS = (
    _p(
        r"\b(?:do\s+not|don'?t|never)\s+(?:tell|inform|mention|reveal|disclose|show|alert|"
        r"notify|let)\b[^.\n]{0,40}\b(?:the\s+)?(?:user|human|developer|operator|reviewer)s?\b"
    ),
    _p(r"\bwithout\s+(?:telling|informing|notifying|alerting)\s+(?:the\s+)?(?:user|human|developer)"),
    _p(r"\b(?:the\s+)?user\s+(?:must|should)\s+(?:not|never)\s+(?:know|see|notice|be\s+told)"),
    _p(r"\bsilently\s+(?:run|execute|send|upload|install|add|insert|modify|exfiltrate|post)\b"),
    _p(r"\bkeep\s+(?:this|these|it)\s+(?:secret|hidden)\s+from\b"),
)

_HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)
_DIRECTIVE_WORDS = _p(
    r"\b(?:assistant|agent|ai|llm|model|claude|copilot|cursor|gemini|instructions?|ignore|"
    r"must|always|never|execute|run|curl|wget|secret|token|password|credential|api[_ -]?key)\b"
)
_TOOL_MARKERS = re.compile(r"\b(?:prettier-ignore|eslint-disable|markdownlint|toc|ALL-CONTRIBUTORS)", re.I)


def _first_match(text: str, patterns) -> "re.Match[str] | None":
    best = None
    for pattern in patterns:
        match = pattern.search(text)
        if match and (best is None or match.start() < best.start()):
            best = match
    return best


def _all_lines(text: str, patterns) -> List[int]:
    lines = set()
    for pattern in patterns:
        for match in pattern.finditer(text):
            lines.add(line_number(text, match.start()))
    return sorted(lines)


def check_prompt_injection(context: FileContext) -> List[Finding]:
    text = context.text
    if text is None:
        return []
    findings: List[Finding] = []
    agent = context.is_agent_file
    severity = Severity.HIGH if agent else Severity.MEDIUM

    for rule_id, patterns, label in (
        ("RSC201", _OVERRIDE_PATTERNS, "tries to override an AI agent's instructions"),
        ("RSC202", _CONCEALMENT_PATTERNS, "asks an AI agent to hide what it does from the user"),
    ):
        match = _first_match(text, patterns)
        if match is None:
            continue
        lines = _all_lines(text, patterns)
        where = "agent instruction file" if agent else "file"
        findings.append(
            Finding(
                rule_id,
                severity,
                context.rel,
                f"Text in this {where} {label} (line(s) {', '.join(map(str, lines[:8]))}).",
                line_number(text, match.start()),
                safe_display(match.group(0)),
            )
        )

    if agent:
        findings.extend(_agent_file_commands(context, text))
        findings.extend(_hidden_comments(context, text))
    findings.extend(_ai_cli_bypass(context, text))
    return findings


def _agent_file_commands(context: FileContext, text: str) -> List[Finding]:
    findings = []
    for number, line in enumerate(text.split("\n"), start=1):
        risk = commands.analyze(line, commands.AGENT_FILE_TAGS - {"ai"})
        if risk.severity is None or risk.severity < Severity.HIGH:
            continue
        findings.append(
            Finding(
                "RSC203",
                Severity.HIGH,
                context.rel,
                f"Agent instruction file line {risk.summary}.",
                number,
                safe_display(line),
            )
        )
        if len(findings) >= 10:
            break
    return findings


def _hidden_comments(context: FileContext, text: str) -> List[Finding]:
    findings = []
    for match in _HTML_COMMENT.finditer(text):
        body = match.group(1).strip()
        if len(body) < 25 or _TOOL_MARKERS.search(body):
            continue
        if not _DIRECTIVE_WORDS.search(body):
            continue
        findings.append(
            Finding(
                "RSC204",
                Severity.MEDIUM,
                context.rel,
                "HTML comment with instructions is hidden when the Markdown is rendered but "
                "is read by AI agents.",
                line_number(text, match.start()),
                safe_display(body),
            )
        )
        if len(findings) >= 5:
            break
    return findings


def _ai_cli_bypass(context: FileContext, text: str) -> List[Finding]:
    findings = []
    for pattern in commands.AI_BYPASS_PATTERNS:
        for match in pattern.finditer(text):
            if context.is_agent_file or not context.is_docs:
                severity = Severity.HIGH
            else:
                severity = Severity.LOW
            findings.append(
                Finding(
                    "RSC312",
                    severity,
                    context.rel,
                    "Starts an AI coding CLI with its permission checks disabled.",
                    line_number(text, match.start()),
                    safe_display(match.group(0)),
                )
            )
            break
    return findings[:3]
