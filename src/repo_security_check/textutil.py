"""Text helpers: safe display of hostile text, lenient JSON and line lookup."""

from __future__ import annotations

import json
import re
import unicodedata
from typing import Any, Optional

_MAX_EVIDENCE = 160


def safe_display(text: str, limit: int = _MAX_EVIDENCE) -> str:
    """Return text that is safe to print to a terminal or embed in a report.

    Scanned repositories are untrusted. Control characters (including ANSI escape
    sequences), invisible characters and bidirectional overrides are replaced by
    visible ``<U+XXXX>`` markers so a hostile file cannot hide or rewrite findings.
    """
    output = []
    for character in text:
        if character in "\t":
            output.append(" ")
            continue
        category = unicodedata.category(character)
        codepoint = ord(character)
        if (
            category in {"Cc", "Cf", "Co", "Cs", "Cn", "Zl", "Zp"}
            or 0xFE00 <= codepoint <= 0xFE0F
            or 0xE0100 <= codepoint <= 0xE01EF
            or codepoint in _INVISIBLE_SPACES
        ):
            output.append(f"<U+{codepoint:04X}>")
        else:
            output.append(character)
    result = "".join(output).strip()
    if len(result) > limit:
        result = result[: limit - 1].rstrip() + "…"
    return result


# Characters that are not format characters but still render as blank space.
_INVISIBLE_SPACES = {0x115F, 0x1160, 0x3164, 0xFFA0, 0x2800}


def line_number(text: str, index: int) -> int:
    """1-based line number for a character offset."""
    return text.count("\n", 0, max(index, 0)) + 1


def find_line(text: str, *needles: str) -> Optional[int]:
    """Line of the first needle found in text (tries JSON-escaped forms too)."""
    for needle in needles:
        if not needle:
            continue
        candidates = [needle, json.dumps(needle)[1:-1]]
        for candidate in candidates:
            index = text.find(candidate)
            if index >= 0:
                return line_number(text, index)
    return None


def line_at(text: str, line: int) -> str:
    lines = text.splitlines()
    if 1 <= line <= len(lines):
        return lines[line - 1]
    return ""


_JSONC_TOKEN = re.compile(
    r'"(?:\\.|[^"\\])*"'  # strings
    r"|//[^\n]*"  # line comments
    r"|/\*.*?\*/",  # block comments
    re.DOTALL,
)
_TRAILING_COMMA = re.compile(r",(\s*[}\]])")


def _strip_jsonc(text: str) -> str:
    def replace(match: "re.Match[str]") -> str:
        token = match.group(0)
        if token.startswith('"'):
            return token
        # Keep line structure so positions stay meaningful.
        return "\n" * token.count("\n") if token.startswith("/*") else ""

    stripped = _JSONC_TOKEN.sub(replace, text)
    # Remove trailing commas outside strings.
    parts = re.split(r'("(?:\\.|[^"\\])*")', stripped)
    for position in range(0, len(parts), 2):
        parts[position] = _TRAILING_COMMA.sub(r"\1", parts[position])
    return "".join(parts)


def parse_jsonc(text: str) -> Optional[Any]:
    """Parse JSON with comments and trailing commas (VS Code style). None on failure."""
    if text.startswith("﻿"):
        text = text[1:]
    try:
        return json.loads(text)
    except ValueError:
        pass
    try:
        return json.loads(_strip_jsonc(text))
    except ValueError:
        return None


def as_command(value: Any) -> str:
    """Render a command given as a string, list or {command, args} object."""
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        return " ".join(str(part) for part in value)
    if isinstance(value, dict):
        pieces = []
        for key in ("command", "args", "commandLine"):
            if key in value:
                pieces.append(as_command(value[key]))
        if pieces:
            return " ".join(pieces)
        return " ".join(as_command(item) for item in value.values())
    return "" if value is None else str(value)
