"""Detection of invisible and display-altering Unicode (RSC101-RSC104)."""

from __future__ import annotations

from typing import List

from ..models import Finding, Severity
from ..textutil import line_number, safe_display
from .context import FileContext

_TAG_START, _TAG_END = 0xE0000, 0xE007F
_CANCEL_TAG = 0xE007F
_BLACK_FLAG = 0x1F3F4  # base of subdivision flag emoji such as England's flag

_BIDI_OPENERS_EMBED = {0x202A, 0x202B, 0x202D, 0x202E}
_BIDI_POP_EMBED = 0x202C
_BIDI_OPENERS_ISOLATE = {0x2066, 0x2067, 0x2068}
_BIDI_POP_ISOLATE = 0x2069
_BIDI = _BIDI_OPENERS_EMBED | _BIDI_OPENERS_ISOLATE | {_BIDI_POP_EMBED, _BIDI_POP_ISOLATE}

# Invisible characters with essentially no legitimate use inside source or config.
_STRONG_INVISIBLE = {
    0x200B,  # zero width space
    0x2060,  # word joiner
    0x2061,  # function application
    0x2062,  # invisible times
    0x2063,  # invisible separator
    0x2064,  # invisible plus
    0x180E,  # mongolian vowel separator
    0x034F,  # combining grapheme joiner
    0x115F,  # hangul choseong filler
    0x1160,  # hangul jungseong filler
    0x3164,  # hangul filler
    0xFFA0,  # halfwidth hangul filler
    0x17B4,  # khmer vowel inherent aq
    0x17B5,  # khmer vowel inherent aa
    0x00AD,  # soft hyphen
    0xFEFF,  # zero width no-break space (outside the leading BOM)
}
# Joiners are required by Persian, Arabic, Indic scripts and emoji sequences,
# so they only count when used in runs or between ASCII characters.
_JOINERS = {0x200C, 0x200D}
_INVISIBLE = _STRONG_INVISIBLE | _JOINERS


def _is_variation_selector(codepoint: int) -> bool:
    return 0xFE00 <= codepoint <= 0xFE0F or 0xE0100 <= codepoint <= 0xE01EF


def _decode_tags(codepoints: List[int]) -> str:
    characters = []
    for codepoint in codepoints:
        value = codepoint - _TAG_START
        if 0x20 <= value <= 0x7E:
            characters.append(chr(value))
        elif value in (0x09, 0x0A, 0x0D):
            characters.append(" ")
    return "".join(characters)


def _decode_variation_selectors(codepoints: List[int]) -> str:
    data = bytearray()
    for codepoint in codepoints:
        if 0xFE00 <= codepoint <= 0xFE0F:
            data.append(codepoint - 0xFE00)
        else:
            data.append(codepoint - 0xE0100 + 16)
    text = data.decode("utf-8", errors="replace")
    printable = sum(1 for character in text if character.isprintable())
    return text if text and printable / len(text) > 0.8 else ""


def _is_flag_tag_sequence(text: str, start: int, end: int) -> bool:
    """Tag runs that spell a subdivision flag (e.g. England) are legitimate emoji."""
    if start == 0 or ord(text[start - 1]) != _BLACK_FLAG:
        return False
    if ord(text[end - 1]) != _CANCEL_TAG or end - start > 8:
        return False
    body = text[start : end - 1]
    return all(
        0xE0030 <= ord(character) <= 0xE0039 or 0xE0061 <= ord(character) <= 0xE007A
        for character in body
    )


def check_hidden_text(context: FileContext) -> List[Finding]:
    text = context.text
    if text is None:
        return []
    # Fast path: plain ASCII files cannot contain any of these characters.
    if text.isascii():
        return []

    findings: List[Finding] = []
    findings.extend(_tag_findings(context, text))
    findings.extend(_bidi_findings(context, text))
    findings.extend(_invisible_findings(context, text))
    findings.extend(_variation_findings(context, text))
    return findings


def _runs(text: str, predicate) -> List[tuple]:
    runs = []
    index = 0
    length = len(text)
    while index < length:
        if predicate(ord(text[index])):
            start = index
            while index < length and predicate(ord(text[index])):
                index += 1
            runs.append((start, index))
        else:
            index += 1
    return runs


def _tag_findings(context: FileContext, text: str) -> List[Finding]:
    findings = []
    runs = [
        run
        for run in _runs(text, lambda codepoint: _TAG_START <= codepoint <= _TAG_END)
        if not _is_flag_tag_sequence(text, *run)
    ]
    for start, end in runs[:5]:
        decoded = _decode_tags([ord(character) for character in text[start:end]])
        findings.append(
            Finding(
                "RSC101",
                Severity.CRITICAL,
                context.rel,
                f"{end - start} invisible Unicode Tag characters hide this text: "
                f'"{safe_display(decoded, 200)}"',
                line_number(text, start),
                safe_display(decoded, 200),
            )
        )
    if len(runs) > 5:
        findings.append(
            Finding(
                "RSC101",
                Severity.CRITICAL,
                context.rel,
                f"{len(runs) - 5} more runs of hidden Unicode Tag characters in this file.",
                line_number(text, runs[5][0]),
            )
        )
    return findings


def _bidi_findings(context: FileContext, text: str) -> List[Finding]:
    unbalanced_lines = []
    balanced_lines = []
    for number, line in enumerate(text.split("\n"), start=1):
        if not any(ord(character) in _BIDI for character in line):
            continue
        embed_depth = isolate_depth = 0
        unbalanced = False
        for character in line:
            codepoint = ord(character)
            if codepoint in _BIDI_OPENERS_EMBED:
                embed_depth += 1
            elif codepoint == _BIDI_POP_EMBED:
                embed_depth -= 1
            elif codepoint in _BIDI_OPENERS_ISOLATE:
                isolate_depth += 1
            elif codepoint == _BIDI_POP_ISOLATE:
                isolate_depth -= 1
            if embed_depth < 0 or isolate_depth < 0:
                unbalanced = True
        if embed_depth or isolate_depth:
            unbalanced = True
        (unbalanced_lines if unbalanced else balanced_lines).append((number, line))

    if not unbalanced_lines and not balanced_lines:
        return []

    sensitive = context.is_code or context.is_agent_file
    if unbalanced_lines:
        severity = Severity.HIGH if sensitive else Severity.MEDIUM
        lines = unbalanced_lines
        detail = "unterminated bidirectional control characters"
    else:
        severity = Severity.MEDIUM if sensitive else Severity.LOW
        lines = balanced_lines
        detail = "bidirectional control characters"
    first_line, first_text = lines[0]
    line_list = ", ".join(str(number) for number, _ in lines[:8])
    more = "…" if len(lines) > 8 else ""
    return [
        Finding(
            "RSC102",
            severity,
            context.rel,
            f"{len(lines)} line(s) contain {detail} that can make displayed text differ from "
            f"what tools read (lines {line_list}{more}).",
            first_line,
            safe_display(first_text),
        )
    ]


def _invisible_findings(context: FileContext, text: str) -> List[Finding]:
    suspicious_positions = []
    longest_run = 0
    for start, end in _runs(text, lambda codepoint: codepoint in _INVISIBLE):
        if start == 0 and text[0] == "﻿" and end == 1:
            continue  # byte order mark
        run = text[start:end]
        length = end - start
        longest_run = max(longest_run, length)
        strong = any(ord(character) in _STRONG_INVISIBLE for character in run)
        if length >= 2:
            suspicious_positions.append((start, length))
        elif strong:
            suspicious_positions.append((start, length))
        else:
            # A lone joiner: legitimate between non-ASCII letters or emoji, odd between ASCII.
            before = text[start - 1] if start > 0 else ""
            after = text[end] if end < len(text) else ""
            if before.isascii() and before.isalnum() and after.isascii() and after.isalnum():
                suspicious_positions.append((start, length))

    if not suspicious_positions:
        return []

    total = sum(length for _, length in suspicious_positions)
    if context.is_agent_file:
        severity = Severity.HIGH
    elif longest_run >= 8:
        severity = Severity.HIGH
    elif context.is_code and total >= 1:
        severity = Severity.MEDIUM
    elif longest_run >= 3:
        severity = Severity.MEDIUM
    else:
        severity = Severity.LOW

    first_index = suspicious_positions[0][0]
    first_line = line_number(text, first_index)
    lines = sorted({line_number(text, index) for index, _ in suspicious_positions})
    line_list = ", ".join(str(number) for number in lines[:8]) + ("…" if len(lines) > 8 else "")
    extra = " A long run like this can encode hidden data." if longest_run >= 8 else ""
    return [
        Finding(
            "RSC103",
            severity,
            context.rel,
            f"{total} zero-width/invisible character(s) on line(s) {line_list}.{extra}",
            first_line,
            safe_display(text.split("\n")[first_line - 1]),
        )
    ]


def _variation_findings(context: FileContext, text: str) -> List[Finding]:
    findings = []
    runs = [run for run in _runs(text, _is_variation_selector) if run[1] - run[0] >= 4]
    for start, end in runs[:3]:
        decoded = _decode_variation_selectors([ord(character) for character in text[start:end]])
        message = f"{end - start} consecutive variation selectors can smuggle hidden bytes."
        if decoded:
            message += f' Decoded: "{safe_display(decoded, 200)}"'
        findings.append(
            Finding(
                "RSC104",
                Severity.HIGH,
                context.rel,
                message,
                line_number(text, start),
                safe_display(decoded, 200) if decoded else "",
            )
        )
    return findings
