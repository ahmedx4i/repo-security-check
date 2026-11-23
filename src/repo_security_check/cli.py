"""Command-line interface for Repo Security Check."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from .scanner import ScanResult, scan_repository


def _text_report(result: ScanResult) -> str:
    lines = [f"Repository security score: {result.score}/100", ""]
    for finding in result.findings:
        lines.append(f"{finding.status.upper():4}  {finding.message}")
    return "\n".join(lines)


def _markdown_report(result: ScanResult) -> str:
    lines = [
        "# Repository Security Check",
        "",
        f"Score: **{result.score}/100**",
        "",
        "| Check | Status | Details |",
        "| --- | --- | --- |",
    ]
    for finding in result.findings:
        status = "Pass" if finding.status == "pass" else "Warning"
        message = finding.message.replace("|", "\\|")
        lines.append(f"| {finding.key} | {status} | {message} |")
    return "\n".join(lines)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Check a local repository for common security hygiene signals."
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        type=Path,
        help="Repository directory to scan. Defaults to the current directory.",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json", "markdown"),
        default="text",
        help="Report format. Defaults to text.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        result = scan_repository(args.path)
    except ValueError as error:
        print(error)
        return 2

    if args.format == "json":
        print(json.dumps(result.as_dict(), ensure_ascii=False, indent=2))
    elif args.format == "markdown":
        print(_markdown_report(result))
    else:
        print(_text_report(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
