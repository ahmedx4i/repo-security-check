"""Committed credentials and sensitive files (RSC501-RSC502)."""

from __future__ import annotations

import posixpath
import re
from typing import List, Tuple

from ..models import Finding, Severity
from ..textutil import line_number
from .context import FileContext

_SECRET_PATTERNS: Tuple[Tuple[str, "re.Pattern[str]"], ...] = (
    ("AWS access key ID", re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b")),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{80,}\b")),
    ("Anthropic API key", re.compile(r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}")),
    ("OpenAI API key", re.compile(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9]{6,}-[0-9A-Za-z-]{10,}")),
    ("Slack webhook", re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,}")),
    ("Stripe live key", re.compile(r"\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}")),
    ("Private key", re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----")),
    ("npm access token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("PyPI API token", re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}")),
    ("Hugging Face token", re.compile(r"\bhf_[A-Za-z0-9]{34,}\b")),
    ("GitLab token", re.compile(r"\bglpat-[0-9A-Za-z_-]{20,}")),
    ("Discord webhook", re.compile(r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]{30,}")),
    ("Telegram bot token", re.compile(r"\b\d{8,10}:AA[0-9A-Za-z_-]{33}\b")),
    ("SendGrid API key", re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b")),
)
_PLACEHOLDER = re.compile(r"example|sample|dummy|placeholder|fake|xxxx|0000000000|your[_-]?", re.I)


def mask(secret: str) -> str:
    if secret.startswith("-----BEGIN"):
        return secret
    if len(secret) <= 10:
        return secret[:2] + "…"
    return f"{secret[:6]}…{secret[-2:]} ({len(secret)} chars)"


def check_secrets(context: FileContext) -> List[Finding]:
    text = context.text
    if text is None:
        return []
    findings: List[Finding] = []
    for label, pattern in _SECRET_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(0)
            if _PLACEHOLDER.search(value):
                continue
            findings.append(
                Finding(
                    "RSC501",
                    Severity.HIGH,
                    context.rel,
                    f"{label} committed in plain text.",
                    line_number(text, match.start()),
                    mask(value),
                )
            )
            if len(findings) >= 10:
                return findings
    return findings


_SENSITIVE_NAMES = {
    ".env", ".env.local", ".env.production", ".env.prod", ".env.development", ".env.staging",
    "credentials.json", "service-account.json", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    ".git-credentials", ".netrc", ".pgpass", "secrets.yml", "secrets.yaml",
}
_SENSITIVE_SUFFIXES = {".p12", ".pfx", ".jks", ".keystore", ".ppk", ".kdbx"}
_SAFE_MARKERS = ("example", "sample", "template", "dist", "defaults")


def check_sensitive_file(context: FileContext) -> List[Finding]:
    base = context.basename.lower()
    if any(marker in base for marker in _SAFE_MARKERS):
        return []
    extension = posixpath.splitext(base)[1]
    reason = None
    if base in _SENSITIVE_NAMES:
        reason = "usually holds credentials"
    elif extension in _SENSITIVE_SUFFIXES:
        reason = "is a key store or private key container"
    elif extension in {".pem", ".key"} and context.text and "PRIVATE KEY" in context.text:
        reason = "contains a private key"
    elif base in {".npmrc", ".pypirc"} and context.text and re.search(
        r"(?:_authToken|_auth|password)\s*[=:]\s*(?!\$\{)[^\s]+", context.text
    ):
        reason = "contains a registry credential"
    if reason is None:
        return []
    return [
        Finding(
            "RSC502",
            Severity.MEDIUM,
            context.rel,
            f"{context.basename} {reason}.",
            None,
            "",
        )
    ]
