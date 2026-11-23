"""Heuristic risk analysis of shell commands and scripts.

The same analysis is used wherever a repository can make something run on a
developer's machine: editor tasks, agent hooks, MCP servers, install scripts,
container lifecycle commands and git hooks.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence

from ..models import Severity


@dataclass(frozen=True)
class Signal:
    tag: str
    severity: Severity
    reason: str
    pattern: "re.Pattern[str]"


def _p(expression: str) -> "re.Pattern[str]":
    return re.compile(expression, re.IGNORECASE)


_DOWNLOADERS = r"(?:curl|wget|fetch|iwr|irm|invoke-webrequest|invoke-restmethod)"
_INTERPRETERS = (
    r"(?:sudo\s+)?(?:ba|z|da|k|fi)?sh|python[0-9.]*|node|deno|bun|perl|ruby|php|"
    r"iex|invoke-expression|pwsh|powershell"
)

# Flags that switch AI coding CLIs into "run anything without asking" mode.
# Built from fragments so this source file does not match its own rules.
_DANGER = "danger" + "ously"
AI_BYPASS_PATTERNS: Sequence["re.Pattern[str]"] = (
    _p(r"\bclaude\b[^\n]{0,200}--" + _DANGER + r"-skip-permissions"),
    _p(r"\bclaude\b[^\n]{0,200}--permission-mode[=\s]+bypassPermissions"),
    _p(r"\bgemini\b[^\n]{0,200}(?:--yo" + r"lo\b|--approval-mode[=\s]+yolo)"),
    _p(r"\bq\s+chat\b[^\n]{0,200}--trust-all" + r"-tools"),
    _p(r"\bcodex\b[^\n]{0,200}(?:--" + _DANGER + r"-bypass-approvals-and-sandbox|--yo" + r"lo\b)"),
    _p(r"\bcopilot\b[^\n]{0,200}(?:--allow-all" + r"-tools|--allow-all\b|--yo" + r"lo\b)"),
)

_EXFIL_HOSTS = (
    r"webhook\.site|requestbin|pipedream\.net|ngrok(?:-free)?\.(?:io|app|dev)|"
    r"burpcollaborator\.net|oastify\.com|interact\.sh|oast\.(?:pro|live|site|online|fun|me)|"
    r"discord(?:app)?\.com/api/webhooks|api\.telegram\.org/bot|pastebin\.com/raw|"
    r"transfer\.sh|trycloudflare\.com|beeceptor\.com|hookbin\.com|canarytokens\.com"
)

SIGNALS: Sequence[Signal] = (
    # Download and execute ---------------------------------------------------
    Signal(
        "exec", Severity.CRITICAL, "downloads code and pipes it into an interpreter",
        _p(_DOWNLOADERS + r"\b[^\n|;&]*\|\s*(?:" + _INTERPRETERS + r")\b"),
    ),
    Signal(
        "exec", Severity.CRITICAL, "executes the output of a download",
        _p(r"(?:\$\(|`|<\()\s*" + _DOWNLOADERS + r"\b"),
    ),
    Signal(
        "exec", Severity.CRITICAL, "PowerShell download-and-execute",
        _p(r"(?:iex|invoke-expression)\b[^\n]{0,80}(?:downloadstring|net\.webclient|iwr|irm|"
           r"invoke-webrequest|invoke-restmethod)|downloadstring\s*\("),
    ),
    Signal(
        "exec", Severity.CRITICAL, "runs an encoded PowerShell command",
        _p(r"(?:powershell|pwsh)(?:\.exe)?\b[^\n]*\s-(?:e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{16,}"),
    ),
    Signal(
        "exec", Severity.CRITICAL, "decodes base64 and executes it",
        _p(r"base64\s+(?:-d|--decode|-D)\b[^\n]*\|\s*(?:" + _INTERPRETERS + r")\b"
           r"|(?:eval|exec|Function)\s*\(\s*(?:atob|Buffer\.from|base64\.b64decode|b64decode|"
           r"codecs\.decode|bytes\.fromhex|zlib\.decompress)"
           r"|FromBase64String"),
    ),
    Signal(
        "revshell", Severity.CRITICAL, "opens a reverse shell or raw network socket",
        _p(r"/dev/(?:tcp|udp)/|\bnc(?:at)?\b[^\n]*\s-(?:e|c)\s|\bsocat\b[^\n]*exec:|"
           r"\bmkfifo\b[^\n]*\bnc\b|socket\.socket\([^\n]*\)\s*[^\n]*\.connect\("),
    ),
    Signal(
        "exfil", Severity.CRITICAL, "contacts a known data-collection or tunnelling service",
        _p(r"(?:https?://)?(?:[\w-]+\.)*(?:" + _EXFIL_HOSTS + r")"),
    ),
    Signal(
        "exfil", Severity.HIGH, "uploads local files or data to a remote host",
        _p(r"\bcurl\b[^\n]*(?:\s-(?:d|F|T)\s*@|--data(?:-binary|-raw)?\s+@|--upload-file|-T\s)"),
    ),
    Signal(
        "exfil", Severity.HIGH, "Markdown image whose URL carries templated data (exfiltration via image fetch)",
        _p(r"!\[[^\]]*\]\(\s*https?://[^)\s]*[?&][\w-]+=(?:\{|\$|<|%7B|\[)"),
    ),
    # Secret access -----------------------------------------------------------
    Signal(
        "secret", Severity.HIGH, "reads credential stores (SSH, cloud, package-registry or browser secrets)",
        _p(r"(?:~|\$HOME|\$\{HOME\}|%USERPROFILE%|homedir\(\)[^\n]{0,20})[/\\]+\."
           r"(?:ssh|aws|gnupg|kube|docker|azure|config/gcloud|npmrc|pypirc|netrc|git-credentials)"
           r"|\bid_(?:rsa|dsa|ecdsa|ed25519)\b|\.git-credentials|Login Data|\bwallet\.dat\b|"
           r"\.config/(?:solana|exodus)|Library/Keychains"),
    ),
    Signal(
        "secret", Severity.HIGH, "dumps all environment variables",
        _p(r"\bprintenv\b|\benv\s*(?:\||>)|JSON\.stringify\(\s*process\.env\s*\)|"
           r"dict\(\s*os\.environ\s*\)|Get-ChildItem\s+env:|\bset\s*\|\s*curl"),
    ),
    # Obfuscation -------------------------------------------------------------
    Signal(
        "obf", Severity.HIGH, "contains a long base64 blob",
        re.compile(r"[A-Za-z0-9+/]{160,}={0,2}"),
    ),
    Signal(
        "obf", Severity.HIGH, "contains heavily escaped or char-coded strings",
        _p(r"(?:\\x[0-9a-f]{2}){12,}|String\.fromCharCode\(\s*\d+(?:\s*,\s*\d+){10,}|"
           r"(?:chr\(\d+\)\s*\+\s*){8,}"),
    ),
    # Persistence and destruction ---------------------------------------------
    Signal(
        "persist", Severity.HIGH, "installs persistence (cron, launch agents, startup items or shell profiles)",
        _p(r"\bcrontab\b|\blaunchctl\b|LaunchAgents|\bschtasks\b|systemctl\s+--user\s+enable|"
           r">>\s*(?:~|\$HOME)/\.(?:bashrc|zshrc|profile|bash_profile)|"
           r"CurrentVersion\\+Run\b|Start Menu\\+Programs\\+Startup"),
    ),
    Signal(
        "destroy", Severity.HIGH, "deletes the home directory or filesystem root",
        _p(r"\brm\s+-(?:[a-z]*r[a-z]*f|[a-z]*f[a-z]*r)[a-z]*\s+(?:/|~|\$HOME|/\*)(?:\s|$|;|&)"),
    ),
    # Plain network and inline interpreters ----------------------------------
    Signal(
        "net", Severity.HIGH, "downloads from the network",
        _p(r"\b(?:curl|wget|invoke-webrequest|iwr|irm|bitsadmin|tftp)\b|certutil[^\n]*-urlcache|"
           r"urllib\.request|requests\.(?:get|post)\(|https?\.get\(|\bfetch\(\s*['\"`]https?:"),
    ),
    Signal(
        "net", Severity.MEDIUM, "references a raw IP address URL",
        _p(r"https?://(?!127\.|0\.0\.0\.0|localhost)\d{1,3}(?:\.\d{1,3}){3}"),
    ),
    Signal(
        "inline", Severity.MEDIUM, "runs inline interpreter code",
        _p(r"\b(?:python[0-9.]*|node|deno|perl|ruby|php)\s+-(?:c|e|r)\s|\beval\b"),
    ),
)

AGENT_FILE_TAGS = {"exec", "revshell", "exfil", "secret", "obf", "persist", "destroy", "ai"}


@dataclass(frozen=True)
class CommandRisk:
    severity: Optional[Severity]
    reasons: List[str]

    @property
    def summary(self) -> str:
        return "; ".join(self.reasons)


def analyze(
    text: str,
    tags: Optional[set] = None,
    caps: Optional[Dict[str, Severity]] = None,
) -> CommandRisk:
    """Return the highest severity and reasons found in a command or script.

    ``tags`` limits which signal families are considered; ``caps`` lowers the
    severity of a family in contexts where it is common and legitimate.
    """
    reasons: List[str] = []
    highest: Optional[Severity] = None
    for signal in SIGNALS:
        if tags is not None and signal.tag not in tags:
            continue
        if signal.pattern.search(text):
            severity = signal.severity
            if caps and signal.tag in caps:
                severity = min(severity, caps[signal.tag])
            if signal.reason not in reasons:
                reasons.append(signal.reason)
            if highest is None or severity > highest:
                highest = severity
    if tags is None or "ai" in tags:
        if any(pattern.search(text) for pattern in AI_BYPASS_PATTERNS):
            reasons.append("starts an AI coding agent with its permission checks disabled")
            highest = Severity.CRITICAL
    return CommandRisk(highest, reasons)


def escalate(base: Severity, risk: CommandRisk) -> Severity:
    if risk.severity is None:
        return base
    return max(base, risk.severity)
