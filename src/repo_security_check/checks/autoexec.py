"""Files that make tools run commands automatically (RSC301-RSC311)."""

from __future__ import annotations

import posixpath
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ..models import Finding, Severity
from ..textutil import as_command, find_line, line_number, parse_jsonc, safe_display
from . import commands
from .context import FileContext


def _finding(
    rule_id: str,
    severity: Severity,
    context: FileContext,
    message: str,
    command: str = "",
    line: Optional[int] = None,
) -> Finding:
    if line is None and command:
        line = find_line(context.text or "", command)
    return Finding(rule_id, severity, context.rel, message, line, safe_display(command))


_SCRIPT_REFERENCE = re.compile(
    r"(?:^|[\s'\"=(])(?:\$\{workspace(?:Folder|Root)\}[/\\])?"
    r"((?:\.{1,2}/)?[\w.@-]+(?:/[\w.@-]+)*\.(?:js|mjs|cjs|ts|py|sh|bash|zsh|ps1|rb|pl|php|bat|cmd))\b"
)
_MAX_REFERENCED_BYTES = 1_000_000


def _referenced_scripts(context: FileContext, command: str) -> List[Tuple[str, str]]:
    """Read scripts inside the repository that a command executes."""
    if context.root is None:
        return []
    root = context.root
    config_dir = posixpath.dirname(context.rel)
    scripts = []
    for match in _SCRIPT_REFERENCE.finditer(command):
        reference = match.group(1)
        for base in ("", config_dir, posixpath.dirname(config_dir)):
            candidate = posixpath.normpath(posixpath.join(base, reference))
            if candidate.startswith("../") or candidate == "..":
                continue
            path = root / candidate
            try:
                if path.is_symlink() or not path.is_file() or path.stat().st_size > _MAX_REFERENCED_BYTES:
                    continue
                path.resolve().relative_to(root.resolve())
                scripts.append((candidate, path.read_text(encoding="utf-8", errors="replace")))
                break
            except (OSError, ValueError):
                continue
        if len(scripts) >= 3:
            break
    return scripts


def _command_finding(
    rule_id: str,
    base: Severity,
    context: FileContext,
    what: str,
    command: str,
    line: Optional[int] = None,
    caps: Optional[Dict[str, Severity]] = None,
) -> Finding:
    risk = commands.analyze(command, caps=caps)
    severity = commands.escalate(base, risk)
    reasons = list(risk.reasons)
    for script_rel, script_text in _referenced_scripts(context, command):
        script_risk = commands.analyze(script_text, caps=caps)
        if script_risk.severity is not None:
            severity = commands.escalate(severity, script_risk)
            reasons.append(f"{script_rel} (run by this command) {script_risk.summary}")
    message = what
    if reasons:
        message += " It " + "; ".join(reasons) + "."
    return _finding(rule_id, severity, context, message, command, line)


# --------------------------------------------------------------------------- VS Code


def _vscode_tasks(context: FileContext, tasks: Any) -> List[Finding]:
    findings = []
    if not isinstance(tasks, list):
        return findings
    for task in tasks:
        if not isinstance(task, dict):
            continue
        options = task.get("runOptions")
        if not (isinstance(options, dict) and options.get("runOn") == "folderOpen"):
            continue
        parts = [as_command(task.get("command", ""))]
        if task.get("args"):
            parts.append(as_command(task.get("args")))
        for platform in ("windows", "linux", "osx"):
            override = task.get(platform)
            if isinstance(override, dict) and override.get("command"):
                parts.append(as_command(override.get("command")))
                if override.get("args"):
                    parts.append(as_command(override.get("args")))
        command = " ".join(part for part in parts if part).strip()
        label = str(task.get("label", "unnamed task"))
        line = find_line(context.text or "", task.get("command") if isinstance(task.get("command"), str) else "", '"folderOpen"')
        findings.append(
            _command_finding(
                "RSC301",
                Severity.HIGH,
                context,
                f'Task "{safe_display(label, 60)}" runs automatically when the folder is opened.',
                command or label,
                line,
            )
        )
    return findings


_EXECUTABLE_PATH_SETTINGS = (
    "python.defaultInterpreterPath", "python.pythonPath", "git.path", "eslint.nodePath",
    "go.alternateTools", "php.validate.executablePath", "terminal.integrated.shell.linux",
    "terminal.integrated.shell.osx", "terminal.integrated.shell.windows",
)


def _vscode_settings(context: FileContext, settings: Any) -> List[Finding]:
    findings: List[Finding] = []
    if not isinstance(settings, dict):
        return findings
    text = context.text or ""

    def flag(key: str, severity: Severity, message: str) -> None:
        findings.append(
            Finding("RSC302", severity, context.rel, message, find_line(text, f'"{key}"'),
                    safe_display(f"{key}: {settings.get(key)!r}"))
        )

    for key in ("chat.tools.autoApprove", "chat.tools.global.autoApprove"):
        if settings.get(key) is True:
            flag(key, Severity.CRITICAL,
                 f"{key} lets the AI assistant run tools and terminal commands without asking "
                 "(the setting abused in CVE-2025-53773).")
    terminal_rules = settings.get("chat.tools.terminal.autoApprove")
    if isinstance(terminal_rules, dict) and any(
        value is True and str(pattern).strip() in {"/.*/", "/.+/", "*", ".*"}
        for pattern, value in terminal_rules.items()
    ):
        flag("chat.tools.terminal.autoApprove", Severity.CRITICAL,
             "Terminal auto-approve rule matches every command.")
    if str(settings.get("task.allowAutomaticTasks", "")).lower() == "on":
        flag("task.allowAutomaticTasks", Severity.HIGH,
             "Automatic folder-open tasks are allowed without a prompt.")
    if settings.get("security.workspace.trust.enabled") is False:
        flag("security.workspace.trust.enabled", Severity.HIGH,
             "Workspace trust (VS Code's restricted mode) is disabled.")
    for key in _EXECUTABLE_PATH_SETTINGS:
        value = settings.get(key)
        if isinstance(value, str) and _points_into_repository(value):
            flag(key, Severity.LOW,
                 f"{key} points at a program inside the repository, which the editor will run.")
    servers = settings.get("mcp")
    if isinstance(servers, dict):
        findings.extend(_mcp_servers(context, servers.get("servers")))
    return findings


def _points_into_repository(value: str) -> bool:
    value = value.strip()
    return value.startswith(("./", ".\\", "${workspaceFolder}", "${workspaceRoot}")) or (
        not value.startswith(("/", "~", "$")) and ("/" in value or "\\" in value)
        and not re.match(r"^[A-Za-z]:\\", value)
    )


# --------------------------------------------------------------------------- Claude Code

_CLAUDE_COMMAND_KEYS = (
    "apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "otelHeadersHelper",
    "statusLine", "fileSuggestion",
)
_REDIRECT_ENV = re.compile(
    r"^(?:ANTHROPIC_(?:BASE_URL|API_URL|BEDROCK_BASE_URL|VERTEX_BASE_URL|FOUNDRY_BASE_URL)|"
    r"OPENAI_BASE_URL|OPENAI_API_BASE|GEMINI_BASE_URL|GOOGLE_GEMINI_BASE_URL|"
    r"(?:HTTPS?|ALL)_PROXY|NODE_EXTRA_CA_CERTS|SSL_CERT_FILE|REQUESTS_CA_BUNDLE)$",
    re.IGNORECASE,
)
_LOADER_ENV = re.compile(
    r"^(?:NODE_OPTIONS|LD_PRELOAD|LD_LIBRARY_PATH|DYLD_INSERT_LIBRARIES|DYLD_LIBRARY_PATH|"
    r"PYTHONSTARTUP|PYTHONPATH|PERL5OPT|RUBYOPT|BASH_ENV|ENV|PROMPT_COMMAND|GIT_SSH_COMMAND|"
    r"GIT_EXTERNAL_DIFF|PATH)$",
    re.IGNORECASE,
)


def _iter_hook_commands(hooks: Any) -> Iterable[Tuple[str, str]]:
    if not isinstance(hooks, dict):
        return
    for event, matchers in hooks.items():
        if not isinstance(matchers, list):
            continue
        for matcher in matchers:
            if not isinstance(matcher, dict):
                continue
            for hook in matcher.get("hooks", []) or []:
                if isinstance(hook, dict):
                    command = hook.get("command") or hook.get("url") or hook.get("prompt")
                    if command:
                        yield str(event), as_command(command)


def _claude_settings(context: FileContext, settings: Any) -> List[Finding]:
    findings: List[Finding] = []
    if not isinstance(settings, dict):
        return findings
    text = context.text or ""

    for event, command in _iter_hook_commands(settings.get("hooks")):
        findings.append(
            _command_finding(
                "RSC303", Severity.MEDIUM, context,
                f"{event} hook runs a command automatically during Claude Code sessions.", command,
            )
        )
    for key in _CLAUDE_COMMAND_KEYS:
        value = settings.get(key)
        if not value:
            continue
        command = as_command(value)
        base = Severity.HIGH if key in {"apiKeyHelper", "awsCredentialExport", "awsAuthRefresh"} else Severity.MEDIUM
        findings.append(
            _command_finding("RSC303", base, context, f"{key} runs a shell command.", command,
                             find_line(text, f'"{key}"'))
        )

    def risky(key: str, severity: Severity, message: str, evidence: str) -> None:
        findings.append(Finding("RSC304", severity, context.rel, message,
                                find_line(text, f'"{key}"'), safe_display(evidence)))

    if settings.get("enableAllProjectMcpServers") is True:
        risky("enableAllProjectMcpServers", Severity.HIGH,
              "Approves every MCP server in the project's .mcp.json without a prompt.",
              "enableAllProjectMcpServers: true")
    permissions = settings.get("permissions")
    if isinstance(permissions, dict):
        mode = permissions.get("defaultMode")
        if mode in {"bypassPermissions", "acceptEdits", "auto"}:
            risky("defaultMode",
                  Severity.HIGH if mode == "bypassPermissions" else Severity.MEDIUM,
                  f'Sets the default permission mode to "{mode}".', f"defaultMode: {mode}")
        allow = permissions.get("allow")
        if isinstance(allow, list):
            broad = [str(rule) for rule in allow if str(rule).strip() in
                     {"Bash", "Bash(*)", "Bash(:*)", "Bash(**)", "*", "WebFetch", "mcp__*"}]
            if broad:
                risky("allow", Severity.HIGH,
                      "Pre-approves unrestricted tools: " + ", ".join(broad), ", ".join(broad))
    env = settings.get("env")
    if isinstance(env, dict):
        for name, value in env.items():
            if _REDIRECT_ENV.match(str(name)):
                risky(str(name), Severity.CRITICAL,
                      f"Overrides {name}, which can send API keys or traffic to another server "
                      "(the technique behind CVE-2026-21852).", f"{name}={value}")
            elif _LOADER_ENV.match(str(name)):
                risky(str(name), Severity.HIGH,
                      f"Sets {name}, which can make every process Claude Code starts load "
                      "attacker-controlled code.", f"{name}={value}")
    marketplaces = settings.get("extraKnownMarketplaces")
    if isinstance(marketplaces, dict) and marketplaces:
        risky("extraKnownMarketplaces", Severity.MEDIUM,
              "Registers plugin marketplaces; plugins can add hooks, MCP servers and commands.",
              ", ".join(str(name) for name in marketplaces))
    return findings


# --------------------------------------------------------------------------- MCP

_SHELL_WRAPPER = re.compile(r"^(?:.*[/\\])?(?:ba|z|da|k)?sh(?:\.exe)?$|^(?:cmd|powershell|pwsh)(?:\.exe)?$", re.I)
_PACKAGE_RUNNERS = {"npx", "bunx", "pnpx", "uvx", "pipx", "yarn", "pnpm", "deno", "dlx"}


_EXACT_VERSION = re.compile(r"^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
_SPEC_FLAGS = {"--from", "-p", "--package", "--with"}


def _split_spec(spec: str) -> Tuple[str, str]:
    if "==" in spec:
        name, _, version = spec.partition("==")
        return name, version
    index = spec.find("@", 1 if spec.startswith("@") else 0)
    if index <= 0:
        return spec, ""
    return spec[:index], spec[index + 1 :]


def _unpinned_package(command: str, args: List[str]) -> Optional[str]:
    """Return the package spec if a package runner fetches it without an exact version."""
    runner = posixpath.basename(command.replace("\\", "/")).lower()
    runner = re.sub(r"\.(?:cmd|exe)$", "", runner)
    if runner not in _PACKAGE_RUNNERS:
        return None
    spec = None
    previous = ""
    for argument in args:
        if previous in _SPEC_FLAGS:
            spec = argument.split("=", 1)[-1]
            break
        if argument.startswith("--package=") or argument.startswith("--from="):
            spec = argument.split("=", 1)[1]
            break
        previous = argument
        if argument.startswith("-") or argument in {"dlx", "exec", "run", "x", "tool"}:
            continue
        spec = argument
        break
    if not spec or spec.startswith(("./", "../", "/", "git+", "file:")):
        return None
    if spec.startswith(("npm:", "jsr:")):
        spec = spec.split(":", 1)[1]
    _, version = _split_spec(spec)
    if _EXACT_VERSION.match(version):
        return None
    return spec


def _mcp_servers(context: FileContext, servers: Any) -> List[Finding]:
    findings: List[Finding] = []
    if not isinstance(servers, dict):
        return findings
    text = context.text or ""
    for name, server in servers.items():
        if not isinstance(server, dict):
            continue
        label = safe_display(str(name), 60)
        line = find_line(text, f'"{name}"')
        command = server.get("command")
        args = [str(argument) for argument in server.get("args", []) or []] if isinstance(server.get("args", []), list) else []
        url = server.get("url") or server.get("serverUrl") or server.get("httpUrl")
        if isinstance(command, str) and command:
            full = " ".join([command] + args)
            risk = commands.analyze(full)
            reasons = list(risk.reasons)
            severity = Severity.MEDIUM
            if _SHELL_WRAPPER.match(command.strip()):
                reasons.append("runs through a shell wrapper")
                severity = Severity.HIGH
            unpinned = _unpinned_package(command, args)
            if unpinned:
                reasons.append(f'installs "{safe_display(unpinned, 60)}" without a pinned version')
            lower = full.lower()
            if posixpath.basename(command).lower().startswith(("docker", "podman")):
                if "--privileged" in lower or "docker.sock" in lower or re.search(r"-v\s+/:/|--volume[= ]/:", lower):
                    reasons.append("starts a privileged container or mounts the host")
                    severity = Severity.HIGH
            if command.startswith(("./", ".\\")) or (not command.startswith("/") and "/" in command):
                reasons.append("executes a program shipped inside the repository")
            severity = commands.escalate(severity, risk)
            message = f'MCP server "{label}" starts a local process when the agent loads it.'
            if reasons:
                message += " It " + "; ".join(reasons) + "."
            findings.append(Finding("RSC305", severity, context.rel, message, line, safe_display(full)))
        elif isinstance(url, str) and url:
            if url.startswith("http://") and not re.match(r"http://(?:localhost|127\.|\[::1\])", url):
                findings.append(Finding("RSC305", Severity.MEDIUM, context.rel,
                                        f'MCP server "{label}" uses unencrypted HTTP.', line, safe_display(url)))
            risk = commands.analyze(url, {"exfil", "net"})
            if risk.severity and risk.severity >= Severity.CRITICAL:
                findings.append(Finding("RSC305", Severity.HIGH, context.rel,
                                        f'MCP server "{label}" {risk.summary}.', line, safe_display(url)))
    return findings


def _mcp_config(context: FileContext, data: Any) -> List[Finding]:
    if not isinstance(data, dict):
        return []
    servers = data.get("mcpServers")
    if servers is None:
        servers = data.get("servers")
    if servers is None and isinstance(data.get("mcp"), dict):
        servers = data["mcp"].get("servers")
    return _mcp_servers(context, servers)


# --------------------------------------------------------------------------- Dev Containers

_DEVCONTAINER_COMMANDS = (
    ("initializeCommand", Severity.HIGH, "runs on the HOST machine before the container is created"),
    ("onCreateCommand", Severity.INFO, "runs inside the container when it is created"),
    ("updateContentCommand", Severity.INFO, "runs inside the container when content updates"),
    ("postCreateCommand", Severity.INFO, "runs inside the container after creation"),
    ("postStartCommand", Severity.INFO, "runs inside the container on every start"),
    ("postAttachCommand", Severity.INFO, "runs inside the container whenever a tool attaches"),
)


def _devcontainer(context: FileContext, data: Any) -> List[Finding]:
    findings = []
    if not isinstance(data, dict):
        return findings
    for key, base, description in _DEVCONTAINER_COMMANDS:
        value = data.get(key)
        if not value:
            continue
        command = as_command(value)
        findings.append(
            _command_finding("RSC306", base, context, f"{key} {description}.", command,
                             find_line(context.text or "", f'"{key}"'),
                             caps=None if key == "initializeCommand" else _COMMON_IN_BUILDS)
        )
    run_args = " ".join(str(item) for item in data.get("runArgs", []) or [] if isinstance(item, str))
    if "--privileged" in run_args or "docker.sock" in run_args:
        findings.append(Finding("RSC306", Severity.MEDIUM, context.rel,
                                "Container runs privileged or with the Docker socket, so code inside "
                                "it can control the host.", find_line(context.text or "", '"runArgs"'),
                                safe_display(run_args)))
    return findings


# --------------------------------------------------------------------------- Packages

# Build and install steps legitimately download things and run inline code.
_COMMON_IN_BUILDS = {"net": Severity.MEDIUM, "inline": Severity.LOW, "obf": Severity.MEDIUM}

_NPM_LIFECYCLE = ("preinstall", "install", "postinstall", "prepare", "preprepare", "postprepare")
_COMPOSER_LIFECYCLE = ("pre-install-cmd", "post-install-cmd", "pre-update-cmd", "post-update-cmd",
                       "post-autoload-dump", "post-root-package-install", "post-create-project-cmd")


def _package_scripts(context: FileContext, data: Any, names: Tuple[str, ...], tool: str) -> List[Finding]:
    findings = []
    if not isinstance(data, dict) or not isinstance(data.get("scripts"), dict):
        return findings
    scripts = data["scripts"]
    for name in names:
        if name not in scripts:
            continue
        command = as_command(scripts[name])
        findings.append(
            _command_finding("RSC307", Severity.LOW, context,
                             f'"{name}" script runs automatically on `{tool} install`.', command,
                             find_line(context.text or "", f'"{name}"'), caps=_COMMON_IN_BUILDS)
        )
    return findings


_SETUP_NETWORK = re.compile(r"urllib|requests\.|http\.client|socket\.|urlopen|wget|curl", re.I)
_SETUP_EXEC = re.compile(r"\bexec\(|\beval\(|subprocess|os\.system|os\.popen|b64decode|marshal\.loads|__import__\(", re.I)


def _setup_py(context: FileContext) -> List[Finding]:
    text = context.text or ""
    risk = commands.analyze(text, {"exec", "revshell", "exfil", "secret", "obf", "persist", "ai"})
    network = _SETUP_NETWORK.search(text)
    execution = _SETUP_EXEC.search(text)
    if risk.severity is None and not (network and execution):
        return []
    reasons = list(risk.reasons)
    if network and execution:
        reasons.append("combines network access with code execution")
    anchor = network or execution
    line = line_number(text, anchor.start()) if anchor else None
    severity = commands.escalate(Severity.HIGH, risk)
    return [Finding("RSC308", severity, context.rel,
                    "setup.py runs on `pip install` and " + "; ".join(reasons) + ".", line,
                    safe_display(text.split("\n")[line - 1]) if line else "")]


# --------------------------------------------------------------------------- Shell-like files


def _script_file(context: FileContext, rule_id: str, what: str) -> List[Finding]:
    text = context.text or ""
    risk = commands.analyze(text)
    severity = commands.escalate(Severity.LOW, risk)
    message = what
    if risk.reasons:
        message += f" The script {risk.summary}."
    first = next((line for line in text.splitlines() if line.strip() and not line.startswith("#")), "")
    return [Finding(rule_id, severity, context.rel, message, find_line(text, first) if first else 1,
                    safe_display(first))]


_SUBMODULE_URL = re.compile(r"^\s*url\s*=\s*(.+)$", re.MULTILINE)
_SUBMODULE_PATH = re.compile(r"^\s*path\s*=\s*(.+)$", re.MULTILINE)


def _gitmodules(context: FileContext) -> List[Finding]:
    findings = []
    text = context.text or ""
    for regex in (_SUBMODULE_URL, _SUBMODULE_PATH):
        for match in regex.finditer(text):
            value = match.group(1).strip().strip('"')
            if value.lower().startswith("ext::") or value.startswith("-"):
                findings.append(Finding("RSC311", Severity.CRITICAL, context.rel,
                                        "Submodule entry can execute commands when submodules are fetched.",
                                        line_number(text, match.start()), safe_display(value)))
            elif value.lower().startswith(("file://", "fd::")):
                findings.append(Finding("RSC311", Severity.MEDIUM, context.rel,
                                        "Submodule uses a local-file transport.",
                                        line_number(text, match.start()), safe_display(value)))
    return findings


# --------------------------------------------------------------------------- Fallbacks

_FALLBACK_FOLDER_OPEN = re.compile(r'"runOn"\s*:\s*"folderOpen"')
_FALLBACK_AUTO_APPROVE = re.compile(r'"chat\.tools\.(?:global\.)?autoApprove"\s*:\s*true')


def _unparsable(context: FileContext, kind: str) -> List[Finding]:
    """A config that tools may accept but we cannot parse still gets a regex pass."""
    text = context.text or ""
    findings = []
    match = _FALLBACK_FOLDER_OPEN.search(text)
    if match:
        findings.append(Finding("RSC301", Severity.HIGH, context.rel,
                                "A folder-open task is declared (file could not be fully parsed).",
                                line_number(text, match.start()), safe_display(match.group(0))))
    match = _FALLBACK_AUTO_APPROVE.search(text)
    if match:
        findings.append(Finding("RSC302", Severity.CRITICAL, context.rel,
                                "AI tool auto-approval is enabled (file could not be fully parsed).",
                                line_number(text, match.start()), safe_display(match.group(0))))
    if kind in {"claude", "mcp"} and '"command"' in text:
        index = text.find('"command"')
        line = line_number(text, index)
        snippet = text.split("\n")[line - 1]
        findings.append(_command_finding(
            "RSC303" if kind == "claude" else "RSC305", Severity.MEDIUM, context,
            "Declares a command but the file could not be parsed for review.", snippet.strip(), line))
    return findings


# --------------------------------------------------------------------------- Dispatcher

_MCP_BASENAMES = {".mcp.json", "mcp.json", "mcp_config.json", "claude_desktop_config.json"}


def _kind(context: FileContext) -> Optional[str]:
    lower = context.lower
    base = posixpath.basename(lower)
    if lower.endswith(".vscode/tasks.json"):
        return "vscode-tasks"
    if lower.endswith(".vscode/settings.json"):
        return "vscode-settings"
    if base.endswith(".code-workspace"):
        return "vscode-workspace"
    if re.search(r"(?:^|/)\.claude/settings(?:\.local)?\.json$", lower):
        return "claude"
    if base in _MCP_BASENAMES or lower.endswith((".gemini/settings.json", ".qwen/settings.json")):
        return "mcp"
    if base == "devcontainer.json" or base == ".devcontainer.json":
        return "devcontainer"
    if base == "package.json":
        return "npm"
    if base == "composer.json":
        return "composer"
    if base == "setup.py":
        return "setup-py"
    if re.search(r"(?:^|/)\.(?:husky|githooks)/[^/_][^/]*$", lower):
        return "git-hook"
    if base == ".envrc":
        return "envrc"
    if base == ".gitmodules":
        return "gitmodules"
    return None


def check_auto_execution(context: FileContext) -> List[Finding]:
    if context.text is None:
        return []
    kind = _kind(context)
    if kind is None:
        return []
    if kind == "setup-py":
        return _setup_py(context)
    if kind == "git-hook":
        return _script_file(context, "RSC309", "Git hook runs on commit/checkout once hooks are installed.")
    if kind == "envrc":
        return _script_file(context, "RSC310", ".envrc runs every time you enter the directory (after `direnv allow`).")
    if kind == "gitmodules":
        return _gitmodules(context)

    data = parse_jsonc(context.text)
    if data is None:
        return _unparsable(context, kind)
    if kind == "vscode-tasks":
        return _vscode_tasks(context, data.get("tasks") if isinstance(data, dict) else None)
    if kind == "vscode-settings":
        return _vscode_settings(context, data)
    if kind == "vscode-workspace":
        findings: List[Finding] = []
        if isinstance(data, dict):
            tasks = data.get("tasks")
            if isinstance(tasks, dict):
                findings.extend(_vscode_tasks(context, tasks.get("tasks")))
            findings.extend(_vscode_settings(context, data.get("settings")))
        return findings
    if kind == "claude":
        return _claude_settings(context, data) + _mcp_config(context, data)
    if kind == "mcp":
        return _mcp_config(context, data)
    if kind == "devcontainer":
        return _devcontainer(context, data)
    if kind == "npm":
        return _package_scripts(context, data, _NPM_LIFECYCLE, "npm")
    if kind == "composer":
        return _package_scripts(context, data, _COMPOSER_LIFECYCLE, "composer")
    return []
