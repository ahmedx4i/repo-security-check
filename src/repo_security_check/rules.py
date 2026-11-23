"""Catalog of every rule the scanner can report.

Each rule carries a description, a remediation hint and public references so
that every finding can be explained and checked independently.
"""

from __future__ import annotations

from typing import Dict

from .models import Rule, Severity

_TROJAN_SOURCE = "https://trojansource.codes/"
_RULES_FILE_BACKDOOR = (
    "https://pillar.security/blog/"
    "new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents"
)
_UNICODE_TAGS_CISCO = (
    "https://blogs.cisco.com/ai/understanding-and-mitigating-unicode-tag-prompt-injection"
)
_UNICODE_TAGS_AWS = (
    "https://aws.amazon.com/blogs/security/"
    "defending-llm-applications-against-unicode-character-smuggling/"
)
_EMOJI_SMUGGLING = "https://paulbutler.org/2025/smuggling-arbitrary-data-through-an-emoji/"
_TOOL_POISONING = "https://simonwillison.net/2025/Apr/9/mcp-prompt-injection/"
_COPILOT_RCE = (
    "https://embracethered.com/blog/posts/2025/"
    "github-copilot-remote-code-execution-via-prompt-injection/"
)
_CLAUDE_PROJECT_FILES = (
    "https://research.checkpoint.com/2026/"
    "rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/"
)
_CLAUDE_SETTINGS = "https://code.claude.com/docs/en/settings"
_MCPOISON = "https://research.checkpoint.com/2025/cursor-vulnerability-mcpoison/"
_VSCODE_TASKS = "https://code.visualstudio.com/docs/editor/tasks"
_VSCODE_TRUST = "https://code.visualstudio.com/docs/editor/workspace-trust"
_SANS_FOLDER_OPEN = (
    "https://isc.sans.edu/diary/Automatic+Script+Execution+In+Visual+Studio+Code/32644/"
)
_DEVCONTAINER = "https://containers.dev/implementors/json_reference/"
_NPM_SCRIPTS = "https://docs.npmjs.com/cli/using-npm/scripts"
_SHAI_HULUD = "https://unit42.paloaltonetworks.com/npm-supply-chain-attack/"
_S1NGULARITY = "https://nx.dev/blog/s1ngularity-postmortem"
_S1NGULARITY_SNYK = (
    "https://snyk.io/blog/weaponizing-ai-coding-agents-for-malware-in-the-nx-malicious-package/"
)
_PWN_REQUESTS = "https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/"
_UNTRUSTED_INPUT = "https://securitylab.github.com/resources/github-actions-untrusted-input/"
_TJ_ACTIONS = (
    "https://www.cisa.gov/news-events/alerts/2025/03/18/"
    "supply-chain-compromise-third-party-github-action-cve-2025-30066"
)
_GIT_EXT_TRANSPORT = "https://nvd.nist.gov/vuln/detail/CVE-2017-1000117"
_AGENT_FILES_GOOGLE = (
    "https://cloud.google.com/blog/products/identity-security/"
    "beyond-source-code-the-files-ai-coding-agents-trust-and-attackers-exploit"
)

HIDDEN = "hidden-text"
INJECTION = "prompt-injection"
AUTOEXEC = "auto-execution"
CI = "ci-cd"
SECRETS = "secrets"
FILESYSTEM = "filesystem"

_RULE_LIST = (
    # Hidden text -------------------------------------------------------------
    Rule(
        "RSC101",
        "unicode-tag-smuggling",
        "Invisible Unicode Tag characters (hidden ASCII text)",
        HIDDEN,
        Severity.CRITICAL,
        "Characters from the Unicode Tags block (U+E0000-U+E007F) mirror ASCII but render "
        "as nothing. Humans and code review tools see an empty string while language models "
        "read the hidden text, which makes them a favourite carrier for invisible prompt "
        "injection. The scanner decodes the hidden text so you can read it.",
        "Delete the characters and review who added them. Treat the file as hostile until "
        "the decoded text is understood.",
        (_UNICODE_TAGS_CISCO, _UNICODE_TAGS_AWS, _RULES_FILE_BACKDOOR),
    ),
    Rule(
        "RSC102",
        "bidi-control-characters",
        "Bidirectional control characters (Trojan Source)",
        HIDDEN,
        Severity.HIGH,
        "Bidirectional override, embedding and isolate characters reorder how text is "
        "displayed, so the code a reviewer sees differs from the code a compiler or an AI "
        "agent reads (CVE-2021-42574).",
        "Remove the control characters from code and configuration. In translations, keep "
        "them balanced and limited to string literals.",
        (_TROJAN_SOURCE,),
    ),
    Rule(
        "RSC103",
        "invisible-characters",
        "Zero-width or invisible characters",
        HIDDEN,
        Severity.HIGH,
        "Zero-width spaces, word joiners, invisible operators and similar characters hide "
        "content from reviewers. Rules files for AI assistants have been backdoored this way.",
        "Strip the invisible characters, then diff the file to see what they were hiding.",
        (_RULES_FILE_BACKDOOR, _AGENT_FILES_GOOGLE),
    ),
    Rule(
        "RSC104",
        "variation-selector-smuggling",
        "Long runs of Unicode variation selectors (data smuggling)",
        HIDDEN,
        Severity.HIGH,
        "Variation selectors are invisible modifiers. One after an emoji is normal; a long run "
        "can encode arbitrary bytes that a model or a script can decode.",
        "Remove the variation selectors and inspect the decoded payload shown in the finding.",
        (_EMOJI_SMUGGLING,),
    ),
    # Prompt injection --------------------------------------------------------
    Rule(
        "RSC201",
        "instruction-override",
        "Prompt-injection phrasing that tries to override an AI agent's instructions",
        INJECTION,
        Severity.HIGH,
        "Text that tells an AI model to discard its previous instructions, switch into an "
        "unrestricted mode or obey a fake system message. Severity is high in files that AI "
        "agents load automatically and medium elsewhere.",
        "Remove the text. If it is test data for an LLM evaluation, keep it out of files that "
        "agents load as instructions.",
        (_RULES_FILE_BACKDOOR, _TOOL_POISONING),
    ),
    Rule(
        "RSC202",
        "concealment-instruction",
        "Instruction to hide actions from the user",
        INJECTION,
        Severity.HIGH,
        "Legitimate project instructions never ask an assistant to keep something from the "
        "person it works for. Concealment is the signature of tool poisoning and rules-file "
        "backdoors.",
        "Remove the instruction and review the rest of the file for hidden behaviour.",
        (_TOOL_POISONING, _RULES_FILE_BACKDOOR),
    ),
    Rule(
        "RSC203",
        "agent-file-dangerous-command",
        "Dangerous command or exfiltration pattern inside an AI agent instruction file",
        INJECTION,
        Severity.HIGH,
        "Files such as AGENTS.md, CLAUDE.md, .cursorrules or copilot-instructions.md are read "
        "as instructions by coding agents. Download-and-execute commands, secret file paths, "
        "reverse shells or data-collection endpoints in them can be executed by the agent.",
        "Remove the command or replace it with a reviewed script that is checked into the "
        "repository.",
        (_AGENT_FILES_GOOGLE, _RULES_FILE_BACKDOOR),
    ),
    Rule(
        "RSC204",
        "hidden-markdown-comment",
        "Directive hidden in an HTML comment inside an agent instruction file",
        INJECTION,
        Severity.MEDIUM,
        "HTML comments are invisible on GitHub and in Markdown previews but are delivered to "
        "AI agents as raw text, so reviewers and agents see different instructions.",
        "Move the text out of the comment so reviewers can see it, or delete it.",
        (_AGENT_FILES_GOOGLE,),
    ),
    # Auto-execution ---------------------------------------------------------
    Rule(
        "RSC301",
        "vscode-folder-open-task",
        "VS Code task that runs automatically when the folder is opened",
        AUTOEXEC,
        Severity.HIGH,
        'A task with "runOn": "folderOpen" runs a command as soon as the workspace is opened '
        "(after trust and automatic-task approval). Malicious repositories use it to run "
        "malware the moment a project is opened.",
        "Remove runOptions.runOn or make the task manual. Never open untrusted repositories in "
        "a trusted workspace.",
        (_VSCODE_TASKS, _SANS_FOLDER_OPEN, _VSCODE_TRUST),
    ),
    Rule(
        "RSC302",
        "vscode-insecure-setting",
        "Workspace setting that disables an editor or AI-assistant safety control",
        AUTOEXEC,
        Severity.HIGH,
        "Workspace settings can turn on automatic approval of AI tool calls (CVE-2025-53773), "
        "allow automatic tasks, disable workspace trust or point executable paths at files in "
        "the repository.",
        "Delete the setting from the repository. Safety settings belong in user settings, not "
        "in files that anyone can commit.",
        (_COPILOT_RCE, _VSCODE_TRUST),
    ),
    Rule(
        "RSC303",
        "claude-code-command-setting",
        "Claude Code project setting that runs shell commands",
        AUTOEXEC,
        Severity.MEDIUM,
        "Hooks, status lines, credential helpers and similar settings in .claude/settings.json "
        "run shell commands during an agent session. Repository-supplied hooks were used for "
        "code execution in CVE-2025-59536.",
        "Review every command. Keep hooks small, pinned to scripts in the repository and free "
        "of network access.",
        (_CLAUDE_PROJECT_FILES, _CLAUDE_SETTINGS),
    ),
    Rule(
        "RSC304",
        "claude-code-risky-setting",
        "Claude Code project setting that weakens safety or redirects credentials",
        AUTOEXEC,
        Severity.HIGH,
        "Project settings can auto-approve MCP servers, widen permissions, register plugin "
        "marketplaces or override environment variables such as ANTHROPIC_BASE_URL, which "
        "was used to exfiltrate API keys (CVE-2026-21852).",
        "Remove the setting from the shared project file. Personal preferences belong in "
        "user settings.",
        (_CLAUDE_PROJECT_FILES, _CLAUDE_SETTINGS),
    ),
    Rule(
        "RSC305",
        "mcp-server-config",
        "Risky MCP server definition in a project configuration file",
        AUTOEXEC,
        Severity.MEDIUM,
        "MCP servers declared in project files start local processes with your privileges. "
        "Shell wrappers, unpinned packages, privileged containers and plain-HTTP endpoints "
        "make them an easy route to code execution or tool poisoning.",
        "Pin packages to exact versions, avoid shell wrappers and review the server's code "
        "before approving it.",
        (_MCPOISON, _TOOL_POISONING),
    ),
    Rule(
        "RSC306",
        "devcontainer-command",
        "Dev Container lifecycle command",
        AUTOEXEC,
        Severity.HIGH,
        "initializeCommand runs on the host machine before the container exists; the other "
        "lifecycle commands run inside the container. Both run automatically when the "
        "container is built or started.",
        "Review the command. Prefer commands that only call scripts committed in the "
        "repository.",
        (_DEVCONTAINER,),
    ),
    Rule(
        "RSC307",
        "package-install-script",
        "Package lifecycle script that runs on install",
        AUTOEXEC,
        Severity.LOW,
        "npm and Composer run lifecycle scripts automatically on install. Worms such as "
        "Shai-Hulud and the s1ngularity attack used install hooks to steal credentials.",
        "Review the script. Install untrusted projects with --ignore-scripts.",
        (_NPM_SCRIPTS, _SHAI_HULUD, _S1NGULARITY),
    ),
    Rule(
        "RSC308",
        "python-setup-code",
        "Suspicious code in setup.py",
        AUTOEXEC,
        Severity.HIGH,
        "setup.py runs during source installs. Network access combined with execution or "
        "decoding in it is a common malware pattern.",
        "Move build logic to a declarative pyproject.toml and review the flagged code.",
        (),
    ),
    Rule(
        "RSC309",
        "git-hook-script",
        "Git hook script shipped in the repository",
        AUTOEXEC,
        Severity.LOW,
        "Hook managers such as Husky install repository hooks automatically, so the scripts "
        "run on every commit or checkout.",
        "Review the hook script before installing dependencies.",
        (),
    ),
    Rule(
        "RSC310",
        "direnv-envrc",
        "direnv .envrc script",
        AUTOEXEC,
        Severity.LOW,
        "An allowed .envrc runs every time you enter the directory.",
        "Read the file before running `direnv allow`.",
        ("https://direnv.net/",),
    ),
    Rule(
        "RSC311",
        "gitmodules-injection",
        "Dangerous submodule URL",
        AUTOEXEC,
        Severity.CRITICAL,
        "Submodule URLs using the ext:: transport or starting with a dash can run commands "
        "when submodules are fetched.",
        "Replace the URL with a plain https:// URL.",
        (_GIT_EXT_TRANSPORT,),
    ),
    Rule(
        "RSC312",
        "ai-cli-permission-bypass",
        "AI coding CLI invoked with its safety checks disabled",
        AUTOEXEC,
        Severity.HIGH,
        "Flags such as Claude Code's skip-permissions flag, Gemini CLI's yolo mode, Amazon Q's "
        "trust-all-tools or Codex's approval-and-sandbox bypass let an AI agent run any "
        "command. The s1ngularity malware drove locally installed AI CLIs this way to hunt "
        "for secrets.",
        "Remove the invocation, or run it only inside a disposable sandbox.",
        (_S1NGULARITY_SNYK, _S1NGULARITY),
    ),
    # CI/CD --------------------------------------------------------------------
    Rule(
        "RSC401",
        "pwn-request",
        "Privileged workflow checks out untrusted pull request code",
        CI,
        Severity.CRITICAL,
        "Workflows triggered by pull_request_target or workflow_run run with secrets and a "
        "write token. Checking out the pull request head lets anyone with a fork run code in "
        "that privileged context.",
        "Use the pull_request trigger for untrusted code, or split the workflow so privileged "
        "steps never execute the pull request's code.",
        (_PWN_REQUESTS,),
    ),
    Rule(
        "RSC402",
        "expression-injection",
        "Untrusted GitHub context interpolated into a shell script",
        CI,
        Severity.HIGH,
        "Issue titles, PR bodies, branch names and commit messages are attacker-controlled. "
        "Interpolating them with ${{ }} inside run: or github-script lets an attacker inject "
        "shell or JavaScript.",
        "Pass the value through an environment variable and quote it in the script.",
        (_UNTRUSTED_INPUT,),
    ),
    Rule(
        "RSC403",
        "unpinned-action",
        "GitHub Action referenced by a mutable tag instead of a commit SHA",
        CI,
        Severity.MEDIUM,
        "Tags can be moved. In March 2025 every tag of tj-actions/changed-files was repointed "
        "to malicious code that dumped CI secrets (CVE-2025-30066).",
        "Pin to a full 40-character commit SHA and keep the version in a comment.",
        (_TJ_ACTIONS,),
    ),
    Rule(
        "RSC404",
        "excessive-permissions",
        "Workflow grants write-all permissions",
        CI,
        Severity.MEDIUM,
        "permissions: write-all gives every job a token that can push code, publish releases "
        "and modify settings.",
        "Declare only the scopes each job needs.",
        (_PWN_REQUESTS,),
    ),
    Rule(
        "RSC405",
        "insecure-workflow-commands",
        "Deprecated insecure workflow commands enabled",
        CI,
        Severity.HIGH,
        "ACTIONS_ALLOW_UNSECURE_COMMANDS re-enables set-env and add-path, which let any "
        "process that prints to the log change the environment of later steps.",
        "Remove the variable and use $GITHUB_ENV / $GITHUB_PATH.",
        (_UNTRUSTED_INPUT,),
    ),
    # Secrets ------------------------------------------------------------------
    Rule(
        "RSC501",
        "hardcoded-secret",
        "Credential committed to the repository",
        SECRETS,
        Severity.HIGH,
        "A string matching the format of a real credential (cloud keys, API tokens, private "
        "keys, webhooks) is present in a tracked file.",
        "Revoke and rotate the credential, then remove it from history.",
        (),
    ),
    Rule(
        "RSC502",
        "sensitive-file",
        "Sensitive file committed to the repository",
        SECRETS,
        Severity.MEDIUM,
        "Environment files, private keys and keystores usually contain credentials.",
        "Remove the file, rotate anything it contained and add it to .gitignore.",
        (),
    ),
    Rule(
        "RSC601",
        "symlink-escape",
        "Symbolic link pointing outside the repository",
        FILESYSTEM,
        Severity.MEDIUM,
        "A symlink that leaves the repository can make tools and AI agents read or write "
        "files elsewhere on your machine, such as SSH keys or cloud credentials.",
        "Replace the link with a regular file.",
        (),
    ),
)

RULES: Dict[str, Rule] = {rule.id: rule for rule in _RULE_LIST}
RULES_BY_NAME: Dict[str, Rule] = {rule.name: rule for rule in _RULE_LIST}


def resolve_rule(identifier: str) -> Rule:
    """Look a rule up by ID (RSC101) or name (unicode-tag-smuggling)."""
    key = identifier.strip()
    if key.upper() in RULES:
        return RULES[key.upper()]
    if key.lower() in RULES_BY_NAME:
        return RULES_BY_NAME[key.lower()]
    raise ValueError(f"Unknown rule: {identifier!r}")
