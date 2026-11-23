"""Per-file context and classification of files that tools treat specially."""

from __future__ import annotations

import posixpath
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

_CODE_EXTENSIONS = {
    ".py", ".pyw", ".pyi", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx",
    ".go", ".rs", ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".m", ".mm", ".java",
    ".kt", ".kts", ".scala", ".groovy", ".gradle", ".swift", ".rb", ".php", ".cs", ".fs",
    ".vb", ".sh", ".bash", ".zsh", ".fish", ".ps1", ".psm1", ".bat", ".cmd", ".lua", ".pl",
    ".pm", ".r", ".jl", ".dart", ".ex", ".exs", ".erl", ".hs", ".ml", ".clj", ".sql",
    ".vue", ".svelte", ".astro", ".zig", ".nim", ".v", ".sol", ".tf", ".hcl",
    ".json", ".jsonc", ".json5", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf",
    ".xml", ".gradle", ".cmake", ".mk", ".dockerfile", ".nix",
}
_CODE_BASENAMES = {
    "makefile", "dockerfile", "containerfile", "jenkinsfile", "vagrantfile", "rakefile",
    "gemfile", "justfile", "procfile", ".envrc", ".bashrc", ".zshrc", ".profile",
}

# Files that AI coding agents load automatically as instructions or context.
_AGENT_BASENAMES = {
    "agents.md", "agent.md", "claude.md", "claude.local.md", "gemini.md", "qwen.md",
    ".cursorrules", ".windsurfrules", ".clinerules", ".goosehints", ".rules",
    "copilot-instructions.md", "skill.md", "conventions.md", ".aider.conventions.md",
    "warp.md", "crush.md", "opencode.md",
}
_AGENT_DIRECTORIES = (
    ".cursor/rules/", ".windsurf/rules/", ".clinerules/", ".roo/", ".kiro/steering/",
    ".continue/rules/", ".claude/commands/", ".claude/agents/", ".claude/skills/",
    ".claude/rules/", ".github/instructions/", ".github/prompts/", ".github/chatmodes/",
    ".github/agents/", ".amazonq/rules/", ".trae/rules/", ".augment/", ".junie/",
    ".gemini/commands/", ".codex/", ".opencode/", ".agents/",
)
_AGENT_EXTENSIONS = {"", ".md", ".mdc", ".mdx", ".txt", ".prompt", ".toml", ".yaml", ".yml"}


def _has_directory(rel: str, directory: str) -> bool:
    return rel.startswith(directory) or ("/" + directory) in rel


def is_agent_instruction_file(rel: str) -> bool:
    lower = rel.lower()
    base = posixpath.basename(lower)
    if base in _AGENT_BASENAMES:
        return True
    extension = posixpath.splitext(base)[1]
    if extension not in _AGENT_EXTENSIONS:
        return False
    if base.endswith((".instructions.md", ".prompt.md", ".chatmode.md", ".agent.md")):
        return True
    return any(_has_directory(lower, directory) for directory in _AGENT_DIRECTORIES)


def is_code_file(rel: str) -> bool:
    base = posixpath.basename(rel.lower())
    if base in _CODE_BASENAMES:
        return True
    return posixpath.splitext(base)[1] in _CODE_EXTENSIONS


def is_documentation(rel: str) -> bool:
    base = posixpath.basename(rel.lower())
    extension = posixpath.splitext(base)[1]
    return extension in {".md", ".mdx", ".rst", ".txt", ".adoc", ".html", ".htm"}


@dataclass
class FileContext:
    """A file being scanned: its repository-relative path and decoded text."""

    rel: str
    text: Optional[str]
    size: int
    root: Optional[Path] = None

    def __post_init__(self) -> None:
        self.is_agent_file = is_agent_instruction_file(self.rel)
        self.is_code = is_code_file(self.rel)
        self.is_docs = is_documentation(self.rel) and not self.is_agent_file
        self.basename = posixpath.basename(self.rel)
        self.lower = self.rel.lower()
