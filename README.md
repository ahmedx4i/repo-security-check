# Repo Security Check

A dependency-free command-line checker for common open-source repository security hygiene.

Repo Security Check is designed for maintainers who want a quick, local baseline. It checks configuration and file names only; it does not upload files, call external services, or replace a full security review.

## What it checks

- An OSI-style LICENSE file
- A security policy in SECURITY.md
- Dependabot configuration
- CodeQL workflow configuration
- GitHub Actions pinned to commit SHAs
- Sensitive-looking files accidentally present in the working tree
- Sensitive file patterns covered by .gitignore

## Install from source

    git clone https://github.com/ahmedx4i/repo-security-check.git
    cd repo-security-check
    python -m pip install -e .

## Usage

Check the current repository:

    repo-security-check

Check another directory and save JSON:

    repo-security-check /path/to/repository --format json

Create a Markdown report:

    repo-security-check . --format markdown

## Example

    Repository security score: 70/100

    PASS  License file found.
    PASS  Security policy found.
    WARN  Dependabot configuration is missing.
    WARN  Some GitHub Actions use mutable version tags.

## Scope and limitations

This tool is deliberately conservative. A passing score does not guarantee that a repository is secure, and a warning does not prove a vulnerability. Use it as a starting point for improving project hygiene.

## Contributing

Contributions are welcome. Please read CONTRIBUTING.md and include tests for behavior changes.

## License

MIT
