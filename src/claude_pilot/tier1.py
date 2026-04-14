"""Tier 1 auto-approval filter. Port of src/tier1.ts.

Returns True if a tool request is safe to auto-approve without relaying to the
external agent. Security principle: deny-list first, conservative default.
When in doubt, return False (relay decides).

Note: Bash shell commands do NOT get path-containment checks (unlike
Write/Edit). Static analysis of shell redirect/copy targets is impractical;
only commands with no write side effects are safe-listed.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any


def is_tier1_auto_approve(tool_name: str, tool_input: dict[str, Any], cwd: str) -> bool:
    if tool_name in ("Read", "Glob", "Grep"):
        return True

    if tool_name == "Bash":
        command = tool_input.get("command", "")
        if not isinstance(command, str) or not command.strip():
            return False
        return is_safe_bash_command(command)

    if tool_name in ("Write", "Edit"):
        file_path = tool_input.get("file_path", "")
        if not isinstance(file_path, str) or not file_path:
            return False
        return is_within_project(file_path, cwd)

    if tool_name == "Skill":
        skill = tool_input.get("skill", "")
        if not isinstance(skill, str):
            return False
        return skill.strip() in TIER1_SAFE_SKILLS

    return False


# ── Pipeline slash commands (Skill tool) ────────────────────────────────────

TIER1_SAFE_SKILLS: frozenset[str] = frozenset({
    # /mika pipeline entrypoint
    "mika",
    # CE workflow commands (short form)
    "ce:plan",
    "ce:work",
    "ce:review",
    "ce:compound",
    "ce:brainstorm",
    # CE workflow commands (fully-qualified form)
    "compound-engineering:ce-plan",
    "compound-engineering:ce-work",
    "compound-engineering:ce-review",
    "compound-engineering:ce-compound",
    "compound-engineering:ce-brainstorm",
    # CE utility commands
    "compound-engineering:resolve_todo_parallel",
    # Doc audit
    "mika-doc-audit",
})


# ── Deny-list ────────────────────────────────────────────────────────────────

TIER3_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"rm\s+(-\w*r\w*f|-\w*f\w*r)\b"),           # rm -rf, rm -fr, rm -rfi
    re.compile(r"git\s+push\s+.*--force\b"),                # git push --force
    re.compile(r"git\s+push\s+.*-\w*f\b"),                  # git push -f
    re.compile(r"git\s+push\s+\S+\s+(main|master)\b"),      # git push origin main/master
    re.compile(r"git\s+reset\s+--hard\b"),                  # git reset --hard
    re.compile(r"git\s+branch\s+.*-\w*D\b"),                # git branch -D
    re.compile(r"\bDROP\s+TABLE\b", re.IGNORECASE),
    re.compile(r"\bDELETE\s+FROM\b", re.IGNORECASE),
    re.compile(r"\bcargo\s+publish\b"),
    re.compile(r"\bsed\s+(-\w*i|-i\w*)\b"),                 # sed -i
    re.compile(r"\bgh\s+label\s+(delete|edit)\b"),
    re.compile(r"\bbash\s+-c\b"),
    re.compile(r"\bsh\s+-c\b"),
    re.compile(r"\beval\s"),
    re.compile(r"\bxargs\b"),
    re.compile(r"\bfind\s.*-(exec|execdir|delete)\b"),
    re.compile(r"\$\("),                                    # $(...)
    re.compile(r"`[^`]*`"),                                 # backticks
    re.compile(r"<\("),                                     # <(...)
    re.compile(r">\("),                                     # >(...)
    re.compile(r"(?:^|[^<])>{1,2}(?!\()"),                  # > or >> (not process sub)
)


def is_tier3_dangerous(command: str) -> bool:
    return any(p.search(command) for p in TIER3_PATTERNS)


# ── Safe Bash command checking ───────────────────────────────────────────────

_COMPOUND_SPLIT_RE = re.compile(r"\s*(?:&&|\|\||[;|])\s*")


def _split_compound_command(command: str) -> list[str]:
    """Naive split on shell operators. Not quote-aware — unsafe splits inside
    quoted strings simply won't match any safe pattern and fall through to
    relay. Safe by design."""
    return [s for s in (part.strip() for part in _COMPOUND_SPLIT_RE.split(command)) if s]


def is_safe_bash_command(command: str) -> bool:
    if is_tier3_dangerous(command):
        return False

    sub_commands = _split_compound_command(command)
    if not sub_commands:
        return False

    return all(_is_safe_sub_command(sub) for sub in sub_commands)


def _is_safe_sub_command(sub: str) -> bool:
    return (
        is_safe_git_command(sub)
        or is_safe_build_command(sub)
        or is_safe_shell_command(sub)
        or is_safe_gh_command(sub)
    )


# ── Safe git commands ────────────────────────────────────────────────────────

SAFE_GIT_SUBCOMMANDS: frozenset[str] = frozenset({
    "status", "log", "diff", "branch", "show", "commit",
    "push", "checkout", "worktree", "rev-parse", "remote",
    "fetch", "pull", "add", "stash", "tag", "merge",
    "rebase", "cherry-pick", "symbolic-ref",
    "ls-files", "describe", "shortlog", "blame",
})

_GIT_CMD_RE = re.compile(r"^\s*git\s+(\S+)")
_FORCE_FLAG_RE = re.compile(r"--force\b|-\w*f\b")
_MAIN_MASTER_RE = re.compile(r"\b(main|master)\b")
_BRANCH_D_RE = re.compile(r"-\w*D\b")


def is_safe_git_command(sub: str) -> bool:
    match = _GIT_CMD_RE.match(sub)
    if not match:
        return False

    git_sub = match.group(1)
    if git_sub not in SAFE_GIT_SUBCOMMANDS:
        return False

    if _FORCE_FLAG_RE.search(sub):
        return False
    if git_sub == "push" and _MAIN_MASTER_RE.search(sub):
        return False
    if git_sub == "branch" and _BRANCH_D_RE.search(sub):
        return False

    return True


# ── Safe build/test commands ─────────────────────────────────────────────────

SAFE_CARGO_SUBCOMMANDS: frozenset[str] = frozenset({
    "check", "test", "clippy", "fmt", "build",
    "clean", "doc", "bench", "tree", "metadata",
})

SAFE_NPM_RUN_SCRIPTS: frozenset[str] = frozenset({
    "build", "dev", "test", "lint", "fmt", "start",
    "typecheck", "type-check", "check",
})

_CARGO_RE = re.compile(r"^\s*cargo\s+(\S+)")
_NPM_RUN_RE = re.compile(r"^\s*npm\s+run\s+(\S+)")
_NPM_BUILTIN_RE = re.compile(r"^\s*npm\s+(test|start)\b")
_NPM_INSTALL_RE = re.compile(r"^\s*npm\s+(install|ci)\b")
_NPX_RE = re.compile(r"^\s*npx\s+(tsc|vitest|prettier|eslint)\b")


def is_safe_build_command(sub: str) -> bool:
    m = _CARGO_RE.match(sub)
    if m and m.group(1) in SAFE_CARGO_SUBCOMMANDS:
        return True

    m = _NPM_RUN_RE.match(sub)
    if m and m.group(1) in SAFE_NPM_RUN_SCRIPTS:
        return True

    if _NPM_BUILTIN_RE.match(sub):
        return True
    if _NPM_INSTALL_RE.match(sub):
        return True
    if _NPX_RE.match(sub):
        return True

    return False


# ── Safe shell commands ──────────────────────────────────────────────────────

SAFE_SHELL_COMMANDS: frozenset[str] = frozenset({
    # Read-only inspection
    "ls", "cat", "head", "tail", "wc", "find", "grep", "sed",
    "awk", "echo", "printf", "dirname", "basename",
    "realpath", "readlink", "stat", "file", "which", "type",
    "pwd", "date", "sort", "uniq", "tr", "cut", "diff",
    "comm", "test", "[",
    # Navigation — safe leaf so compound `cd <path> && <tier1>` auto-approves.
    # `cd` has no write side effects; path-traversal risk is addressed by the
    # TIER3 command-substitution blockers ($(...), backticks, <(...)) that
    # run on the raw compound before splitting.
    "cd",
    # `command -v <name>` is equivalent to `which <name>`; already safe.
    "command",
})

_FIRST_WORD_RE = re.compile(r"^\s*(\S+)")
_SED_INPLACE_RE = re.compile(r"\s-\w*i\b")
_FIND_DANGEROUS_RE = re.compile(r"-(exec|execdir|delete)\b")


def is_safe_shell_command(sub: str) -> bool:
    match = _FIRST_WORD_RE.match(sub)
    if not match:
        return False

    cmd = match.group(1)
    if cmd not in SAFE_SHELL_COMMANDS:
        return False

    if cmd == "sed" and _SED_INPLACE_RE.search(sub):
        return False
    if cmd == "find" and _FIND_DANGEROUS_RE.search(sub):
        return False

    return True


# ── Safe GitHub CLI commands ─────────────────────────────────────────────────

SAFE_GH_SUBCOMMANDS: dict[str, frozenset[str]] = {
    "pr":       frozenset({"create", "view", "list", "checkout", "diff", "checks"}),
    "issue":    frozenset({"view", "list"}),
    "run":      frozenset({"view", "list"}),
    "repo":     frozenset({"view"}),
    "release":  frozenset({"view", "list"}),
    "workflow": frozenset({"view", "list"}),
}

_GH_DOMAIN_RE = re.compile(r"^\s*gh\s+(\S+)\s+(\S+)")
_GH_API_RE = re.compile(r"^\s*gh\s+api\b")
_GH_API_MUTATION_RE = re.compile(r"-(X|method)\b|-(f|F|field|raw-field)\b|--input\b")


def is_safe_gh_command(sub: str) -> bool:
    match = _GH_DOMAIN_RE.match(sub)
    if match:
        allowed = SAFE_GH_SUBCOMMANDS.get(match.group(1))
        if allowed is not None:
            return match.group(2) in allowed

    if _GH_API_RE.match(sub):
        if _GH_API_MUTATION_RE.search(sub):
            return False
        return True

    return False


# ── Write/Edit path safety ───────────────────────────────────────────────────


def is_within_project(file_path: str, cwd: str) -> bool:
    """Check whether a file path resolves within the project directory.

    Uses Path.resolve(strict=False) which resolves symlinks on existing
    components and leaves non-existent tails as-is — equivalent to the TS
    realpathSync with parent-dir fallback for new files.
    """
    if not file_path:
        return False

    try:
        resolved_cwd = Path(cwd).resolve(strict=True)
    except OSError:
        return False

    abs_path = (resolved_cwd / file_path).resolve(strict=False) if not Path(file_path).is_absolute() else Path(file_path).resolve(strict=False)

    try:
        abs_path.relative_to(resolved_cwd)
        return True
    except ValueError:
        return False
