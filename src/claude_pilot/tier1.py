"""Tier 1 auto-approval filter. Port of src/tier1.ts.

Returns True if a tool request is safe to auto-approve without relaying to the
external agent. Security principle: deny-list first, conservative default.
When in doubt, return False (relay decides).

Note: Bash shell commands do NOT get path-containment checks (unlike
Write/Edit). Static analysis of shell redirect/copy targets is impractical;
only commands with no write side effects are safe-listed.

Quote-aware metacharacter scanning (mika#946, mika#944): backtick, ``$(`` and
``$'`` (ANSI-C quoting) rejection uses ``contains_unquoted_metacharacter()`` —
a character-state-machine that mirrors the Rust
``contains_unquoted_metacharacter`` in
``crates/mika-agent/src/server/permission_pre_classifier.rs``. Both sides
follow POSIX single-quote semantics (backslash is literal inside ``'...'``).
See the F5 sentinel comment in the Rust module for the cross-language coupling
contract.
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

# Strip universal stderr/stdout silencing (`2>/dev/null`, `1>/dev/null`) before
# running the TIER3_PATTERNS regex check. `is_tier3_dangerous` denies any `>`
# redirect via the generic `(?<!<)>{1,2}(?!\(|&[\d-])` pattern below, which
# false-positives on the universally-safe fd-to-/dev/null silencing idiom. The
# strip pre-pass leaves the safe pattern invisible to the dangerous-pattern
# check while preserving denial for `>file`, `>>file`, and other redirect
# targets that could overwrite arbitrary destinations.
#
# Surfaced by mika#1327 dev-pilot dispatch 2026-05-28: `ls /path/ 2>/dev/null`
# was Tier-1-denied → cpp#20 default-deny → interrupt=True halt.
# Anchor the trailing edge with a negative lookahead instead of `\b` -- `\b`
# fires between `l` (word) and `/` (non-word) so `2>/dev/null/etc/passwd`
# would strip to `/etc/passwd` and slip past the redirect-to-file check.
# The negative lookahead `(?![/\w.])` rejects additional path/word/dot
# characters, blocking `/dev/nullified`, `/dev/null.txt`, and path-suffix
# attacks while permitting whitespace, end-of-string, or shell separators
# (`;`, `&`, `|`, `)`, `>`, `<`).
_FD_DEVNULL_RE = re.compile(r"\b\d+>/dev/null(?![/\w.])")


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
    # NOTE: $( and backtick patterns removed — replaced by quote-aware
    # contains_unquoted_metacharacter() check in is_safe_bash_command().
    # See mika#946 (resolution of mika#938 F5 sentinel divergence).
    re.compile(r"<\("),                                     # <(...)
    re.compile(r">\("),                                     # >(...)
    re.compile(r"(?<!<)>{1,2}(?!\(|&[\d-])"),               # > or >> (not process sub, not fd-manipulation)
)


def is_tier3_dangerous(command: str) -> bool:
    # Strip universal fd-to-/dev/null silencing before the dangerous-pattern
    # check (see _FD_DEVNULL_RE comment). The strip is invisible to all other
    # patterns; only the bare-`>` redirect pattern is affected.
    stripped = _FD_DEVNULL_RE.sub("", command)
    return any(p.search(stripped) for p in TIER3_PATTERNS)


# ── Model-facing prevention hint (mika#1409) ─────────────────────────────────
#
# Prevention-only half of mika#1409 (Approach #2). The headless pilot model has
# no preflight visibility into the deny-list above, so it reaches for forbidden
# shell idioms (`find … -exec`, cross-worktree `md5sum`, `sed -i`) when an
# auto-approved native tool serves the same goal. A policy denial returns
# `PermissionResultDeny(interrupt=True)` (permissions.py / cpp#20 joint 2) and
# the session DIES — so a single bad reach forces a manual rescue.
#
# This constant is injected into the SDK system prompt by agent.py. It lives
# HERE, next to the patterns it describes (TIER3_PATTERNS, _FIND_DANGEROUS_RE,
# SAFE_SHELL_COMMANDS, is_within_project), so the documentation cannot drift
# from the enforcement. n=2 evidence: claude-pilot logs 6f97dc72 (find -exec
# crashed the mika#1381 groom) and 548191b8 (cross-worktree md5sum crashed the
# mika#1255 AC verification).
#
# Honest-closure note: this hint reduces the RATE of denied reaches; it does
# NOT close the session-fatality class. Novel denied patterns still crash the
# session — that class closes only when cpp#20 joint 2's contract is revised to
# distinguish adaptation from fabrication (mika#1410).
DENIED_BASH_PATTERNS_HINT: str = """\
## Bash commands that crash this session — use the native tool instead

The permission policy DENIES the Bash patterns below, and a denied Bash call
terminates this session immediately (no retry, no recovery). Never reach for
them — use the auto-approved native tool, which accomplishes the same goal:

- `find … -exec` / `find … -execdir` / `find … -delete` (denied as RCE-class,
  regardless of path) → use the **Grep** tool to search file contents and the
  **Glob** tool to find files by name. To search inside matched files, combine
  Glob (find paths) then Grep (search them) — never `find -exec grep`.
- Hashing or inspecting a file with a non-safe-listed command (e.g. `md5sum`,
  `sha256sum`) → use the **Read** tool to read the file directly. Only a small
  allow-list of read-only shell tools is auto-approved; others like `md5sum`
  are denied on ANY path. Read works on any absolute path, inside or outside
  the current worktree — so prefer it for cross-worktree file comparison.
- In-place edits via `sed -i` → use the **Edit** tool.
- Writing files via shell redirect (`>`, `>>`) → use the **Write** tool.
- `xargs`, `eval`, `bash -c`, `sh -c` → use the dedicated native tool
  (Grep/Glob/Read/Edit/Write) for the underlying goal.

Prefer Read, Write, Edit, Grep, and Glob over their shell equivalents: they are
auto-approved and never halt the session."""


# ── Safe Bash command checking ───────────────────────────────────────────────

_COMPOUND_SPLIT_RE = re.compile(r"\s*(?:&&|\|\||[;|\n])\s*")


def _split_compound_command(command: str) -> list[str]:
    """Naive split on shell operators AND raw newlines. Not quote-aware —
    unsafe splits inside quoted strings simply won't match any safe pattern
    and fall through to relay. Safe by design.

    `\\n` is included because bash treats a bare newline as a command
    separator equivalent to `;`. Without splitting on `\\n`, a payload like
    ``git status\\nrm -rf /`` would be evaluated as one segment, miss the
    rm-rf regex on the second line, and auto-approve via the safe-git prefix.
    """
    return [s for s in (part.strip() for part in _COMPOUND_SPLIT_RE.split(command)) if s]


def contains_unquoted_metacharacter(command: str) -> bool:
    """Return True if *command* contains an unquoted backtick, ``$(`` or ``$'``.

    Mirrors ``contains_unquoted_metacharacter`` in
    ``crates/mika-agent/src/server/permission_pre_classifier.rs`` (mika repo).
    Quote handling follows POSIX semantics:

    - Inside ``"..."`` regions, ``\\"`` is an escape pair (skipped atomically).
    - Inside ``'...'`` regions, backslash is literal — ``'foo\\\\'`` closes at
      the second ``'`` and any backtick that follows is unquoted.
    - Unterminated quotes: the scanner treats all remaining bytes as inside the
      quote (conservative — falls through to the LLM relay on malformed input).

    See mika#944 (ANSI-C quoting bypass), mika#946 (mika#938 F5 sentinel).
    """
    n = len(command)
    i = 0
    quote_state: str | None = None  # None / "'" / '"'

    while i < n:
        ch = command[i]
        if quote_state is not None:
            # Inside a quoted region — handle escape (double-quoted only) then close.
            if quote_state == '"' and ch == '\\' and i + 1 < n:
                i += 2
                continue
            if ch == quote_state:
                quote_state = None
            i += 1
            continue

        # Unquoted region — open a quote or check for metacharacters.
        if ch == "'" or ch == '"':
            quote_state = ch
            i += 1
            continue
        if ch == "`":
            return True
        if ch == "$" and i + 1 < n and command[i + 1] == "(":
            return True
        # $' (ANSI-C quoting — escapes like \xNN expand at execution time)
        # mika#944: mirrors the Rust scanner's $' check.
        if ch == "$" and i + 1 < n and command[i + 1] == "'":
            return True
        i += 1

    return False


def is_safe_bash_command(command: str) -> bool:
    if contains_unquoted_metacharacter(command):
        return False
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
        or is_safe_mika_dispatch(sub)
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
    "issue":    frozenset({"view", "list", "edit", "comment"}),
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


# ── Safe intra-platform agent dispatch ───────────────────────────────────────
#
# Narrow allow-list for `mika ask --agent <agent>` calls between platform
# agents. The `mika-arch` first-pass / second-pass groom briefs, dev-pilot
# acceptance pings, and qa-review escalations all flow through this verb.
# Mirrors the prose entry at mika/skills/bundled/permission-policy/system_prompt.md:21.
#
# Sentinel cross-ref: mika/crates/mika-agent/src/well_known_agents.rs:386-396
# documents this as a deliberately duplicated list across languages with a
# "if it grows beyond 5 entries OR diverges, escalate to build-time codegen"
# callout. 3 entries < 5, so manual duplication is acceptable for Phase A.

INTRA_PLATFORM_AGENTS: frozenset[str] = frozenset({
    "mika-arch",
    "mika-dev",
    "mika-qa",
})

_MIKA_DISPATCH_RE = re.compile(r"^\s*mika\s+ask\s+--agent\s+(\S+)\b")


def is_safe_mika_dispatch(sub: str) -> bool:
    match = _MIKA_DISPATCH_RE.match(sub)
    if not match:
        return False
    return match.group(1) in INTRA_PLATFORM_AGENTS


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
