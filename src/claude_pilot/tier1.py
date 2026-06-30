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
#
# TIER3 is a "deny these even though tier1 would otherwise pass them" list,
# NOT the safety boundary. The allow-list (SAFE_SHELL_COMMANDS + per-command
# sub-feature guards) is the safety boundary. TIER3 catches known-dangerous
# patterns in commands that would otherwise pass tier1's allow-list.
# If a TIER3 entry is the SOLE protection against a tier1-allowed command's
# sub-feature (e.g., relying on `rm -rf` substring to block
# `awk 'BEGIN{system("rm -rf ~")}'`), the allow-list is misshapen — fix the
# allow-list, not the denylist. cpp#27 was an instance: awk + sed were dropped
# from SAFE_SHELL_COMMANDS because their sub-feature exec routes can't be
# exhaustively guarded.

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
    # NOTE: the blanket `\bxargs\b` deny was REMOVED here (cpp#40), for the same
    # reason the `find … -exec` blanket deny was (cpp#33): it was the SOLE guard
    # for xargs' inner command, which the header doctrine forbids. xargs safety
    # now lives in the allow-list layer: `_is_safe_xargs_command()` admits
    # `xargs [flags] <cmd>` only when `<cmd>` is in the SAME closed-world
    # FIND_EXEC_SAFE_COMMANDS read-only allowlist `find -exec` uses. `xargs sh -c`
    # / `xargs bash -c` stay independently caught by the `sh -c`/`bash -c`
    # patterns just above (defense in depth); `xargs sudo`/`xargs rm` deny because
    # they are not in the allowlist.
    # NOTE: the blanket `find … -(exec|execdir|delete)` deny was REMOVED here
    # (cpp#33). It was the SOLE protection for find's exec sub-feature, which
    # the TIER3 header doctrine above forbids — a denylist entry must never be
    # the only guard for a safe-listed command's sub-feature. find-exec safety
    # now lives in the allow-list layer: `_is_safe_find_command()` admits
    # `-exec/-execdir/-ok/-okdir <cmd>` only when every `<cmd>` is in the
    # closed-world FIND_EXEC_SAFE_COMMANDS read-only allowlist, and denies
    # `-delete` and any command-substitution. `sh -c`/`bash -c` wrappers inside
    # `-exec` stay independently caught by the patterns just above (defense in
    # depth).
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
# HERE, next to the patterns it describes (TIER3_PATTERNS, FIND_EXEC_SAFE_COMMANDS,
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

- `find … -exec`/`-execdir`/`-ok`/`-okdir` with a NON-read-only inner command
  (e.g. `find … -exec rm`, `find … -exec sh -c …`, `find … -exec sudo …`), and
  `find … -delete` (denied as filesystem-mutating / RCE-class, regardless of
  path). Read-only inner commands (`grep`, `cat`, `head`, `tail`, `ls`, `stat`,
  `wc`, `echo`, …) ARE auto-approved, so
  `find . -name "*.rs" -exec grep -l "struct" {} \\;` runs without halting. Still
  prefer the **Grep** tool to search file contents and the **Glob** tool to find
  files by name — they never risk a denial — but a read-only `find … -exec` no
  longer crashes the session.
- Hashing or inspecting a file with a non-safe-listed command (e.g. `md5sum`,
  `sha256sum`) → use the **Read** tool to read the file directly. Only a small
  allow-list of read-only shell tools is auto-approved; others like `md5sum`
  are denied on ANY path. Read works on any absolute path, inside or outside
  the current worktree — so prefer it for cross-worktree file comparison.
- In-place edits via `sed -i` → use the **Edit** tool.
- Writing files via shell redirect (`>`, `>>`) → use the **Write** tool.
- `xargs` with a NON-read-only inner command (`xargs rm`, `xargs sh -c …`,
  `xargs bash -c …`, `xargs sudo …`) → use the dedicated native tool. A read-only
  inner command (`grep`, `cat`, `head`, `tail`, `ls`, `stat`, `wc`, `echo`, …) IS
  auto-approved, so `find … | xargs grep -l "pattern"` runs without halting. Still
  prefer **Grep**/**Glob** for searching, but a read-only `xargs` no longer crashes
  the session.
- `eval`, `bash -c`, `sh -c` → use the dedicated native tool
  (Grep/Glob/Read/Edit/Write) for the underlying goal.

Prefer Read, Write, Edit, Grep, and Glob over their shell equivalents: they are
auto-approved and never halt the session."""


# ── Safe Bash command checking ───────────────────────────────────────────────


def _split_compound_command(command: str) -> list[str]:
    """Quote-aware split on shell operators AND raw newlines.

    Splits on ``&&``, ``||``, ``;``, ``|``, and ``\\n`` only when they appear
    OUTSIDE of single- or double-quoted regions. Quote handling mirrors POSIX
    semantics used by ``contains_unquoted_metacharacter`` in this module:

    - Inside ``"..."``, ``\\"`` is an escape pair (skipped atomically); other
      backslash sequences pass through as-is so ``"a\\|b"`` does not close the
      quote on ``\\``.
    - Inside ``'...'``, backslash is literal — only a closing ``'`` ends the
      quoted region.
    - Unterminated quotes: remaining bytes are treated as inside the quote
      (conservative — falls through to the LLM relay on malformed input).

    ``\\n`` is included because bash treats a bare newline as a command
    separator equivalent to ``;``. Without splitting on ``\\n``, a payload like
    ``git status\\nrm -rf /`` would be evaluated as one segment, miss the
    rm-rf regex on the second line, and auto-approve via the safe-git prefix.

    Pre-fix: split was a single quote-blind regex that matched ``|`` inside
    grep regex alternations (``grep "a\\|b\\|c"``), shredding the segment list
    into nonsense substrings. Every "segment" then failed the safe-list checks,
    tier1 rejected the entire research grep, and the downstream chain-safety
    check halted the pilot with `policy-deny [bash-grep]` even though the
    research command was inherently safe (read-only grep + cargo doc).
    Observed wedging mika#96 and mika#623 dispatch on 2026-06-14.
    """
    segments: list[str] = []
    n = len(command)
    i = 0
    seg_start = 0
    quote_state: str | None = None  # None / "'" / '"'

    while i < n:
        ch = command[i]

        if quote_state is None:
            if ch in ("'", '"'):
                quote_state = ch
                i += 1
                continue
            if ch in (";", "\n"):
                segments.append(command[seg_start:i].strip())
                i += 1
                seg_start = i
                continue
            if ch == "&" and i + 1 < n and command[i + 1] == "&":
                segments.append(command[seg_start:i].strip())
                i += 2
                seg_start = i
                continue
            if ch == "|":
                if i + 1 < n and command[i + 1] == "|":
                    segments.append(command[seg_start:i].strip())
                    i += 2
                    seg_start = i
                else:
                    segments.append(command[seg_start:i].strip())
                    i += 1
                    seg_start = i
                continue
            i += 1
            continue

        # inside a quote
        if quote_state == '"':
            if ch == "\\" and i + 1 < n and command[i + 1] == '"':
                i += 2
                continue
            if ch == '"':
                quote_state = None
            i += 1
            continue

        # quote_state == "'"
        if ch == "'":
            quote_state = None
        i += 1

    tail = command[seg_start:].strip()
    if tail:
        segments.append(tail)
    return [s for s in segments if s]


def contains_unquoted_metacharacter(command: str) -> bool:
    """Return True if *command* contains a backtick, ``$(`` or ``$'`` that bash
    would expand — i.e. anywhere EXCEPT inside single quotes.

    Bash performs command substitution inside double quotes; only single quotes
    suppress it. So the name is historical: the function flags substitution
    markers in unquoted AND double-quoted regions, treating only single-quoted
    regions as inert. Quote handling follows POSIX semantics:

    - Outside quotes, a bare backtick, ``$(`` or ``$'`` returns True.
    - Inside ``"..."`` regions, a bare backtick or ``$(`` returns True (cpp#41
      closed the double-quoted gap — bash expands both there). ``$'`` is NOT
      flagged inside double quotes: ANSI-C ``$'...'`` quoting is only recognized
      outside quotes, so inside a double-quoted region ``$'`` is literal.
    - Inside ``"..."`` regions, ``\\X`` is an escape pair (skipped atomically),
      so a backslash-suppressed ``\\$(``/``\\```` is NOT flagged and ``\\"`` does
      not close the region.
    - Inside ``'...'`` regions, backslash is literal — ``'foo\\\\'`` closes at
      the second ``'`` and any backtick that follows is unquoted.
    - Unterminated quotes: the scanner treats all remaining bytes as inside the
      quote (conservative — falls through to the LLM relay on malformed input).

    NOTE: the Rust mirror ``contains_unquoted_metacharacter`` in
    ``crates/mika-agent/src/server/permission_pre_classifier.rs`` (mika repo) does
    NOT yet detect double-quoted substitution. This Python side intentionally
    diverges (hardened) until the paired-audit ticket mirrors the cpp#41 fix.

    See mika#944 (ANSI-C quoting bypass), mika#946 (mika#938 F5 sentinel),
    cpp#41 (double-quoted substitution gap).
    """
    n = len(command)
    i = 0
    quote_state: str | None = None  # None / "'" / '"'

    while i < n:
        ch = command[i]
        if quote_state is not None:
            # Inside a quoted region — handle escape (double-quoted only) first.
            if quote_state == '"' and ch == '\\' and i + 1 < n:
                # Skip the `\X` pair. In bash, `\` inside double quotes suppresses
                # `$`/backtick, so `"\$(x)"` / "\`x\`" are literal — skipping the
                # pair correctly prevents flagging a SUPPRESSED substitution. `\"`
                # likewise does not close the region (handled by skipping here).
                i += 2
                continue
            if ch == quote_state:
                quote_state = None
                i += 1
                continue
            # cpp#41: bash performs command substitution inside DOUBLE quotes —
            # only SINGLE quotes suppress it. The pre-cpp#41 scanner treated a
            # double-quoted region as inert and missed `$(`/backtick, so
            # `grep "$(id)"` auto-approved and bash ran `id`. Scan double-quoted
            # regions for the two markers bash STILL expands there: `$(` and
            # backtick. `$'` is deliberately NOT flagged inside double quotes —
            # ANSI-C `$'...'` quoting is only recognized OUTSIDE quotes; inside a
            # double-quoted region `$'` is a literal dollar + apostrophe (no
            # expansion), so flagging it would be a false positive (mika#944's
            # `$'` guard correctly lives in the UNQUOTED branch only). Single-
            # quoted regions stay fully inert (bash literal semantics).
            if quote_state == '"':
                if ch == "`":
                    return True
                if ch == "$" and i + 1 < n and command[i + 1] == "(":
                    return True
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
        or is_safe_make_command(sub)
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


# ── Safe make targets ────────────────────────────────────────────────────────
#
# Closed-world allowlist (cpp#45 / mika#1639; architect session 783d4a04, n=3
# permission-policy-errs-strict class): only explicitly-enumerated read-only
# `make` targets auto-approve. `make verify-bundled-skills` is the bundled-skill
# pre-merge gate (mika#1575) CI runs on every PR — read-only, no side effects
# beyond stdout/exit code, same class as the cargo/npm verification commands.
#
# Stricter than _CARGO_RE: the pattern is full-anchored (`...\s*$`), so NO
# trailing tokens are allowed. `make` arguments can override variables and
# change behavior, so a trailing token must NOT ride the allowed prefix. Chain
# safety (`make verify-bundled-skills && rm -rf ~`) is handled upstream by
# _split_compound_command + the all-subs-safe check in is_safe_bash_command, not
# here. Each new target needs its own evidence-gated ticket (cpp#34 discipline).

SAFE_MAKE_TARGETS: frozenset[str] = frozenset({"verify-bundled-skills"})

_MAKE_RE = re.compile(r"^\s*make\s+(\S+)\s*$")


def is_safe_make_command(sub: str) -> bool:
    m = _MAKE_RE.match(sub)
    return bool(m and m.group(1) in SAFE_MAKE_TARGETS)


# ── Safe shell commands ──────────────────────────────────────────────────────

SAFE_SHELL_COMMANDS: frozenset[str] = frozenset({
    # Read-only inspection. `awk` and `sed` excluded by design (cpp#27):
    # both are general-purpose interpreters with arbitrary-code-execution
    # sub-features (awk `system()`/`print|"cmd"`/`getline|"cmd"`/`BEGIN{cmd}`,
    # GNU sed `e` command/flag) that an exhaustive sub-feature guard can't
    # enumerate safely. Both route to policy/relay where intent is judged
    # explicitly. See plan: docs/plans/2026-06-08-001-fix-27-tier1-drop-awk-sed-plan.md
    "ls", "cat", "head", "tail", "wc", "find", "grep",
    "echo", "printf", "dirname", "basename",
    # `xargs` is NOT read-only on its own — it runs an inner command. Membership
    # here only passes the SAFE_SHELL_COMMANDS gate; the actual safety decision is
    # made by the `xargs` special-case in is_safe_shell_command (cpp#40), exactly
    # like `find` is special-cased to _is_safe_find_command.
    "xargs",
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

# Closed-world allowlist of read-only commands permitted after find's exec-class
# flags (cpp#33). find runs the inner command DIRECTLY (no shell), so the first
# token after the flag is the binary that executes. We match it by exact-literal
# equality against this set — we never parse the inner command's arguments or
# semantics. This is the same shape ratified for the cpp#34 substitution
# allowlist (docs/solutions/security-issues/command-string-policy-allow-rules-are-compound-unsafe.md §4):
# over-blocking is the correct failure mode; widening the set is an
# evidence-gated follow-up, not a code change made on a hunch.
#
# An entry belongs here ONLY if the binary cannot execute another command or
# write a file through its OWN flags (we don't parse those flags). `rg`
# (ripgrep) was REMOVED before merge: `rg --pre <CMD>` / `--hostname-bin` /
# `--search-zip` execute external commands, so `find -exec rg --pre evil` is a
# proven-live RCE (cpp#33 security review). The native Grep tool (ripgrep-backed)
# covers the search use case without the exec surface.
#
# LOAD-BEARING PRECONDITION (cpp#44, RESOLVED): `grep`/`egrep`/`fgrep` are
# read-only ONLY under GNU grep. `ugrep` (a drop-in `grep` on some
# Gentoo/BSD/Homebrew hosts) adds `--filter=CMD` / `--pager` / `--view`, which
# execute commands — the same RCE class as `rg --pre` (which got `rg` dropped in
# cpp#33). This allowlist also backs `xargs <cmd>` (cpp#40), so the precondition
# governs both `find -exec grep` and `xargs grep`.
#
# Resolution (cpp#44): the cpp#33 security review empirically verified that the
# pilot's standard-Linux deployment containers resolve `find -exec` to GNU
# `/bin/grep` 3.12, which REJECTS `--filter`/`--pager`/`--view`. The ugrep exec
# vector is therefore NOT live in the deployment target. Decision: keep
# `grep`/`egrep`/`fgrep` (dropping them would defeat cpp#33 — its founding
# incidents mika#1381/#1572 are exactly `find -exec grep -l`), and treat the
# GNU-grep premise as an ACCEPTED + tracked risk documented right here.
#
# Hardening boundary: NEVER denylist `--filter`/`--pager`/`--view` by parsing the
# inner command's arguments — inner-arg lexing is forbidden (solution-doc §4). If
# a host that presents ugrep as `grep` ever enters scope, DROP the grep-family
# entries instead. A defense-in-depth startup ugrep-detection warning could live
# in `cli.py` (NOT this pure subprocess-free classifier) and is intentionally not
# added here. Do not add a new grep-family entry without re-checking this premise.
FIND_EXEC_SAFE_COMMANDS: frozenset[str] = frozenset({
    "grep", "egrep", "fgrep",
    "cat", "head", "tail", "wc",
    "ls", "stat", "file",
    "basename", "dirname", "readlink", "realpath",
    "echo", "printf",
})

# `-delete` is a built-in find action that removes matched files — always deny.
_FIND_DELETE_RE = re.compile(r"-delete\b")
# find's file-WRITING actions: `-fprintf FILE FORMAT` writes attacker-controlled
# content to an arbitrary FILE; `-fprint`/`-fprint0`/`-fls` write filenames /
# listings to FILE. None are exec or `-delete`, so they bypass the other guards
# and would otherwise fall through to the pure-search allow path — an arbitrary
# file-write primitive (cpp#33 security review, proven vs real bash). Deny them.
# `\b` keeps `-fprint` from being a false prefix of `-fprintf`/`-fprint0`; the
# stdout forms (`-printf`/`-print`/`-print0`/`-ls`) are not matched and stay
# allowed.
_FIND_WRITE_RE = re.compile(r"-(?:fprintf|fprint0|fprint|fls)\b")
# `-exec`/`-execdir`/`-ok`/`-okdir` all run an external command; capture the
# first token after each (the executed binary). Longest alternative first so
# `-execdir`/`-okdir` aren't mis-split as `-exec`/`-ok`. `-ok`/`-okdir` are
# folded in here (cpp#33) — they are exec-class (prompt-then-run) and were a
# pre-existing auto-approval gap when only `-exec`/`-execdir` were guarded.
_FIND_EXEC_INNER_RE = re.compile(r"-(?:execdir|exec|okdir|ok)\b\s+(\S+)")


def _contains_substitution(sub: str) -> bool:
    """True if *sub* contains any command-substitution marker (`$(`, backtick,
    `$'`). Used as a defense-in-depth guard by the exec-class allowlist gates
    (`_is_safe_find_command`, `_is_safe_xargs_command`): a read-only `find`/`xargs`
    invocation never needs substitution, so its presence smuggles execution.
    Shared so the two gates cannot drift. Note `is_safe_bash_command` also runs
    `contains_unquoted_metacharacter` first, which catches unquoted and
    double-quoted substitution; this substring check additionally vetoes the
    single-quoted (inert) form — the safe-direction over-block."""
    return "$(" in sub or "`" in sub or "$'" in sub


def _is_safe_find_command(sub: str) -> bool:
    """Decide whether a `find` invocation is safe to auto-approve (cpp#33).

    Safe iff it neither deletes, writes to a file, nor execs a non-read-only
    command:

    - `-delete` modifies the filesystem → deny.
    - `-fprintf`/`-fprint`/`-fprint0`/`-fls` write to an arbitrary FILE → deny
      (a write primitive that is neither exec nor `-delete`).
    - `-exec`/`-execdir`/`-ok`/`-okdir` run an external command → allow only
      when EVERY such inner command is in FIND_EXEC_SAFE_COMMANDS (exact-literal
      match; no inner-argument parsing).
    - Any command substitution (`$(`, backtick, `$'`) anywhere in the find
      invocation → deny. A legitimate read-only `find … -exec grep PATTERN …`
      never needs substitution; bash expands `$()`/backtick BEFORE find runs, so
      their presence means an outer substitution is smuggling execution. This
      guard makes the find path sound independent of whether
      ``contains_unquoted_metacharacter`` catches double-quoted `$()` (it does
      NOT today — see the separately-filed broader-gap ticket). Mirrors the
      permissions.py cpp#34 §4 rule that backtick/`$'` are never allowlistable.
    - No exec-class clause and no `-delete` → a pure read-only search → allow.

    `sh -c`/`bash -c` inside `-exec` are denied here (not in the allowlist) and
    independently by the TIER3 `sh -c`/`bash -c` patterns (defense in depth).
    """
    if _FIND_DELETE_RE.search(sub) or _FIND_WRITE_RE.search(sub):
        return False

    inner_commands = _FIND_EXEC_INNER_RE.findall(sub)
    if not inner_commands:
        return True  # pure search — no exec-class clause, no -delete

    if _contains_substitution(sub):
        return False

    return all(inner in FIND_EXEC_SAFE_COMMANDS for inner in inner_commands)


# `xargs` short flags that take a REQUIRED SEPARATE value token (e.g. `-I {}`,
# `-n 1`, `-d ,`, `-P 4`). When one of these appears as its own token, the NEXT
# token is its value, not the inner command — skip both. Attached forms (`-n1`,
# `-I{}`, `-P4`) and value-less flags (`-0`, `-r`, `-t`, `-x`, `-p`) are a single
# token and skip just themselves.
#
# This set lists ONLY getopt *required-argument* short flags. The deprecated
# `-e[eof]`/`-i[replace]`/`-l[lines]` are getopt *optional-argument* forms — an
# optional argument is taken ONLY when attached (`-i{}`), NEVER as a separate
# token. They are deliberately EXCLUDED: if they were here, `xargs -i rm cat`
# would skip `-i` AND `rm` (treating the real command `rm` as `-i`'s value) and
# allow on `cat` — a confirmed auto-approval of `rm` (cpp#40 security review, P0).
# Excluded, they fall to the single-token skip below, so `xargs -i rm cat`
# correctly evaluates `rm` and denies. This is a parser-arity contract with GNU
# getopt; over-block is the safe direction, NEVER under-block.
_XARGS_VALUE_FLAGS: frozenset[str] = frozenset(
    {"-a", "-d", "-E", "-I", "-L", "-n", "-P", "-s"}
)


def _is_safe_xargs_command(sub: str) -> bool:
    """Decide whether an `xargs` invocation is safe to auto-approve (cpp#40).

    Sibling to `_is_safe_find_command`: `xargs [flags] <cmd> …` runs `<cmd>` for
    each stdin record, so the safety question is identical to `find -exec <cmd>`.
    Allow iff the first non-flag token after `xargs` (the executed binary) is in
    the SAME closed-world FIND_EXEC_SAFE_COMMANDS read-only allowlist. We skip
    xargs' own flags structurally (see _XARGS_VALUE_FLAGS) but never parse the
    inner command's arguments — exact-literal match only, no inner lexing.

    Denies:
    - any command substitution (`$(`, backtick, `$'`) anywhere — a read-only
      `xargs grep …` never needs it; its presence smuggles execution (mirrors
      `_is_safe_find_command`; also caught at the scanner layer by cpp#41).
    - `xargs sh -c`/`xargs bash -c` (sh/bash not in the allowlist; also caught by
      the TIER3 `sh -c`/`bash -c` patterns — defense in depth).
    - `xargs sudo`/`xargs rm`/etc. (not in the allowlist).
    - a bare `xargs` with no inner command (defaults to `echo`, but ambiguous →
      over-block is the safe default).
    """
    if _contains_substitution(sub):
        return False

    tokens = sub.split()
    if not tokens or tokens[0] != "xargs":
        return False

    i = 1
    while i < len(tokens):
        tok = tokens[i]
        if tok == "--":  # explicit end-of-options; next token is the command
            i += 1
            break
        if tok.startswith("--"):
            # GNU long option. A getopt long option's value may be SEPARATE
            # (`--arg-file cat`) or `=form` (`--arg-file=cat`); we cannot know a
            # given option's arity without a full getopt table, and assuming
            # `=form`-only let `xargs --arg-file cat rm` skip just `--arg-file`,
            # land on `cat`, and allow while real xargs runs `rm` (cpp#40 security
            # review, P0). `=form` packs the value into this one token, so the
            # NEXT token is reliably the command/another flag → skip one. A BARE
            # `--long` has unknowable arity → deny (over-block). The inner command
            # may still follow `--` or an `=form` option.
            if "=" in tok:
                i += 1
                continue
            return False
        if tok.startswith("-"):
            if tok in _XARGS_VALUE_FLAGS:  # separate-value short flag → skip value
                i += 2
                continue
            i += 1  # attached-value or value-less short flag → single token
            continue
        return tok in FIND_EXEC_SAFE_COMMANDS  # first non-flag token = inner cmd

    if i < len(tokens):  # token immediately after `--`
        return tokens[i] in FIND_EXEC_SAFE_COMMANDS

    return False  # no inner command found → deny


def is_safe_shell_command(sub: str) -> bool:
    match = _FIRST_WORD_RE.match(sub)
    if not match:
        return False

    cmd = match.group(1)
    if cmd not in SAFE_SHELL_COMMANDS:
        return False

    if cmd == "find":
        return _is_safe_find_command(sub)

    if cmd == "xargs":
        return _is_safe_xargs_command(sub)

    return True


# ── Safe GitHub CLI commands ─────────────────────────────────────────────────

SAFE_GH_SUBCOMMANDS: dict[str, frozenset[str]] = {
    "pr":       frozenset({"create", "view", "list", "checkout", "diff", "checks"}),
    "issue":    frozenset({"view", "list", "edit", "comment"}),
    "run":      frozenset({"view", "list"}),
    "repo":     frozenset({"view"}),
    "release":  frozenset({"view", "list"}),
    "workflow": frozenset({"view", "list"}),
    # `auth status` is read-only — surfaces which gh installation is active,
    # which scopes are granted, and whether the cached token works. The
    # output never includes the raw token value. Other `gh auth` verbs
    # (login, logout, refresh, setup-git, token) MUST stay out — `token`
    # emits secret to stdout, the rest are mutation/auth-flow operations.
    "auth":     frozenset({"status"}),
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
