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
    is_safe_bash_command,
    is_safe_git_command,
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
        "echo `whoami`",
        "cat <(echo hi)",
    ],
)
def test_tier3_denies(command: str) -> None:
    assert is_tier3_dangerous(command) is True, command
    assert is_safe_bash_command(command) is False, command


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
