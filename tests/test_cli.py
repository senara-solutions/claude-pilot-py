"""CLI smoke tests — --help renders, all 14 flags present."""

from __future__ import annotations

import subprocess
import sys

REQUIRED_FLAGS = [
    "--task-id",
    "--no-relay",
    "--relay-config",
    "--cwd",
    "--log-dir",
    "--command",
    "--verbose",
    "--max-turns",
    "--max-budget",
    "--stall-threshold",
    "--empty-threshold",
    "--idle-timeout",
    "--min-detection-turns",
    "--no-guardrails",
]


def test_help_lists_all_flags() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "claude_pilot.cli", "--help"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    output = result.stdout + result.stderr
    missing = [flag for flag in REQUIRED_FLAGS if flag not in output]
    assert not missing, f"missing flags in --help: {missing}"


def test_missing_prompt_exits_nonzero() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "claude_pilot.cli"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode != 0
    assert "prompt is required" in result.stderr.lower()


def test_command_must_start_with_slash() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "claude_pilot.cli", "--command", "mika", "hello"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode != 0
    assert "must start with /" in result.stderr


def test_invalid_max_turns_exits_nonzero() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "claude_pilot.cli", "--max-turns", "0", "hello"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode != 0
