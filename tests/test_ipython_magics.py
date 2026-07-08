"""IPython magic surface tests (claude-pilot#81).

Covers extension registration (AC 1), line-magic prompt parsing + single-turn
lifecycle (AC 2), and cell-magic session continuity (AC 3) against a fake
``ClaudeSDKClient`` — the same fake-the-SDK-seam strategy as test_agent.py.
The permission chain itself is NOT re-tested here: the magics reuse
``create_permission_handler`` verbatim, whose behavior test_permissions.py /
test_tier1.py / test_rules.py already own.

The shell is the singleton ``InteractiveShell.instance()`` (magics need a real
magics_manager); each test loads the extension fresh and unloads in teardown
so the persistent ``%%claude`` session never leaks across tests.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from typing import Any, ClassVar

import pytest
from claude_agent_sdk.types import AssistantMessage, ResultMessage, TextBlock
from IPython.core.error import UsageError
from IPython.core.interactiveshell import InteractiveShell

from claude_pilot.ipython import magics as magics_module
from claude_pilot.ipython import session as session_module
from claude_pilot.ipython.magics import parse_line_prompt


class _FakeSDKClient:
    """Stand-in for ClaudeSDKClient: records lifecycle calls, echoes prompts."""

    instances: ClassVar[list[_FakeSDKClient]] = []

    def __init__(self, options: Any = None) -> None:
        self.options = options
        self.prompts: list[str] = []
        self.connect_calls = 0
        self.disconnect_calls = 0
        type(self).instances.append(self)

    async def connect(self) -> None:
        self.connect_calls += 1

    async def disconnect(self) -> None:
        self.disconnect_calls += 1

    async def query(self, prompt: str) -> None:
        self.prompts.append(prompt)

    async def interrupt(self) -> None:  # pragma: no cover — Ctrl-C path only
        return None

    def receive_response(self) -> AsyncIterator[Any]:
        async def gen() -> AsyncIterator[Any]:
            yield AssistantMessage(
                content=[TextBlock(text=f"echo:{self.prompts[-1]}")],
                model="claude-test",
            )
            yield ResultMessage(
                subtype="success",
                duration_ms=10,
                duration_api_ms=5,
                is_error=False,
                num_turns=1,
                session_id="sess_test",
                total_cost_usd=0.0012,
            )

        return gen()


@pytest.fixture()
def shell(monkeypatch: pytest.MonkeyPatch) -> Iterator[InteractiveShell]:
    monkeypatch.setattr(session_module, "ClaudeSDKClient", _FakeSDKClient)
    _FakeSDKClient.instances = []
    sh = InteractiveShell.instance()
    sh.extension_manager.load_extension("claude_pilot.ipython")
    yield sh
    sh.extension_manager.unload_extension("claude_pilot.ipython")


# ── AC 1: %load_ext registers both magics ─────────────────────────────────


def test_load_ext_registers_line_and_cell_magic(shell: InteractiveShell) -> None:
    magic_tables = shell.magics_manager.magics
    assert "claude" in magic_tables["line"]
    assert "claude" in magic_tables["cell"]


def test_unload_ext_closes_persistent_session(shell: InteractiveShell) -> None:
    shell.run_cell_magic("claude", "", "hello")
    (client,) = _FakeSDKClient.instances
    shell.extension_manager.unload_extension("claude_pilot.ipython")
    assert client.disconnect_calls == 1
    # Re-load so the fixture's teardown unload has something to unload.
    shell.extension_manager.load_extension("claude_pilot.ipython")


# ── magic argument parsing ────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ('"What files are here?"', "What files are here?"),
        ("'single quoted'", "single quoted"),
        ("bare unquoted prompt", "bare unquoted prompt"),
        ('  "  padded  "  ', "padded"),
        ('say "hi" twice', 'say "hi" twice'),  # inner quotes preserved
        ("", ""),
    ],
)
def test_parse_line_prompt(line: str, expected: str) -> None:
    assert parse_line_prompt(line) == expected


def test_line_magic_empty_prompt_raises_usage_error(shell: InteractiveShell) -> None:
    with pytest.raises(UsageError):
        shell.run_line_magic("claude", "")
    assert _FakeSDKClient.instances == []


def test_cell_magic_rejects_line_arguments(shell: InteractiveShell) -> None:
    with pytest.raises(UsageError):
        shell.run_cell_magic("claude", "--bogus", "prompt body")
    assert _FakeSDKClient.instances == []


def test_cell_magic_empty_body_raises_usage_error(shell: InteractiveShell) -> None:
    with pytest.raises(UsageError):
        shell.run_cell_magic("claude", "", "   \n  ")
    assert _FakeSDKClient.instances == []


# ── AC 2: %claude single-turn exchange, output rendered ───────────────────


def test_line_magic_runs_single_turn_and_streams_output(
    shell: InteractiveShell, capsys: pytest.CaptureFixture[str]
) -> None:
    shell.run_line_magic("claude", '"what is 2+2?"')

    (client,) = _FakeSDKClient.instances
    assert client.prompts == ["what is 2+2?"]
    captured = capsys.readouterr()
    assert "echo:what is 2+2?" in captured.out
    assert "success" in captured.err  # result footer goes to stderr

    # Single-turn: the throwaway session is connected and torn down per call.
    assert client.connect_calls == 1
    assert client.disconnect_calls == 1


def test_line_magic_does_not_share_session_across_calls(
    shell: InteractiveShell,
) -> None:
    shell.run_line_magic("claude", '"first"')
    shell.run_line_magic("claude", '"second"')
    assert len(_FakeSDKClient.instances) == 2
    assert [c.prompts for c in _FakeSDKClient.instances] == [["first"], ["second"]]


# ── AC 3: %%claude multi-turn continuity within the kernel ────────────────


def test_cell_magic_persists_session_across_invocations(
    shell: InteractiveShell, capsys: pytest.CaptureFixture[str]
) -> None:
    shell.run_cell_magic("claude", "", "remember the number 41\n")
    shell.run_cell_magic("claude", "", "add one to it\n")

    # ONE client for both invocations — the continuity contract.
    (client,) = _FakeSDKClient.instances
    assert client.prompts == ["remember the number 41", "add one to it"]
    assert client.connect_calls == 1
    assert client.disconnect_calls == 0  # stays alive for the next cell

    captured = capsys.readouterr()
    assert "echo:remember the number 41" in captured.out
    assert "echo:add one to it" in captured.out


# ── AC 4: permission relay is wired, not re-implemented ───────────────────


def test_session_options_carry_permission_handler(shell: InteractiveShell) -> None:
    """The SDK client must be constructed with a can_use_tool callback built by
    create_permission_handler — same chain as the headless pilot."""
    shell.run_cell_magic("claude", "", "hello")
    (client,) = _FakeSDKClient.instances
    assert client.options is not None
    assert client.options.can_use_tool is not None
    assert client.options.permission_mode == "default"
    assert "ScheduleWakeup" in client.options.disallowed_tools


def test_magics_module_has_no_permission_logic() -> None:
    """Guard against re-implementation drift: the ipython surface must import
    its permission handling from claude_pilot.permissions."""
    import inspect

    source = inspect.getsource(session_module)
    assert "create_permission_handler" in source
    for module in (magics_module, session_module):
        assert not hasattr(module, "is_tier1_auto_approve")
