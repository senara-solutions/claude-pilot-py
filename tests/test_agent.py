"""Agent integration tests — turn-boundary marker logging (cpp#10).

Drives `run_agent` via a fake `ClaudeSDKClient` that yields a scripted sequence
of SDK messages. The seam exercised is `run_agent` ↔ SDK messages ↔ guardrails
↔ ui — the surface that actually breaks in production when a thinking-only
turn leaves the log empty.

Fake-stream over helper extraction: extracting the AssistantMessage loop into a
testable helper would add indirection with one caller. Driving the public
entrypoint with a fake stream keeps production code unchanged and validates
the integrated behavior (cpp#10 plan §Test strategy).
"""

from __future__ import annotations

from typing import Any

import pytest
from claude_agent_sdk.types import (
    AssistantMessage,
    ResultMessage,
    SystemMessage,
    TextBlock,
    ThinkingBlock,
    ToolUseBlock,
)

from claude_pilot import agent as agent_module
from claude_pilot.agent import run_agent
from claude_pilot.guardrails import SessionGuardrails
from claude_pilot.types import ResolvedGuardrailConfig


def _config() -> ResolvedGuardrailConfig:
    return ResolvedGuardrailConfig(
        maxTurns=200,
        maxBudgetUsd=0.0,
        # Disable stall/empty detection so thinking-only runs don't abort early.
        stallThreshold=0,
        emptyResponseThreshold=0,
        idleTimeoutMs=0,
        minTurnsBeforeDetection=0,
    )


def _assistant(blocks: list[Any], message_id: str) -> AssistantMessage:
    return AssistantMessage(content=blocks, model="claude-test", message_id=message_id)


def _result() -> ResultMessage:
    return ResultMessage(
        subtype="success",
        duration_ms=100,
        duration_api_ms=50,
        is_error=False,
        num_turns=1,
        session_id="sess_test",
        total_cost_usd=0.0,
    )


def _init() -> SystemMessage:
    return SystemMessage(subtype="init", data={"session_id": "sess_test", "model": "claude-test"})


class _FakeClient:
    def __init__(self, messages: list[Any]) -> None:
        self._messages = messages

    async def __aenter__(self) -> _FakeClient:
        return self

    async def __aexit__(self, *_: Any) -> None:
        return None

    async def query(self, _prompt: str) -> None:
        return None

    async def interrupt(self) -> None:
        return None

    def receive_response(self) -> Any:
        async def gen() -> Any:
            for m in self._messages:
                yield m

        return gen()


def _install_fake_client(monkeypatch: pytest.MonkeyPatch, messages: list[Any]) -> None:
    """Replace ClaudeSDKClient in agent.py with a constructor that returns a
    FakeClient yielding the scripted message sequence."""

    def _factory(*_args: Any, **_kwargs: Any) -> _FakeClient:
        return _FakeClient(messages)

    monkeypatch.setattr(agent_module, "ClaudeSDKClient", _factory)


async def _noop_permission(*_args: Any, **_kwargs: Any) -> Any:  # pragma: no cover
    raise AssertionError("permission handler must not be invoked in these tests")


@pytest.mark.asyncio
async def test_thinking_only_turns_emit_one_marker_each(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Feed N thinking-only turns (each a distinct message_id) followed by a
    ResultMessage. Expect N `[turn k] thinking-only, no actions` markers — k-1
    from boundary events + 1 from `close_final_turn` (cpp#10 AC 1)."""
    n_turns = 3
    messages: list[Any] = [_init()]
    for i in range(n_turns):
        messages.append(
            _assistant([ThinkingBlock(thinking="planning", signature="sig")], f"msg_{i}")
        )
    messages.append(_result())

    _install_fake_client(monkeypatch, messages)
    guardrails = SessionGuardrails(_config())

    exit_code = await run_agent(
        prompt="test",
        cwd=".",
        verbose=False,
        task_id=None,
        permission_handler=_noop_permission,
        guardrails=guardrails,
    )

    captured = capsys.readouterr()
    err = captured.err
    for k in range(1, n_turns + 1):
        assert f"[turn {k}]" in err, f"missing marker for turn {k}; stderr was:\n{err}"
        assert "thinking-only, no actions" in err
    assert exit_code == 0


@pytest.mark.asyncio
async def test_text_and_tool_turn_emits_no_marker(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A turn carrying [ThinkingBlock, TextBlock, ToolUseBlock] is productive —
    `_on_boundary` suppresses the marker for both the AssistantMessage-driven
    boundary event AND `close_final_turn` (cpp#10 AC 2, marker-suppression
    half).

    NOTE: AC 2 in the plan also reads "assert log contains the text line".
    That assertion exercises `_text_of` in agent.py, which has the same
    SDK-dataclass `type`-attribute gap that `_block_type` worked around in
    cpp#4. That latent bug is out of scope for cpp#10 (the silent-turn marker
    fix) and is left for a follow-up. Only the marker-suppression behavior is
    asserted here.
    """
    text = "here is the plan with enough content to clear text-len threshold"
    messages: list[Any] = [
        _init(),
        _assistant(
            [
                ThinkingBlock(thinking="x", signature="sig"),
                TextBlock(text=text),
                ToolUseBlock(id="t1", name="Bash", input={"command": "ls"}),
            ],
            "msg_1",
        ),
        _assistant(
            [
                ThinkingBlock(thinking="y", signature="sig"),
                TextBlock(text=text),
                ToolUseBlock(id="t2", name="Bash", input={"command": "pwd"}),
            ],
            "msg_2",
        ),
        _result(),
    ]
    _install_fake_client(monkeypatch, messages)
    guardrails = SessionGuardrails(_config())

    await run_agent(
        prompt="test",
        cwd=".",
        verbose=False,
        task_id=None,
        permission_handler=_noop_permission,
        guardrails=guardrails,
    )

    err = capsys.readouterr().err
    assert "[turn 1]" not in err, "productive turn must not emit a marker"
    assert "[turn 2]" not in err, "productive final turn must not emit a marker via close_final_turn"
    assert "thinking-only" not in err
    assert "no observable output" not in err


@pytest.mark.asyncio
async def test_final_thinking_only_turn_marker_fires_via_close_final_turn(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A single thinking-only AssistantMessage followed immediately by a
    ResultMessage. No subsequent AssistantMessage means the boundary event is
    never emitted from `on_assistant_message` — `close_final_turn()` is the
    only path that fires the marker (cpp#10 AC 1 final-turn coverage)."""
    messages: list[Any] = [
        _init(),
        _assistant([ThinkingBlock(thinking="planning", signature="sig")], "msg_1"),
        _result(),
    ]
    _install_fake_client(monkeypatch, messages)
    guardrails = SessionGuardrails(_config())

    await run_agent(
        prompt="test",
        cwd=".",
        verbose=False,
        task_id=None,
        permission_handler=_noop_permission,
        guardrails=guardrails,
    )

    err = capsys.readouterr().err
    assert "[turn 1]" in err, (
        f"close_final_turn must emit the marker for the unclosed final turn; stderr was:\n{err}"
    )
    assert "thinking-only, no actions" in err


@pytest.mark.asyncio
async def test_text_only_final_turn_emits_no_marker(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """NF7 guard: if `close_final_turn` ever forgot to populate `had_text` /
    `had_tool_use`, `_on_boundary` would defensively print 'no observable
    output' for a text+tool final turn. Lock that out (cpp#10 plan NF7)."""
    text = "final productive turn with sufficient observable content"
    messages: list[Any] = [
        _init(),
        _assistant(
            [
                TextBlock(text=text),
                ToolUseBlock(id="t1", name="Bash", input={"command": "ls"}),
            ],
            "msg_1",
        ),
        _result(),
    ]
    _install_fake_client(monkeypatch, messages)
    guardrails = SessionGuardrails(_config())

    await run_agent(
        prompt="test",
        cwd=".",
        verbose=False,
        task_id=None,
        permission_handler=_noop_permission,
        guardrails=guardrails,
    )

    err = capsys.readouterr().err
    assert "[turn 1]" not in err
    assert "no observable output" not in err
    assert "thinking-only" not in err


# ---- cpp#12: _text_of must handle SDK dataclass TextBlock (no `type` attr) ----


def test_text_of_returns_text_for_sdk_dataclass_textblock() -> None:
    """SDK dataclass `TextBlock` instances do not carry a `type` attribute —
    the wire-format `type` is consumed by the parser. `_text_of` must fall
    back on class name so `log_text` fires for production text-emitting turns.
    Regression for cpp#12 (production pilot logs emitting zero [text] lines).
    """
    block = TextBlock(text="hello world")
    assert agent_module._text_of(block) == "hello world"


def test_text_of_returns_text_for_dict_shaped_block() -> None:
    """Dict-shaped blocks (legacy wire-format) must continue to work."""
    block = {"type": "text", "text": "hello world"}
    assert agent_module._text_of(block) == "hello world"


def test_text_of_returns_none_for_non_text_block() -> None:
    """Non-text blocks (ThinkingBlock, ToolUseBlock) must return None."""
    assert agent_module._text_of(ThinkingBlock(thinking="x", signature="sig")) is None
    assert agent_module._text_of(ToolUseBlock(id="t1", name="Bash", input={})) is None


@pytest.mark.asyncio
async def test_single_init_no_reconnect(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Regression guard for cpp#7: a normal session with one init must emit
    exactly one `[init]` line and zero `[reconnect]` lines."""
    messages: list[Any] = [_init(), _result()]

    _install_fake_client(monkeypatch, messages)
    guardrails = SessionGuardrails(_config())

    exit_code = await run_agent(
        prompt="test",
        cwd=".",
        verbose=False,
        task_id=None,
        permission_handler=_noop_permission,
        guardrails=guardrails,
    )

    err = capsys.readouterr().err
    assert err.count("[init]") == 1
    assert err.count("[reconnect]") == 0
    assert exit_code == 0


@pytest.mark.asyncio
async def test_multi_init_logs_reconnect_after_first(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """cpp#7: when the SDK emits multiple `SystemMessage(subtype="init")`
    events for a single session (transient reconnects), only the first should
    log `[init]` + `[prompt]`. Subsequent inits log `[reconnect]` instead so
    audits don't see fake re-dispatches.

    Mirrors the original incident shape: three rapid inits in a row.

    Also pins the invariant that `log_prompt` (file-log sink, invisible to
    capsys) is called exactly once across the reconnect sequence — guards
    against a future refactor that moves the prompt emission out of the
    `if not seen_init` branch.
    """
    prompt_calls: list[str] = []

    def _record_prompt(prompt: str) -> None:
        prompt_calls.append(prompt)

    monkeypatch.setattr(agent_module, "log_prompt", _record_prompt)

    messages: list[Any] = [_init(), _init(), _init(), _result()]

    _install_fake_client(monkeypatch, messages)
    guardrails = SessionGuardrails(_config())

    exit_code = await run_agent(
        prompt="test",
        cwd=".",
        verbose=False,
        task_id=None,
        permission_handler=_noop_permission,
        guardrails=guardrails,
    )

    err = capsys.readouterr().err
    assert err.count("[init]") == 1, f"expected one [init], got:\n{err}"
    assert err.count("[reconnect]") == 2, f"expected two [reconnect], got:\n{err}"
    assert err.index("[init]") < err.index("[reconnect]")
    assert prompt_calls == ["test"], f"expected one log_prompt call, got: {prompt_calls}"
    assert exit_code == 0


# ────────────────────────────────────────────────────────────────────────────
# cpp#20 joint 2 synthetic-emit regression test
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_agent_emits_synthetic_terminal_on_silent_stream_end(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """cpp#20 joint 2 safety contract: when the SDK message stream ends
    without yielding a ResultMessage (the Case-B failure mode introduced
    by ``PermissionResultDeny(interrupt=True)`` at the can_use_tool
    boundary), ``run_agent`` MUST emit a synthetic terminal ResultJson
    to stdout so dispatch-lib's ``grep -m1 '^{' | jq -r '.status'``
    parsing always sees a non-success status. Without this guard the
    pilot would exit silently with empty stdout — the seam joint 2's
    safety story rests on.

    Mock the SDK client to yield only init + assistant messages (no
    ResultMessage), simulating the CLI closing its stdio pipe cleanly
    after the SDK relays interrupt=True. Capture stdout, parse the
    first ``^{`` line, assert it has status="error" and the
    cpp#20-defined subtype.
    """
    import json

    messages: list[Any] = [
        _init(),
        _assistant([TextBlock(text="going to run a denied tool now")], "msg1"),
        # No ResultMessage — stream just ends. This is the Case-B trigger.
    ]

    _install_fake_client(monkeypatch, messages)
    guardrails = SessionGuardrails(_config())

    exit_code = await run_agent(
        prompt="test",
        cwd=".",
        verbose=False,
        task_id="task_synthetic_test",
        permission_handler=_noop_permission,
        guardrails=guardrails,
    )

    captured = capsys.readouterr()
    # Exactly one terminal JSON line on stdout — no double-emit, no silent exit.
    json_lines = [line for line in captured.out.splitlines() if line.startswith("{")]
    assert len(json_lines) == 1, (
        f"expected exactly one terminal JSON line, got {len(json_lines)}:\n{captured.out!r}"
    )

    payload = json.loads(json_lines[0])
    # dispatch-lib parses .status with `jq -r '.status // empty'` — assert the
    # value is a non-success that maps cleanly.
    assert payload["status"] == "error", (
        f"expected status=error for silent stream end, got {payload!r}"
    )
    assert payload["subtype"] == "stream_ended_without_result", (
        f"expected subtype=stream_ended_without_result, got {payload!r}"
    )
    assert payload["task_id"] == "task_synthetic_test"
    # exit code reflects the silent-stream-end as a non-success run.
    assert exit_code == 1


# ── mika#1409: denied-Bash prevention hint is injected into the system prompt ─


def test_1409_system_prompt_helper_is_preset_append_with_hint() -> None:
    """`_system_prompt_with_hint()` must PRESERVE the claude_code preset and
    append the denied-Bash hint — a plain string would wipe the preset and
    break the headless /mika pipeline."""
    from claude_pilot.tier1 import DENIED_BASH_PATTERNS_HINT

    sp = agent_module._system_prompt_with_hint()
    assert sp["type"] == "preset"
    assert sp["preset"] == "claude_code"
    assert sp["append"] == DENIED_BASH_PATTERNS_HINT
    assert "-exec" in sp["append"] and "Grep" in sp["append"]


@pytest.mark.asyncio
async def test_1409_run_agent_passes_system_prompt_into_options(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end wiring: run_agent constructs ClaudeAgentOptions with the
    preset-append system_prompt, so every pilot session actually sees the hint.
    """
    captured: dict[str, Any] = {}

    def _capturing_options(*_args: Any, **kwargs: Any) -> Any:
        captured.update(kwargs)
        return object()  # FakeClient ignores options

    monkeypatch.setattr(agent_module, "ClaudeAgentOptions", _capturing_options)
    _install_fake_client(monkeypatch, [_init(), _result()])

    await run_agent(
        prompt="test",
        cwd=".",
        verbose=False,
        task_id=None,
        permission_handler=_noop_permission,
        guardrails=SessionGuardrails(_config()),
    )

    sp = captured.get("system_prompt")
    assert isinstance(sp, dict)
    assert sp["type"] == "preset" and sp["preset"] == "claude_code"
    assert "-exec" in sp["append"] and "Grep" in sp["append"]
