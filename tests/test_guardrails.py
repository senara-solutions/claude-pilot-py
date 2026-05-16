"""Guardrail tests — turn boundary detection across SDK content-block events.

The Python claude-agent-sdk emits one AssistantMessage per content block (Thinking,
Text, ToolUse, ...), all sharing the same `message_id` for a single logical Claude
turn. The TS SDK emits one SDKAssistantMessage per logical turn with all blocks
inside. The guardrail must group same-message_id events into a single turn or it
will mis-count stalls — exploding stall count for thinking-heavy turns and tripping
the abort prematurely (claude-pilot-py#4).
"""

from __future__ import annotations

import pytest
from claude_agent_sdk.types import TextBlock, ThinkingBlock, ToolUseBlock

from claude_pilot.guardrails import SessionGuardrails
from claude_pilot.types import ResolvedGuardrailConfig


def _config(stall: int = 5, min_turns: int = 0) -> ResolvedGuardrailConfig:
    return ResolvedGuardrailConfig(
        maxTurns=200,
        maxBudgetUsd=0.0,
        stallThreshold=stall,
        emptyResponseThreshold=5,
        idleTimeoutMs=300_000,
        minTurnsBeforeDetection=min_turns,
    )


def _think(text: str = "planning") -> ThinkingBlock:
    return ThinkingBlock(thinking=text, signature="sig")


def _text(t: str = "ok") -> TextBlock:
    return TextBlock(text=t)


def _tool(name: str = "Bash", input_data: dict | None = None) -> ToolUseBlock:
    return ToolUseBlock(id="t1", name=name, input=input_data or {"command": "ls"})


@pytest.fixture
def guardrails() -> SessionGuardrails:
    """Fresh guardrail with stall=5, no warmup."""
    return SessionGuardrails(_config())


# ── Turn-boundary tests (claude-pilot-py#4) ──────────────────────────────────


@pytest.mark.asyncio
async def test_consecutive_blocks_with_same_message_id_count_as_one_turn(
    guardrails: SessionGuardrails,
) -> None:
    """The SDK splits one Claude turn across multiple AssistantMessage events
    sharing the same message_id (Thinking, Text, ToolUse). The guardrail must
    treat them as ONE turn."""
    msg_id = "msg_abc"
    # Same-msg_id sequence: thinking → text → tool_use (all part of turn 1)
    guardrails.on_assistant_message([_think()], message_id=msg_id)
    guardrails.on_assistant_message([_text("here is the plan")], message_id=msg_id)
    guardrails.on_assistant_message([_tool()], message_id=msg_id)
    assert guardrails.turns == 1, "All same-message_id events form one turn"
    assert not guardrails.aborted


@pytest.mark.asyncio
async def test_thinking_only_blocks_within_a_turn_do_not_inflate_stall(
    guardrails: SessionGuardrails,
) -> None:
    """A turn containing thinking + text + tool_use should reset the stall
    counter once. Currently the buggy code increments stall for the thinking
    sub-event then text sub-event, then resets on tool_use — net wrong if any
    sub-event is missed."""
    # Five complete turns, each: thinking → text → tool_use (same msg_id within turn)
    for i in range(5):
        mid = f"msg_{i}"
        guardrails.on_assistant_message([_think()], message_id=mid)
        guardrails.on_assistant_message([_text(f"step {i}")], message_id=mid)
        guardrails.on_assistant_message([_tool()], message_id=mid)
    # Five productive turns: never stall
    assert guardrails.turns == 5
    assert not guardrails.aborted, "Productive thinking+text+tool turns must not stall"


@pytest.mark.asyncio
async def test_text_only_distinct_turns_still_trigger_stall(
    guardrails: SessionGuardrails,
) -> None:
    """Preserve existing behavior: 5 text-only turns with DIFFERENT message_ids
    indicate Claude has stopped using tools — stall trip is correct."""
    for i in range(5):
        guardrails.on_assistant_message([_text(f"narrating turn {i}")], message_id=f"msg_{i}")
    assert guardrails.aborted
    assert guardrails.abort_reason is not None
    assert guardrails.abort_reason.guardrail == "stall_detected"


@pytest.mark.asyncio
async def test_message_id_change_marks_new_turn_boundary(
    guardrails: SessionGuardrails,
) -> None:
    """Text-only across two different msg_ids = 2 turns, not 1."""
    guardrails.on_assistant_message([_text("first")], message_id="msg_1")
    guardrails.on_assistant_message([_text("second")], message_id="msg_2")
    assert guardrails.turns == 2


@pytest.mark.asyncio
async def test_missing_message_id_falls_back_to_per_message_turn_count(
    guardrails: SessionGuardrails,
) -> None:
    """Defensive: if the SDK doesn't provide message_id (older versions, edge cases),
    each call counts as its own turn. Backward-compatible with current behavior."""
    guardrails.on_assistant_message([_text("a")])  # no message_id
    guardrails.on_assistant_message([_text("b")])
    assert guardrails.turns == 2


# ── ToolUseBlock recognition (latent bug from the same root cause) ───────────


@pytest.mark.asyncio
async def test_sdk_tool_use_block_dataclass_is_recognized(
    guardrails: SessionGuardrails,
) -> None:
    """SDK dataclass ToolUseBlock has no `type` attribute — the guardrail must
    still recognize it and reset the stall counter. Regression guard for the
    class-name fallback returning `tooluse` (without underscore) which never
    matched `tool_use`."""
    # Prime stall counter with text-only turns
    guardrails.on_assistant_message([_text("a"), _text("b")], message_id="msg_1")
    guardrails.on_assistant_message([_text("c")], message_id="msg_2")
    assert guardrails._consecutive_stall_turns >= 1
    # Now a tool turn must reset it
    guardrails.on_assistant_message([_tool()], message_id="msg_3")
    assert guardrails._consecutive_stall_turns == 0


# ── mika#940: pipeline-completion PR-detection ──────────────────────────────


@pytest.mark.asyncio
async def test_pr_created_starts_false(guardrails: SessionGuardrails) -> None:
    """A fresh SessionGuardrails has pr_created == False (mika#940)."""
    assert guardrails.pr_created is False


@pytest.mark.asyncio
async def test_pr_created_set_by_bash_gh_pr_create(
    guardrails: SessionGuardrails,
) -> None:
    """A Bash tool_use containing `gh pr create` flips pr_created to True
    (mika#940). The dispatch-lib pipeline-completion contract reads this
    after CLAUDE_PILOT_REQUIRE_PR=1 sessions to detect premature-EndTurn."""
    guardrails.on_assistant_message(
        [_tool(name="Bash", input_data={"command": "gh pr create --fill"})],
        message_id="msg_1",
    )
    assert guardrails.pr_created is True


@pytest.mark.asyncio
async def test_pr_created_not_set_by_other_bash(
    guardrails: SessionGuardrails,
) -> None:
    """Bash tool_use without `gh pr create` substring does NOT flip
    pr_created (mika#940). False-negative coverage."""
    guardrails.on_assistant_message(
        [_tool(name="Bash", input_data={"command": "git add -A && git commit -m x"})],
        message_id="msg_1",
    )
    assert guardrails.pr_created is False


@pytest.mark.asyncio
async def test_pr_created_not_set_by_other_tool(
    guardrails: SessionGuardrails,
) -> None:
    """A non-Bash tool_use (e.g. Edit) does NOT flip pr_created even if its
    input string contains `gh pr create` (mika#940). Name-guard coverage."""
    guardrails.on_assistant_message(
        [_tool(name="Edit", input_data={"command": "gh pr create"})],
        message_id="msg_1",
    )
    assert guardrails.pr_created is False


@pytest.mark.asyncio
async def test_pr_created_is_sticky(guardrails: SessionGuardrails) -> None:
    """Once pr_created flips True, subsequent turns without `gh pr create`
    do not reset it (mika#940). The PR-creation contract is per-session,
    not per-turn."""
    guardrails.on_assistant_message(
        [_tool(name="Bash", input_data={"command": "gh pr create --fill"})],
        message_id="msg_1",
    )
    assert guardrails.pr_created is True
    guardrails.on_assistant_message(
        [_tool(name="Bash", input_data={"command": "echo done"})],
        message_id="msg_2",
    )
    assert guardrails.pr_created is True


@pytest.mark.asyncio
async def test_pr_created_substring_match(guardrails: SessionGuardrails) -> None:
    """Substring match is sufficient (mika#940 plan §Risks 1 accepts false
    positives). `gh pr create` embedded mid-command flips the flag."""
    guardrails.on_assistant_message(
        [
            _tool(
                name="Bash",
                input_data={
                    "command": "cd worktree && gh pr create --title foo && cd .."
                },
            )
        ],
        message_id="msg_1",
    )
    assert guardrails.pr_created is True
