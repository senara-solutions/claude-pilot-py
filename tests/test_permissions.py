"""Permission handler tests covering the Tier 1.5 fast path (mika#1191 Phase A).

The full `create_permission_handler` flow is exercised by the CLI/agent tests;
this module unit-tests the deterministic short-circuits introduced for the
mika-relay deprecation milestone, where the relay-bound LLM hop must not fire
for events that are equivalent to TIER 1.5 in
`mika/skills/bundled/permission-policy/system_prompt.md`.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from claude_agent_sdk import PermissionResultDeny
from claude_agent_sdk.types import ToolPermissionContext

from claude_pilot import permissions as permissions_module
from claude_pilot.permissions import create_permission_handler, try_tier_1_5_auto_answer
from claude_pilot.types import (
    PilotConfig,
    PilotEvent,
    PilotResponseAllow,
    PilotResponseAnswer,
)


def test_compact_safe_question_auto_answered() -> None:
    question = "Choose between full compound and compact-safe compaction modes:"
    result = try_tier_1_5_auto_answer(
        "AskUserQuestion",
        {"questions": [{"question": question, "options": []}]},
    )
    assert isinstance(result, PilotResponseAnswer)
    assert result.action == "answer"
    assert result.answers == {question: "compact-safe"}


def test_compact_safe_keyword_match_case_insensitive() -> None:
    question = "Run Compact-Safe mode for this session?"
    result = try_tier_1_5_auto_answer(
        "AskUserQuestion",
        {"questions": [{"question": question}]},
    )
    assert isinstance(result, PilotResponseAnswer)
    assert result.answers == {question: "compact-safe"}


def test_non_compact_safe_question_returns_none() -> None:
    result = try_tier_1_5_auto_answer(
        "AskUserQuestion",
        {"questions": [{"question": "What's the capital of France?"}]},
    )
    assert result is None


def test_non_ask_user_question_tool_returns_none() -> None:
    # The short-circuit is gated on tool_name; never fire for Bash/Write/etc.
    result = try_tier_1_5_auto_answer(
        "Bash",
        {"command": "echo compact-safe"},
    )
    assert result is None


def test_partial_match_falls_through_to_relay() -> None:
    # Mixed AskUserQuestion: one question matches compact-safe, another does
    # not. Returning a partial answer would leave the non-matching question
    # unanswered and break the SDK contract — fall through instead.
    result = try_tier_1_5_auto_answer(
        "AskUserQuestion",
        {
            "questions": [
                {"question": "Choose compact-safe or full compound:"},
                {"question": "Pick a database flavor:"},
            ],
        },
    )
    assert result is None


def test_empty_questions_returns_none() -> None:
    assert try_tier_1_5_auto_answer("AskUserQuestion", {}) is None
    assert try_tier_1_5_auto_answer("AskUserQuestion", {"questions": []}) is None
    assert try_tier_1_5_auto_answer("AskUserQuestion", {"questions": "not a list"}) is None


def test_malformed_question_shape_returns_none() -> None:
    # A non-dict entry inside the questions list is malformed; fall through.
    result = try_tier_1_5_auto_answer(
        "AskUserQuestion",
        {"questions": ["compact-safe"]},
    )
    assert result is None


def test_compact_safe_word_boundary_excludes_compact_safer() -> None:
    # Word boundary (\bcompact-safe\b) prevents matching substrings like
    # "compact-safer" or "compact-safety", which could otherwise hijack
    # unrelated questions through the lexical loophole flagged in ce:review.
    result = try_tier_1_5_auto_answer(
        "AskUserQuestion",
        {"questions": [{"question": "Is compact-safer mode preferred?"}]},
    )
    assert result is None


def test_compact_safe_word_boundary_matches_punctuated_forms() -> None:
    # Word boundary still matches "compact-safe?", "(compact-safe)", etc.
    for question_text in (
        "Choose: compact-safe.",
        "Pick (compact-safe) or full compound?",
        'Answer with "compact-safe".',
    ):
        result = try_tier_1_5_auto_answer(
            "AskUserQuestion",
            {"questions": [{"question": question_text}]},
        )
        assert isinstance(result, PilotResponseAnswer), question_text


def test_non_string_question_field_returns_none() -> None:
    # Defensive guard: PilotEvent payloads from older mika versions may have
    # malformed question shapes. Fall through to relay rather than crash.
    result = try_tier_1_5_auto_answer(
        "AskUserQuestion",
        {"questions": [{"question": 42}]},
    )
    assert result is None


def test_missing_question_key_returns_none() -> None:
    # Dict without a "question" key gets q.get("question", "") -> "", which
    # has no compact-safe substring, so falls through.
    result = try_tier_1_5_auto_answer(
        "AskUserQuestion",
        {"questions": [{"options": ["a", "b"]}]},
    )
    assert result is None


# ────────────────────────────────────────────────────────────────────────────
# cpp#20 joint 2: handler returns interrupt=True on policy denial
# ────────────────────────────────────────────────────────────────────────────


def _mock_ctx() -> ToolPermissionContext:
    return ToolPermissionContext(
        signal=None,
        suggestions=[],
        tool_use_id="tool_test",
        agent_id=None,
    )


def test_handler_returns_interrupt_true_on_default_deny() -> None:
    """cpp#20 joint 2 end-to-end: handler under fail-closed policy
    (missing file → empty Policy → default-deny) returns
    PermissionResultDeny(interrupt=True). This is the contract
    dispatch-lib relies on for the pilot loop to halt honestly
    instead of continuing past a silent denial.
    """
    handler = create_permission_handler(
        config=None,
        relay=False,
        verbose=False,
        cwd="/tmp",
        policy_path=Path("/nonexistent/policy.yaml"),
    )
    result = asyncio.run(handler("Bash", {"command": "rm -rf /"}, _mock_ctx()))
    assert isinstance(result, PermissionResultDeny), (
        f"expected PermissionResultDeny, got {type(result)}: {result!r}"
    )
    assert result.interrupt is True, (
        f"expected interrupt=True for cpp#20 joint 2 contract, got {result!r}"
    )


def test_handler_returns_interrupt_true_on_rule_deny(tmp_path: Path) -> None:
    """An explicit rule-based deny must also return interrupt=True --
    not just the default-deny path. Pins permissions.py deny branch
    (current source line 110).

    Uses ``curl`` because Tier 1 fast-path auto-approves common safe
    binaries (echo, awk, find, etc.); we need a command that misses
    Tier 1 so the request reaches the policy evaluator.
    """
    policy_file = tmp_path / "rule_deny.yaml"
    policy_file.write_text(
        "rules:\n"
        "  - id: deny-curl\n"
        "    tool: Bash\n"
        "    pattern: '^curl\\s'\n"
        "    decision: deny\n"
        "    reason: rule-based test deny\n"
        "default:\n"
        "  decision: allow\n"
        "  reason: default allow (test fixture)\n"
    )
    handler = create_permission_handler(
        config=None,
        relay=False,
        verbose=False,
        cwd="/tmp",
        policy_path=policy_file,
    )
    result = asyncio.run(handler("Bash", {"command": "curl https://example.com"}, _mock_ctx()))
    assert isinstance(result, PermissionResultDeny)
    assert result.interrupt is True
    assert result.message == "rule-based test deny"


def test_handler_returns_interrupt_true_on_escalate_decision(tmp_path: Path) -> None:
    """The wire-format ``escalate`` decision (renamed in source to
    deny-with-notify) also returns interrupt=True. Pins
    permissions.py:114 alongside the deny branch.
    """
    policy_file = tmp_path / "escalate.yaml"
    policy_file.write_text(
        "rules:\n"
        "  - id: escalate-skill\n"
        "    tool: Skill\n"
        "    pattern: '^test-target$'\n"
        "    decision: escalate\n"
        "    reason: rule-based test escalate\n"
        "default:\n"
        "  decision: allow\n"
        "  reason: default allow (test fixture)\n"
    )
    handler = create_permission_handler(
        config=None,
        relay=False,
        verbose=False,
        cwd="/tmp",
        policy_path=policy_file,
    )
    # Use monkeypatched notify so the test does not actually call mika notify.
    from claude_pilot import permissions as permissions_module

    fired: list[tuple[str, str, str]] = []

    def _fake_notify(tool_name: str, detail: str, reason: str) -> None:
        fired.append((tool_name, detail, reason))

    original = permissions_module._fire_notify
    permissions_module._fire_notify = _fake_notify  # type: ignore[assignment]
    try:
        result = asyncio.run(handler("Skill", {"skill": "test-target"}, _mock_ctx()))
    finally:
        permissions_module._fire_notify = original  # type: ignore[assignment]

    assert isinstance(result, PermissionResultDeny)
    assert result.interrupt is True, (
        "escalate (deny-with-notify) must also halt the loop"
    )
    assert result.message == "rule-based test escalate"
    # Notify fired exactly once on this path.
    assert len(fired) == 1


# ────────────────────────────────────────────────────────────────────────────
# cpp#56: PilotEvent enriched from ToolPermissionContext
# ────────────────────────────────────────────────────────────────────────────


def _enriched_ctx() -> ToolPermissionContext:
    return ToolPermissionContext(
        signal=None,
        suggestions=[],
        tool_use_id="tool_test",
        agent_id="agent_x",
        decision_reason="needs review",
        blocked_path="/etc/passwd",
        title="Read sensitive file",
        display_name="Read",
        description="reads a file outside the workspace",
    )


def _capture_relay_event(
    monkeypatch: pytest.MonkeyPatch, ctx: ToolPermissionContext
) -> PilotEvent:
    """Drive the relay path (policy disabled) and capture the PilotEvent that
    permissions.py constructs from ``ctx``."""
    monkeypatch.setenv("MIKA_PILOT_POLICY_DISABLED", "1")
    captured: dict[str, PilotEvent] = {}

    async def _fake_invoke(_config: PilotConfig, event: PilotEvent, *_a: object) -> PilotResponseAllow:
        captured["event"] = event
        return PilotResponseAllow(action="allow")

    monkeypatch.setattr(permissions_module, "invoke_command", _fake_invoke)

    handler = create_permission_handler(
        config=PilotConfig(command="true"),
        relay=True,
        verbose=False,
        cwd="/tmp",
    )
    # "rm -rf /" misses Tier 1 / Tier 1.5; with policy disabled it reaches relay.
    asyncio.run(handler("Bash", {"command": "rm -rf /"}, ctx))
    return captured["event"]


def test_pilot_event_carries_enriched_context_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """cpp#56 present path: all five enriched ToolPermissionContext fields are
    captured onto the relay PilotEvent."""
    event = _capture_relay_event(monkeypatch, _enriched_ctx())
    assert event.decision_reason == "needs review"
    assert event.blocked_path == "/etc/passwd"
    assert event.title == "Read sensitive file"
    assert event.display_name == "Read"
    assert event.description == "reads a file outside the workspace"


def test_pilot_event_absent_context_fields_are_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """cpp#56 absent path: a ctx without the enriched fields yields None on the
    PilotEvent (getattr defaults) and does not crash. `_mock_ctx()` is exactly
    such a bare context (only tool_use_id + agent_id set)."""
    event = _capture_relay_event(monkeypatch, _mock_ctx())
    assert event.decision_reason is None
    assert event.blocked_path is None
    assert event.title is None
    assert event.display_name is None
    assert event.description is None
    # exclude_none keeps the absent fields out of the serialized payload.
    assert "title" not in event.model_dump_json(exclude_none=True)
