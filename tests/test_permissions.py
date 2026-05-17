"""Permission handler tests covering the Tier 1.5 fast path (mika#1191 Phase A).

The full `create_permission_handler` flow is exercised by the CLI/agent tests;
this module unit-tests the deterministic short-circuits introduced for the
mika-relay deprecation milestone, where the relay-bound LLM hop must not fire
for events that are equivalent to TIER 1.5 in
`mika/skills/bundled/permission-policy/system_prompt.md`.
"""

from __future__ import annotations

from claude_pilot.permissions import try_tier_1_5_auto_answer
from claude_pilot.types import PilotResponseAnswer


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
