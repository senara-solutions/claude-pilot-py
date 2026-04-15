"""ResultJson cost_usd semantics — claude-pilot-py#5.

When a session terminates with no cost information available (guardrail trip
before ResultMessage arrives, or fatal CLI error), cost_usd must be `None`
rather than a misleading `0.0`. The handler in mika-skills/claude-pilot parses
cost via `jq -r '.cost_usd // empty'` so absent/None is handled as unknown.
"""

from __future__ import annotations

import json

import pytest

from claude_pilot.types import ResultJson


def test_result_json_accepts_none_cost() -> None:
    r = ResultJson(
        status="terminated",
        subtype="stall_detected",
        turns=14,
        cost_usd=None,
        duration_ms=71000,
    )
    assert r.cost_usd is None


def test_result_json_excludes_none_cost_from_serialized_line() -> None:
    """`to_line()` uses exclude_none — None cost becomes absent field downstream,
    which the shell handler parses as empty string (unknown)."""
    r = ResultJson(
        status="terminated",
        subtype="stall_detected",
        turns=14,
        cost_usd=None,
        duration_ms=71000,
    )
    line = r.to_line()
    parsed = json.loads(line)
    assert "cost_usd" not in parsed


def test_result_json_preserves_real_cost() -> None:
    r = ResultJson(
        status="success",
        subtype="success",
        turns=57,
        cost_usd=3.847488349999999,
        duration_ms=717835,
    )
    parsed = json.loads(r.to_line())
    assert parsed["cost_usd"] == pytest.approx(3.847488349999999)


def test_result_json_rejects_zero_confused_with_unknown() -> None:
    """0.0 is a valid cost (rare but possible on cached-only runs). We keep
    the type as float | None so None means unknown and 0.0 means genuinely zero."""
    r = ResultJson(
        status="success",
        subtype="success",
        turns=1,
        cost_usd=0.0,
        duration_ms=100,
    )
    parsed = json.loads(r.to_line())
    # exclude_none leaves 0.0 in the output (0 is not None)
    assert parsed["cost_usd"] == 0.0
