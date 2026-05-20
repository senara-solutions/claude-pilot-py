"""Tests for the orchestrator inbox writer (mika#1189)."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from claude_pilot.inbox_writer import (
    _build_url,
    _is_valid_orchestrator_id,
    is_orchestrator_inbox_enabled,
    post_handoff,
)
from claude_pilot.types import ResultJson

# -- Pure helpers --


@pytest.mark.parametrize(
    "raw,expected",
    [
        (None, False),
        ("", False),
        ("0", False),
        ("false", False),
        ("False", False),
        ("FALSE", False),
        ("2", False),  # reserved future value — currently disabled
        ("anything-else", False),
        ("1", True),
        (" 1 ", True),
        ("true", True),
        ("True", True),
        ("TRUE", True),
        ("\ttrue\n", True),
    ],
)
def test_is_orchestrator_inbox_enabled(raw: str | None, expected: bool) -> None:
    assert is_orchestrator_inbox_enabled(raw) is expected


@pytest.mark.parametrize(
    "value,expected",
    [
        ("", False),
        ("a", True),
        ("550e8400-e29b-41d4-a716-446655440000", True),
        ("20260517T204027Z-12345", True),
        ("vincent_desktop_orch_1", True),
        ("a" * 128, True),
        ("a" * 129, False),
        ("../etc/passwd", False),
        ("foo/bar", False),
        ("foo bar", False),
        ("foo@bar", False),
        ("foo$bar", False),
    ],
)
def test_is_valid_orchestrator_id(value: str, expected: bool) -> None:
    assert _is_valid_orchestrator_id(value) is expected


def test_build_url_normalises_trailing_slash() -> None:
    assert (
        _build_url("https://gw.example/", "orch-1")
        == "https://gw.example/orchestrator/inbox/orch-1/message"
    )
    assert (
        _build_url("https://gw.example", "orch-1")
        == "https://gw.example/orchestrator/inbox/orch-1/message"
    )
    assert (
        _build_url("https://gw.example//", "orch-1")
        == "https://gw.example/orchestrator/inbox/orch-1/message"
    )


# -- post_handoff env-gating --


def _result(**overrides: Any) -> ResultJson:
    base = {
        "status": "success",
        "subtype": "success",
        "task_id": "t-1",
        "session_id": "sess-1",
        "turns": 12,
        "cost_usd": 0.42,
        "duration_ms": 12345,
    }
    base.update(overrides)
    return ResultJson(**base)


def test_post_handoff_skips_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MIKA_ORCHESTRATOR_INBOX_ENABLED", raising=False)
    monkeypatch.setenv("MIKA_ORCHESTRATOR_ID", "orch-1")
    monkeypatch.setenv("MIKA_GATEWAY_URL", "https://gw.example")
    monkeypatch.setenv("MIKA_INTERNAL_TOKEN", "tok")
    assert post_handoff(_result()) is False


def test_post_handoff_skips_when_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MIKA_ORCHESTRATOR_INBOX_ENABLED", "0")
    monkeypatch.setenv("MIKA_ORCHESTRATOR_ID", "orch-1")
    monkeypatch.setenv("MIKA_GATEWAY_URL", "https://gw.example")
    monkeypatch.setenv("MIKA_INTERNAL_TOKEN", "tok")
    assert post_handoff(_result()) is False


def test_post_handoff_skips_when_orchestrator_id_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MIKA_ORCHESTRATOR_INBOX_ENABLED", "1")
    monkeypatch.delenv("MIKA_ORCHESTRATOR_ID", raising=False)
    monkeypatch.setenv("MIKA_GATEWAY_URL", "https://gw.example")
    monkeypatch.setenv("MIKA_INTERNAL_TOKEN", "tok")
    assert post_handoff(_result()) is False


def test_post_handoff_skips_when_orchestrator_id_invalid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MIKA_ORCHESTRATOR_INBOX_ENABLED", "1")
    monkeypatch.setenv("MIKA_ORCHESTRATOR_ID", "../etc/passwd")
    monkeypatch.setenv("MIKA_GATEWAY_URL", "https://gw.example")
    monkeypatch.setenv("MIKA_INTERNAL_TOKEN", "tok")
    assert post_handoff(_result()) is False


def test_post_handoff_skips_when_gateway_url_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MIKA_ORCHESTRATOR_INBOX_ENABLED", "1")
    monkeypatch.setenv("MIKA_ORCHESTRATOR_ID", "orch-1")
    monkeypatch.delenv("MIKA_GATEWAY_URL", raising=False)
    monkeypatch.setenv("MIKA_INTERNAL_TOKEN", "tok")
    assert post_handoff(_result()) is False


def test_post_handoff_skips_when_internal_token_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MIKA_ORCHESTRATOR_INBOX_ENABLED", "1")
    monkeypatch.setenv("MIKA_ORCHESTRATOR_ID", "orch-1")
    monkeypatch.setenv("MIKA_GATEWAY_URL", "https://gw.example")
    monkeypatch.delenv("MIKA_INTERNAL_TOKEN", raising=False)
    assert post_handoff(_result()) is False


# -- post_handoff success path --


def test_post_handoff_posts_envelope_to_gateway(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MIKA_ORCHESTRATOR_INBOX_ENABLED", "1")
    monkeypatch.setenv("MIKA_ORCHESTRATOR_ID", "orch-abc")
    monkeypatch.setenv("MIKA_GATEWAY_URL", "https://gw.example")
    monkeypatch.setenv("MIKA_INTERNAL_TOKEN", "tok-xyz")
    monkeypatch.setenv("MIKA_SPAWN_ID", "spawn-xyz")

    response = MagicMock()
    response.status = 201
    response.__enter__ = lambda self: response
    response.__exit__ = lambda self, exc_type, exc_val, exc_tb: None

    captured: dict[str, Any] = {}

    def fake_urlopen(req: Any, timeout: float) -> Any:
        captured["url"] = req.full_url
        captured["method"] = req.get_method()
        captured["headers"] = dict(req.headers)
        captured["body"] = req.data
        captured["timeout"] = timeout
        return response

    with patch("claude_pilot.inbox_writer.urllib.request.urlopen", side_effect=fake_urlopen):
        assert post_handoff(_result()) is True

    assert captured["url"] == "https://gw.example/orchestrator/inbox/orch-abc/message"
    assert captured["method"] == "POST"
    assert captured["headers"]["Authorization"] == "Bearer tok-xyz"
    assert captured["headers"]["Content-type"] == "application/json"
    assert captured["timeout"] > 0

    parsed = json.loads(captured["body"])
    assert parsed["spawn_id"] == "spawn-xyz"
    assert parsed["kind"] == "handoff"
    assert parsed["body"]["result"]["status"] == "success"
    assert parsed["body"]["result"]["turns"] == 12


def test_post_handoff_uses_explicit_spawn_id_over_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MIKA_ORCHESTRATOR_INBOX_ENABLED", "1")
    monkeypatch.setenv("MIKA_ORCHESTRATOR_ID", "orch-1")
    monkeypatch.setenv("MIKA_GATEWAY_URL", "https://gw.example")
    monkeypatch.setenv("MIKA_INTERNAL_TOKEN", "tok")
    monkeypatch.setenv("MIKA_SPAWN_ID", "env-spawn")

    response = MagicMock()
    response.status = 201
    response.__enter__ = lambda self: response
    response.__exit__ = lambda self, exc_type, exc_val, exc_tb: None

    captured: dict[str, Any] = {}

    def fake_urlopen(req: Any, timeout: float) -> Any:
        captured["body"] = req.data
        return response

    with patch("claude_pilot.inbox_writer.urllib.request.urlopen", side_effect=fake_urlopen):
        assert post_handoff(_result(), spawn_id="explicit-spawn") is True

    parsed = json.loads(captured["body"])
    assert parsed["spawn_id"] == "explicit-spawn"


def test_post_handoff_skips_when_payload_oversized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MIKA_ORCHESTRATOR_INBOX_ENABLED", "1")
    monkeypatch.setenv("MIKA_ORCHESTRATOR_ID", "orch-1")
    monkeypatch.setenv("MIKA_GATEWAY_URL", "https://gw.example")
    monkeypatch.setenv("MIKA_INTERNAL_TOKEN", "tok")

    huge_payload = {"giant": "x" * (300 * 1024)}

    with patch("claude_pilot.inbox_writer.urllib.request.urlopen") as urlopen_mock:
        assert post_handoff(_result(), extra_body=huge_payload) is False
        urlopen_mock.assert_not_called()


def test_post_handoff_returns_false_on_404(monkeypatch: pytest.MonkeyPatch) -> None:
    """Gateway has the feature flag off — caller must keep filesystem inbox as
    canonical (silent no-op semantics)."""
    monkeypatch.setenv("MIKA_ORCHESTRATOR_INBOX_ENABLED", "1")
    monkeypatch.setenv("MIKA_ORCHESTRATOR_ID", "orch-1")
    monkeypatch.setenv("MIKA_GATEWAY_URL", "https://gw.example")
    monkeypatch.setenv("MIKA_INTERNAL_TOKEN", "tok")

    response = MagicMock()
    response.status = 404
    response.__enter__ = lambda self: response
    response.__exit__ = lambda self, exc_type, exc_val, exc_tb: None

    with patch("claude_pilot.inbox_writer.urllib.request.urlopen", return_value=response):
        assert post_handoff(_result()) is False


def test_post_handoff_returns_false_on_transport_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MIKA_ORCHESTRATOR_INBOX_ENABLED", "1")
    monkeypatch.setenv("MIKA_ORCHESTRATOR_ID", "orch-1")
    monkeypatch.setenv("MIKA_GATEWAY_URL", "https://gw.example")
    monkeypatch.setenv("MIKA_INTERNAL_TOKEN", "tok")

    import urllib.error

    with patch(
        "claude_pilot.inbox_writer.urllib.request.urlopen",
        side_effect=urllib.error.URLError("connection refused"),
    ):
        # Must not raise; must return False.
        assert post_handoff(_result()) is False


def test_post_handoff_returns_false_on_http_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MIKA_ORCHESTRATOR_INBOX_ENABLED", "1")
    monkeypatch.setenv("MIKA_ORCHESTRATOR_ID", "orch-1")
    monkeypatch.setenv("MIKA_GATEWAY_URL", "https://gw.example")
    monkeypatch.setenv("MIKA_INTERNAL_TOKEN", "tok")

    import urllib.error

    with patch(
        "claude_pilot.inbox_writer.urllib.request.urlopen",
        side_effect=urllib.error.HTTPError(
            "https://gw.example",
            500,
            "boom",
            {},
            None,  # type: ignore[arg-type]
        ),
    ):
        assert post_handoff(_result()) is False


def test_post_handoff_returns_false_on_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MIKA_ORCHESTRATOR_INBOX_ENABLED", "1")
    monkeypatch.setenv("MIKA_ORCHESTRATOR_ID", "orch-1")
    monkeypatch.setenv("MIKA_GATEWAY_URL", "https://gw.example")
    monkeypatch.setenv("MIKA_INTERNAL_TOKEN", "tok")

    with patch(
        "claude_pilot.inbox_writer.urllib.request.urlopen",
        side_effect=TimeoutError("slow gateway"),
    ):
        assert post_handoff(_result()) is False
