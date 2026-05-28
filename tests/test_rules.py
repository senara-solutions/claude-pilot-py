"""Tests for the deterministic rule-file evaluator (mika#1192)."""

from __future__ import annotations

from pathlib import Path

import pytest

from claude_pilot.policy import (
    Policy,
    PolicyDecision,
    PolicyDefault,
    PolicyRule,
    evaluate,
    load_policy,
)


class TestRuleModel:
    def test_minimal_valid(self) -> None:
        rule = PolicyRule(id="r1", tool="Bash", pattern=".*", decision="allow", reason="test")
        assert rule.id == "r1"

    def test_extra_fields_allowed(self) -> None:
        rule = PolicyRule(id="r1", tool="Bash", pattern=".*", decision="deny", reason="test", severity="high", added_in="v2")
        assert rule.id == "r1"

    def test_invalid_decision_rejected(self) -> None:
        with pytest.raises(Exception, match="decision must be one of"):
            PolicyRule(id="r1", tool="Bash", pattern=".*", decision="maybe", reason="test")

    def test_invalid_regex_rejected(self) -> None:
        with pytest.raises(Exception, match="invalid regex"):
            PolicyRule(id="r1", tool="Bash", pattern="[invalid", decision="allow", reason="test")


class TestDefaultModel:
    def test_defaults(self) -> None:
        assert PolicyDefault().decision == "escalate"

    def test_invalid_decision(self) -> None:
        with pytest.raises(Exception, match="decision must be one of"):
            PolicyDefault(decision="yolo")


class TestDocModel:
    def test_empty(self) -> None:
        p = Policy()
        assert p.rules == []
        assert p.default.decision == "escalate"

    def test_full(self) -> None:
        p = Policy(
            rules=[PolicyRule(id="r1", tool="Bash", pattern="gh\\s+issue", decision="deny", reason="blocked")],
            default=PolicyDefault(decision="allow", reason="default allow"),
        )
        assert len(p.rules) == 1

    def test_extra_fields_allowed(self) -> None:
        p = Policy(version="2.0", rules=[], default=PolicyDefault())
        assert p.rules == []


class TestLoadRules:
    def test_load_from_valid_file(self, tmp_path: Path) -> None:
        f = tmp_path / "rules.yaml"
        f.write_text("rules:\n  - id: test-rule\n    tool: Bash\n    pattern: \"echo hello\"\n    decision: allow\n    reason: safe command\ndefault:\n  decision: deny\n  reason: everything else denied\n")
        p = load_policy(f)
        assert len(p.rules) == 1
        assert p.rules[0].id == "test-rule"
        assert p.default.decision == "deny"

    def test_missing_file_graceful(self, tmp_path: Path) -> None:
        p = load_policy(tmp_path / "nonexistent.yaml")
        assert p.rules == []
        assert p.default.decision == "escalate"

    def test_malformed_yaml_graceful(self, tmp_path: Path) -> None:
        f = tmp_path / "bad.yaml"
        f.write_text(": : : not valid yaml [[[")
        p = load_policy(f)
        assert p.rules == []
        assert p.default.decision == "escalate"

    def test_non_mapping_graceful(self, tmp_path: Path) -> None:
        f = tmp_path / "list.yaml"
        f.write_text("- item1\n- item2\n")
        p = load_policy(f)
        assert p.rules == []
        assert p.default.decision == "escalate"

    def test_validation_error_graceful(self, tmp_path: Path) -> None:
        f = tmp_path / "invalid.yaml"
        f.write_text("rules:\n  - id: bad\n    tool: Bash\n    pattern: \"[invalid\"\n    decision: allow\n    reason: test\n")
        p = load_policy(f)
        assert p.rules == []
        assert p.default.decision == "escalate"

    def test_env_var_resolution(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        f = tmp_path / "env_rules.yaml"
        f.write_text("rules: []\ndefault:\n  decision: allow\n  reason: env-loaded\n")
        monkeypatch.setenv("MIKA_PILOT_POLICY_PATH", str(f))
        p = load_policy()
        assert p.default.decision == "allow"
        assert p.default.reason == "env-loaded"

    def test_bundled_default_loads(self) -> None:
        p = load_policy()
        assert len(p.rules) >= 1
        assert p.default.decision == "escalate"


class TestEvaluateRules:
    @pytest.fixture()
    def rules(self) -> Policy:
        return Policy(
            rules=[
                PolicyRule(id="bash-gh-issue", tool="Bash", pattern=r"gh\s+issue\s+create", decision="deny", reason="blocked"),
                PolicyRule(id="bash-echo", tool="Bash", pattern=r"^echo\s", decision="allow", reason="safe"),
                PolicyRule(id="skill-ask", tool="Skill", pattern=r"^mika-ask$", decision="escalate", reason="escalated"),
            ],
            default=PolicyDefault(decision="escalate", reason="default escalate"),
        )

    def test_rule_match(self, rules: Policy) -> None:
        result = evaluate(rules, "Bash", {"command": "gh issue create --title test"})
        assert result.decision == "deny"
        assert result.rule_id == "bash-gh-issue"

    def test_no_match_uses_default(self, rules: Policy) -> None:
        result = evaluate(rules, "Bash", {"command": "ls -la"})
        assert result.decision == "escalate"
        assert result.rule_id is None

    def test_tool_mismatch_skips(self, rules: Policy) -> None:
        result = evaluate(rules, "Skill", {"skill": "gh issue create"})
        assert result.decision == "escalate"
        assert result.rule_id is None

    def test_first_match_wins(self, rules: Policy) -> None:
        result = evaluate(rules, "Bash", {"command": "echo hello"})
        assert result.decision == "allow"
        assert result.rule_id == "bash-echo"

    def test_skill_match(self, rules: Policy) -> None:
        result = evaluate(rules, "Skill", {"skill": "mika-ask"})
        assert result.decision == "escalate"
        assert result.rule_id == "skill-ask"

    def test_write_tool_uses_file_path(self) -> None:
        p = Policy(
            rules=[PolicyRule(id="block-env", tool="Write", pattern=r"\.env$", decision="deny", reason="no .env writes")],
            default=PolicyDefault(decision="allow", reason="default allow"),
        )
        result = evaluate(p, "Write", {"file_path": "/home/user/.env"})
        assert result.decision == "deny"

    def test_empty_rules_returns_default(self) -> None:
        p = Policy(rules=[], default=PolicyDefault(decision="allow", reason="wide open"))
        result = evaluate(p, "Bash", {"command": "anything"})
        assert result.decision == "allow"
        assert result.rule_id is None

    def test_escalate_decision(self, rules: Policy) -> None:
        result = evaluate(rules, "Skill", {"skill": "mika-ask"})
        assert result == PolicyDecision(decision="escalate", reason="escalated", rule_id="skill-ask")


def test_no_relay_config_graceful() -> None:
    """Verify _load_config returns None when config file does not exist."""
    import tempfile

    from claude_pilot.cli import _load_config
    with tempfile.TemporaryDirectory() as d:
        result = _load_config(Path(d), None)
        assert result is None, "_load_config should return None for missing config"
