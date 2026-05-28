"""Deterministic policy-file evaluator for permission events.

Replaces the relay LLM call for tier2 decisions (Phase B of mika#1188).
Rules are matched in order; first hit wins. If no rule matches, the
policy default applies.  Graceful degradation: missing file or parse
error -> empty rules -> default deny (fail-closed; cpp#20 joint 1
hardens the prior default-escalate posture into default-deny on every
fail-closed path).
"""

from __future__ import annotations

import importlib.resources
import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, field_validator

logger = logging.getLogger(__name__)

# ── Models ──────────────────────────────────────────────────────────────────

VALID_DECISIONS = frozenset({"allow", "deny", "escalate"})


class PolicyRule(BaseModel):
    """A single permission rule: match tool + pattern -> decision."""

    model_config = ConfigDict(extra="allow")

    id: str
    tool: str
    pattern: str
    decision: str
    reason: str

    @field_validator("decision")
    @classmethod
    def _validate_decision(cls, v: str) -> str:
        if v not in VALID_DECISIONS:
            raise ValueError(f"decision must be one of {sorted(VALID_DECISIONS)}, got {v!r}")
        return v

    @field_validator("pattern")
    @classmethod
    def _validate_pattern(cls, v: str) -> str:
        try:
            re.compile(v)
        except re.error as err:
            raise ValueError(f"invalid regex pattern: {err}") from err
        return v


class PolicyDefault(BaseModel):
    """Fallback when no rule matches."""

    model_config = ConfigDict(extra="allow")

    decision: str = "deny"
    reason: str = "no matching rule -- denied by default (fail-closed)"

    @field_validator("decision")
    @classmethod
    def _validate_decision(cls, v: str) -> str:
        if v not in VALID_DECISIONS:
            raise ValueError(f"decision must be one of {sorted(VALID_DECISIONS)}, got {v!r}")
        return v


class Policy(BaseModel):
    """Top-level policy document."""

    model_config = ConfigDict(extra="allow")

    rules: list[PolicyRule] = []
    default: PolicyDefault = PolicyDefault()


@dataclass(frozen=True)
class PolicyDecision:
    """Result of evaluating a permission event against a policy."""

    decision: str
    reason: str
    rule_id: str | None = None


# ── Primary input field extraction ──────────────────────────────────────────

# Maps tool names to the key that holds the "primary" matchable input.
_PRIMARY_INPUT_FIELDS: dict[str, str] = {
    "Bash": "command",
    "Write": "file_path",
    "Edit": "file_path",
    "Read": "file_path",
    "Glob": "pattern",
    "Grep": "pattern",
    "Skill": "skill",
}


def _get_primary_input(tool_name: str, tool_input: dict[str, Any]) -> str:
    """Extract the primary matchable string from a tool invocation."""
    field = _PRIMARY_INPUT_FIELDS.get(tool_name)
    if field is not None:
        return str(tool_input.get(field, ""))
    # Fallback: JSON-ish representation for unknown tools
    return str(tool_input)


# ── Loader ──────────────────────────────────────────────────────────────────

_BUNDLED_POLICY_RESOURCE = "policies"
_BUNDLED_POLICY_FILE = "permissions.yaml"


def _load_bundled_policy_path() -> Path | None:
    """Resolve the path to the bundled default policy file."""
    try:
        ref = importlib.resources.files("claude_pilot").joinpath(
            _BUNDLED_POLICY_RESOURCE, _BUNDLED_POLICY_FILE
        )
        # importlib.resources may return a Traversable; as_posix works for
        # on-disk packages.  For zip-imported packages this would need
        # importlib.resources.as_file(), but claude-pilot is always installed
        # editable or as a wheel with on-disk files.
        path = Path(str(ref))
        if path.is_file():
            return path
    except Exception:
        pass
    return None


def load_policy(path: Path | None = None) -> Policy:
    """Load a policy file with three-tier resolution.

    1. Explicit *path* argument
    2. ``MIKA_PILOT_POLICY_PATH`` environment variable
    3. Bundled default at ``policies/permissions.yaml``

    On any error (missing file, parse failure, validation failure) the
    function returns a safe fallback: empty rules with ``default: deny``
    (fail-closed; cpp#20 joint 1).
    """
    resolved: Path | None = path

    if resolved is None:
        env_path = os.environ.get("MIKA_PILOT_POLICY_PATH")
        if env_path:
            resolved = Path(env_path)

    if resolved is None:
        resolved = _load_bundled_policy_path()

    if resolved is None:
        logger.warning("policy: no policy file found — using default deny")
        return Policy()

    try:
        raw = resolved.read_text(encoding="utf-8")
    except FileNotFoundError:
        logger.warning("policy: file not found %s — using default deny", resolved)
        return Policy()
    except OSError as err:
        logger.warning("policy: cannot read %s: %s — using default deny", resolved, err)
        return Policy()

    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as err:
        logger.warning("policy: malformed YAML in %s: %s — using default deny", resolved, err)
        return Policy()

    if not isinstance(data, dict):
        logger.warning("policy: expected mapping in %s — using default deny", resolved)
        return Policy()

    try:
        return Policy.model_validate(data)
    except Exception as err:
        logger.warning("policy: validation error in %s: %s — using default deny", resolved, err)
        return Policy()


# ── Evaluator ───────────────────────────────────────────────────────────────


def evaluate(policy: Policy, tool_name: str, tool_input: dict[str, Any]) -> PolicyDecision:
    """Evaluate a tool invocation against *policy*.

    Rules are matched in order.  A rule matches when:
    1. ``rule.tool`` equals *tool_name* (case-sensitive), AND
    2. ``rule.pattern`` (regex) searches the tool's primary input field.

    First matching rule wins.  If no rule matches, the policy default is
    returned.
    """
    primary = _get_primary_input(tool_name, tool_input)

    for rule in policy.rules:
        if rule.tool != tool_name:
            continue
        try:
            if re.search(rule.pattern, primary):
                return PolicyDecision(
                    decision=rule.decision,
                    reason=rule.reason,
                    rule_id=rule.id,
                )
        except re.error:
            # Shouldn't happen (validated at load), but be defensive.
            continue

    return PolicyDecision(
        decision=policy.default.decision,
        reason=policy.default.reason,
        rule_id=None,
    )
