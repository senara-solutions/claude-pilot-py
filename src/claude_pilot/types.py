"""Configuration, event, and result schemas.

Port of src/types.ts (zod → pydantic v2). Field names match the TS wire format
exactly so downstream consumers (mika-skills/claude-pilot/handlers/run.sh,
mika-dev relay) keep parsing unchanged.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class GuardrailConfig(BaseModel):
    """Application-level guardrails. Fields are optional; defaults from GUARDRAIL_DEFAULTS."""

    model_config = ConfigDict(extra="forbid")

    maxTurns: int | None = Field(default=None, ge=1)
    maxBudgetUsd: float | None = Field(default=None, ge=0.01)
    stallThreshold: int | None = Field(default=None, ge=0)
    emptyResponseThreshold: int | None = Field(default=None, ge=0)
    idleTimeoutMs: int | None = Field(default=None, ge=0, le=3_600_000)
    minTurnsBeforeDetection: int | None = Field(default=None, ge=0)


class ResolvedGuardrailConfig(BaseModel):
    """All-fields-present variant used internally after defaults are applied."""

    model_config = ConfigDict(extra="forbid")

    maxTurns: int
    maxBudgetUsd: float
    stallThreshold: int
    emptyResponseThreshold: int
    idleTimeoutMs: int
    minTurnsBeforeDetection: int


GUARDRAIL_DEFAULTS = ResolvedGuardrailConfig(
    maxTurns=200,
    maxBudgetUsd=0.0,  # 0 = disabled
    stallThreshold=5,
    emptyResponseThreshold=5,
    idleTimeoutMs=300_000,
    minTurnsBeforeDetection=10,
)


class PilotConfig(BaseModel):
    """Relay configuration loaded from .claude/claude-pilot.json."""

    model_config = ConfigDict(extra="forbid")

    command: str = Field(min_length=1)
    args: list[str] | None = None
    timeout: int | None = Field(default=None, ge=1000, le=600_000)
    model: str | None = Field(default=None, min_length=1)
    guardrails: GuardrailConfig | None = None


class PilotEvent(BaseModel):
    """Event payload sent to the external relay agent via stdin."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["permission", "question"]
    tool_name: str
    tool_input: dict[str, Any]
    tool_use_id: str
    agent_id: str | None = None
    decision_reason: str | None = None
    blocked_path: str | None = None
    error: str | None = None


class PilotResponseAllow(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["allow"]


class PilotResponseDeny(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["deny"]
    message: str | None = None


class PilotResponseAnswer(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["answer"]
    answers: dict[str, str]


PilotResponse = PilotResponseAllow | PilotResponseDeny | PilotResponseAnswer


class ResultJson(BaseModel):
    """Single-line JSON written to stdout on completion. Parsed by
    mika-skills/claude-pilot/handlers/run.sh.

    Subtype values:
        - "success" — SDK ResultMessage reported success.
        - "early_exit_zero_action" — fewer than CLAUDE_PILOT_MIN_TOOL_CALLS
          tool calls observed; session re-prompted or terminated.
        - "pipeline_incomplete" (mika#940) — CLAUDE_PILOT_REQUIRE_PR=1 set
          (dev-pilot sessions via dispatch-lib) and the session completed
          successfully but never invoked `gh pr create`. Indicates the
          premature-EndTurn family — model emits `[done] Success` after
          Edit/Compound phases without reaching git push + gh pr create.
          Work may be stranded in the worktree.
        - SDK termination subtypes (e.g. "error_max_turns", "error_during_execution")
          — see SDK_TERMINATION_SUBTYPES in agent.py.
    """

    model_config = ConfigDict(extra="forbid")

    status: Literal["success", "error", "terminated"]
    subtype: str
    task_id: str | None = None
    session_id: str | None = None
    turns: int
    # Unknown when the session terminated before a ResultMessage arrived (e.g.
    # guardrail trip, fatal CLI error). Serialized as absent field via
    # `exclude_none` so downstream handlers parse it as unknown.
    cost_usd: float | None = None
    duration_ms: int
    errors: list[str] | None = None
    termination_reason: str | None = None

    def to_line(self) -> str:
        """Serialize to a single JSON line (no trailing newline)."""
        return self.model_dump_json(exclude_none=True)


class GuardrailAbortReason(BaseModel):
    """Reason attached when SessionGuardrails aborts the SDK session."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["guardrail"] = "guardrail"
    guardrail: Literal["stall_detected", "empty_response", "idle_timeout"]
    turns: int
    detail: str


class TransportError(Exception):
    """Raised when the relay subprocess fails or returns malformed output."""
