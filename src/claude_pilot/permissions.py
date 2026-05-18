"""can_use_tool callback builder. Port of src/permissions.ts.

Tier 1 → fast-path allow.
Relay disabled → interactive fallback (or auto-deny in non-TTY).
Otherwise → invoke external agent, retry once on transient error, map
response to SDK PermissionResult.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from claude_agent_sdk import PermissionResultAllow, PermissionResultDeny
from claude_agent_sdk.types import ToolPermissionContext

from .guardrails import SessionGuardrails
from .policy import Policy, evaluate, load_policy
from .tier1 import is_tier1_auto_approve
from .transport import invoke_command
from .types import (
    PilotConfig,
    PilotEvent,
    PilotResponse,
    PilotResponseAllow,
    PilotResponseAnswer,
    PilotResponseDeny,
    TransportError,
)
from .ui import (
    log_denied,
    log_escalate,
    log_fallback,
    log_policy_allow,
    log_policy_deny,
    log_policy_escalate,
    log_question,
    log_question_escalate,
    log_relay_recv,
    log_relay_send,
    log_retry,
    log_tool,
    log_tool_request,
)

_policy_logger = logging.getLogger(__name__)

PermissionResult = PermissionResultAllow | PermissionResultDeny
CanUseTool = Callable[
    [str, dict[str, Any], ToolPermissionContext],
    Awaitable[PermissionResult],
]


def _fire_notify(tool_name: str, detail: str, reason: str) -> None:
    """Best-effort operator notification on escalation via ``mika notify``."""
    from .notify import notify_escalation

    notify_escalation(f"{tool_name}: {detail}: {reason}")


def create_permission_handler(
    *,
    config: PilotConfig | None,
    relay: bool,
    verbose: bool,
    cwd: str,
    guardrails: SessionGuardrails | None = None,
    task_id: str | None = None,
    policy_path: Path | None = None,
) -> CanUseTool:
    # Load policy once at handler creation time (cached for session).
    policy = load_policy(policy_path)
    policy_enabled = os.environ.get("MIKA_PILOT_POLICY_DISABLED", "").strip() != "1"

    async def handler(
        tool_name: str,
        tool_input: dict[str, Any],
        ctx: ToolPermissionContext,
    ) -> PermissionResult:
        log_tool_request(tool_name, _summarize_input(tool_name, tool_input))

        # Tier 1 fast path
        if is_tier1_auto_approve(tool_name, tool_input, cwd):
            log_tool(tool_name, _summarize_input(tool_name, tool_input), "AUTO")
            return PermissionResultAllow(updated_input=tool_input)

        # Tier 1.5 fast path — deterministic auto-answer (compact-safe)
        auto_answer = try_tier_1_5_auto_answer(tool_name, tool_input)
        if auto_answer is not None:
            log_tool(tool_name, _summarize_input(tool_name, tool_input), "AUTO")
            return _map_response(tool_name, tool_input, auto_answer)

        # Tier 2: deterministic policy-file lookup (mika#1192)
        if policy_enabled:
            pd = evaluate(policy, tool_name, tool_input)
            detail = _summarize_input(tool_name, tool_input)
            if pd.decision == "allow":
                log_policy_allow(tool_name, detail, pd.rule_id)
                return PermissionResultAllow(updated_input=tool_input)
            if pd.decision == "deny":
                log_policy_deny(tool_name, detail, pd.rule_id)
                return PermissionResultDeny(message=pd.reason, interrupt=False)
            # escalate: best-effort notify, then deny
            log_policy_escalate(tool_name, detail, pd.rule_id)
            _fire_notify(tool_name, detail, pd.reason)
            return PermissionResultDeny(message=pd.reason, interrupt=False)

        # TODO(mika#1193 Phase C): remove relay block below once policy has soaked ≥7 days.
        # The relay path is only reachable when MIKA_PILOT_POLICY_DISABLED=1 (emergency rollback).

        # No relay → interactive fallback
        if not relay or config is None:
            return await _interactive_fallback(tool_name, tool_input)

        event = PilotEvent(
            type="question" if tool_name == "AskUserQuestion" else "permission",
            tool_name=tool_name,
            tool_input=tool_input,
            tool_use_id=ctx.tool_use_id or "",
            agent_id=ctx.agent_id,
        )

        log_relay_send(tool_name)
        if guardrails is not None:
            guardrails.pause_idle_timer()

        try:
            start = time.monotonic()
            try:
                response = await invoke_command(config, event, verbose, task_id)
                latency_ms = int((time.monotonic() - start) * 1000)
                log_relay_recv(tool_name, response.action, latency_ms)
                return _map_response(tool_name, tool_input, response)
            except TransportError as err:
                latency_ms = int((time.monotonic() - start) * 1000)
                log_relay_recv(tool_name, "error", latency_ms)
                log_retry(f"{err} — retrying with error feedback")

                retry_event = event.model_copy(
                    update={
                        "error": (
                            f"Previous response was malformed: {err}. "
                            'Expected JSON: {"action": "allow"} or {"action": "deny"} '
                            'or {"action": "answer", "answers": {"question": "answer"}}'
                        )
                    }
                )

                start = time.monotonic()
                try:
                    response = await invoke_command(config, retry_event, verbose, task_id)
                    latency_ms = int((time.monotonic() - start) * 1000)
                    log_relay_recv(tool_name, response.action, latency_ms)
                    return _map_response(tool_name, tool_input, response)
                except TransportError as retry_err:
                    latency_ms = int((time.monotonic() - start) * 1000)
                    log_relay_recv(tool_name, "error", latency_ms)
                    log_fallback(str(retry_err))
                    return await _interactive_fallback(tool_name, tool_input)
        finally:
            if guardrails is not None:
                guardrails.resume_idle_timer()

    return handler


def _map_response(
    tool_name: str,
    original_input: dict[str, Any],
    response: PilotResponse,
) -> PermissionResult:
    if isinstance(response, PilotResponseAllow):
        log_tool(tool_name, _summarize_input(tool_name, original_input), "ALLOW")
        return PermissionResultAllow(updated_input=original_input)

    if isinstance(response, PilotResponseDeny):
        log_denied(tool_name, _summarize_input(tool_name, original_input))
        return PermissionResultDeny(
            message=response.message or "Denied by external agent",
            interrupt=False,
        )

    assert isinstance(response, PilotResponseAnswer)
    first_q = next(iter(response.answers.keys()), "")
    first_a = next(iter(response.answers.values()), "")
    log_question(first_q, first_a)
    return PermissionResultAllow(
        updated_input={
            "questions": original_input.get("questions"),
            "answers": response.answers,
        }
    )


# ── Tier 1.5: deterministic compact-safe auto-answer ─────────────────────────
#
# Mirrors mika/skills/bundled/permission-policy/system_prompt.md TIER 1.5
# (lines 31-32): /ce:compound Phase 0 prompts choose between "full compound"
# and "compact-safe"; headless sessions always pick "compact-safe" (see #79).
# Ported into claude-pilot as a deterministic short-circuit so the LLM-backed
# relay is never invoked for this class of question (mika#1191 Phase A).

_COMPACT_SAFE_RE = re.compile(r"\bcompact-safe\b", re.IGNORECASE)


def try_tier_1_5_auto_answer(
    tool_name: str,
    tool_input: dict[str, Any],
) -> PilotResponseAnswer | None:
    """Auto-answer compact-safe compaction-mode questions without relay.

    Returns a `PilotResponseAnswer` selecting "compact-safe" when EVERY
    question in the tool_input contains the case-insensitive substring
    `"compact-safe"`. Returns `None` for any other tool call or any
    AskUserQuestion that includes a non-matching sibling question — those
    fall through to the relay for normal handling.
    """
    if tool_name != "AskUserQuestion":
        return None

    questions = tool_input.get("questions")
    if not isinstance(questions, list) or not questions:
        return None

    answers: dict[str, str] = {}
    for q in questions:
        if not isinstance(q, dict):
            return None
        question_text = q.get("question", "")
        if not isinstance(question_text, str) or not _COMPACT_SAFE_RE.search(question_text):
            return None
        answers[question_text] = "compact-safe"

    return PilotResponseAnswer(action="answer", answers=answers)


async def _interactive_fallback(
    tool_name: str,
    tool_input: dict[str, Any],
) -> PermissionResult:
    if not sys.stdin.isatty():
        log_denied(tool_name, "non-interactive mode — auto-denied")
        return PermissionResultDeny(
            message="Non-interactive mode: auto-denied", interrupt=False
        )

    if tool_name == "AskUserQuestion":
        return await _interactive_question(tool_input)
    return await _interactive_permission(tool_name, tool_input)


async def _interactive_permission(
    tool_name: str,
    tool_input: dict[str, Any],
) -> PermissionResult:
    detail = _summarize_input(tool_name, tool_input)
    log_escalate(tool_name, detail)
    answer = await _ainput("  Allow? (y/n): ")
    if answer.strip().lower().startswith("y"):
        log_tool(tool_name, detail, "ALLOW")
        return PermissionResultAllow(updated_input=tool_input)
    log_denied(tool_name, detail)
    return PermissionResultDeny(message="Denied by user", interrupt=False)


async def _interactive_question(tool_input: dict[str, Any]) -> PermissionResult:
    questions = tool_input.get("questions")
    if not isinstance(questions, list):
        return PermissionResultDeny(
            message="Malformed AskUserQuestion: missing questions array",
            interrupt=False,
        )

    answers: dict[str, str] = {}
    for q in questions:
        if not isinstance(q, dict):
            continue
        question = str(q.get("question", ""))
        options = q.get("options") if isinstance(q.get("options"), list) else None
        log_question_escalate(question)
        if options:
            for i, opt in enumerate(options, start=1):
                label = opt.get("label", "") if isinstance(opt, dict) else str(opt)
                sys.stderr.write(f"  {i}. {label}\n")
            raw = (await _ainput("\n  Your answer: ")).strip()
            try:
                idx = int(raw)
                if 1 <= idx <= len(options):
                    opt = options[idx - 1]
                    answers[question] = opt.get("label", "") if isinstance(opt, dict) else str(opt)
                    continue
            except ValueError:
                pass
            answers[question] = raw
        else:
            answers[question] = (await _ainput("\n  Your answer: ")).strip()

    first_q = questions[0].get("question", "") if isinstance(questions[0], dict) else ""
    first_a = next(iter(answers.values()), "")
    log_question(first_q, first_a)
    return PermissionResultAllow(
        updated_input={"questions": questions, "answers": answers}
    )


async def _ainput(prompt: str) -> str:
    import asyncio

    sys.stderr.write(prompt)
    sys.stderr.flush()
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, sys.stdin.readline)


# ── Input summarizers (shared with relay payloads) ──────────────────────────

_BEARER_RE = re.compile(r"(Bearer\s+)\S+", re.IGNORECASE)
_SK_ANT_RE = re.compile(r"(sk-ant-\S{0,6})\S*")
_GHP_RE = re.compile(r"(ghp_\S{0,4})\S*")
_XOXB_RE = re.compile(r"(xoxb-\S{0,4})\S*")
_KV_SECRET_RE = re.compile(r"(TOKEN|KEY|SECRET|PASSWORD|CREDENTIAL|API_KEY)=\S+", re.IGNORECASE)


def _scrub_secrets(text: str) -> str:
    text = _BEARER_RE.sub(r"\1[REDACTED]", text)
    text = _SK_ANT_RE.sub(r"\1...[REDACTED]", text)
    text = _GHP_RE.sub(r"\1...[REDACTED]", text)
    text = _XOXB_RE.sub(r"\1...[REDACTED]", text)
    text = _KV_SECRET_RE.sub(r"\1=[REDACTED]", text)
    return text


def _summarize_input(tool_name: str, tool_input: dict[str, Any]) -> str:
    if tool_name == "Bash":
        return _scrub_secrets(str(tool_input.get("command", ""))[:200])
    if tool_name in ("Write", "Edit", "Read"):
        return str(tool_input.get("file_path", ""))
    if tool_name in ("Glob", "Grep"):
        return str(tool_input.get("pattern", ""))
    if tool_name == "Skill":
        skill = str(tool_input.get("skill", "unknown"))
        args = tool_input.get("args")
        suffix = f" {_scrub_secrets(str(args)[:100])}" if args else ""
        return f"{skill}{suffix}"
    return _scrub_secrets(json.dumps(tool_input, default=str)[:150])
