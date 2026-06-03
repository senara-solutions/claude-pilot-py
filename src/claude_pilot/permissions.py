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
from .policy import evaluate, load_policy
from .tier1 import is_tier1_auto_approve, is_tier3_dangerous
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
    log_policy_deny_with_notify,
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


# ── Chained-danger guard over policy Bash allow (claude-pilot#25) ────────────
#
# policy.evaluate() matches a single regex against the WHOLE command string
# (policy.py first-match-wins) — it does NOT compound-split, run
# is_tier3_dangerous, or scan for command-substitution metacharacters. Those
# guards live only in tier1, which has already returned False to reach the
# policy evaluator. Without this guard a policy `allow` rule on e.g. `^mkdir\s`
# would also allow `mkdir foo && rm -rf ~` — the dangerous tail rides along the
# allowed prefix. The same latent flaw affects the pre-existing groom-phase
# rules (`git status && rm -rf ~` matches `^git\s+status`).
#
# Two vectors a whole-string allow regex cannot see:
#   1. Command chaining a dangerous tail: ``mkdir foo && rm -rf ~`` — caught by
#      re-applying tier1's ``is_tier3_dangerous`` (rm -rf, force-push, sed -i,
#      redirect-to-file, etc.) over the full command.
#   2. Command substitution: ``mkdir "$(curl evil)"`` — caught by forbidding
#      ``$(``, backtick, and ``$'`` outright. This is DELIBERATELY stricter than
#      tier1's quote-aware ``contains_unquoted_metacharacter`` (which ignores
#      substitution inside double quotes, mirroring the Rust pre-classifier —
#      mika#944/#946). The new dev-pilot rules are write-capable (mkdir/cp/rm),
#      so a policy-allowed command never legitimately needs substitution; any
#      that does must go through the relay, not the deterministic allow path.
#
# Heredoc exemption: the pre-existing ``bash-cat-heredoc-tmp`` rule deliberately
# allows a ``/tmp``-scoped ``cat >`` heredoc whose body is inert data and may
# legitimately contain redirects, ``rm``, or ``$(...)`` as literal script text.
# Running the tier3/substitution scan over it would re-deny exactly what that
# rule exists to permit (tier1 already rejected the redirect — that is *why* the
# policy rule is there). So a heredoc is exempt ONLY when it is the sole
# top-level command (no chaining operator before ``<<``); ``mkdir x && rm -rf ~
# <<X`` is therefore NOT exempt and still gets the full scan. Residual: a
# command chained *after* the heredoc terminator is not re-scanned — this is the
# rule's pre-existing behavior, unchanged by this guard, tracked as follow-up.

# Heredoc is the sole top-level command: starts with cat/tee, no &/;/| before <<.
_SAFE_HEREDOC_RE = re.compile(r"^\s*(?:cat|tee)\b[^&;|]*<<")

# Command-substitution markers forbidden on the non-heredoc policy-allow path.
_SUBSTITUTION_MARKERS = ("$(", "`", "$'")


def _bash_allow_is_chain_safe(tool_name: str, tool_input: dict[str, Any]) -> bool:
    """Whether a policy ``allow`` decision is safe to honor.

    Returns ``True`` for every non-Bash tool (nothing to scan). For Bash,
    returns ``False`` when an allowed prefix is chained to a tier3-dangerous
    tail or contains a command-substitution marker. A ``/tmp``-scoped
    sole-command heredoc is exempt (see module comment above).
    """
    if tool_name != "Bash":
        return True
    command = tool_input.get("command", "")
    if not isinstance(command, str):
        return False
    if _SAFE_HEREDOC_RE.search(command):
        return True
    if any(marker in command for marker in _SUBSTITUTION_MARKERS):
        return False
    if is_tier3_dangerous(command):
        return False
    return True


def _fire_notify(tool_name: str, detail: str, reason: str) -> None:
    """Best-effort operator notification on deny-with-notify via ``mika notify``.

    Wire-format keeps the legacy ``escalate`` decision string for back-compat
    with existing operator-authored permissions.yaml overlays; the runtime
    semantics post-cpp#20 joint 2 are deny-with-notify (no relay roundtrip,
    pilot loop halts via ``interrupt=True``).
    """
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

        # Tier 2: deterministic policy-file lookup (mika#1192).
        # cpp#20 joint 2: denial paths return PermissionResultDeny(interrupt=True)
        # so the SDK aborts the agent loop instead of surfacing the denial as a
        # tool_result error the LLM can fabricate around. The pilot exits
        # honestly; downstream parsers (mika dispatch-lib `_run_claude_pilot`)
        # see a clean terminal ResultJson with status != "success" via the
        # synthetic-emit guard in agent.py.
        if policy_enabled:
            pd = evaluate(policy, tool_name, tool_input)
            detail = _summarize_input(tool_name, tool_input)
            if pd.decision == "allow":
                # Chained-danger guard (claude-pilot#25): a policy allow rule
                # matches a whole-command regex; veto it if a dangerous tail is
                # chained onto the allowed prefix. Halt honestly (interrupt=True)
                # like every other policy denial (cpp#20 joint 2).
                if not _bash_allow_is_chain_safe(tool_name, tool_input):
                    veto_reason = (
                        f"policy allow ({pd.rule_id}) vetoed — command chains a "
                        "tier3-dangerous or command-substitution tail onto the "
                        "allowed prefix"
                    )
                    log_policy_deny(tool_name, detail, pd.rule_id)
                    return PermissionResultDeny(message=veto_reason, interrupt=True)
                log_policy_allow(tool_name, detail, pd.rule_id)
                return PermissionResultAllow(updated_input=tool_input)
            if pd.decision == "deny":
                log_policy_deny(tool_name, detail, pd.rule_id)
                return PermissionResultDeny(message=pd.reason, interrupt=True)
            # Wire-format `escalate` = deny-with-notify: best-effort operator
            # notify + halt the pilot loop. Wire keyword preserved for
            # back-compat with existing operator overlays; runtime semantics
            # post-cpp#20 joint 2 are identical to `deny` plus the notify
            # side-effect (cpp#21 rename is source-only).
            log_policy_deny_with_notify(tool_name, detail, pd.rule_id)
            _fire_notify(tool_name, detail, pd.reason)
            return PermissionResultDeny(message=pd.reason, interrupt=True)

        # TODO(mika#1193 Phase C): remove relay block below once policy has soaked >= 7 days.
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
