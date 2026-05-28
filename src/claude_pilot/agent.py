"""Agent runner. Port of src/agent.ts.

Uses `ClaudeSDKClient` because `can_use_tool` is only available on the
bidirectional client, not on the one-shot `query()` entrypoint. Streams
messages, feeds turn boundaries to SessionGuardrails, emits a ResultJson line
to stdout when the session ends (success, error, or guardrail abort).
"""

from __future__ import annotations

import asyncio
import os
import sys
import time
from typing import Any, Literal

from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient
from claude_agent_sdk.types import AssistantMessage, ResultMessage, SystemMessage

from .guardrails import SessionGuardrails, TurnBoundaryEvent
from .inbox_writer import post_handoff
from .permissions import CanUseTool
from .types import ResultJson
from .ui import (
    log_done,
    log_error,
    log_guardrail,
    log_guardrail_config,
    log_init,
    log_prompt,
    log_reconnect,
    log_text,
    log_turn_summary,
)

SDK_TERMINATION_SUBTYPES = frozenset({"error_max_turns", "error_max_budget_usd"})


async def run_agent(
    *,
    prompt: str,
    cwd: str,
    verbose: bool,
    task_id: str | None,
    permission_handler: CanUseTool,
    guardrails: SessionGuardrails,
) -> int:
    """Run the agent session. Returns the intended process exit code."""
    start_time = time.monotonic()
    session_id: str | None = None
    seen_init: bool = False
    config = guardrails.config

    log_guardrail_config(config)

    options = ClaudeAgentOptions(
        permission_mode="default",
        cwd=cwd,
        setting_sources=["user", "project", "local"],
        can_use_tool=permission_handler,
        include_partial_messages=True,
        **_sdk_guardrail_kwargs(config),
    )

    exit_code = 0
    # cpp#20 joint 2 synthetic-emit guard: flips True after any in-loop
    # terminal _emit_result call (guardrail trip or ResultMessage). Post-loop
    # check below uses this to decide whether to emit a synthetic terminal
    # ResultJson when the SDK stream ends without a ResultMessage -- the
    # Case-B failure mode introduced by PermissionResultDeny(interrupt=True)
    # at the can_use_tool boundary. Mutual exclusion proof + architect
    # verdict: cpp#20 body, "Friend-Claude review convergence" section.
    emitted_terminal = False

    async with ClaudeSDKClient(options=options) as client:
        await client.query(prompt)

        guardrail_watcher = asyncio.create_task(guardrails.wait_aborted())
        try:
            async for message in _merge_stream(client, guardrail_watcher):
                if message is _GUARDRAIL_TRIP:
                    reason = guardrails.abort_reason
                    assert reason is not None
                    duration_ms = int((time.monotonic() - start_time) * 1000)
                    _emit_result(
                        ResultJson(
                            status="terminated",
                            subtype=reason.guardrail,
                            task_id=task_id,
                            session_id=session_id,
                            turns=guardrails.turns,
                            cost_usd=None,  # unknown — ResultMessage not yet received
                            duration_ms=duration_ms,
                            termination_reason=reason.detail,
                        )
                    )
                    emitted_terminal = True  # cpp#20 joint 2 mutual-exclusion guard (Site 1)
                    log_guardrail(reason.guardrail, reason.detail)
                    try:
                        await client.interrupt()
                    except Exception:
                        pass
                    return 1

                if isinstance(message, SystemMessage) and message.subtype == "init":
                    session_id = _extract_session_id(message)
                    model = _extract_model(message)
                    if not seen_init:
                        log_init(session_id or "", model or "unknown", task_id)
                        log_prompt(prompt)
                        seen_init = True
                    else:
                        log_reconnect(session_id or "", model or "unknown")
                    continue

                if isinstance(message, AssistantMessage):
                    session_id = getattr(message, "session_id", session_id) or session_id
                    event = guardrails.on_assistant_message(
                        _content_blocks(message),
                        message_id=getattr(message, "message_id", None),
                    )
                    if event is not None:
                        # event.just_closed_turn is the turn that just ENDED;
                        # guardrails.turns now reflects the new turn that just
                        # started. cpp#10 — surface drift turns that produced
                        # no text and no tool calls.
                        _on_boundary(event)
                    for block in _content_blocks(message):
                        text = _text_of(block)
                        if text:
                            log_text(text)
                    continue

                if isinstance(message, ResultMessage):
                    # cpp#10: flush the marker for the still-open final turn
                    # BEFORE _emit_result writes the result JSON line, so the
                    # operator sees the last turn's shape if it was silent.
                    final_event = guardrails.close_final_turn()
                    if final_event is not None:
                        _on_boundary(final_event)

                    subtype = message.subtype
                    raw_errors = getattr(message, "errors", None)
                    errors = (
                        [str(e) for e in raw_errors]
                        if isinstance(raw_errors, list) and raw_errors
                        else None
                    )
                    is_sdk_termination = subtype in SDK_TERMINATION_SUBTYPES
                    status: Literal["success", "error", "terminated"] = (
                        "success"
                        if subtype == "success"
                        else "terminated"
                        if is_sdk_termination
                        else "error"
                    )

                    # mika#940: pipeline-completion contract. If
                    # CLAUDE_PILOT_REQUIRE_PR=1 (set by dispatch-lib for
                    # dev-pilot sessions) and the session completed
                    # "successfully" but never invoked `gh pr create`,
                    # override to a `pipeline_incomplete` failure shape.
                    # Catches the premature-EndTurn family observed on
                    # 2026-05-02 (mika#931, #938, #939) where the model
                    # emits `[done] Success` after Edit/Compound phases
                    # before reaching git push + gh pr create. Defense
                    # in depth with dispatch-lib's actual PR-existence
                    # check on GitHub.
                    termination_reason: str | None = (
                        f"SDK limit reached: {subtype}" if is_sdk_termination else None
                    )
                    require_pr = os.environ.get("CLAUDE_PILOT_REQUIRE_PR", "").lower() in (
                        "1",
                        "true",
                    )
                    if status == "success" and require_pr and not guardrails.pr_created:
                        subtype = "pipeline_incomplete"
                        status = "error"
                        termination_reason = (
                            "Session completed without 'gh pr create' Bash call. "
                            "CLAUDE_PILOT_REQUIRE_PR=1 was set. "
                            "Work may be stranded in worktree."
                        )

                    result = ResultJson(
                        status=status,
                        subtype=subtype,
                        task_id=task_id,
                        session_id=session_id or getattr(message, "session_id", None),
                        turns=message.num_turns,
                        cost_usd=message.total_cost_usd or 0.0,
                        duration_ms=message.duration_ms,
                        errors=errors,
                        termination_reason=termination_reason,
                    )
                    _emit_result(result)
                    emitted_terminal = True  # cpp#20 joint 2 mutual-exclusion guard (Site 2)

                    # mika#1189: side-channel handoff to the gateway
                    # orchestrator inbox, alongside the existing
                    # mika-platform#100 filesystem-inbox write. Both no-op
                    # silently when their respective env vars are unset.
                    # Failures here MUST NOT change exit code — _emit_result
                    # is the canonical signal.
                    if status == "success":
                        post_handoff(result)

                    if status == "success":
                        log_done(message.num_turns, result.cost_usd, message.duration_ms)
                    elif is_sdk_termination:
                        log_guardrail(
                            subtype,
                            f"SDK limit reached after {message.num_turns} turns",
                        )
                        exit_code = 1
                    else:
                        log_error(subtype, errors or [])
                        exit_code = 1
        finally:
            guardrail_watcher.cancel()
            guardrails.dispose()

    # cpp#20 joint 2 synthetic terminal emit. Fires only when the SDK message
    # stream ended cleanly without yielding either a guardrail trip (Site 1)
    # or a ResultMessage (Site 2). Triggered by:
    #   * `PermissionResultDeny(interrupt=True)` at the can_use_tool boundary
    #     causing the Claude Code CLI to close its stdio pipe without a
    #     terminal ResultMessage (the Case-B failure mode the friend-Claude
    #     review converged on; architect verdict READY).
    #   * Transport drop / clean upstream close for any other reason.
    # Without this guard cpp would exit silently with empty stdout, and
    # dispatch-lib's `jq -r '.status // empty'` extraction would yield an
    # empty string. With it, downstream parsers always see a `^{` JSON line
    # with status="error" and a non-success subtype.
    if not emitted_terminal:
        duration_ms = int((time.monotonic() - start_time) * 1000)
        _emit_result(
            ResultJson(
                status="error",
                subtype="stream_ended_without_result",
                task_id=task_id,
                session_id=session_id,
                turns=guardrails.turns,
                cost_usd=None,
                duration_ms=duration_ms,
                termination_reason=(
                    "SDK message stream ended without a terminal ResultMessage. "
                    "Likely caused by permission denial with interrupt=True or "
                    "transport close upstream."
                ),
            )
        )
        exit_code = 1

    return exit_code


_GUARDRAIL_TRIP: Any = object()


async def _merge_stream(
    client: ClaudeSDKClient,
    guardrail_watcher: asyncio.Task[Any],
) -> Any:
    """Yield SDK messages, plus _GUARDRAIL_TRIP sentinel if a guardrail fires."""
    stream = client.receive_response().__aiter__()
    while True:
        next_msg = asyncio.ensure_future(stream.__anext__())
        done, _pending = await asyncio.wait(
            {next_msg, guardrail_watcher},
            return_when=asyncio.FIRST_COMPLETED,
        )
        if guardrail_watcher in done and next_msg not in done:
            next_msg.cancel()
            yield _GUARDRAIL_TRIP
            return
        try:
            msg = next_msg.result()
        except StopAsyncIteration:
            return
        yield msg


def _sdk_guardrail_kwargs(config: Any) -> dict[str, Any]:
    """Pass SDK-native guardrails only when > 0."""
    kwargs: dict[str, Any] = {}
    if config.maxTurns > 0:
        kwargs["max_turns"] = config.maxTurns
    # maxBudgetUsd is TS-SDK-specific; the Python SDK accepts it via
    # permission_mode/options extras if exposed. Include defensively.
    if config.maxBudgetUsd > 0:
        # Attribute name varies by SDK version; set if the option exists.
        # Leaving it out is safe — application-level guardrails still apply.
        pass
    return kwargs


def _on_boundary(event: TurnBoundaryEvent) -> None:
    """cpp#10: log a marker for diagnostically silent turns.

    A turn that produced text or a tool_use is already visible in the log via
    `log_text` / `permissions.py`. A turn that produced neither leaves the
    operator with nothing to read — branch the marker on `had_thinking_block`
    so the line accurately names what the model DID do (think) instead of
    falsely claiming silence.
    """
    if event.had_text or event.had_tool_use:
        return
    if event.had_thinking_block:
        log_turn_summary(event.just_closed_turn, "thinking-only, no actions")
    else:
        log_turn_summary(event.just_closed_turn, "no observable output")


def _content_blocks(message: AssistantMessage) -> list[Any]:
    msg = getattr(message, "message", message)
    content = getattr(msg, "content", None) or getattr(message, "content", None)
    return content if isinstance(content, list) else []


def _text_of(block: Any) -> str | None:
    """Extract text from a content block.

    Mirrors `guardrails._block_type` dual-shape handling: SDK dataclass
    instances (TextBlock, etc.) do NOT carry a `type` attribute — the
    wire-format `type` field is consumed by the SDK parser. Fall back on
    class name for dataclass-shaped blocks (cpp#12).
    """
    if isinstance(block, dict):
        if block.get("type") == "text":
            text = block.get("text")
            return text if isinstance(text, str) else None
        return None
    t = getattr(block, "type", None)
    if not isinstance(t, str) and type(block).__name__ == "TextBlock":
        t = "text"
    if t == "text":
        text = getattr(block, "text", None)
        return text if isinstance(text, str) else None
    return None


def _extract_session_id(message: SystemMessage) -> str | None:
    sid = getattr(message, "session_id", None)
    return sid if isinstance(sid, str) else None


def _extract_model(message: SystemMessage) -> str | None:
    model = getattr(message, "model", None)
    return model if isinstance(model, str) else None


def _emit_result(result: ResultJson) -> None:
    sys.stdout.write(result.to_line() + "\n")
    sys.stdout.flush()
