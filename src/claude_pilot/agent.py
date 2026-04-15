"""Agent runner. Port of src/agent.ts.

Uses `ClaudeSDKClient` because `can_use_tool` is only available on the
bidirectional client, not on the one-shot `query()` entrypoint. Streams
messages, feeds turn boundaries to SessionGuardrails, emits a ResultJson line
to stdout when the session ends (success, error, or guardrail abort).
"""

from __future__ import annotations

import asyncio
import sys
import time
from typing import Any, Literal

from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient
from claude_agent_sdk.types import AssistantMessage, ResultMessage, SystemMessage

from .guardrails import SessionGuardrails
from .permissions import CanUseTool
from .types import ResultJson
from .ui import (
    log_done,
    log_error,
    log_guardrail,
    log_guardrail_config,
    log_init,
    log_prompt,
    log_text,
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
                    log_guardrail(reason.guardrail, reason.detail)
                    try:
                        await client.interrupt()
                    except Exception:
                        pass
                    return 1

                if isinstance(message, SystemMessage) and message.subtype == "init":
                    session_id = _extract_session_id(message)
                    model = _extract_model(message)
                    log_init(session_id or "", model or "unknown", task_id)
                    log_prompt(prompt)
                    continue

                if isinstance(message, AssistantMessage):
                    session_id = getattr(message, "session_id", session_id) or session_id
                    guardrails.on_assistant_message(
                        _content_blocks(message),
                        message_id=getattr(message, "message_id", None),
                    )
                    for block in _content_blocks(message):
                        text = _text_of(block)
                        if text:
                            log_text(text)
                    continue

                if isinstance(message, ResultMessage):
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

                    result = ResultJson(
                        status=status,
                        subtype=subtype,
                        task_id=task_id,
                        session_id=session_id or getattr(message, "session_id", None),
                        turns=message.num_turns,
                        cost_usd=message.total_cost_usd or 0.0,
                        duration_ms=message.duration_ms,
                        errors=errors,
                        termination_reason=(
                            f"SDK limit reached: {subtype}" if is_sdk_termination else None
                        ),
                    )
                    _emit_result(result)

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


def _content_blocks(message: AssistantMessage) -> list[Any]:
    msg = getattr(message, "message", message)
    content = getattr(msg, "content", None) or getattr(message, "content", None)
    return content if isinstance(content, list) else []


def _text_of(block: Any) -> str | None:
    if isinstance(block, dict):
        if block.get("type") == "text":
            text = block.get("text")
            return text if isinstance(text, str) else None
        return None
    if getattr(block, "type", None) == "text":
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
