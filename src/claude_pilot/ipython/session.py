"""Kernel-resident Claude session driving claude-agent-sdk from IPython magics.

The SDK is async; IPython magics are synchronous entrypoints that may run
inside a kernel that already owns a running event loop (Jupyter) or none at
all (terminal IPython). Driving the SDK on the kernel's own loop would require
yielding control back to the kernel mid-magic, which the magic contract does
not allow. Each session therefore owns a dedicated background thread running a
private event loop: magic invocations block the calling thread on
``asyncio.run_coroutine_threadsafe(...).result()`` while streamed text is
written incrementally from the loop thread (both terminal IPython's stdout and
Jupyter's ``OutStream`` replacement are thread-safe writers). The persistent
``ClaudeSDKClient`` lives entirely on that loop, which is what gives the
``%%claude`` cell magic multi-turn continuity across invocations.

Permission behavior is INHERITED, not re-implemented: the session builds its
``can_use_tool`` callback with :func:`claude_pilot.permissions.create_permission_handler`,
so the magics get the exact Tier-1 filter -> policy -> relay chain as the
headless pilot. A kernel typically has no TTY, so the interactive fallback
auto-denies — the same posture as a headless non-TTY run; being in a REPL
grants no silent privilege widening (issue #81 AC 4).

Rendering streams at MESSAGE granularity: each completed assistant message's
text blocks print as they arrive on the stream. Delta-level (partial-message)
rendering is deliberately out of scope for this first cut — it would double-
print against the completed messages without extra bookkeeping.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import threading
from pathlib import Path

from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient
from claude_agent_sdk.types import AssistantMessage, ResultMessage
from pydantic import ValidationError

from ..agent import _content_blocks, _system_prompt_with_hint, _text_of
from ..permissions import create_permission_handler
from ..types import PilotConfig

_CLOSE_TIMEOUT_S = 10.0


class SessionConfigError(Exception):
    """A `.claude/claude-pilot.json` was found but is unusable. Raised (never
    ``sys.exit`` like the CLI's loader) so a bad config surfaces as a cell
    error instead of killing the kernel."""


def load_pilot_config(cwd: Path) -> PilotConfig | None:
    """Discover `.claude/claude-pilot.json` under ``cwd``, mirroring the CLI.

    Returns ``None`` when absent (no-relay mode, policy chain still applies).
    """
    path = cwd / ".claude" / "claude-pilot.json"
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except OSError as err:
        raise SessionConfigError(f"cannot read {path}: {err}") from err
    try:
        return PilotConfig.model_validate(json.loads(raw))
    except json.JSONDecodeError as err:
        raise SessionConfigError(f"invalid JSON in {path}: {err}") from err
    except ValidationError as err:
        msgs = ", ".join(issue["msg"] for issue in err.errors())
        raise SessionConfigError(f"invalid {path}: {msgs}") from err


class ClaudeKernelSession:
    """One Claude Code session bound to the current kernel.

    Lifecycle: lazily connects the SDK client on first :meth:`ask`; stays
    connected (multi-turn) until :meth:`close`. The ``%claude`` line magic
    uses a throwaway instance per invocation (single-turn); the ``%%claude``
    cell magic keeps one instance per kernel (session continuity).
    """

    def __init__(self, cwd: str | None = None) -> None:
        self._cwd = str(Path(cwd).resolve()) if cwd else os.getcwd()
        # Config + permission handler are built eagerly so a malformed config
        # fails at magic time with a clear message, not mid-exchange.
        config = load_pilot_config(Path(self._cwd))
        self._handler = create_permission_handler(
            config=config,
            relay=config is not None,
            verbose=False,
            cwd=self._cwd,
        )
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._client: ClaudeSDKClient | None = None

    # ── public sync surface (called from the kernel thread) ──────────────

    def ask(self, prompt: str) -> None:
        """Run one prompt->response exchange, blocking until the turn ends.

        Streams assistant text to stdout as it arrives; writes a result footer
        to stderr. Ctrl-C / kernel interrupt sends ``client.interrupt()``
        best-effort before re-raising so the SDK subprocess is not left
        mid-turn.
        """
        loop = self._ensure_loop()
        future = asyncio.run_coroutine_threadsafe(self._ask(prompt), loop)
        try:
            future.result()
        except KeyboardInterrupt:
            if self._client is not None:
                asyncio.run_coroutine_threadsafe(self._client.interrupt(), loop)
            future.cancel()
            raise

    def close(self) -> None:
        """Disconnect the SDK client and stop the background loop thread.

        Idempotent; safe to call on a session that never connected.
        """
        if self._loop is None:
            return
        if self._client is not None:
            try:
                asyncio.run_coroutine_threadsafe(
                    self._client.disconnect(), self._loop
                ).result(timeout=_CLOSE_TIMEOUT_S)
            except Exception:
                pass  # best-effort — the daemon thread dies with the kernel anyway
            self._client = None
        self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread is not None:
            self._thread.join(timeout=_CLOSE_TIMEOUT_S)
        self._loop.close()
        self._loop = None
        self._thread = None

    # ── background-loop internals ─────────────────────────────────────────

    def _ensure_loop(self) -> asyncio.AbstractEventLoop:
        if self._loop is None:
            self._loop = asyncio.new_event_loop()
            self._thread = threading.Thread(
                target=self._loop.run_forever,
                name="claude-pilot-ipython",
                daemon=True,
            )
            self._thread.start()
        return self._loop

    async def _ask(self, prompt: str) -> None:
        if self._client is None:
            client = ClaudeSDKClient(options=self._build_options())
            await client.connect()
            self._client = client
        await self._client.query(prompt)
        async for message in self._client.receive_response():
            if isinstance(message, AssistantMessage):
                for block in _content_blocks(message):
                    text = _text_of(block)
                    if text:
                        sys.stdout.write(text + "\n")
                        sys.stdout.flush()
            elif isinstance(message, ResultMessage):
                _write_footer(message)

    def _build_options(self) -> ClaudeAgentOptions:
        # Mirrors agent.run_agent's options: same permission_mode, same
        # preset+append system prompt (plain string would REPLACE the Claude
        # Code preset — mika#1409), same ScheduleWakeup exclusion (cpp#59).
        # Guardrails (stall/empty/idle) are headless-loop machinery and are
        # intentionally absent here: the operator IS the loop in a REPL.
        return ClaudeAgentOptions(
            permission_mode="default",
            cwd=self._cwd,
            setting_sources=["user", "project", "local"],
            can_use_tool=self._handler,
            system_prompt=_system_prompt_with_hint(),
            disallowed_tools=["ScheduleWakeup"],
        )


def ask_once(prompt: str, cwd: str | None = None) -> None:
    """Single-turn exchange in a throwaway session (`%claude` line magic)."""
    session = ClaudeKernelSession(cwd=cwd)
    try:
        session.ask(prompt)
    finally:
        session.close()


def _write_footer(result: ResultMessage) -> None:
    """Compact end-of-turn footer on stderr, keeping stdout pure model text."""
    cost = f", ${result.total_cost_usd:.4f}" if result.total_cost_usd else ""
    sys.stderr.write(
        f"[claude-pilot] {result.subtype} — {result.num_turns} turn(s){cost}\n"
    )
    sys.stderr.flush()
