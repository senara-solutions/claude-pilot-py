# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**claude-pilot** is a Python CLI that wraps Claude Code using `claude-agent-sdk` (PyPI). It runs Claude Code headlessly and intercepts tool permission requests and questions via the SDK's `can_use_tool` callback, forwarding them to an external agent (e.g. `mika --agent mika-dev ask`) for automated decision-making.

This is a port of the archived TypeScript implementation at `senara-solutions/claude-pilot-ts`. The port was motivated by reproducible Node ESM loader failures (see `senara-solutions/mika-platform#31`). All external contracts are preserved: CLI flags, relay protocol, `.claude/claude-pilot.json` shape, and stdout `ResultJson`.

## Commands

```bash
uv sync --all-extras       # Install dev dependencies
uv run pytest              # Run tests
uv run ruff check          # Lint
uv run mypy src            # Type check
uv tool install --force .  # Install the claude-pilot binary on PATH
```

## Architecture

```
src/claude_pilot/cli.py          → Entry point: argparse, config loading, signal handling, asyncio.run
src/claude_pilot/agent.py        → ClaudeSDKClient wrapper, message streaming, ResultJson emission
src/claude_pilot/permissions.py  → can_use_tool: tier1 short-circuit, relay, retry, interactive fallback
src/claude_pilot/tier1.py        → Auto-approval filter: deny-list, safe command patterns, path safety
src/claude_pilot/transport.py    → asyncio.create_subprocess_exec transport with Pydantic validation
src/claude_pilot/guardrails.py   → Stall / empty / idle-timeout detection with pausable idle timer
src/claude_pilot/inbox_writer.py → mika#1189 side-channel handoff to mika-gateway orchestrator inbox
src/claude_pilot/ui.py           → Stderr log renderer (ANSI colors)
src/claude_pilot/types.py        → Pydantic models: PilotConfig, PilotEvent, PilotResponse, ResultJson
src/claude_pilot/logger.py       → File + stderr sink with ANSI stripping
```

**Flow:** CLI → `ClaudeSDKClient(options={can_use_tool})` → on tool permission needed → format `PilotEvent` → invoke external command via `asyncio.create_subprocess_exec` (stdin JSON) → validate response with Pydantic → map to SDK `PermissionResultAllow`/`Deny` → return to SDK.

**Key design decisions:**

- External agent is a **black box** — claude-pilot sends events and waits. If the agent escalates internally (e.g. asks a human via Telegram), it just takes longer to respond.
- Response contract is minimal: `{"action": "allow"}`, `{"action": "deny"}`, `{"action": "answer", "answers": {...}}`.
- Malformed JSON triggers one retry with error feedback, then falls back to interactive user prompt.
- Non-interactive mode (no TTY) auto-denies on failure.
- `asyncio.create_subprocess_exec` (not shell) prevents injection.
- Sensitive env vars (`KEY`, `SECRET`, `TOKEN`, `AUTH`, `PRIVATE`, `DATABASE_URL`, `DSN`, etc.) are scrubbed before spawning the relay subprocess.
- **Session guardrails** detect degenerate loops (stall, empty responses, idle) and terminate cleanly with structured `ResultJson` output. SDK-native `max_turns` is passed through to the SDK. Idle timer pauses during `can_use_tool` to avoid false positives from slow relay agents.
- **Pipeline slash commands bypass relay approval.** The `Skill` tool invocations for `/mika`, `/ce:*`, `/compound-engineering:resolve_todo_parallel`, and `/mika-doc-audit` are auto-approved at Tier 1. These are the agent's own orchestration steps — routing them through the relay exposes them to LLM-driven denials that rationalize fabricated rejections. The allow-list is in `TIER1_SAFE_SKILLS` in `src/claude_pilot/tier1.py`.
- **Relay payload prefix.** Events are written to relay stdin as `[claude-pilot] <PilotEvent JSON>`. The prefix is load-bearing — LLM-backed relay agents key on it to distinguish claude-pilot events from user prose and webhook notifications.
- **System prompt is preset+append, never a plain string (mika#1409).** `agent.py` sets `ClaudeAgentOptions.system_prompt` to a `SystemPromptPreset` — `{"type": "preset", "preset": "claude_code", "append": DENIED_BASH_PATTERNS_HINT}`. The preset+append shape is load-bearing: a plain-string `system_prompt` would REPLACE the Claude Code preset and break the headless `/mika` + `/ce:*` pipeline that depends on it. The appended hint (defined in `tier1.py` next to the deny-list patterns it mirrors, so it cannot drift) names the most-commonly-denied Bash patterns (`find … -exec`, non-safe-listed tools like `md5sum`, `sed -i`, `>` redirects) and their auto-approved native-tool substitutes, so the model avoids reaching for a policy-denied command that would halt the session via `interrupt=True` (cpp#20 joint 2). Prevention-only; the recoverable-denial half is deferred to mika#1410.
- **Orchestrator inbox side-channel (mika#1189).** On the success path, after `_emit_result(result)` in `agent.py`, the session calls `inbox_writer.post_handoff(result)` — a best-effort HTTP POST to `${MIKA_GATEWAY_URL}/orchestrator/inbox/{MIKA_ORCHESTRATOR_ID}/message`. Dual-write with the mika-platform#100 filesystem inbox; filesystem write remains canonical. Gated by `MIKA_ORCHESTRATOR_INBOX_ENABLED=1` AND a valid `MIKA_ORCHESTRATOR_ID`. Failures are logged to stderr but never change the exit code. The function returns `False` (silent no-op) when env is incomplete OR the gateway responds 404 (its own feature flag off). See `inbox_writer.py` constants and the gateway plan: `mika/docs/plans/2026-05-17-003-feat-1189-mika-gateway-orchestrator-inbox-v2-plan.md`.

## Environment Variables

Place a `.env` file in the package root (alongside `pyproject.toml`). Values do NOT override existing `os.environ` entries. See `.env.example` for available variables.

The `.env` file is gitignored and not copied to worktrees. Autonomous sessions inherit env vars from the parent process.

**Note:** Variables matching sensitive patterns (`TOKEN`, `KEY`, `SECRET`, `AUTH`, etc.) are scrubbed from the relay child process by `scrub_env()` in `transport.py`, but remain visible to the Claude Code SDK subprocess — by design. Claude Code needs tokens like `GH_TOKEN` to operate; the relay agent should not see them.

### Orchestrator inbox (mika#1189)

The inbox writer reads four env vars at call time — all four must be set for the side-channel post to fire:

- `MIKA_ORCHESTRATOR_INBOX_ENABLED` — `1` / `true` (case-insensitive) enables; `0`, `2`, `false`, empty, or unset disables. The `2` (gateway-only cutover) value is reserved for a future ticket and currently treated as disabled to avoid silent partial cutover.
- `MIKA_ORCHESTRATOR_ID` — orchestrator session id (1-128 chars, `[A-Za-z0-9_-]`). Exported by `scripts/mika-platform-spawn` from a cached id at `~/.mika/orchestrator/id`.
- `MIKA_GATEWAY_URL` — base URL of the mika-gateway (e.g. `https://gateway.example`). Trailing slash is normalised away.
- `MIKA_INTERNAL_TOKEN` — bearer token shared with the gateway (already known to claude-pilot for other paths).

`MIKA_SPAWN_ID` is read opportunistically to populate the `spawn_id` correlation field; absent → null in the envelope.

## Key SDK Types

From `claude_agent_sdk`:

- `can_use_tool(tool_name: str, tool_input: dict, ctx: ToolPermissionContext) -> PermissionResult` — async callback, blocks tool execution until it resolves.
- `PermissionResultAllow(updated_input=...)` / `PermissionResultDeny(message=..., interrupt=False)`.
- `AskUserQuestion` — intercepted via `can_use_tool` when `tool_name == "AskUserQuestion"`; response requires `PermissionResultAllow(updated_input={"questions": ..., "answers": ...})`.
- `ClaudeSDKClient(options=ClaudeAgentOptions(...))` — bidirectional client; `can_use_tool` is NOT supported on the one-shot `query()` entrypoint.

## Documented Solutions

`docs/solutions/` — documented solutions to past problems (bugs, security findings, workflow patterns), organized by category with YAML frontmatter (`module`, `tags`, `problem_type`). Relevant when implementing or debugging in documented areas — e.g. the permission classifier (`policy.py`/`permissions.py`/`tier1.py`) has a load-bearing learning on command-string allow-rule safety.

## Planning Documents

- Plan: `senara-solutions/mika-platform/docs/plans/2026-04-14-001-feat-port-claude-pilot-to-python-plan.md`
- Originating issue: `senara-solutions/mika-platform#31`
