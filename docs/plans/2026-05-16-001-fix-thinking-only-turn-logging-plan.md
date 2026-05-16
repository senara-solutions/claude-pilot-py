---
type: fix
issue: senara-solutions/claude-pilot-py#10
original_filing: senara-solutions/mika#1142 (closed; refiled to cpp#10 because the fix targets src/claude_pilot/agent.py and prior agent.py bugs — cpp#4, cpp#5 — were tracked here)
branch: fix/10/log-emits-zero-events-when-model
date: 2026-05-16
---

# Plan: log thinking-only turns so operators can debug pilot-drift sessions

## Problem (one line)

When the underlying model produces a logical turn containing only `ThinkingBlock`s — no `TextBlock`, no `ToolUseBlock` — claude-pilot's per-task log emits zero events for that turn. A 20-turn / $1.03 / 81-second drift session (mika#920 today) leaves operators with five-line logs ending in `[error] pipeline_incomplete:` and no diagnostic surface.

## Why this is in cpp not mika

- The code change lives in `src/claude_pilot/agent.py` and `src/claude_pilot/ui.py` (this repo).
- Prior agent.py bug fixes were filed here (cpp#4 — thinking-block stall miscount; cpp#5 — cost reporting on guardrail termination).
- mika#1142 was the original filing; closed with a pointer to this issue.

## Root cause (verified by reading code on this branch)

`src/claude_pilot/agent.py:99-109`:

```python
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
```

`_text_of` (lines 232-241) returns text only when `block.type == "text"`. `ThinkingBlock` has `type="thinking"` and exposes its content via the `thinking` field, not `text` (verified in `tests/test_guardrails.py:31-32` — `ThinkingBlock(thinking=text, signature="sig")`). Pure-thinking turns therefore loop through `_content_blocks` without emitting any log line.

Tool-use blocks are also `_text_of`-empty, but they are logged through the permission-handler path (`log_tool_request` / `log_tool` / `log_relay_send` / `log_relay_recv` in `ui.py`). The diagnostic gap is specifically **text-less and tool-less** AssistantMessages.

## Scope (deliberately narrow per ticket Option A)

The ticket explicitly endorses Option A as sufficient: *"once the operator sees `thinking-only` for 20 turns, the failure shape is obvious."* This plan ships Option A only — one marker line per logical thinking-only turn. Option B (per-block content dump or block-kind summary) is deferred to a follow-up ticket if Option A turns out to be too thin in practice; first instance of "I needed more than the count" will reopen the design.

Per `feedback_implementation_scope_bundling.md` — no silent scope expansion.

## Design

### One marker per logical turn, not per AssistantMessage

The Python `claude-agent-sdk` splits one logical Claude turn into N `AssistantMessage` events, one per content block, all sharing the same `message_id`. A naive "emit when this AssistantMessage has no text and no tool_use" check would spam N markers for a turn with N thinking blocks. `guardrails.py:102-119` already documents this grouping (it was the root cause of cpp#4).

The fix tracks the same `message_id` boundary in `agent.py` and emits the marker exactly once per logical turn, at the moment a new turn boundary is observed (or at session end via `ResultMessage`).

### What to emit

```
[turn 3] thinking-only, no actions
```

Format mirrors existing `ui.py` markers (`[init]`, `[tool]`, `[done]`, `[guardrail]`) — bracketed-tag prefix, `DIM` color, single line.

Turn number sourced from `guardrails.turns` — already incremented at the new-turn boundary inside `on_assistant_message`.

### State to track in agent.py

Two new locals in `run_agent`:

| Variable | Purpose |
|---|---|
| `prev_message_id: str \| None = None` | message_id of the last-seen AssistantMessage. New value signals turn boundary. |
| `prev_turn_logged_content: bool = False` | True if the just-closed turn produced any `log_text` call OR contained any tool_use block. Reset on new turn. |

On each `AssistantMessage`:
1. Compute `mid = getattr(message, "message_id", None)`.
2. If `mid != prev_message_id` and `prev_message_id is not None`: a turn boundary just closed. If `not prev_turn_logged_content`, emit the marker for `guardrails.turns - 1` (the just-closed logical turn). Reset `prev_turn_logged_content = False`.
3. Process the blocks as today (`log_text` per text block; `guardrails.on_assistant_message` for state).
4. After the loop, set `prev_turn_logged_content = prev_turn_logged_content or any_text or any_tool_use`.
5. Update `prev_message_id = mid`.

On `ResultMessage`:
- Before the existing `_emit_result` block: if `prev_message_id is not None` and `not prev_turn_logged_content`, emit the marker for `guardrails.turns` (the final turn never got a "next message_id" boundary).

`message_id is None` fallback (older SDKs or callers without the field): treat each AssistantMessage as its own turn — same backward-compat path the guardrails already use. The marker still fires per text-less-tool-less event.

### New ui.py function

```python
def log_turn_summary(turn: int, summary: str) -> None:
    _log(f"{DIM}[turn {turn}]{RESET} {summary}")
```

Hard-coded callers use the single string `"thinking-only, no actions"`. Keeping the second argument open allows the Option B follow-up to extend without touching call sites again.

## Files touched

| File | Change |
|---|---|
| `src/claude_pilot/agent.py` | Add `prev_message_id` / `prev_turn_logged_content` tracking; emit marker on turn boundary and at session end. Import `log_turn_summary`. |
| `src/claude_pilot/ui.py` | Add `log_turn_summary(turn, summary)` — single line, matches existing format. |
| `tests/test_agent.py` (new) | Three test cases: thinking-only turn emits marker once; turn with text/tool does not emit marker; final unclosed turn emits marker on ResultMessage. |

Estimated diff: ~25 LOC source + ~80 LOC test scaffolding. No public API change.

## Acceptance (matches ticket AC verbatim, with verification path)

1. **Thinking-only run emits N markers.** Reproduce by feeding `N` AssistantMessages each containing a single `ThinkingBlock` with distinct `message_id`s; assert log file contains exactly N `[turn k] thinking-only, no actions` lines (k = 1..N).
2. **Regression: text+tool runs unchanged.** Feed a turn with `[ThinkingBlock, TextBlock("hello"), ToolUseBlock(Bash)]` (same `message_id`); assert log contains the text line and NO `[turn N] thinking-only` marker. Snapshot existing `test_guardrails.py` log expectations as a guard.
3. **Cost: per-line addition only.** Verify by inspection — no per-character allocation, no buffering changes, no IO frequency increase beyond at most one extra `write_log` call per logical turn.

Live verification (after implementation):
- Pick any closed mika dispatch worktree that produced a drift session; replay its session JSONL through a `run_agent` test harness; confirm the marker appears.
- Or — instrument a single mika-dev dispatch with the new build; observe log on next thinking-only drift.

## Test strategy

A new `tests/test_agent.py` is needed (none exists today). Use the same pattern as `test_guardrails.py`:

- `from claude_agent_sdk.types import TextBlock, ThinkingBlock, ToolUseBlock`
- Construct synthetic `AssistantMessage` instances (or mock the SDK message stream).
- Drive `run_agent` via a fake SDK client OR — simpler — extract the AssistantMessage-handling loop into a small helper function that takes a message + state and emits log calls, then unit-test the helper directly with `capsys` / file-log capture.

Preference: keep the loop in `run_agent` (no extract), and test by mocking the SDK stream. The agent.py code already uses `_merge_stream` which is testable. If mocking proves heavy, fall back to the helper-extraction approach — but only if the architect agrees the indirection is worth it.

Concretely the first cut: pytest `test_thinking_only_turn_logs_marker` that drives a hand-rolled async generator yielding the synthetic AssistantMessage events into `run_agent`. The relay/permission callback is no-op for these tests (no tool calls).

## Risks

1. **`message_id` may not exist on all SDK versions.** Already handled by the existing `getattr(message, "message_id", None)` and the `is_continuation` fallback in `guardrails.py:143-145`. The new code uses the same defensive `getattr`.
2. **Turn-counter drift between agent.py and guardrails.py.** `guardrails.turns` is the source of truth. The plan reads it after `guardrails.on_assistant_message()` so it reflects the NEW turn count. The marker uses `guardrails.turns - 1` when closing a prior turn (because the boundary signal is "we just saw the next message_id"), and `guardrails.turns` at session end.
3. **Marker noise in healthy sessions.** Healthy sessions intersperse text/tool with thinking, so the marker should be near-zero in normal operation. If it fires once per session for the final `[done]` turn, that's a tolerable false positive. The acceptance criteria explicitly verify it does NOT fire for text+tool turns.
4. **Final-turn emission ordering vs `_emit_result`.** The marker for the final turn must be emitted BEFORE `_emit_result` writes the result JSON line to stdout, so the log+stdout interleaving stays readable. The plan emits inside the `if isinstance(message, ResultMessage)` branch but before `_emit_result(result)`.

## What I deliberately did NOT do

- **No content dump of thinking blocks** (Option B). Ticket says Option A is sufficient. Will reopen if a future drift incident proves the count alone is too thin.
- **No verbosity flag** (`--log-thinking` or similar). Option A is cheap enough to be always-on; a flag adds config surface for negligible cost savings.
- **No backfill of past drift sessions.** The log file is append-only; existing logs stay as they are. Only future sessions benefit.
- **No change to guardrails.py.** The thinking-only condition is already correctly detected by the stall guardrail (it counts text-less + tool-less turns). The bug is purely a logging gap, not a detection gap.

## Open questions for first-pass architect review

1. **Is the per-logical-turn aggregation worth the state-tracking complexity, vs. per-AssistantMessage emission?** Per-AssistantMessage is simpler (no boundary state) but noisier — a turn with 8 thinking blocks would emit 8 markers. I picked per-turn to avoid that noise, but the simpler-and-noisier path is defensible.
2. **Should the marker carry the count of thinking blocks observed in that turn?** E.g. `[turn 5] thinking-only, 3 blocks`. Trivial to add; useful for "long-thinking" diagnosis. Holding back per "Option A only" but flagging.
3. **Should the marker also fire for genuinely empty turns (no thinking, no text, no tool)?** I assume yes — it's the same operator-visibility need — but the ticket's evidence is specifically thinking-heavy. The current plan covers both incidentally (it fires whenever `not prev_turn_logged_content`).
