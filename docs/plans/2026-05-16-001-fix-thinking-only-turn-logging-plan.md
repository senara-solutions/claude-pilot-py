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

---

## Phase 0 — Pin (load-bearing source state)

**Base commit:** `e00565742f64f5d0a16d11908253f1a64b726268` (`origin/main` at grooming time — `feat(claude-pilot): detect pipeline-incomplete sessions via CLAUDE_PILOT_REQUIRE_PR (mika#940) (#9)`).

All design claims below are pinned against this SHA. If main moves before implementation, the implementer must re-verify each pin or rebase the plan.

### Pin A — `SessionGuardrails.on_assistant_message` and turns-increment site

`src/claude_pilot/guardrails.py:102-172` (verbatim, abbreviated to the load-bearing lines):

```python
def on_assistant_message(
    self,
    content: list[dict[str, Any]] | Any,
    message_id: str | None = None,
) -> None:
    """..."""
    blocks = content if isinstance(content, list) else []
    has_tool_use = any(_block_type(b) == "tool_use" for b in blocks)
    text_len = sum(
        len((_block_text(b) or "").strip()) for b in blocks if _block_type(b) == "text"
    )

    # mika#940: PR-creation detection (sticky)
    if not self._pr_created:
        for block in blocks:
            if _block_type(block) != "tool_use": continue
            if _tool_use_name(block) != "Bash": continue
            command = _tool_use_command(block)
            if command and "gh pr create" in command:
                self._pr_created = True
                break

    is_continuation = (
        message_id is not None and message_id == self._current_message_id
    )

    if is_continuation:
        # Same logical turn — accumulate.
        self._current_turn_text_len += text_len
        if has_tool_use and not self._current_turn_has_tool:
            self._current_turn_has_tool = True
            if self._stall_incremented_for_current_turn:
                self._consecutive_stall_turns = max(0, self._consecutive_stall_turns - 1)
                self._stall_incremented_for_current_turn = False
            if self._empty_incremented_for_current_turn:
                self._consecutive_empty_turns = max(0, self._consecutive_empty_turns - 1)
                self._empty_incremented_for_current_turn = False
        return

    # New turn boundary.
    self._turn_count += 1                  # <-- INCREMENT HAPPENS HERE, BEFORE block scanning of new turn
    self._current_message_id = message_id
    self._current_turn_has_tool = has_tool_use
    self._current_turn_text_len = text_len
    # ...stall/empty bookkeeping for the new turn follows
```

**Confirmed ordering** (load-bearing for F3-resolution and the design below): `self._turn_count += 1` runs at the new-turn boundary, BEFORE the new turn's content is analyzed for stall/empty. Therefore inside `on_assistant_message`, at the moment we detect a boundary, `self._turn_count` already names the NEW turn; the just-closed turn is `self._turn_count - 1`.

### Pin B — `SessionGuardrails` public interface

`src/claude_pilot/guardrails.py:73-100`:

| Member | Kind | Used in agent.py? |
|---|---|---|
| `config` | property → `ResolvedGuardrailConfig` | yes (line 48) |
| `turns` | property → `int` | yes (line 79) |
| `pr_created` | property → `bool` | yes (line 146) |
| `aborted` | property → `bool` | no |
| `abort_reason` | property → `GuardrailAbortReason \| None` | yes (line 70) |
| `wait_aborted()` | async → `GuardrailAbortReason` | yes (line 66) |
| `on_assistant_message(content, message_id)` | method → `None` | yes (line 101) |
| `pause_idle_timer()` | method | called by `permissions.py` |
| `resume_idle_timer()` | method | called by `permissions.py` |
| `dispose()` | method | yes (line 181) |

**No turn-boundary signal is currently exposed.** The internal state — `_current_message_id`, `_current_turn_has_tool`, `_current_turn_text_len` — is private. This is F2's design input: there IS no observable boundary signal today, so a fix that needs one must either (a) add one (changing the guardrail API), or (b) duplicate the detection in agent.py (F2's BLOCKING concern).

**This plan picks (a)** — change `on_assistant_message` to return `TurnBoundaryEvent | None`. Rationale in F2-resolution below.

### Pin C — `run_agent` AssistantMessage handling loop

`src/claude_pilot/agent.py:99-110` (verbatim):

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

**Confirmed:** the only "logged content" path inside the AssistantMessage branch is `log_text(text)` for text blocks. Tool calls are logged elsewhere (via `permissions.py` → `log_tool_request` / `log_relay_send` / `log_relay_recv` / `log_tool`). So `prev_turn_logged_content` (post-F2 resolution: `was_silent` flag on the boundary event) only needs to consider text-emitted plus tool-use observed.

### Pin D — `_text_of` and `_content_blocks`

`src/claude_pilot/agent.py:226-241` (verbatim):

```python
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
```

`_text_of` returns text ONLY when `block.type == "text"`. `ThinkingBlock`'s content is in `block.thinking`, not `block.text`, and its type discriminates as `"thinking"` (via `_SDK_BLOCK_CLASS_TO_TYPE` in `guardrails.py:265-271`). Confirms the root cause.

---

## Scope (deliberately narrow per ticket Option A)

The ticket explicitly endorses Option A as sufficient: *"once the operator sees `thinking-only` for 20 turns, the failure shape is obvious."* This plan ships Option A only — one marker line per logical turn that produced no text and no tool calls. Option B (per-block content dump or block-kind summary) is deferred to a follow-up ticket if Option A turns out to be too thin in practice; first instance of "I needed more than the count" will reopen the design.

Per `feedback_implementation_scope_bundling.md` — no silent scope expansion.

---

## Design (post-iteration v2)

### F2 resolution — single boundary owner: `SessionGuardrails`

The first-pass plan duplicated `message_id` boundary detection in `agent.py`, recreating exactly the divergence cpp#4 was meant to prevent. The corrected design keeps boundary detection inside `SessionGuardrails` and exposes the result via the return value of `on_assistant_message`.

**API change to `SessionGuardrails`:**

```python
# New module-level dataclass:
from dataclasses import dataclass

@dataclass(frozen=True)
class TurnBoundaryEvent:
    """Emitted by on_assistant_message when a logical turn just closed.

    `just_closed_turn` is the 1-indexed turn number of the turn that just ended
    (not the new turn that's starting). `had_text` and `had_tool_use` summarize
    what the just-closed turn produced — operators read these to decide whether
    the turn was diagnostically silent.

    `had_thinking_block` distinguishes "model thought but didn't act" from
    "SDK emitted a truly empty turn" — see F3 resolution.
    """
    just_closed_turn: int
    had_text: bool
    had_tool_use: bool
    had_thinking_block: bool


def on_assistant_message(
    self,
    content,
    message_id=None,
) -> TurnBoundaryEvent | None:
    """Returns a TurnBoundaryEvent when this call CLOSES a prior logical turn
    (i.e. message_id changed from the previously-seen one). Returns None on
    same-turn continuations and on the very first turn (no prior turn to close).
    """
```

**Existing call-site impact:** Today there is exactly one in-tree caller (`agent.py:101`) and one test-suite caller (`test_guardrails.py`). Tests ignore the return value (side-effect-only) and continue to work. The agent.py caller starts using the return value.

**State tracked inside SessionGuardrails to compute `TurnBoundaryEvent`:** the existing `_current_message_id`, `_current_turn_has_tool`, and `_current_turn_text_len` already track most of this. Add:

| New private field | Purpose |
|---|---|
| `_current_turn_had_thinking: bool` | True if any `ThinkingBlock` was observed in the current logical turn. Set by scanning blocks for `_block_type(b) == "thinking"`. Resets at new turn boundary. |

**Session-end (final turn) signal:** Add a new method `close_final_turn() -> TurnBoundaryEvent | None`. Called by `agent.py` from the `ResultMessage` branch BEFORE `_emit_result`. Returns a `TurnBoundaryEvent` for the still-open final turn (if any), then clears internal state so it's idempotent.

### F3 resolution — committed marker semantics

The first-pass plan emitted `"thinking-only, no actions"` regardless of whether thinking actually happened. The corrected design branches on `had_thinking_block`:

```python
# In agent.py:
def _on_boundary(event: TurnBoundaryEvent) -> None:
    if event.had_text or event.had_tool_use:
        return  # Turn produced observable output — already logged elsewhere.
    if event.had_thinking_block:
        # guardrails.turns reflects the NEW turn; event.just_closed_turn is the
        # prior turn that just ended.
        log_turn_summary(event.just_closed_turn, "thinking-only, no actions")
    else:
        # Truly empty turn — no text, no tool_use, no thinking either.
        # Should be vanishingly rare given the SDK's content-block model, but
        # defensive accuracy beats a lie in the log.
        log_turn_summary(event.just_closed_turn, "no observable output")
```

**Rationale for picking the conditional branch over the other two options the architect named:**
- *Generic text* (`"no observable output"` for all silent turns): loses the diagnostic signal that motivated the fix. The ticket's failure mode is specifically thinking-rumination drift; the marker text should name it.
- *Split-marker with different prefixes*: introduces a second log tag (`[turn]` vs e.g. `[silent]`) for one bit of information. Operators end up scanning twice. One tag, two summary strings, is simpler.
- *Conditional summary text* (picked): one tag, accurate text per case, no false claim in the zero-block case.

### Files touched

| File | Change |
|---|---|
| `src/claude_pilot/guardrails.py` | (a) Add `TurnBoundaryEvent` dataclass. (b) Add `_current_turn_had_thinking` field. (c) Change `on_assistant_message` return type to `TurnBoundaryEvent \| None`, returning the event at new-turn boundaries with the just-closed turn's summary. (d) Add `close_final_turn()` method for the ResultMessage path. (e) Update docstring of `on_assistant_message` to describe the new contract. |
| `src/claude_pilot/agent.py` | (a) Import `log_turn_summary`. (b) In the AssistantMessage branch, capture the return value of `on_assistant_message` and call a small local `_on_boundary` helper that emits the marker per F3 rules. (c) In the ResultMessage branch, call `guardrails.close_final_turn()` BEFORE `_emit_result` and route through `_on_boundary`. |
| `src/claude_pilot/ui.py` | Add `log_turn_summary(turn: int, summary: str) -> None`. Single line, `DIM` color, `[turn N]` prefix. Open-string summary preserves Option B extensibility (NF2 confirmed). |
| `tests/test_guardrails.py` | Add three test cases asserting the new return-value contract: (1) same-`message_id` continuation returns None; (2) new-`message_id` after a thinking-only turn returns `TurnBoundaryEvent(had_text=False, had_tool_use=False, had_thinking_block=True)`; (3) new-`message_id` after a text+tool turn returns event with `had_text=True, had_tool_use=True`. |
| `tests/test_agent.py` (new) | Three integration cases asserting log output: (a) N thinking-only turns → N `[turn k] thinking-only, no actions` lines; (b) text+tool turn → no marker; (c) ResultMessage with unclosed thinking-only turn → marker fires once via `close_final_turn`. |

Estimated diff: ~40 LOC source (vs. ~25 in v1 — the guardrail change adds ~15) + ~100 LOC tests.

### Inline comment directive (NF3)

At the agent.py call site that uses `event.just_closed_turn`, add the inline comment from NF3 — adapted to the new design where `event.just_closed_turn` is computed inside the guardrail rather than via `guardrails.turns - 1`:

```python
event = guardrails.on_assistant_message(...)
if event is not None:
    # event.just_closed_turn is the turn that just ENDED; guardrails.turns
    # now reflects the new turn that just started.
    _on_boundary(event)
```

This prevents a future refactor of `_turn_count` increment timing from silently breaking the labeling.

---

## Acceptance (matches ticket AC verbatim, with verification path)

1. **Thinking-only run emits N markers.** Feed N AssistantMessages each carrying a single `ThinkingBlock` with distinct `message_id`s, followed by a `ResultMessage`. Assert log file contains exactly N `[turn k] thinking-only, no actions` lines (k = 1..N) — N-1 from boundary events + 1 from `close_final_turn`.
2. **Regression: text+tool runs unchanged.** Feed a turn with `[ThinkingBlock, TextBlock("hello"), ToolUseBlock(Bash)]` (same `message_id`); assert log contains the text line and NO `[turn N] thinking-only` marker (the boundary event has `had_text=True`).
3. **Cost: per-line addition only.** Per-turn at most one extra `_log(...)` call. No per-character allocation, no buffering changes. Verified by inspection.

Live verification (after implementation): pick any closed mika dispatch worktree that produced a drift session, replay its session JSONL through a `run_agent` test harness (via the fake-stream pattern below), confirm marker appears.

---

## Test strategy (NF5 — committed)

`tests/test_agent.py` is created from scratch (no existing agent tests). Pattern matches `test_guardrails.py`: use `claude_agent_sdk.types.{TextBlock, ThinkingBlock, ToolUseBlock}` to construct synthetic block instances, wrap in `AssistantMessage` / `ResultMessage` shapes the SDK emits.

**Fake-stream approach (committed, not helper-extraction):** drive `run_agent` via a fake async generator that yields the synthetic SDK messages in order. The ClaudeSDKClient is mocked at the boundary. The permission callback is a no-op (no tool calls in these tests).

**Rationale for fake-stream over helper extraction:** extracting the AssistantMessage-handling loop into a standalone helper would introduce indirection not justified by production requirements — the helper would have a single caller and exist only for testability. The fake-stream exercises the integration seam (run_agent ↔ SDK messages ↔ guardrails ↔ ui) directly, which is the surface that actually breaks in production. This prevents PR reviewer re-litigation per NF5.

If the fake-stream scaffolding proves to be > ~50 LOC of boilerplate, that's a signal that the SDK boundary is hard to mock and the helper-extraction trade-off should be revisited in code review — flagged here, not pre-committed.

---

## Risks

1. **`message_id` may not exist on all SDK versions.** Already handled by `getattr(message, "message_id", None)` and the `is_continuation` fallback in the existing guardrail. The new return-value contract degrades cleanly: `message_id=None` makes every call a "new turn" boundary, so the event fires every time — slightly noisier for legacy SDKs but functionally correct.
2. **Tests that call `on_assistant_message` ignoring the return value.** Existing tests in `test_guardrails.py` don't assign the return; they continue to work. New tests check the return type explicitly. No breakage.
3. **`close_final_turn()` idempotency.** Must be safe to call multiple times — clear internal `_current_message_id` to `None` after returning the event, so a second call returns None.
4. **Final-turn marker ordering vs `_emit_result`.** The marker for the final turn must be emitted BEFORE `_emit_result` writes the result JSON line to stdout. Implemented by calling `guardrails.close_final_turn()` at the top of the `ResultMessage` branch.
5. **API change to `on_assistant_message` ripples to relay code paths?** No — searched, only `agent.py` and `tests/test_guardrails.py` call it. `permissions.py` calls `pause_idle_timer`/`resume_idle_timer` only.

---

## What I deliberately did NOT do

- **No content dump of thinking blocks** (Option B). Ticket says Option A is sufficient. Will reopen if a future drift incident proves the count alone is too thin.
- **No verbosity flag** (`--log-thinking` or similar). Option A is cheap enough to be always-on.
- **No backfill of past drift sessions.** Log file is append-only.
- **No observer/callback shape for the turn-boundary signal.** Return-value is simpler than registering a callback; agent.py has exactly one observation point.

---

## First-pass disposition resolution log

| Finding | Original architect concern | Resolution in v2 |
|---|---|---|
| F1 (BLOCKING) | Phase 0 Pin absent | Added Phase 0 with base SHA `e0056574...` and four verbatim pins (Pin A: turns-increment site; Pin B: SessionGuardrails public interface; Pin C: run_agent AssistantMessage loop; Pin D: `_text_of`/`_content_blocks`). |
| F2 (BLOCKING) | DRY duplication of `message_id` boundary detection | Removed `prev_message_id` from agent.py. Boundary detection stays in `SessionGuardrails`; new `TurnBoundaryEvent` return type from `on_assistant_message` exposes the signal. cpp#4-class divergence prevented. |
| F3 (BLOCKING) | Marker text mismatch for zero-block turns | Committed to *conditional summary text*: `had_thinking_block` branches between `"thinking-only, no actions"` and `"no observable output"`. Rationale documented vs. the two rejected alternatives (generic text / split-marker). |
| NF3 | Add inline comment on turn-counter ordering | Comment added at the agent.py call site (adapted to the new `event.just_closed_turn` field per F2's API change). |
| NF5 | Test design — record fake-stream rationale | Added committed-choice section with rationale; preempts code-review re-litigation. |
| NF1, NF2, NF4 | (Non-blocking, confirmed correct) | No change. |

## Open questions for second-pass review

None outstanding — F1/F2/F3 are committed designs, not deferrals. If the architect disagrees with the F2 API-change direction (return-value vs. observer/callback), that's a structural critique worth ESCALATEing rather than another iterate cycle.
