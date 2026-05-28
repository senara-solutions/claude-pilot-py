---
title: "feat(cpp#7): log [reconnect] instead of repeated [init]/[prompt] on SDK re-init"
type: feat
status: active
date: 2026-05-28
---

# feat(cpp#7): log [reconnect] instead of repeated [init]/[prompt] on SDK re-init

## Overview

When the Claude Code SDK emits more than one `SystemMessage(subtype="init")` during a session — observed during transient reconnects — `agent.py` currently runs the full `[init]` + `[prompt]` log pair every time. The result is a log that looks like the prompt was re-dispatched, even though the SDK never asked us to re-query. Replace the second-and-onward `[init]/[prompt]` pair with a single `[reconnect]` line that still surfaces `session_id` and `model`.

## Problem Frame

- Observed in cpp session `b8be0cda-dbe5-40ed-a1d3-a53a2216a78b`: three rapid `[init]`/`[prompt]` pairs at log lines 356-361 immediately after a normal tool call, with no actual `client.query()` re-dispatch.
- Cause: `src/claude_pilot/agent.py:94-99` unconditionally calls `log_init(...)` and `log_prompt(prompt)` for every `SystemMessage` whose `subtype == "init"`.
- Effect: log audits read like the agent re-sent the prompt — high cognitive friction for operators and for /mika-audit.
- Priority: Low. Cosmetic only — no behavioral change in tool dispatch, guardrails, or relay.

## Requirements Trace

- R1. The first `SystemMessage(subtype="init")` of a session still produces exactly one `[init]` log line and one `[prompt]` log line (no regression for the happy path).
- R2. Every subsequent `init` produces a single `[reconnect]` line carrying `session_id` and `model`, and does **not** re-emit `[init]` or `[prompt]`.
- R3. No other observable behavior changes: same `ResultJson`, same exit codes, same turn count, same guardrail behavior.
- R4. `uv run ruff check`, `uv run mypy src`, and `uv run pytest` all pass.

## Scope Boundaries

- Logging behavior only. No changes to `permissions.py`, `guardrails.py`, `inbox_writer.py`, the SDK interaction, or the `ResultJson` schema.
- No new log levels, sinks, or color conventions — `[reconnect]` reuses the existing `_log()` + `DIM` styling that `[init]` already uses.
- Do not change `log_init` or `log_prompt` signatures — additive only.

### Deferred to Separate Tasks

- Investigating *why* the SDK is emitting repeated `init` events for a single session is out of scope for cpp#7 (cosmetic fix). If the pattern persists or correlates with failure modes, file a separate ticket against `claude-agent-sdk` upstream.

## Context & Research

### Relevant Code and Patterns

- `src/claude_pilot/agent.py:94-99` — the unconditional `log_init` / `log_prompt` call site (the only fix site).
- `src/claude_pilot/ui.py:23-25` — `log_init` definition; `[reconnect]` should mirror this shape (`DIM` tag + `RESET`, short `session_id`, `model`).
- `src/claude_pilot/ui.py:100-101` — `log_prompt` writes to the file log via `write_file_log`. `[reconnect]` is stderr-only (matches `log_init`), so it uses `_log()` not `write_file_log` — there is no prompt re-emission.
- `src/claude_pilot/ui.py` log-helper conventions: lowercase tag in `DIM`, `BOLD` for emphasis on key fields, no trailing newlines (added by `_log()`).
- `tests/test_agent.py:62-63` — `_init()` test helper that constructs `SystemMessage(subtype="init", data={...})`. Reused below.
- `tests/test_agent.py:90-97` — `_install_fake_client` pattern lets us script SDK message sequences; perfect for asserting multi-`init` behavior.
- `tests/test_agent.py:105-137` — pattern for asserting stderr content via `capsys.readouterr()`; the new test follows the same shape.

### Institutional Learnings

- Existing log tags use lowercase bracketed prefix (`[init]`, `[tool]`, `[done]`). `[reconnect]` follows the same convention.

## Key Technical Decisions

- **Track "first init seen" with a local `seen_init` bool in `run_agent`**, not as instance state. `run_agent` is the only consumer; one local flag is the smallest viable change and matches the ticket's proposed shape verbatim.
- **Add `log_reconnect` to `ui.py` (no `logger.py` re-export needed).** `agent.py` already imports its log helpers directly from `claude_pilot.ui`, not from `logger`. Mirroring that pattern keeps the diff minimal and avoids a stylistic re-export the project doesn't otherwise use.
- **`[reconnect]` writes stderr only, not the file log.** `log_init` is stderr-only; `log_prompt` is file-log-only. Reconnects do not include a new prompt, so there is nothing to write to the file log — emitting stderr matches the operator-readable surface where `[init]` already lives.
- **`[reconnect]` carries `session_id` (truncated to 8 like `[init]`) and `model`.** Same shape as `[init]` so operators can spot the correlation across the same session id.

## Open Questions

### Resolved During Planning

- *Should `[reconnect]` go to the file log too?* No — `log_prompt` is the only file-log writer in this code path, and we are explicitly suppressing the re-prompt. Operator stderr surface is sufficient and matches `[init]`.
- *Should the helper accept `task_id`?* No — `task_id` is the per-dispatch identifier captured at session start; it does not change on reconnect. Omitting it keeps `[reconnect]` lines short.

### Deferred to Implementation

- Exact wording of the `[reconnect]` line (e.g., "Session %s, model %s reconnected" vs. "reconnect to session %s, model %s") — implementer should match the tone of `log_init` once eyes are on the file.

## Implementation Units

- [ ] **Unit 1: Add `log_reconnect` helper to `ui.py`**

**Goal:** Provide a single-line stderr log helper that follows the visual convention of `log_init`.

**Requirements:** R2

**Dependencies:** None

**Files:**
- Modify: `src/claude_pilot/ui.py`
- Test: covered by Unit 3's integration test (helper is exercised end-to-end through `run_agent`)

**Approach:**
- Add a `log_reconnect(session_id: str, model: str) -> None` function next to `log_init` (near `ui.py:23`).
- Implementation mirrors `log_init` styling: `DIM` `[reconnect]` tag, truncated session id (`[:8]`), model.
- No `task_id` argument; reconnects do not carry a new task.

**Patterns to follow:**
- `src/claude_pilot/ui.py:23-25` (`log_init`).

**Test scenarios:**
- Test expectation: none — pure formatting helper; behavior asserted by the Unit 3 integration test through stderr capture (R1 + R2). Adding a unit test that re-asserts string formatting against the helper would couple to ANSI control codes for no extra coverage value.

**Verification:**
- `log_reconnect` exists, is type-hinted, has no side effects beyond `_log()`, and is exported from `ui.py` alongside the other `log_*` helpers.

- [ ] **Unit 2: Gate `[init]`/`[prompt]` behind `seen_init` in `run_agent`**

**Goal:** Emit `log_init` + `log_prompt` exactly once per session; route subsequent `init` messages to `log_reconnect`.

**Requirements:** R1, R2, R3

**Dependencies:** Unit 1

**Files:**
- Modify: `src/claude_pilot/agent.py`
- Test: `tests/test_agent.py` (covered by Unit 3)

**Approach:**
- Add `seen_init: bool = False` to the local state declared near `session_id: str | None = None` (around `agent.py:49`).
- In the `SystemMessage` `init` branch (currently `agent.py:94-99`), extract `session_id` and `model` unconditionally (they are useful for both branches), then branch on `seen_init`:
  - If `not seen_init`: call `log_init(...)` + `log_prompt(prompt)`, set `seen_init = True`.
  - Else: call `log_reconnect(session_id or "", model or "unknown")`.
- Import `log_reconnect` from `.ui` in the existing `from .ui import (...)` block at `agent.py:24-33`.
- Keep the `continue` at the end of the branch unchanged.

**Patterns to follow:**
- Existing `from .ui import (...)` block in `agent.py` — alphabetical ordering preserved.
- Existing `session_id = _extract_session_id(message)` / `model = _extract_model(message)` lines remain on the outer path (no longer inside an `if not seen_init` guard) so that `session_id` continues to be tracked across reconnects.

**Test scenarios:**
- Test expectation: none — behavior is asserted by the Unit 3 integration test. Adding a separate unit test that mocks `log_init`/`log_reconnect` against a non-async helper would require extracting the branch into a function purely to test it, which adds indirection the test note in `tests/test_agent.py:8-11` explicitly argues against.

**Verification:**
- Diff hunks affect only `agent.py:24-33` (import) and `agent.py:94-99` (handler) plus the new `seen_init` local declaration.
- No other functions modified.

- [ ] **Unit 3: Add `test_multi_init_logs_reconnect`**

**Goal:** End-to-end coverage that a scripted SDK stream with N `init` messages produces exactly one `[init]`+`[prompt]` pair and N-1 `[reconnect]` lines on stderr.

**Requirements:** R1, R2

**Dependencies:** Units 1 and 2

**Files:**
- Modify: `tests/test_agent.py`

**Approach:**
- New `@pytest.mark.asyncio` test `test_multi_init_logs_reconnect_after_first` next to the existing tests.
- Scripted message stream: `[_init(), _init(), _init(), _result()]`. (Three `init`s mirrors the original incident's "3 rapid pairs".)
- Reuse `_install_fake_client`, `_config`, `_noop_permission` — no new helpers.
- After `await run_agent(...)`, capture stderr via `capsys.readouterr()` and assert:
  - `err.count("[init]") == 1` — happy path single emission (R1).
  - `err.count("[reconnect]") == 2` — N-1 reconnects (R2).
  - The single `[init]` line precedes the first `[reconnect]` line (ordering: `err.index("[init]") < err.index("[reconnect]")`).
- Optional second test `test_single_init_unchanged`: same fake stream as the existing `_init()` test but explicitly assert `err.count("[reconnect]") == 0` to guard against false-positive `[reconnect]` emissions during normal sessions (R1 regression guard).

**Patterns to follow:**
- `tests/test_agent.py:104-137` (`test_thinking_only_turns_emit_one_marker_each`) for the stream-then-assert-stderr shape.
- `_init()` helper at `tests/test_agent.py:62-63`.

**Test scenarios:**
- Happy path — single init: `[_init(), _result()]` → stderr contains one `[init]`, no `[reconnect]` (R1).
- Multi-init: `[_init(), _init(), _init(), _result()]` → stderr contains one `[init]` and two `[reconnect]` lines (R2).
- Ordering: the `[init]` line appears before any `[reconnect]` line in stderr (R1+R2 sequence).

**Verification:**
- `uv run pytest tests/test_agent.py` passes with the new tests.
- `uv run pytest` (full suite) passes — no regressions in adjacent test files.

## System-Wide Impact

- **Interaction graph:** Only `agent.run_agent` ↔ `ui.log_*` is touched. No permissions, no guardrails, no inbox writer.
- **Error propagation:** Unchanged.
- **State lifecycle risks:** `seen_init` is a function-local flag with the same lifetime as the `async with ClaudeSDKClient(...)` block — no shared state, no cleanup hazard.
- **API surface parity:** None — `log_reconnect` is internal to `claude_pilot.ui`.
- **Unchanged invariants:** `ResultJson` shape, `[prompt]` file-log content, all tool-permission paths, guardrail thresholds, exit codes.

## Risks & Dependencies

| Risk | Mitigation |
|------|------------|
| A test downstream consumer greps `[init]` and silently counts on multiple per session. | Likelihood low — `[init]` already documents session-start. The regression-guard test in Unit 3 asserts single emission for normal flow. If a downstream consumer relies on the broken behavior, surface in PR review. |
| `seen_init` is set to `True` even when `log_init` would have failed (it can't, but defensively). | `log_init` writes to stderr; failure modes are I/O errors that would also fail every other log call. No realistic regression. |

## Sources & References

- Originating issue: `senara-solutions/claude-pilot-py#7`
- Fix site: `src/claude_pilot/agent.py:94-99`
- Log helpers: `src/claude_pilot/ui.py:23-25` (`log_init`), `src/claude_pilot/ui.py:100-101` (`log_prompt`)
- Test patterns: `tests/test_agent.py:62-63`, `tests/test_agent.py:90-97`, `tests/test_agent.py:104-137`
