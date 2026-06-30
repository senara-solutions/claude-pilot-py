---
artifact_contract: ce-unified-plan/v1
artifact_readiness: implementation-ready
execution: code
product_contract_source: ce-plan-bootstrap
origin: senara-solutions/claude-pilot-py#59
date: 2026-06-30
type: fix
---

# fix: Prevent `ScheduleWakeup` from silently stalling headless claude-pilot sessions (cpp#59)

## Summary

In headless claude-pilot SDK sessions, the model occasionally calls the `ScheduleWakeup`
tool as a "wait" primitive after dispatching an `Agent`/`Explore` subagent. `ScheduleWakeup`
is Claude Code's `/loop` dynamic-pacing primitive: it schedules a future wake that the
**interactive** harness handles. In headless SDK mode there is no harness to fire the wake —
the call is a no-op, the model concludes "nothing more to do this turn," and the session
ends (`PIPELINE_INCOMPLETE`). Founding incident: mika#1652 dev-groom pilot stalled at
$2.36 / 11 turns with no plan written.

This plan adds two guards in `src/claude_pilot/agent.py`: a **load-bearing system-prompt
prevention hint** and a **defense-in-depth tool-surface exclusion** (`disallowed_tools`).

> **Mechanism correction (load-bearing — read before implementing).** The originating
> ticket/brief proposed denying `ScheduleWakeup` in `tier1.py`'s `TIER3_PATTERNS` (a Bash
> deny-list). That fix is **inert** and must NOT be implemented. See Problem Frame for the
> hard evidence. The viable fix lives in `agent.py`, not `tier1.py`/`permissions.yaml`.

---

## Problem Frame

### Why the originally-specified fix is impossible

1. **`TIER3_PATTERNS` only scan Bash command *strings*.** `is_tier3_dangerous()` is called
   solely from `is_safe_bash_command()`, which runs only when `tool_name == "Bash"`
   (`src/claude_pilot/tier1.py:32-36`, `:395`). `ScheduleWakeup` is a separate tool; a regex
   added there would never execute against it.

2. **`ScheduleWakeup` never reaches claude-pilot's permission layer.** The incident
   transcript (session `d70b3d70…`, tool-use at line 46, tool-result at line 47) shows the
   call returned `is_error=false` with the harness's own message: *"Next wakeup scheduled…
   the harness re-invokes you when the wakeup fires."* claude-pilot has **no allow path** for
   it — `is_tier1_auto_approve` → `False`, `try_tier_1_5_auto_answer` → `None`, policy default
   → `deny` (`src/claude_pilot/policy.py:64-65`) which maps to
   `PermissionResultDeny(interrupt=True)` (`src/claude_pilot/permissions.py:376-378`). Had the
   call reached `can_use_tool`, it would have **halted with a deny**, not succeeded. It
   succeeded → the SDK/CLI runtime handles `ScheduleWakeup` **internally** and bypasses
   `can_use_tool` entirely. No `tier1.py` or `permissions.yaml` rule can intercept it.

3. **Authoritative SDK guidance** (claude-agent-sdk 0.2.110): `ScheduleWakeup` is a
   harness/CLI runtime primitive, not a permissionable SDK tool; it is never surfaced to
   `can_use_tool`; and in headless SDK mode it is structurally non-functional (fire-and-forget,
   nothing re-invokes the session).

### What actually works

- **System-prompt hint** — already the established prevention channel (mika#1409,
  `DENIED_BASH_PATTERNS_HINT` injected via `_system_prompt_with_hint()` at
  `src/claude_pilot/agent.py:295`). The model reads it. **Load-bearing guard.**
- **`disallowed_tools=["ScheduleWakeup"]`** on `ClaudeAgentOptions` → CLI `--disallowedTools`.
  Transcript evidence shows `ScheduleWakeup` is a real surfaced/executed tool (genuine harness
  `tool_result`, not "tool not found"), so a bare-name deny *should* remove it from the request
  per SDK docs. **But the SDK docs do not definitively confirm `--disallowedTools` filters
  runtime primitives** — so this is documented defense-in-depth, not the load-bearing guard.

### Honest-closure boundary

Per project doctrine (`feedback_prompt_enforcement_fragile`,
`feedback_prompt_enforcement_empirically_confirmed_at_loop_substrate`), prompt-only
enforcement **reduces the rate** of a stochastic trap but does **not close the class** — the
existing `DENIED_BASH_PATTERNS_HINT` carries the same honesty note. If `disallowed_tools` is
empirically confirmed to suppress the tool (AC5), the structural guard closes the class; if
not, the hint remains a rate-reducer only. The plan documents whichever outcome holds.

---

## Requirements

- **R1.** The headless pilot's system prompt instructs the model never to call
  `ScheduleWakeup` (and why: no harness wake → the session ends), and that a dispatched
  `Agent`/subagent result is already available synchronously next turn so no "wait" is needed.
- **R2.** `ScheduleWakeup` is added to `ClaudeAgentOptions.disallowed_tools` as documented
  defense-in-depth, with the runtime-primitive uncertainty noted in a code comment.
- **R3.** The prevention hint stays co-located with the existing prevention-hint family so
  documentation cannot drift from enforcement, carrying an honest-closure note.
- **R4.** Existing tests stay green (446+ floor from cpp PR57); `ruff` + `mypy` clean.
- **R5.** Empirically determine whether `disallowed_tools=["ScheduleWakeup"]` suppresses the
  call in a real headless session; record the result honestly in the PR.

---

## Key Technical Decisions

- **KTD1 — Extend `DENIED_BASH_PATTERNS_HINT` in place rather than adding a new constant.**
  `_system_prompt_with_hint()` appends exactly that constant, and `test_agent.py:444` asserts
  `append == DENIED_BASH_PATTERNS_HINT`. Adding a new `## Tools that are no-ops in headless
  mode` section *inside* the constant keeps the wiring and the equality test intact (zero
  churn to `agent.py`'s append shape) and satisfies the co-location requirement (R3). The
  constant's role is "the model-facing prevention-hint payload," which a harness-no-op section
  fits; a short comment notes the name predates the broadened scope. Rejected: a sibling
  constant concatenated in `_system_prompt_with_hint()` — more churn, breaks the equality test,
  no real benefit at this size.

- **KTD2 — Keep `disallowed_tools` as best-effort defense-in-depth, not the primary guard.**
  Include it (harmless if it no-ops; structural if it works) but document the uncertainty so a
  future reader does not mistake it for a proven hard block. The hint is load-bearing.

- **KTD3 — Reject the SDK guide's `permission_mode="dontAsk"` + `allowed_tools` allowlist.**
  That would replace claude-pilot's entire tiered relay/policy permission architecture
  (`permission_mode="default"` + `can_use_tool` + `policy.py`). Out of scope and architecturally
  wrong for this repo.

---

## Implementation Units

### U1. System-prompt prevention hint for headless no-op harness tools

**Goal:** Tell the model, in the injected system prompt, never to call `ScheduleWakeup` in
headless mode and what to do instead.

**Requirements:** R1, R3.

**Dependencies:** none.

**Files:**
- `src/claude_pilot/tier1.py` — extend `DENIED_BASH_PATTERNS_HINT` with a new
  `## Tools that are no-ops in headless mode` section naming `ScheduleWakeup`, explaining the
  no-harness-wake failure mode, and stating that a dispatched `Agent`/subagent result is already
  available synchronously next turn (so no "wait" is needed). Add a one-line comment noting the
  constant's scope now covers harness-no-op tools as well as denied Bash patterns, plus the
  honest-closure note (prompt-only reduces rate, does not close the class).
- `tests/test_agent.py` — add a test asserting the appended hint contains the
  `ScheduleWakeup` headless block and the "synchronous subagent result" guidance.

**Approach:** Pure string-constant edit + a co-located comment. No change to
`_system_prompt_with_hint()` or `agent.py` wiring — the existing append already carries the
extended constant verbatim.

**Patterns to follow:** Mirror the existing `DENIED_BASH_PATTERNS_HINT` block style and its
honest-closure note (`src/claude_pilot/tier1.py:161-214`). Mirror the existing assertion style
in `test_1409_system_prompt_helper_is_preset_append_with_hint`
(`tests/test_agent.py:435-445`).

**Test scenarios:**
- The string returned by `_system_prompt_with_hint()["append"]` contains `"ScheduleWakeup"`.
- It contains the headless-mode no-op section header (e.g. `"no-ops in headless mode"`).
- It contains the synchronous-subagent guidance (e.g. asserts the substring about the Agent/
  subagent result already being available / not needing to wait).
- The existing `append == DENIED_BASH_PATTERNS_HINT` equality assertion still passes (regression
  guard — do not break it).

**Verification:** `uv run pytest tests/test_agent.py` green; the new assertions pass and the
pre-existing mika#1409 system-prompt tests still pass.

### U2. `disallowed_tools` tool-surface exclusion (defense-in-depth)

**Goal:** Add `ScheduleWakeup` to the SDK tool-deny list so, where the runtime honors it, the
model never sees the tool.

**Requirements:** R2.

**Dependencies:** none (independent of U1; can land in the same commit).

**Files:**
- `src/claude_pilot/agent.py` — add `disallowed_tools=["ScheduleWakeup"]` to the
  `ClaudeAgentOptions(...)` constructor (`src/claude_pilot/agent.py:62-69`), with a comment
  documenting: (a) `ScheduleWakeup` is a harness runtime primitive, (b) SDK docs do not
  definitively confirm `--disallowedTools` filters runtime primitives, (c) the system-prompt
  hint (U1) is the load-bearing guard, (d) cross-ref cpp#59.
- `tests/test_agent.py` — add a test asserting the captured `ClaudeAgentOptions` kwargs include
  `disallowed_tools` containing `"ScheduleWakeup"`.

**Approach:** One kwarg on the options constructor + an explanatory comment. Reuse the existing
`_capturing_options` monkeypatch harness to assert the wiring end-to-end.

**Patterns to follow:** Mirror `test_1409_run_agent_passes_system_prompt_into_options`
(`tests/test_agent.py:448-476`) — the `_capturing_options` monkeypatch that captures
`ClaudeAgentOptions` kwargs.

**Test scenarios:**
- `run_agent(...)` constructs `ClaudeAgentOptions` with `disallowed_tools` present and
  containing `"ScheduleWakeup"` (via the `_capturing_options` capture).

**Verification:** `uv run pytest tests/test_agent.py` green; `uv run ruff check` and
`uv run mypy src` clean.

---

## Verification Contract

- `uv run pytest` — full suite green, ≥446 tests (cpp PR57 floor preserved).
- `uv run ruff check` — clean.
- `uv run mypy src` — clean.
- **AC5 / R5 empirical check (manual, documented in PR):** Run (or reuse) a headless pilot
  session and confirm whether `disallowed_tools=["ScheduleWakeup"]` actually prevents the
  model from issuing a successful `ScheduleWakeup` `tool_use`. Record the observed behavior
  honestly in the PR body:
  - If suppressed → note that the structural guard closes the class; hint is belt-and-suspenders.
  - If NOT suppressed → note that the hint is the active guard and `disallowed_tools` stays as
    documented best-effort. Either outcome is an acceptable, honest close.

---

## Definition of Done

- U1 and U2 implemented per the file lists above.
- All Verification Contract gates pass (pytest ≥446 green, ruff clean, mypy clean).
- The AC5 empirical outcome is recorded in the PR body (suppressed or not — honestly stated).
- PR body documents the **mechanism correction** (tier1/policy deny is inert; fix is in
  `agent.py`) and surfaces it for architect/orchestrator awareness, since the groomed shape
  was wrong.
- PR closes cpp#59.

---

## Scope Boundaries

**In scope:** the two `agent.py`-layer guards for `ScheduleWakeup` and their tests.

### Out of scope (non-goals)

- Any `tier1.py` `TIER3_PATTERNS` or `permissions.yaml` rule for `ScheduleWakeup` — **inert,
  would be misleading dead code.**
- Switching to `permission_mode="dontAsk"` + `allowed_tools` allowlist (KTD3).
- Re-routing `ScheduleWakeup` to an in-headless equivalent (no harness wake → no equivalent).

### Deferred to Follow-Up Work

- Enumerating *all* interactive-only harness tools for headless exclusion — no n=2 yet on a
  second harness-only tool. Revisit when a different one traps a session.

---

## Sources & Research

- cpp#59 issue body (hard evidence, frequency baseline 1/139 sessions).
- Incident transcript `~/.claude/projects/…fix-1652…/d70b3d70-4fa9-44b8-afdc-2d7acaa5f45b.jsonl`
  (lines 46-47: the `is_error=false` harness success result that proves `can_use_tool` was
  bypassed).
- claude-agent-sdk 0.2.110 — `ClaudeAgentOptions.disallowed_tools` → `--disallowedTools`
  (`subprocess_cli.py:265-266`); permission-evaluation flow docs.
- Existing prevention-hint prior art: `src/claude_pilot/tier1.py` `DENIED_BASH_PATTERNS_HINT`
  (mika#1409); `src/claude_pilot/agent.py:295` `_system_prompt_with_hint()`.
