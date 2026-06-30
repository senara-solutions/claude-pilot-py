---
artifact_contract: ce-unified-plan/v1
artifact_readiness: implementation-ready
execution: code
product_contract_source: ce-plan-bootstrap
title: "fix(agent): SDK 0.2.x composite — session/model extraction + api_error_status + ToolPermissionContext enrichment"
date: 2026-06-30
type: fix
issues: [cpp#55, cpp#54, cpp#56]
branch: fix/agent-composite-55-54-56-sdk-stage2
---

# fix(agent): SDK 0.2.x composite — cpp#55 + cpp#54 + cpp#56

## Summary

Three evidence-gated, backward-compatible changes to `claude-pilot-py`, all surfaced by the `claude-agent-sdk` 0.1.59 → 0.2.110 bump (cpp#52 / PR #53). They are bundled into one PR because all three touch the `agent.py` / `types.py` / `permissions.py` cluster on the same SDK lineage:

- **cpp#55 (bug, regression):** `SystemMessage` nests `session_id`/`model` inside `.data` in SDK 0.2.x; the extractors read top-level attrs and log empty `[init]` ids.
- **cpp#54 (enhancement):** SDK now exposes `ResultMessage.api_error_status` (HTTP 429/500/529); surface it into `ResultJson` for deterministic overload classification downstream.
- **cpp#56 (enhancement):** SDK enriched `ToolPermissionContext` with `title`/`display_name`/`description` (alongside existing `decision_reason`/`blocked_path`); capture them into `PilotEvent` for richer relay telemetry.

All additions are `Optional`, default `None`, and serialize as absent via `exclude_none` — no downstream parser breaks on a missing field.

## Problem Frame

cpp#52 (PR #53) was a **mechanical** SDK bump — version numbers only, no API adoption. It both (a) introduced a latent regression in two extractor helpers that had silently read the wrong location even before the bump, and (b) left net-new SDK capabilities unadopted. The friction analysis at the time named the Stage-2 work explicitly. This plan closes the regression and adopts the two highest-value additive capabilities, with the typed-`TaskUpdatedMessage` part of cpp#56 deliberately deferred (no consumer exists).

**Why now:** cpp#55 is a real (cosmetic-severity) regression confirmed by live smoke logs (`[init] Session , model unknown`). cpp#54 closes a loop-reliability observability gap — the pilot today cannot deterministically distinguish a transient API overload (429/500/529) from a genuine failure. cpp#56 is cheap additive enrichment riding the same file cluster.

## Requirements

- **R1 (cpp#55):** `_extract_session_id` / `_extract_model` MUST return the real id/model from `SystemMessage.data` under SDK 0.2.x, while preserving the legacy top-level-attr path for back-compat with any mock or future SDK that reverts the nesting.
- **R2 (cpp#54):** `ResultJson` MUST carry an `api_error_status` field populated from `ResultMessage.api_error_status` when present, absent when null/missing.
- **R3 (cpp#56):** `PilotEvent` MUST carry `title`, `display_name`, `description` (new) plus the already-declared `decision_reason`, `blocked_path`, all populated from `ToolPermissionContext` when the SDK supplies them, `None` otherwise.
- **R4 (cross-cutting):** Every new field is `Optional`, defaults `None`, uses the SDK's verbatim field name, and serializes absent when `None`. No scope widening beyond these three changes.

## Key Technical Decisions

- **KTD1 — guarded `.data` access for cpp#55.** Read `message.data.get(...)` first, then fall back to the existing top-level `getattr(...)`. `SystemMessage` in SDK 0.2.110 has fields exactly `(subtype, data)` (verified via `dataclasses.fields`), but a guarded pattern (`data = getattr(message, "data", None)`) survives a future SDK that reverts the shape and keeps the existing test mocks valid. Both paths funnel through the existing `isinstance(..., str)` type-narrowing so a non-string `data` value can't leak through.
- **KTD2 — `getattr` for SDK reads on cpp#54/#56.** Use `getattr(message, "api_error_status", None)` and `getattr(ctx, "<field>", None)` rather than direct attribute access, so cpp keeps running against an SDK minor that hasn't yet added (or has removed) the field. This mirrors the existing defensive `getattr` style already used in `agent.py` (`getattr(message, "session_id", None)`, `getattr(message, "errors", None)`).
- **KTD3 — verbatim SDK field names.** `api_error_status`, `title`, `display_name`, `description` match the SDK exactly. No renaming — diverging adds drift cost on every future bump (spawn-brief hard rule).
- **KTD4 — defer typed `TaskUpdatedMessage`.** `guardrails.py` has zero `Task*` consumers today; the cpp#56 ticket marks this "only adopt if a concrete need arises." Out of scope here.
- **KTD5 — enrich PilotEvent at its single construction site.** `permissions.py` builds `PilotEvent` in exactly one place (the relay block, reachable only under `MIKA_PILOT_POLICY_DISABLED=1`). The enrichment is purely additive there; no behavioral change to the live policy path.

---

## Implementation Units

### U1. cpp#55 — fix `_extract_session_id` / `_extract_model` to read `SystemMessage.data`

**Goal:** Return the real session id and model under SDK 0.2.x nesting, with top-level fallback.

**Requirements:** R1, R4.

**Dependencies:** none.

**Files:**
- `src/claude_pilot/agent.py` — rewrite `_extract_session_id` (currently lines 366-369) and `_extract_model` (370-373).
- `tests/test_agent.py` — add focused unit tests for both helpers.

**Approach:** In each helper, first attempt `data = getattr(message, "data", None)`; if it is a dict, read the relevant key (`session_id` / `model`). If that yields a string, return it. Otherwise fall back to the existing top-level `getattr(message, "<attr>", None)` path. Keep the final `isinstance(..., str)` narrowing so non-string values return `None`. The existing `_init()` fixture (`SystemMessage(subtype="init", data={"session_id": "sess_test", "model": "claude-test"})`) means several existing agent tests will now log non-empty ids — verify they still pass.

**Patterns to follow:** the existing defensive `getattr(... , None)` + `isinstance(..., str)` style already in these two helpers.

**Test scenarios:**
- `_extract_session_id(SystemMessage(subtype="init", data={"session_id": "abc-123"}))` returns `"abc-123"` (nested-data path).
- `_extract_model(SystemMessage(subtype="init", data={"model": "claude-x"}))` returns `"claude-x"`.
- Back-compat fallback: a stub object exposing a top-level `.session_id`/`.model` str attr and no usable `.data` returns the top-level value. (Construct a lightweight stand-in so the test pins the fallback branch even though the real 0.2.110 `SystemMessage` won't populate top-level.)
- Missing both: `SystemMessage(subtype="init", data={})` returns `None` for each helper (no crash).
- Non-string nested value: `data={"session_id": 42}` returns `None` (type narrowing holds).

**Verification:** the two helpers return the nested value; full `tests/test_agent.py` passes including the pre-existing init/reconnect tests that consume `_init()`.

### U2. cpp#54 — surface `ResultMessage.api_error_status` into `ResultJson`

**Goal:** Give downstream consumers (mika-dev dispatch-lib) a deterministic 429/500/529 signal.

**Requirements:** R2, R4.

**Dependencies:** none (independent of U1).

**Files:**
- `src/claude_pilot/types.py` — add `api_error_status: int | None = None` to `ResultJson` (after `errors` / `termination_reason`); extend the model docstring noting the field's meaning.
- `src/claude_pilot/agent.py` — in the `ResultMessage` branch (the `result = ResultJson(...)` construction around lines 192-202), pass `api_error_status=getattr(message, "api_error_status", None)`.
- `tests/test_agent.py` — add coverage; `tests/test_types.py` may host the serialization-absence assertion if that's the better home (implementer's call — follow existing test layout).

**Approach:** `ResultMessage.api_error_status` is typed `int | None` in SDK 0.2.110 (verified). Thread it into the single `ResultJson(...)` build on the ResultMessage path. The synthetic/guardrail `ResultJson` emissions (stream-ended, guardrail-trip) leave it at its `None` default — those paths never have a ResultMessage to read from. `to_line()` already uses `model_dump_json(exclude_none=True)`, so a `None` value is omitted from the JSON line automatically (back-compat).

**Patterns to follow:** the sibling `errors=` / `cost_usd=` extractions in the same `ResultJson(...)` constructor; the existing `cost_usd: float | None = None` Optional-field pattern in `types.py`.

**Test scenarios:**
- Present path: feed a fake `ResultMessage` with `api_error_status=429` through `run_agent` (via the existing `_install_fake_client` harness); the emitted stdout `ResultJson` line parses with `api_error_status == 429`.
- Absent path: the existing `_result()` fixture (no `api_error_status`) → emitted JSON line has NO `api_error_status` key (exclude_none).
- Model-level: `ResultJson(... , api_error_status=None).to_line()` does not contain `"api_error_status"`; `ResultJson(..., api_error_status=529).to_line()` does.

**Verification:** a 429-bearing ResultMessage round-trips to `ResultJson.api_error_status == 429`; null/absent omits the field from the line.

### U3. cpp#56 — enrich `PilotEvent` with `ToolPermissionContext` fields

**Goal:** Capture the SDK's richer permission-context fields into the relay event payload.

**Requirements:** R3, R4.

**Dependencies:** none (independent of U1/U2).

**Files:**
- `src/claude_pilot/types.py` — add `title: str | None = None`, `display_name: str | None = None`, `description: str | None = None` to `PilotEvent` (it already declares `decision_reason` and `blocked_path`).
- `src/claude_pilot/permissions.py` — at the single `PilotEvent(...)` construction (lines 395-401), populate `decision_reason`, `blocked_path`, `title`, `display_name`, `description` via `getattr(ctx, "<field>", None)`.
- `tests/test_permissions.py` — add coverage; extend `_mock_ctx()` usage to supply the enriched fields.

**Approach:** `ToolPermissionContext` in SDK 0.2.110 carries `tool_use_id, agent_id, blocked_path, decision_reason, title, display_name, description` (all `str | None`, verified). Add the three new fields to `PilotEvent` and populate all five enriched fields at construction with `getattr(ctx, ..., None)` for resilience against an SDK minor lacking a field. `model_config = ConfigDict(extra="forbid")` on `PilotEvent` means the three new fields MUST be declared before they can be passed — declaration and population land together in this unit. Note: the relay construction site is only reached under `MIKA_PILOT_POLICY_DISABLED=1`; the enrichment is additive and changes no live policy-path behavior.

**Patterns to follow:** the existing `agent_id=ctx.agent_id` / `tool_use_id=ctx.tool_use_id or ""` assignments at the same construction; the existing `decision_reason`/`blocked_path` Optional declarations in `PilotEvent`.

**Test scenarios:**
- Present path: build a `ToolPermissionContext` with `decision_reason`, `blocked_path`, `title`, `display_name`, `description` set; drive the relay path (handler with `relay=True`, `MIKA_PILOT_POLICY_DISABLED=1`, and a mocked `invoke_command` that captures the `PilotEvent`); assert all five fields are carried on the event.
- Absent path: a `ToolPermissionContext` without the new fields (e.g. the current `_mock_ctx()` shape) yields `PilotEvent` with those fields `None` and no crash — confirms the `getattr` defaults and `extra="forbid"` declaration coexist.
- Model-level (lighter alternative if driving the relay path is heavy): construct `PilotEvent(...)` directly with and without the new fields and assert the schema accepts them and `exclude_none` omits the `None` ones — pick the level that gives clean coverage without over-mocking the relay machinery.

**Verification:** an enriched `ToolPermissionContext` produces a `PilotEvent` carrying the five fields; an unenriched one produces `None`s without error.

---

## Scope Boundaries

**In scope:** the three field/extractor changes above and their tests.

### Deferred to Follow-Up Work
- Typed `TaskUpdatedMessage` adoption (cpp#56 part 2) — no `Task*` consumer exists in `guardrails.py` today.
- Retry/backoff policy keyed on the new `api_error_status` signal — cpp#54 explicitly scopes this to a separate behavioral ticket once the signal exists.
- `SessionStore` adapter integration and `skills` option migration — cpp#52 Stage 3, separately tracked.
- Filing an upstream SDK issue about the `SystemMessage` shape change — optional, not required (spawn-brief out-of-scope note).

**Out of scope (do not touch):** `tier1.py` / policy logic (cpp#38/#42 territory). No refactors of unrelated code in the touched files.

---

## System-Wide Impact

- **mika-dev dispatch-lib** parses the stdout `ResultJson` line. The new `api_error_status` is additive and absent-when-null; existing parsing is unaffected. No dispatch-lib change is required by this PR (consuming the new signal is a separate ticket).
- **mika-dev relay** consumes `PilotEvent`. New fields are additive optional; the relay need not consume them. The relay construction path is dormant in production (policy-enabled by default), so this is telemetry-readiness, not a live behavior change.
- **No cross-repo companion PR** is required — all changes are internal to claude-pilot-py and backward-compatible at every external contract.

---

## Risks & Dependencies

- **Low risk overall** — all additive/optional, guarded reads, no live-path behavior change.
- **Pre-existing test interaction (U1):** the `_init()` fixture already nests ids in `data=`, so any existing assertion that depended on the *empty* logged id (unlikely, but check) would flip. Mitigation: run the full `test_agent.py` suite and read any failure.
- **`extra="forbid"` ordering (U3):** the new `PilotEvent` fields must be declared in `types.py` before they're passed in `permissions.py`, or Pydantic rejects them. Mitigation: both land in U3 together.

---

## Verification Contract

- `uv run ruff check` clean.
- `uv run mypy src` clean (new fields are properly typed `int | None` / `str | None`).
- `uv run pytest` — all tests pass; test count maintained or grown (baseline ~516 post-PR #57).
- Each unit's enumerated test scenarios are implemented (present-field AND absent-field paths for U2 and U3 per the spawn-brief hard rule).
- **cpp#55 regression closure (deterministic):** the new U1 unit tests assert non-empty extraction from nested `data`. The full live smoke (relay-mode `/mika` dispatch confirming `[init]` logs a non-empty session_id/model) is operator-host-time; the unit test is the in-pipeline regression confirmation, with the live smoke surfaced to the operator as a runtime check.

## Definition of Done

- All three units implemented with passing tests covering present + absent paths.
- `ResultJson` and `PilotEvent` schema changes are additive/optional and serialize absent when `None`.
- Quality gates (ruff, mypy, pytest) green.
- PR opened on `senara-solutions/claude-pilot-py` from `fix/agent-composite-55-54-56-sdk-stage2`, body closing cpp#55, cpp#54, cpp#56, citing each part.
- Operator surface: PR URL, test count, cpp#55 regression note, any new substrate tickets.
