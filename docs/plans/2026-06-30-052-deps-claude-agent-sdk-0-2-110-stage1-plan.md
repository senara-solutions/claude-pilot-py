# Plan: bump claude-agent-sdk 0.1.59 → 0.2.110 (Stage 1 — mechanical)

Issue: cpp#52 · Branch: `deps/52/claude-agent-sdk-0-2-110-stage1`

## WHY

`claude-pilot` is the Python wrapper that runs every autonomous dispatch through the
`claude-agent-sdk`. It was pinned at `0.1.59` while latest is `0.2.110` — a major `0.1→0.2`
boundary plus 60+ skipped minors. The unreviewed-surface backlog keeps growing and the bundled
Claude CLI (which actually runs in headless pilot sessions) ages with it. Vincent flagged the
v0.2.110 release as priority. A research agent produced a friction analysis (cross-referencing
51 release bodies v0.1.60→v0.2.110) whose headline is: **the upgrade retires zero existing cpp
workarounds outright — the SDK is orthogonal to cpp's shell-injection/permission gate** — and a
short Stage-1 watch list of four items that need verification on the bump.

**Stage 1 is mechanical-only: bump + verify + smoke. No opportunistic API adoption.** Stages 2–3
(enrich `PilotEvent` with new `ToolPermissionContext` fields, surface `api_error_status`, typed
`TaskUpdatedMessage`, `SessionStore`, `skills` option) are deferred follow-up tickets.

### Backlog cross-reference (does anything disappear or get fixable-better?)

Evidence-backed: **no open ticket is retired or fixed-better-for-free.**
- **mika core is out of reach** — it is Rust and imports `claude_agent_sdk` in zero source files.
- **cpp backlog is orthogonal** — every open cpp issue (#38/#40/#41/#42/#44) is tier1/permissions
  shell-safety; the SDK has no counterpart (it sits upstream of `can_use_tool`). This is the moat.
- **New SDK surface maps to no existing ticket** → net-new, correctly scoped Stage 2/3.
- **One genuine net-new gap** worth a follow-up: cpp has zero Claude-API-error classification today
  (`permissions.py` retries only relay-transport errors); v0.1.76 `api_error_status` on
  `ResultMessage` closes that. File as Stage 2.

## WHAT

### Code changes
1. `pyproject.toml` — `claude-agent-sdk==0.1.59` → `==0.2.110` (only direct dep change).
2. `uv.lock` — regenerated via `uv sync --all-extras`. Delta: SDK 0.1.59→0.2.110, `sniffio` newly
   declared as a direct SDK dep, `mcp` unchanged at 1.27.0.
3. `docs/solutions/tooling-decisions/sdk-system-prompt-must-be-preset-append-not-plain-string.md` —
   version-cite refreshed to 0.2.110 after confirming the preset→CLI mapping holds.

### Four watch-list verifications (all PASS)
| # | Item | Result |
|---|------|--------|
| 1 | v0.2.82 `TodoWrite`→`Task*` | No consumers in `src/`/`tests/` — nothing to port |
| 2 | v0.2.82 background MCP (`status:"pending"`) | No test asserts MCP status; full suite green |
| 3 | `SystemPromptPreset` preset+append (mika#1409, load-bearing) | Mapping unchanged at `subprocess_cli.py:227-238`; preset+append → `--append-system-prompt`. New additive `type:"file"` branch, unused by cpp |
| 4 | `mcp<2.0.0` pin (v0.2.96) | `mcp` resolves to 1.27.0 — satisfies ≥1.23 (CVE-2025-66416) and <2.0.0 |

### Verification
- `uv sync --all-extras`: clean.
- `uv run pytest`: **474 collected, 474 passed**.
- `uv run ruff check`: clean. `uv run mypy src`: clean (14 files).
- Smoke (isolated fake-allow relay, throwaway cwd): session boots on 0.2.110; `can_use_tool` fires
  for Write on both branches — AUTO-approve (in-cwd) → success `ResultJson`, exit 0; policy-deny
  (out-of-cwd) → `interrupt` → synthetic terminal `error_during_execution` `ResultJson`, exit 1.
  Both `ResultJson` shapes (success + error) emit correctly. Bash commands auto-resolve via host
  settings before the callback (documented SDK "fires only on ask" behavior).

### Observation (NOT fixed here — Stage 1 is mechanical)
`agent.py:_extract_session_id`/`_extract_model` read top-level `message.session_id`/`.model`, but
`SystemMessage` exposes only `{subtype, data}` (session_id lives in `.data`). The live `[init]` log
shows empty session_id/model. **Pre-existing** (test fixtures already put session_id in `.data`),
cosmetic — reconnect detection is `seen_init`-keyed and `ResultJson.session_id` is captured
correctly downstream. File as a Stage 2 follow-up.

## Out of scope
Mika core (Rust). Bundling the Claude CLI separately. Any opportunistic adoption of new SDK API
(all Stage 2/3). No `pydantic`/`anyio`/`httpx` bumps beyond what `uv sync` resolves transitively.
