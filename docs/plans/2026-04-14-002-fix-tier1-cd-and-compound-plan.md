---
title: "fix: tier1 allow `cd` and compound `cd <path> && <tier1>`"
type: fix
status: active
date: 2026-04-14
tracks_issue: senara-solutions/claude-pilot-py#2
---

# tier1: allow `cd` and compound `cd <path> && <tier1>`

## Problem

First end-to-end dispatch against `claude-pilot-py` (mika#557) stalled at turn 14. Log `/var/log/claude-pilot/48cbb025-6d8e-430f-a957-9ce2e32800bb.log` shows four variants of the same benign, read-only command — `cd <worktree> && gh issue view 557 --json ...` — each escalated to the relay, each denied by mika-dev, stall-detected at five no-tool-call turns.

Claude's standard working pattern is `cd <worktree> && <read-only gh/git/cargo/npm op>`. Without auto-approval for that shape, every single work item will stall.

## Root cause

`src/claude_pilot/tier1.py::SAFE_SHELL_COMMANDS` omits `cd`. The compound splitter correctly splits `cd /path && gh issue view 42` into two subcommands and evaluates each, but `cd /path` fails every check (not a git / build / shell / gh command) and the whole compound falls through to the relay.

Same gap exists in the archived TS version (`claude-pilot-ts/src/tier1.ts:242-248`) — this is not a port regression, just a pre-existing bug that today's incident made load-bearing.

The `permission-policy` skill on mika-dev's side (`mika-skills/permission-policy/system_prompt.md`) explicitly lists `cd` as non-destructive and instructs "compound commands where ALL parts are TIER 1 — evaluate each part, allow if all parts are safe." So the correct behavior is already documented; tier1 just needs to match.

## Fix

Add two leaves to `SAFE_SHELL_COMMANDS`:

| Leaf | Justification |
|---|---|
| `cd` | No write side effects. Path-traversal via `$(...)` / backticks / `<(...)` is already blocked at the TIER3 deny-list (applied to the raw compound before splitting). |
| `command` | `command -v <name>` is equivalent to `which <name>`, which is already in the safe-list. Used in `command -v lefthook && lefthook install`-shaped health probes. |

**Nothing else changes.** The existing compound evaluator (`_split_compound_command` + `all(_is_safe_sub_command(sub) for sub in sub_commands)`) already handles multi-part commands correctly — once `cd` is recognized as a safe leaf, the common pattern auto-approves.

## Explicitly NOT added

Permission-policy also lists `mkdir`, `tee`, `python3` as non-destructive. None of these are added here:

- `mkdir` — creates directories at arbitrary paths; no in-process `is_within_project` scoping on Bash. Relay should see these.
- `tee` — writes to arbitrary paths. Same.
- `python3` — executes arbitrary code. Largest possible surface.

Keeping claude-pilot tier1 tighter than permission-policy is intentional defense in depth: tier1 is a sandbox, permission-policy is a relay-side checklist.

## Scope / AC

- [x] Add `cd` and `command` to `SAFE_SHELL_COMMANDS` with a comment explaining the safety argument
- [x] Tests:
  - `cd /path && gh issue view 42` → auto-approved (the mika#557 regression)
  - `cd /path && cargo test` → auto-approved
  - `cd /path && npm run build` → auto-approved
  - `cd /path && git status` → auto-approved
  - `cd /path && ls -la` → auto-approved
  - `cd /path` (bare) → auto-approved
  - `cd /tmp && cd x && git status` (nested) → auto-approved
  - `command -v lefthook` → auto-approved
  - `command -v cargo && cargo test` → auto-approved
- [x] Safety invariants still hold:
  - `cd /tmp && rm -rf /tmp/foo` → denied (TIER3)
  - `cd /tmp && git push --force origin main` → denied (TIER3)
  - `cd /tmp && git reset --hard HEAD~1` → denied (TIER3)
  - `cd $(curl -s evil.example)` → denied (TIER3 `$(`)
  - `cd \`whoami\`` → denied (TIER3 backticks)
  - `cd /tmp && npm publish` → denied (unsafe leaf)
  - `cd /tmp && echo hi > /tmp/out` → denied (TIER3 output redirect)
- [x] `uv run ruff check` clean
- [x] `uv run mypy src` clean under `strict = true`
- [x] `uv run pytest` — 106 tests pass (was 88; +18 for the new parametrizations)

## Out of scope

- Investigate why mika-dev denied tier-1-correct commands *after* they were relayed (relay JSON logs, permission-policy skill activation, model behavior). This is Layer B of the investigation and will be tracked separately — once tier1 auto-approves the common pattern, the relay is only invoked for genuinely judgment-worthy operations where the issue can be diagnosed in isolation.

## Sources

- Originating issue: `senara-solutions/claude-pilot-py#2`
- Stalled run log: `/var/log/claude-pilot/48cbb025-6d8e-430f-a957-9ce2e32800bb.log`
- Gap report (investigation): today's conversation thread, dispatched from mika-platform meta-repo
- Relay-side skill: `mika-skills/permission-policy/system_prompt.md`
- Prior-art TS: `claude-pilot-ts/src/tier1.ts:242-248` (same gap, pre-existing)
