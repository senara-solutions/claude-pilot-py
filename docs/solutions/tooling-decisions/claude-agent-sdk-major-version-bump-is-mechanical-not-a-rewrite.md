---
title: "A claude-agent-sdk major-version jump is a mechanical bump, not a rewrite — verify against a watch list"
date: 2026-06-30
module: claude_pilot
component: dependencies
problem_type: tooling_decision
category: tooling-decisions
tags: [claude-agent-sdk, dependency-upgrade, staged-upgrade, watch-list, mika-1409, cpp-52, semver]
applies_when: "bumping claude-agent-sdk across many minors or a 0.x major boundary in claude-pilot"
---

# A claude-agent-sdk major-version jump is mechanical — verify, don't rewrite

## Context

cpp#52 jumped `claude-agent-sdk` 0.1.59 → 0.2.110: a `0.1→0.2` boundary plus 60+ skipped minors,
including a v0.2.82 cluster of *breaking* changes (`TodoWrite`→`Task*`, background MCP connect, mcp
CVE pin). The instinct on "major version, 60 releases behind, breaking changes" is to brace for a
refactor. The reality: **one line of `pyproject.toml`, a regenerated lock, a doc cite, zero source
edits, 474/474 tests green.** The cost of catching up was bounded and almost entirely *verification*,
not adaptation.

## Guidance

### 1. The SDK surface cpp actually touches is tiny — map it before fearing the changelog

claude-pilot imports exactly **6 symbols across 2 files**: `agent.py`
(`ClaudeAgentOptions`, `ClaudeSDKClient`, `AssistantMessage`, `ResultMessage`, `SystemMessage`,
`SystemPromptPreset`) and `permissions.py` (`PermissionResultAllow`, `PermissionResultDeny`,
`ToolPermissionContext`). 90% of the changelog (new options, tool types, transport internals) is
surface cpp never imports. Grep the real import set first; size the risk against *that*, not the
release notes.

### 2. Two structural facts bound what any SDK bump can affect

- **mika core (Rust) does not depend on the python SDK** (`grep -rl claude_agent_sdk mika/` → zero
  source). An SDK bump can never touch a mika-core ticket. The blast radius is cpp only.
- **cpp's permission gate (tier1/policy) is orthogonal to the SDK.** It sits *upstream* of
  `can_use_tool`. No SDK release competes with or retires the shell-injection/compound-safety work
  (cpp#33/#34/#35/#37/#42/#43/#45/#47). That gate is the moat; the SDK leaves it untouched.

So a backlog scan "does this upgrade moot/improve any open ticket?" answers **no** structurally — the
only reachable backlog (cpp) is shell-safety, which the SDK doesn't address. New SDK surface is
always *net-new* value (Stage 2/3 follow-ups), never a free fix to an existing ticket.

### 3. Run a watch list, not a vibe check

For each known-breaking change, write the verification *before* bumping:
- **`TodoWrite`→`Task*`**: `grep -rn "TodoWrite\|TaskUpdatedMessage\|DeferredToolUse" src/ tests/` →
  empty means nothing to port.
- **Load-bearing `SystemPromptPreset`** (see the sibling doc): after `uv sync`, read the *installed*
  SDK's `_internal/transport/subprocess_cli.py` and confirm the preset+append → `--append-system-prompt`
  mapping still holds. It did (lines 227-238); a new additive `type:"file"` branch appeared, unused.
- **mcp pin**: confirm `uv.lock` resolves an `mcp` satisfying the SDK's range (here 1.27.0, in
  [1.23, 2.0.0)). It's transitive — no direct cpp constraint to fight.

### 4. Smoke against an isolated relay, and know when the callback won't fire

A throwaway `--relay-config` pointing at a fake `{"action":"allow"}` script + a throwaway `--cwd`
exercises boot → `can_use_tool` → `ResultJson` without touching the live mika-dev relay. Two gotchas:
- `prompt` is `argparse.REMAINDER` — **all flags must precede the prompt** or they're swallowed.
- `can_use_tool` fires **only on tools the SDK resolves to "ask"**. Host `~/.claude` settings
  (loaded via `setting_sources`) auto-allow Bash *before* the callback, so a Bash smoke won't reach
  the relay. Use a tool set to "ask" (Write outside cwd → deny/interrupt; Write inside cwd → tier1
  AUTO) to drive the callback. The external-relay round-trip itself is covered by unit tests.

## Latent finding (pre-existing, surfaced by the smoke)

`agent.py:_extract_session_id`/`_extract_model` read top-level `message.session_id`/`.model`, but
`SystemMessage` is `{subtype, data}` — the id/model live in `.data`. The `[init]` log prints empty
session_id/model. It's **cosmetic and pre-existing** (the unit fixtures already nest session_id in
`.data`): reconnect detection is `seen_init`-keyed and `ResultJson.session_id` is captured correctly
from later messages. Worth a Stage-2 fix (read `.data`), not a Stage-1 blocker.

## Why This Matters

- Treating a version jump as "presumed rewrite" invites scope creep — opportunistic API adoption
  rides in on a mechanical bump and turns a 1-line PR into a risky one. Keep the bump mechanical;
  file the adoption as its own ticket.
- The expensive part of a 60-version catch-up is verification, and verification is cheap if you've
  mapped the import surface and written the watch list up front. **Track latest within ~a week** so
  you never face the v0.2.82-style cliff cold.

## Related
- `sdk-system-prompt-must-be-preset-append-not-plain-string.md` — the load-bearing preset mapping
- cpp#52 — this upgrade · mika#1409 — the SystemPromptPreset founding incident
