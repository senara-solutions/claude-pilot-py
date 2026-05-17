---
type: feat
issue: mika#1191
parent: mika#1188 (milestone: Deprecate mika-relay)
title: Companion plan reference for tier1.py expansion (mika#1191, Phase A)
date: 2026-05-17
---

# Companion plan: claude-pilot-py tier1.py expansion (mika#1191, Phase A)

This claude-pilot-py PR implements [mika#1191](https://github.com/senara-solutions/mika/issues/1191) (Phase A of milestone #28, "Deprecate mika-relay").

## Canonical plan location

The architect-groomed plan (two-pass `GROOMED` verdict by `mika-arch`, session `5e52c28c`) lives on the mika repo at:

```
mika/docs/plans/2026-05-17-004-feat-1191-tier1-expansion-plan.md
```

committed on the matching branch `feat/1191/port-permission-policy-tier1-rules-into-tier1-py`. The mika companion PR carries the plan doc; this claude-pilot-py PR carries the source implementation that the plan specifies.

## Why the plan lives on mika

The milestone (`Deprecate mika-relay`, mika#1188) is owned by mika because the relay agent is a mika-side concept. Phase A's implementation surface, however, is entirely in claude-pilot-py — the deterministic classifier lives in this repo. Per `mika-platform/CLAUDE.md` cross-repo conventions, the issue/plan home is on the milestone owner's repo while the implementation lands wherever the code is.

## What this PR ships (Phase A)

- `src/claude_pilot/tier1.py`: `is_safe_mika_dispatch` (intra-platform agents allow-list `{mika-arch, mika-dev, mika-qa}`); `SAFE_GH_SUBCOMMANDS["issue"]` extended with `"edit"` and `"comment"`.
- `src/claude_pilot/permissions.py`: `try_tier_1_5_auto_answer` short-circuit for `compact-safe` AskUserQuestion events — no relay round-trip.
- `tests/test_tier1.py`: 25 new tests (intra-platform dispatch, gh issue authoring, TIER 3 parity guard, newline-smuggling regression).
- `tests/test_permissions.py`: 11 new tests for the TIER 1.5 fast path (word-boundary, malformed shapes, partial matches).
- `tests/replay/replay_relay_decisions.py`: operator-runnable replay harness reading `~/.mika/data/mika.db`, with NF3 anti-vacuous-truth hard-floor.
- `_COMPOUND_SPLIT_RE` updated to split on `\n` (closes ce:review ADV-1 newline-smuggling regression).

## Companion PR

The mika-side PR carries the plan doc and the milestone bookkeeping. See PR body for cross-repo reference.

## Out of scope

Phase B (`mika#1192` — deterministic policy file replacing the relay invocation path) and Phase C (`mika#1193` — relay retirement) are sequential follow-ups gated on Phase A merging + soaking ≥3 days.
