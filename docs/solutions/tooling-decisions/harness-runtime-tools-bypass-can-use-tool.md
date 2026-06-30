---
title: "Harness/CLI runtime tools (ScheduleWakeup) bypass claude-pilot's can_use_tool — tier1/policy denies are inert"
date: 2026-06-30
problem_type: tooling_decision
track: knowledge
module: permissions
component: permission-classifier
tags:
  - claude-pilot
  - can_use_tool
  - tier1
  - policy
  - schedulewakeup
  - sdk
  - headless
applies_when: "A ticket or instinct says 'deny tool X in claude-pilot' (tier1.py / permissions.yaml), or a headless pilot session silently ends after calling a Claude Code interactive primitive (ScheduleWakeup, /loop pacing, etc.)."
---

# Harness/CLI runtime tools bypass claude-pilot's `can_use_tool`

## Context

claude-pilot intercepts tool permissions via the Agent SDK's `can_use_tool`
callback, then runs a tiered classifier — `tier1.py` (auto-approve allow-list),
`tier1.5` (deterministic auto-answer), `policy.py` (`permissions.yaml`,
default-deny). The natural assumption is that *every* tool the model calls flows
through this chain, so "deny tool X" means "add a rule to tier1/policy."

**That assumption is false for a whole class of tools.** Some tools are
**Claude Code harness/CLI runtime primitives** — handled internally by the CLI
runtime before/without ever consulting `can_use_tool`. For those tools, no
`tier1.py` regex and no `permissions.yaml` rule can intercept the call. A deny
added there is **structurally inert dead code** that *looks* like protection.

Founding case: cpp#59. A headless dev-groom pilot called `ScheduleWakeup` (the
`/loop` dynamic-pacing primitive) to "wait" for a dispatched subagent, then the
session silently ended (`PIPELINE_INCOMPLETE`, $2.36 wasted, mika#1652). The
originating ticket proposed denying `ScheduleWakeup` in `tier1.py`'s
`TIER3_PATTERNS` — which only ever scan **Bash command strings**
(`is_tier3_dangerous` runs solely under `tool_name == "Bash"`), so it could
never fire for a non-Bash tool anyway. The deeper finding is below.

## Guidance

**Before adding any "deny tool X" rule to claude-pilot's classifier, confirm X
actually routes through `can_use_tool`.** The cheapest authoritative check is the
incident transcript: look at the `tool_result` for the call.

- If claude-pilot **denied** it, the result is an error (`is_error=true`) carrying
  the policy reason — the call reached `can_use_tool`, and a tier1/policy rule
  *can* control it.
- If the result is `is_error=false` with the **harness's own success message**
  (e.g. `"Next wakeup scheduled … the harness re-invokes you when the wakeup
  fires"`), the SDK runtime handled it internally. `can_use_tool` never saw it.
  No classifier rule will ever catch it.

Corroborating signal: claude-pilot has **no allow path** for an unknown tool
(`tier1` → `False`, `tier1.5` → `None`, policy default → `deny` +
`interrupt=True`). So if such a tool *succeeds*, it provably bypassed the chain —
had it reached `can_use_tool`, the default-deny would have **halted** the session
with a deny message, not returned success.

**Where the viable controls live (SDK options layer, `agent.py`):**

1. **System-prompt hint — load-bearing.** Append guidance to the SDK system
   prompt (claude-pilot does this via `DENIED_BASH_PATTERNS_HINT` +
   `_system_prompt_with_hint()`, the preset-append shape from mika#1409). The
   model reads it; this is the only channel that actually reaches the model for
   this class. cpp#59 added a "Tools that are no-ops in headless mode" section
   naming `ScheduleWakeup` and noting that a dispatched subagent result is
   already available synchronously, so no "wait" is needed.
2. **`disallowed_tools=[...]` — best-effort defense-in-depth.** Maps to the CLI
   `--disallowedTools` flag. A bare-name deny *should* remove a surfaced tool
   from the request, but the SDK docs do **not** definitively confirm
   `--disallowedTools` filters *runtime primitives* — so treat it as
   belt-and-suspenders, not the load-bearing guard.

**Honest-closure boundary:** prompt-only enforcement reduces the **rate** of a
stochastic trap (ScheduleWakeup was n=1 of 139 sessions) but does not close the
class — the same honesty note `DENIED_BASH_PATTERNS_HINT` already carries. The
class closes only if `disallowed_tools` is empirically confirmed to suppress the
tool.

## Why This Matters

Adding an inert deny to tier1/policy is worse than doing nothing: it reads as
"handled" in the diff and the ticket closes, while the trap remains live. The
diagnostic — "does this tool route through `can_use_tool` at all?" — is a 30-
second transcript check that redirects the fix from a dead layer to the layer
that can actually act. It also generalizes: any future Claude Code
interactive-only primitive (not just `ScheduleWakeup`) will exhibit the same
bypass, so the same agent.py-layer controls apply.

## When to Apply

- A ticket says "deny / block / disallow tool X in claude-pilot" and X is **not**
  Bash, Read, Glob, Grep, Write, Edit, or Skill (the tools the classifier
  actually sees).
- A headless pilot session ends unexpectedly right after calling a Claude Code
  interactive feature (`ScheduleWakeup`, `/loop`-related pacing, or any
  harness-driven wait/resume primitive).
- You are about to write a `TIER3_PATTERNS` entry or a `permissions.yaml` rule
  for a tool and have not first confirmed the tool reaches `can_use_tool`.

## Examples

**Inert (do NOT do this) — tier1/policy deny for a runtime primitive:**

```python
# tier1.py TIER3_PATTERNS — NEVER fires for ScheduleWakeup:
# these regexes only scan Bash command strings (is_tier3_dangerous is gated on
# tool_name == "Bash"). ScheduleWakeup is a separate tool → never matched.
re.compile(r"\bScheduleWakeup\b"),   # dead code
```

**Viable (cpp#59) — controls at the SDK options layer in `agent.py`:**

```python
options = ClaudeAgentOptions(
    ...
    system_prompt=_system_prompt_with_hint(),   # load-bearing: hint names ScheduleWakeup
    disallowed_tools=["ScheduleWakeup"],         # best-effort: maps to --disallowedTools
    ...
)
```

Related: `docs/solutions/security-issues/command-string-policy-allow-rules-are-compound-unsafe.md`
(the other load-bearing learning on the same permission-classifier surface — but
that one is about commands the classifier *does* see; this one is about a tool it
never sees).
