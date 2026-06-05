---
title: "claude-agent-sdk system_prompt must be preset+append, never a plain string"
date: 2026-06-05
module: claude_pilot.agent
component: sdk-options
problem_type: tooling_decision
category: tooling-decisions
tags: [claude-agent-sdk, system-prompt, claude-code-preset, headless, permission-policy, mika-1409, drift-guard]
applies_when: "setting or reviewing ClaudeAgentOptions.system_prompt, or adding a model-facing hint to a headless claude-pilot session"
---

# claude-agent-sdk system_prompt must be preset+append, never a plain string

## Context

mika#1409: headless claude-pilot sessions die with `error_during_execution` when
the model reaches for a policy-denied Bash command (e.g. `find … -exec`). The
permission policy correctly denies via `PermissionResultDeny(interrupt=True)`
(cpp#20 joint 2), but `interrupt=True` aborts the SDK agent loop — the session
does not recover. The prevention-only fix (Approach #2; recoverable-denial half
deferred to mika#1410) injects a `DENIED_BASH_PATTERNS_HINT` into the session
system prompt so the model avoids the denied patterns and uses the auto-approved
native tools (Grep/Glob/Read/Edit/Write) instead.

Wiring that hint surfaced two non-obvious lessons.

## Guidance

### 1. Use `SystemPromptPreset` (preset+append), not a plain string

`ClaudeAgentOptions.system_prompt` accepts `str | SystemPromptPreset |
SystemPromptFile | None`. The string form **replaces** the Claude Code preset
system prompt. A headless `/mika` + `/ce:*` pipeline depends on that preset
(tool knowledge, slash-command behavior), so a plain string silently breaks the
pipeline. To *add* to the preset, use the preset+append dict:

```python
# agent.py — preserves the claude_code preset, appends the hint
options = ClaudeAgentOptions(
    ...,
    system_prompt={
        "type": "preset",
        "preset": "claude_code",
        "append": DENIED_BASH_PATTERNS_HINT,
    },
)
```

Verified mapping (SDK 0.1.59 `subprocess_cli.py`): `None` → `--system-prompt ""`,
`str` → `--system-prompt <str>` (**replace**), preset+append → `--append-system-prompt
<hint>` (**preserve**). Annotate the helper's return type as `SystemPromptPreset`
so mypy rejects a future regression to a bare string.

### 2. "Co-location prevents drift" is false unless a test backs it

The hint constant lives in `tier1.py` next to the deny-list patterns it
documents, with a comment claiming co-location keeps the documentation from
drifting from enforcement. The code review found the hint had **already
drifted**: a bullet claimed "Bash file reads outside the worktree are denied,"
but `cat` is on the shell safe-list and gets no path check — `cat` outside the
worktree is auto-*approved*. The real n=2 `md5sum` denial was because `md5sum`
is not safe-listed (denied on *any* path), not because of a worktree boundary.

Proximity is not a guard. The fix makes the "cannot drift" promise falsifiable
with a test that cross-checks each hint claim against the actual classifier:

```python
def test_1409_hint_claims_match_enforcement() -> None:
    for cmd in ['find /x -name "*.rs" -exec grep -l Y {} +',
                "md5sum /a/b", "sha256sum /tmp/x", "sed -i 's/a/b/' f",
                "echo x > /tmp/y"]:
        assert is_safe_bash_command(cmd) is False   # hint says denied → must be
    for cmd in ["cat /etc/hostname", 'grep -rn "X" src']:
        assert is_safe_bash_command(cmd) is True     # hint must not mislead
```

## Why This Matters

- A plain-string `system_prompt` is a silent, total regression of the headless
  pipeline — no error, just a model that no longer knows the Claude Code tools.
  The type annotation + the preset+append shape are the only thing standing
  between a one-character edit and a broken loop.
- Documentation-next-to-code reads as self-keeping but isn't. Any prose that
  asserts a property of nearby code (a deny-list, a schema, an invariant) drifts
  the moment the code changes unless a test asserts the two agree.

## When to Apply

- Any time you set `ClaudeAgentOptions.system_prompt` — reach for the preset+append
  dict, never a bare string, unless you deliberately intend to discard the
  Claude Code preset.
- Any time you write a comment or doc string claiming it mirrors a list/regex/
  schema elsewhere — add a test that fails when they diverge.

## Honest scope (mika#1409)

Prevention reduces the *rate* of denied reaches; it does not close the
session-fatality *class*. A behavioral A/B (`claude -p` with/without the hint on
the exact #1381 search task) could not isolate the hint's causal effect because
the Opus CLI baseline already prefers Grep — the original `find -exec` reach was
specific to the pilot's dispatch model. What ships is deterministically proven
(the exact denial is real; the hint is wired into every session). The class
closes only when cpp#20 joint-2's contract distinguishes adaptation from
fabrication — **mika#1410**.

## Related

- mika#1409 — this fix (prevention-only)
- mika#1410 — recoverable-denial follow-up (cpp#20 joint-2 contract revision)
- claude-pilot-py#20 — the `interrupt=True` honest-halt contract
- `docs/solutions/security-issues/` — command-string policy allow-rule safety (the enforcement side)
