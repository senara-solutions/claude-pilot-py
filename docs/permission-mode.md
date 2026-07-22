# Permission-policy mode selection

`claude-pilot` ships two Bash permission-policy evaluators. The
`MIKA_PERMISSION_POLICY_MODE` environment variable selects which one runs.

| Value | Evaluator | Status |
|---|---|---|
| `classic` *(default)* | Syntactic pattern-matching over the shell text — `tier1.py` allowlist + `policies/permissions.yaml`. | Stable, deployed. |
| `per_spawn` | Bashlex decomposition + `cwd_stack` state-tracking + per-binary safety functions — `per_spawn.py`. | Phase 1 opt-in (mika#1708). |

The switch is **Bash-scoped**. Non-Bash tools (Read, Write, Edit, Glob, Grep,
Skill, AskUserQuestion, …) always follow the classic tier1 → policy → relay
path. `per_spawn` only replaces the shell-parsing half of the Bash decision.

## When to flip

- **`classic`** — safe default. Every deployment starts here.
- **`per_spawn`** — flip when the classic evaluator is denying legitimate
  compositional shell (pipes-to-conditional-`awk`, `cd`-then-`grep`, etc.)
  and blocking your pilot loop. mika#1686 documents the n=8+ shape class
  the syntactic approach can't discriminate semantically.

Flip per session (canary):

```bash
MIKA_PERMISSION_POLICY_MODE=per_spawn \
  mika ask --agent mika-dev "verify cd + grep + sed passes"
```

Or persistently in `~/.mika/.env`:

```
MIKA_PERMISSION_POLICY_MODE=per_spawn
MIKA_PERMISSION_POLICY_MODULE=mika.permission_policy:get_policy
```

## Registering per-binary safety functions

`per_spawn.py` ships with an **empty** `DEFAULT_POLICY`. Downstream projects
(Mika, or any consumer) supply the allow/deny CONTENTS via a plugin module.

Set `MIKA_PERMISSION_POLICY_MODULE=<package.module>:<attribute>`. The
attribute may be:

- A `dict[str, PolicyFn]` — the registry itself, OR
- A zero-arg callable that returns the dict.

Example plugin:

```python
# in mika/permission_policy.py

from claude_pilot.per_spawn import PolicyFn

def _grep_ok(argv: list[str], cwd: str) -> bool:
    # Any grep flags allowed; grep is intrinsically read-only.
    return True

def _cat_ok(argv: list[str], cwd: str) -> bool:
    # cat with any file arg; readonly on the filesystem.
    return True

def get_policy() -> dict[str, PolicyFn]:
    return {
        "grep": _grep_ok,
        "cat": _cat_ok,
        # ... per-binary safety functions
    }
```

Then set:

```bash
MIKA_PERMISSION_POLICY_MODE=per_spawn
MIKA_PERMISSION_POLICY_MODULE=mika.permission_policy:get_policy
```

If `MIKA_PERMISSION_POLICY_MODULE` is unset or the load fails, the evaluator
falls back to `DEFAULT_POLICY` (empty). **Empty policy denies every spawn.**
This is fail-safe: denials fall through to the classic tier2 / relay path
during Phase 1 opt-in, not into a silent allow.

## Rollback semantics

Every `create_permission_handler` call emits an audit event to stderr:

```
[claude-pilot audit_event] {"kind": "perm_policy_mode", "ts": "...", "detail": {...}}
```

When `per_spawn` denies a Bash command, a second event is emitted:

```
[claude-pilot audit_event] {"kind": "perm_policy_rollback", "ts": "...", "detail": {"reason": "...", "command_head": "...", ...}}
```

The consumer (mika-agent) decides what to do with `perm_policy_rollback` —
per the mika#1708 plan, the recommended action is a global env-var flip
back to `classic` and a re-dispatch. The evaluator itself just names the
signal; it does not flip anything mid-session.

Within the current session, the handler falls through to the classic
tier2 / relay path so the request has a chance to succeed via the old
evaluator (defense in depth during Phase 1 opt-in).

## Supported / unsupported shell constructs

Supported (decomposed and evaluated):

- Simple commands
- Pipelines (`|`)
- Sequences (`;`, `&`, newline)
- Logical operators (`&&`, `||`)
- Redirects (`>`, `<`, `>>`)
- Command substitution (`$(...)`, up to `MAX_SUBSTITUTION_DEPTH=5`)
- Group commands (`{ ... }`, `( ... )`)

Unsupported — fail-safe DENY with a named reason so operators can diagnose:

- Heredocs (`<<`, `<<-`, `<<<`)
- Process substitution (`<(...)`, `>(...)`)
- Backticks (`` `...` ``) — deprecated, rewrite as `$(...)`
- Arithmetic expansion (`$((...))`)
- Control flow (`if`, `for`, `while`, `case`, `select`, `until`, functions)
- `eval`, `source`, `.` — dynamic execution

## Migration (per architect-ratified plan)

1. **Phase 1** — opt-in via env var. Default `classic`. Operators flip a
   canary session; audit events accumulate.
2. **Phase 2** — flip default after **N ≥ 50** dispatches with zero
   `perm_policy_rollback` events attributable to per_spawn.
3. **Phase 3** — retire `tier1.py`'s Bash paths and `permissions.yaml`'s
   Bash rules after **M ≥ 7 days** on default `per_spawn` with zero
   rollbacks.

Design source: mika#1708 (Prime-ratified 2026-07-01 ~10:40Z, architect
session `22d21b66-eacd-4120-bb0a-cc11ce5b4f5d` ~11:35Z).
