---
artifact_contract: ce-unified-plan/v1
artifact_readiness: implementation-ready
execution: code
product_contract_source: ce-plan-bootstrap
issue: senara-solutions/claude-pilot-py#60
branch: fix/60/tier1-command-builtin-guard
---

# fix(tier1): guard the `command` builtin — recursive closed-world classification

## Summary

`command` is in tier1 `SAFE_SHELL_COMMANDS` (`src/claude_pilot/tier1.py:565`) with **no inner sub-command guard**. `is_safe_shell_command` returns `True` for `command <anything>`, so `command cp …` / `command tee …` / `command mkdir …` are Tier-1 auto-approved and never reach the Tier-2 policy path or the cpp#38/#42 destination validator. Because `command` is a *run-this-other-command* wrapper, safe-listing it unguarded re-opens exactly the control-plane-write holes (`.git/hooks/*`, `.github/workflows/*`, `.claude/*`) that cpp#42 closed.

Fix: special-case `command` in the `is_safe_shell_command` dispatch — the same architectural move cpp#33 (`find -exec`) and cpp#40 (`xargs`) established — routing to a new `_is_safe_command_builtin(sub)` helper that admits only the read-only `command -v`/`-V` lookup form **or** an inner command that is itself tier1-safe (recursive), and denies everything else.

## Problem Frame

**Evidence (issue cpp#60 body, exploit executed against current tree):**

```python
is_tier1_auto_approve("Bash", {"command": "command cp src .git/hooks/x"}, "/tmp")   # True (should be False)
is_tier1_auto_approve("Bash", {"command": "command tee .git/x"}, "/tmp")            # True
is_tier1_auto_approve("Bash", {"command": "command mkdir .claude/x"}, "/tmp")       # True
```

The comment at `tier1.py:564-565` states the entry's intent was only `command -v <name>` (read-only `which`-equivalent), but the bare `frozenset` membership admits any inner command. `command tee <path>` is additionally an arbitrary-file-write primitive not otherwise tier1-reachable.

This is the same allowlist-soundness class as `awk`/`sed` (cpp#27, dropped) and `find`/`xargs` (cpp#33/#40, given sub-command allowlists): an allowlist entry is only as sound as each entry's read-only premise (`docs/solutions/security-issues/command-string-policy-allow-rules-are-compound-unsafe.md` §6).

## Requirements

- **R1.** `command cp/tee/mkdir/<any-non-safe-listed>` must NOT auto-approve at Tier 1 (must route to policy/relay).
- **R2.** The existing dev-pilot footprint must keep working: `command -v <name>` lookups (`command -v lefthook`, `command -v cargo && cargo test`, `command -v gh`) continue to auto-approve. (`tests/test_tier1.py:670-672,702` are the regression anchors.)
- **R3.** A `command <inner>` whose `<inner>` is itself a tier1-safe *shell* command (e.g. `command grep foo file`) auto-approves. `command` must be no *more* permissive than the inner command alone. It is intentionally *narrower* than full tier1-safe — the recursion re-enters `is_safe_shell_command` only, so `command cargo test`/`command git status`/`command gh …` deny (over-block, safe direction; see KTD-2). This matches the brief's explicit `is_safe_shell_command` instruction and the read-only posture of find/xargs.
- **R4.** Shell wrappers and privilege escalation through `command` (`command sh -c …`, `command bash -c …`, `command sudo …`) continue to deny (AC4 parity with cpp#33).
- **R5.** Command-substitution anywhere in a `command …` invocation denies (defense-in-depth mirror of `_is_safe_find_command` / `_is_safe_xargs_command`).

### Decision record: brief vs. issue-body divergence

The issue body proposed admitting **only** `command -v`/`-V`, routing every other `command <x>` (including read-only `command grep`) to policy. The spawn brief (this task's contract) chose the **recursive** design: `-v`/`-V` lookup *plus* recursive classification of the inner command. Both deny the actual exploit (`command cp/tee/mkdir`). The recursive design is sounder — it makes `command` a transparent pass-through with permission parity to the inner command — and it is the explicit instruction for this task. **Carried** the brief's design (it completes the closed-world-recursion intent the brief's title invokes); the divergence from the issue body's narrower proposal is intentional and noted in the PR body. This is a *carry* (completes plain intent), not an overturn of a groomed architect resolution.

## Key Technical Decisions

- **KTD-1 — Dispatch parity with find/xargs.** Add `if cmd == "command": return _is_safe_command_builtin(sub)` to `is_safe_shell_command` (`tier1.py:765-780`), alongside the existing `find`/`xargs` branches. The `command` entry STAYS in `SAFE_SHELL_COMMANDS` as a marker that passes the membership gate; the recursive helper is the real guard — identical pattern to `xargs` (see the comment at `tier1.py:551-555`).
- **KTD-2 — Recursion via `is_safe_shell_command`, not `_is_safe_sub_command`.** The inner command is re-classified through `is_safe_shell_command` only (matching the narrow `FIND_EXEC_SAFE_COMMANDS` discipline find/xargs use), NOT the full dispatch (`is_safe_git_command`/`is_safe_build_command`/…). Consequence: `command git status` / `command cargo build` deny → route to policy. Over-block is the correct, safe failure direction. Recursion terminates: each call strips the leading `command ` token, so the string strictly shrinks.
- **KTD-3 — Read-only flag allowlist is closed-world.** Only `-v` and `-V` are admitted as the lookup form. `-p` (run with default PATH — *not* read-only), `--help`, and any other leading-dash token deny. Adding `-p` or other variants is an evidence-gated follow-up, never a hunch (cpp#34 discipline).
- **KTD-4 — Substitution guard reuses `_contains_substitution`.** Same shared helper find/xargs use (`tier1.py:634-643`), so the three gates cannot drift.

## High-Level Technical Design

`_is_safe_command_builtin(sub)` decision flow (directional guidance, not implementation spec):

```
sub = "command …"
├─ _contains_substitution(sub)?           → DENY   (R5)
├─ tokens = sub.split(); rest = tokens[1:]
├─ rest is empty (bare `command`)?         → DENY
├─ rest[0] in {"-v", "-V"}?                → ALLOW  (R2 read-only lookup)
├─ rest[0].startswith("-")?                → DENY   (KTD-3 closed-world: -p, --help, …)
└─ else recurse: is_safe_shell_command(" ".join(rest))   (R1, R3, R4)
```

Worked cases: `command -v gh` → ALLOW (rest[0]=="-v"). `command grep foo file` → recurse `is_safe_shell_command("grep foo file")` → ALLOW. `command cp src dst` → recurse → `cp` ∉ `SAFE_SHELL_COMMANDS` → DENY. `command sh -c '…'` → recurse → `sh` ∉ list → DENY. `command find . -delete` → recurse → `_is_safe_find_command` → DENY. `command -p cp src dst` → rest[0]=="-p" leading-dash, not `-v`/`-V` → DENY.

---

## Implementation Units

### U1. Add `_is_safe_command_builtin` helper and dispatch branch

**Goal:** Guard the `command` builtin so it is no more permissive than its inner command.

**Requirements:** R1, R2, R3, R4, R5.

**Dependencies:** none.

**Files:**
- `src/claude_pilot/tier1.py` — add `_is_safe_command_builtin(sub)` near `_is_safe_xargs_command` (after `tier1.py:762`); add the `if cmd == "command":` branch in `is_safe_shell_command` (`tier1.py:774-778`); update the `command` comment at `tier1.py:564-565` to point at the guard (mirror the `xargs` marker comment at `tier1.py:551-555`).

**Approach:** Follow the decision flow in High-Level Technical Design. Reuse `_contains_substitution` (KTD-4). Recurse through `is_safe_shell_command` (KTD-2). Closed-world `-v`/`-V` only (KTD-3). Write a module-level docstring on the helper in the same voice as `_is_safe_xargs_command` (`tier1.py:704-723`): state the read-only-lookup intent, the recursion-as-pass-through rationale, the deny list, and the closed-world flag discipline.

**Patterns to follow:** `_is_safe_xargs_command` / `_is_safe_find_command` (`tier1.py:646-762`) and their dispatch wiring (`tier1.py:765-780`). The `xargs` marker comment in `SAFE_SHELL_COMMANDS` (`tier1.py:551-555`) is the template for the updated `command` comment.

**Test scenarios:** covered by U2 (single atomic commit — helper + tests land together for a security-boundary change).

**Verification:** `is_safe_shell_command("command cp src dst")` is `False`; `is_safe_shell_command("command -v gh")` is `True`; `is_safe_shell_command("command grep foo file")` is `True`. Recursion does not raise on `command command grep foo`.

### U2. AC matrix tests for the `command` guard

**Goal:** Pin every allow/deny case at the real auto-approve entrypoint, including the executed-exploit regression.

**Requirements:** R1–R5.

**Dependencies:** U1.

**Files:**
- `tests/test_tier1.py` — add a `# ── cpp#60: command builtin recursive guard ──` block after the xargs block (`tests/test_tier1.py:414+`), mirroring the find/xargs parametrized structure.

**Approach:** Assert through `is_safe_bash_command` (the real compound-split entrypoint) for the allow/deny matrix, matching `test_find_exec_*` convention (`tests/test_tier1.py:326,345`). Add one `is_tier1_auto_approve(...)` end-to-end assertion for the headline exploit (matches the issue body's reproduction).

**Test scenarios:**
- ALLOW (read-only lookup, dev-pilot footprint — R2): `command -v gh`, `command -v cargo`, `command -v lefthook`, `command -V printf`.
- ALLOW (recursive tier1-safe inner — R3): `command grep foo file`, `command cat file`, `command ls -la`.
- DENY (non-safe-listed inner — R1): `command cp src dst`, `command tee /etc/passwd`, `command mkdir foo`, `command rm x`.
- DENY (shell wrapper / sudo — R4): `command sh -c 'rm -rf /'`, `command bash -c id`, `command sudo whoami`.
- DENY (closed-world flag — KTD-3): `command -p cp src dst`, `command --help`.
- DENY (bare / no inner): `command`.
- DENY (recursion into nested guard): `command find . -delete`, `command xargs rm`.
- DENY (substitution — R5): ``command grep `id` file``, `command grep "$(id)" file`.
- End-to-end exploit regression: `is_tier1_auto_approve("Bash", {"command": "command cp src .git/hooks/x"}, "/tmp")` is `False`.

**Verification:** `uv run pytest tests/test_tier1.py` green; new cases all pass; pre-existing `command -v` regression tests (`tests/test_tier1.py:670-672,702`) still pass.

---

## Scope Boundaries

**In scope:** the `command` guard (helper + dispatch branch + comment update) and its AC matrix.

### Deferred to Follow-Up Work
- Other bash builtins (`builtin`, `exec`) — separate evidence-gated tickets only if they surface (issue cpp#60 "out of scope").
- Refactoring `SAFE_SHELL_COMMANDS` itself — the `command` entry stays as a marker; the recursive check is the guard.

## Verification Contract

- `uv run pytest` green (full suite, not just the new block).
- `uv run ruff check` clean.
- `uv run mypy src` clean.
- `bash scripts/verify-pipeline.sh` passes (plan doc + source change present).

## Definition of Done

- `_is_safe_command_builtin` added; `command` dispatch branch wired; line-565 comment updated to point at the guard.
- AC matrix (U2) covers every R1–R5 case plus the executed-exploit regression, all green.
- All three quality gates (ruff, mypy, pytest) pass.
- PR opened with `Closes #60`, noting the brief/issue-body divergence (recursive design carried) and flagging this as a security-boundary change that must NOT be author-self-merged (cpp#27/#33/#40 precedent).

## Sources & Research

- Issue: `senara-solutions/claude-pilot-py#60` (body + executed exploit).
- Class precedent: cpp#27 (awk/sed dropped), cpp#33 (`find -exec` allowlist, `tier1.py:646-681`), cpp#40 (`xargs` allowlist, `tier1.py:704-762`).
- `docs/solutions/security-issues/command-string-policy-allow-rules-are-compound-unsafe.md` §6 (allowlist entry is only as sound as its read-only premise).
- cpp#38/#42 destination validator (the Tier-2 protection this bypass evades).
