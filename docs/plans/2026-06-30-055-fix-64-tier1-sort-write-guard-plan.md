---
artifact_contract: ce-unified-plan/v1
artifact_readiness: implementation-ready
execution: code
product_contract_source: ce-plan-bootstrap
issue: senara-solutions/claude-pilot-py#64
branch: fix/64/tier1-sort-write-guard
date: 2026-06-30
type: fix
---

# fix(tier1): guard `sort -o FILE` arbitrary-file-write primitive (cpp#64)

## Summary

`sort` is in tier1 `SAFE_SHELL_COMMANDS` unconditionally, but `sort -o FILE`
(and `--output=FILE` / `--output FILE`) writes its sorted output to an arbitrary
`FILE` — a `sort` built-in flag, not a shell redirect, so neither the Tier-2
policy nor the Tier-3 `>` redirect pattern catches it. This is a tier1-reachable
arbitrary-file-write primitive, including the control plane
(`.git/hooks/*`, `.github/workflows/*`, `.claude/*`).

Fix: special-case `sort` in `is_safe_shell_command` with a new
`_is_safe_sort_command(sub)` guard that **denies** any invocation carrying the
output flag (closed-world: deny the write flag, allow the read-only forms),
exactly mirroring the cpp#33 (`find`), cpp#40 (`xargs`), and cpp#60 (`command`)
sibling guards. Denial routes the command to policy/relay — not a hard block.

## Problem Frame

**WHY.** Evidence — issue cpp#64 body, exploit executed against current `main`:

```python
is_tier1_auto_approve("Bash", {"command": "sort -o /etc/passwd input"}, "/tmp")  # True (bug)
is_tier3_dangerous("sort -o /etc/passwd input")                                  # False
```

`sort -o .git/hooks/post-checkout <attacker-content>` writes an executable hook
that runs on the next checkout — the same control-plane-write class cpp#42's
destination validator closes for bare `cp`/`mv`/`mkdir`, and the same class
cpp#60 closed for `command tee/cp`. Root cause is the §6(a) precondition in
`docs/solutions/security-issues/command-string-policy-allow-rules-are-compound-unsafe.md`:
**an allowlist entry is only as safe as the read-only premise of its own flags.**
`sort`'s read-only premise is false for `-o`/`--output`.

This is a security-boundary change — must not be author-self-merged
(cpp#27/#33/#40/#60 precedent); needs executed-exploit verification and
adversarial review.

## Requirements

- **R1.** `sort -o <anything>` auto-approval at Tier 1 → DENY (route to
  policy/relay). Covers `-o FILE` (separate value) and `-oFILE` (attached value).
- **R2.** `sort --output=FILE` and `sort --output FILE` → DENY (long forms),
  **including every GNU getopt prefix abbreviation** — `--output`, `--outpu`,
  `--outp`, `--out`, `--ou`, `--o` (with `=FILE` or a separate value). `--output`
  is `sort`'s only `--o…` option, so each abbreviation binds to it and writes.
  (Caught by the cpp#64 adversarial review; an exact `--output` match was the
  founding bypass — `sort --o=.git/hooks/post-checkout` re-opened the hole.)
- **R3.** The output flag is caught wherever it appears in the token stream,
  including after positional args (`sort in.txt -o out.txt`) and inside a
  combined short-flag cluster where `-o` is reached before any value-taking flag
  (`-uo FILE`). The cluster is parsed with getopt semantics (left-to-right; a
  value-taking flag -k/-S/-t/-T consumes the rest of the token), so read-only
  forms whose attached value contains the letter `o` — `sort -T/tmp/foo`,
  `sort -to` — stay allowed and are NOT false-denied. (Caught by the cpp#64
  correctness review.)
- **R4.** Read-only `sort` continues to auto-approve: `sort file.txt`,
  `sort -k 2 file.txt`, `sort -u file.txt`, `sort -n -r file.txt`,
  `cat file.txt | sort` (pipe segments are split upstream by
  `_is_safe_sub_command`, so each segment reaches the guard as a bare `sort …`).
- **R5.** Command-substitution defense-in-depth: any `$(`/backtick/`$'` in a
  `sort` invocation → DENY, via the shared `_contains_substitution` helper,
  mirroring the find/xargs/command guards.

## Key Technical Decisions

- **KTD1 — Closed-world deny, no destination validation.** The guard denies on
  the *presence* of the output flag; it does not parse or validate the
  destination path. Destination scoping (worktree containment, control-plane
  denylist) is cpp#42's layer and only relevant once the command routes through
  Tier 2 — Tier 1's job is just to stop auto-approving the write primitive. This
  matches the brief's hard rule and the cpp#60 posture (deny the unsafe shape,
  let the lower tier decide the rest). Widening to allow `sort -o <scratch>` is
  explicitly out of scope and evidence-gated.

- **KTD2 — Token-scan, not regex.** Mirror `_is_safe_xargs_command`'s
  `sub.split()` token walk rather than a regex, so the three flag shapes
  (`-o`/`-oFILE`/`--output[=]`) and cluster forms are handled with explicit,
  auditable arity logic. `-o` requires a value, so a token that is exactly `-o`
  or whose short-flag cluster ends in `o` (e.g. `-uo`), or that starts with
  `-o` (attached `-oFILE`), denies. A `--` end-of-options token stops flag
  scanning — tokens after `--` are positional file operands, never flags
  (`sort -- -o` sorts a file literally named `-o`, no write). GNU `sort` itself
  honors `--`.

- **KTD3 — Plumb into the existing dispatch.** Add the `cmd == "sort"` branch to
  `is_safe_shell_command` alongside `find`/`xargs`/`command`. No change to
  `SAFE_SHELL_COMMANDS` membership — `sort` stays listed; the new guard is the
  real safety decision, identical to the cpp#33/#40/#60 pattern.

## Implementation Units

### U1. Add `_is_safe_sort_command` guard + dispatch

**Goal:** Deny Tier-1 auto-approval of `sort` invocations that carry the output
write flag; allow read-only forms.

**Requirements:** R1, R2, R3, R4, R5.

**Dependencies:** none.

**Files:**
- `src/claude_pilot/tier1.py` — new `_is_safe_sort_command(sub: str) -> bool`
  (sibling to `_is_safe_command_builtin`, ~tier1.py:770), plus a
  `if cmd == "sort": return _is_safe_sort_command(sub)` branch in
  `is_safe_shell_command` (~tier1.py:840-849).
- `tests/test_tier1.py` — AC matrix (see U2).

**Approach:**
1. `_contains_substitution(sub)` → `False` first (R5), mirroring the siblings.
2. `tokens = sub.split()`; confirm `tokens[0] == "sort"` (defensive; dispatch
   already guarantees it).
3. Walk `tokens[1:]`:
   - `--` → stop flag scanning (rest are operands); break.
   - `--output` (exact) or `--output=…` → return `False` (R2). Bare `--output`
     takes the next token as value but presence alone denies, so no lookahead
     needed.
   - a short-flag token (`startswith("-")`, not `--`): deny if it is `-o`,
     starts with `-o` (attached `-oFILE`), or is a cluster ending in `o`
     (`-uo`, `-no`) — i.e. the arg-taking `-o` is the cluster's last flag
     (R1, R3). Other short flags (`-k`, `-u`, `-n`, `-r`, `-b`, …) skip.
     *Conservative note:* `sort` has no other single-letter flag that consumes a
     following path we'd care about; we do not skip separate values, because no
     non-`o` `sort` short flag points at a write target. Over-block is safe.
   - positional / value tokens: skip.
4. No output flag found → return `True` (R4).

**Patterns to follow:** `_is_safe_command_builtin` (tier1.py:770) and
`_is_safe_xargs_command` (tier1.py:709) for the docstring shape, the
`_contains_substitution` guard, the `sub.split()` token walk, and the
closed-world over-block framing. Add the same class-precedent docstring header
referencing cpp#64 and the §6(a) learning.

**Verification:** `is_tier1_auto_approve("Bash", {"command": "sort -o /etc/passwd input"}, "/tmp")`
is `False`; the read-only forms in R4 remain `True`. `uv run ruff check`,
`uv run mypy src`, `uv run pytest` all clean.

### U2. AC-matrix tests

**Goal:** Lock R1–R5 with a parametrized allow/deny matrix and an exploit
regression, mirroring the cpp#60 test block (`tests/test_tier1.py:528+`).

**Requirements:** R1–R5.

**Dependencies:** U1.

**Files:** `tests/test_tier1.py` — new `# ── cpp#64: sort -o write guard ──`
section near the command-builtin block.

**Approach:** Parametrized `test_sort_readonly_allowed` and
`test_sort_write_denied` calling `_is_safe_sort_command` directly, plus a
`test_sort_write_exploit_regression` asserting at the `is_tier1_auto_approve`
boundary (matching `test_command_builtin_exploit_regression`, tier1.py test:590),
plus a `test_sort_write_deny_not_via_tier3` confirming the deny comes from the
Tier-1 guard, not the Tier-3 pattern (`is_tier3_dangerous("sort -o x in")` is
`False` — same shape as `test_command_builtin_deny_not_via_tier3`:620), plus a
substitution-guard test mirroring tier1.py test:609.

**Test scenarios:**
- ALLOW: `sort file.txt`, `sort -k 2 file.txt`, `sort -u file.txt`,
  `sort -n -r file.txt`, `sort -- -o` (literal filename `-o` after `--`).
- ALLOW via `is_tier1_auto_approve` (pipe): `cat file.txt | sort`.
- DENY: `sort -o out.txt in.txt`, `sort -oout.txt in.txt` (attached),
  `sort --output=out.txt in.txt`, `sort --output out.txt in.txt`,
  `sort -o /etc/passwd in.txt`, `sort in.txt -o .git/hooks/post-checkout`
  (flag after positional), `sort -uo out.txt in.txt` (cluster).
- DENY (substitution): `sort '$(id)'`, `sort '` + backtick-`id`-backtick + `'`.
- Exploit regression at `is_tier1_auto_approve`:
  `sort -o /etc/passwd input` → `False`;
  `sort input -o .git/hooks/post-checkout` → `False`.
- `test_sort_write_deny_not_via_tier3`: `is_tier3_dangerous("sort -o /etc/passwd input")`
  is `False`, proving the Tier-1 guard (not Tier 3) is what closes the hole.

**Verification:** `uv run pytest tests/test_tier1.py` green; new tests fail
against pre-fix `is_safe_shell_command` (confirm by reasoning / the exploit
regression).

## Scope Boundaries

**In scope:** the `sort -o`/`--output` guard + dispatch + tests.

### Deferred to Follow-Up Work
- Auditing other potentially write/exec-capable `SAFE_SHELL_COMMANDS` siblings
  (`tee`, `dd`, `paste`, `tr`?) for the §6(a) precondition — separate
  evidence-gated tickets if a concrete write primitive surfaces. (The issue's
  "audit siblings while here" note is satisfied by *recording* this deferral
  with the §6(a) reference; no new primitive is claimed without an executed
  exploit per the hard-evidence discipline.)
- Allowing `sort -o` to a worktree-internal scratch path — closed-world deny is
  the conservative call; widen only on evidence.

## Verification Contract

- `uv run ruff check` — clean.
- `uv run mypy src` — clean.
- `uv run pytest` — all green, including the new cpp#64 matrix.
- Executed-exploit check: `is_tier1_auto_approve("Bash", {"command": "sort -o /etc/passwd input"}, "/tmp")`
  returns `False` post-fix.

## Definition of Done

- `_is_safe_sort_command` added and dispatched; R1–R5 satisfied.
- AC matrix + exploit regression + not-via-tier3 + substitution tests pass.
- Quality gates green.
- PR opened with `Closes #64`, executed-exploit evidence in the body, and a
  no-self-merge note (security-boundary, cpp#27/#33/#40/#60 precedent).
