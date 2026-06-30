---
title: "fix(tier1): xargs allowlist + double-quoted metachar detection + ugrep precondition (cpp#40, #41, #44)"
date: 2026-06-30
artifact_contract: ce-unified-plan/v1
artifact_readiness: implementation-ready
execution: code
product_contract_source: ce-plan-bootstrap
issues: [cpp#40, cpp#41, cpp#44]
architect_lineage: 783d4a04
module: claude_pilot.tier1
---

# fix(tier1): xargs allowlist + double-quoted metachar detection + ugrep precondition (cpp#40, #41, #44)

## Summary

Three orthogonal hardening/relaxation fixes to the claude-pilot Tier-1 auto-approval
classifier (`src/claude_pilot/tier1.py`), shipped as **one PR** because they share the
one file and the same architectural lineage (mika-arch session `783d4a04`'s
closed-world-allowlist verdict):

1. **cpp#40 (loop-slowdown relax):** stop blanket-denying `xargs`; allow
   `xargs <readonly-cmd>` by reusing cpp#33's existing `FIND_EXEC_SAFE_COMMANDS`
   closed-world allowlist — the same mechanism `find -exec` already uses.
2. **cpp#41 (security harden):** `contains_unquoted_metacharacter` misses command
   substitution (`$(`, backtick, `$'`) inside **double** quotes, so `grep "$(id)"`
   auto-approves and bash executes `id`. Close the gap — double quotes do not
   suppress substitution in bash; only single quotes do.
3. **cpp#44 (precondition resolution):** record the resolution of the GNU-grep
   precondition on `grep`/`egrep`/`fgrep` in `FIND_EXEC_SAFE_COMMANDS` — the
   deployment containers resolve `find -exec` to GNU `/bin/grep` (verified by the
   cpp#33 security review), so the ugrep `--filter=CMD` exec vector is not live in
   the deployment target; the precondition is an accepted + tracked risk.

All three honor the hard rules: closed-world allowlists only, no regex/lexing of
inner content, no parser differential, `sh -c`/`bash -c` continues to deny
everywhere, and the existing veto suite (446+ tests) is the regression floor.

---

## Problem Frame

`tier1.py` is a pure, subprocess-free string classifier: it decides whether a Bash
command is safe to auto-approve at Tier 1 (bypassing the LLM relay). It is the
deliberate safety surface of the autonomous loop — over-blocking is the correct
failure mode, but two of its current behaviors are wrong in opposite directions:

- **Over-blocks `xargs` (cpp#40).** `xargs` is blanket-denied at TIER3
  (`tier1.py:125`, `re.compile(r"\bxargs\b")`). The most common content-search shape
  grooms use — `find … | xargs grep -l` — is denied even though it is exactly as
  safe as `find … -exec grep -l`, which cpp#33 already opened up. Hard evidence:
  mika#1639's auto-groom dispatch (claude-pilot session `25ab3b6c`, 2026-06-30,
  $0.59 wasted) halted on `find ... -name "system_prompt.md" | xargs grep -l ...`.
  Loop-slowdown class, n=4 in the permission-policy-errs-strict family.

- **Under-blocks double-quoted substitution (cpp#41).** `contains_unquoted_metacharacter`
  (`tier1.py:292`) only flags `$(`/backtick/`$'` in **unquoted** regions. Inside a
  double-quoted region (`tier1.py:313–321`) it handles only the `\"` escape and the
  closing quote — it never scans for substitution markers. But bash performs
  command substitution inside double quotes, so any safe-listed command carrying
  `"$(…)"` auto-approves and executes the inner command. Hard repro (cpp#41 body,
  against `main`): `grep "$(id)"` → `cum=False safe=True` while bash runs `id`.
  Security class. The `find -exec` path is already independently guarded
  (`_is_safe_find_command` denies on any `$(`/backtick/`$'`, `tier1.py:571`), so this
  is the residual gap for every *other* safe-listed command.

- **Undocumented-resolution precondition (cpp#44).** `FIND_EXEC_SAFE_COMMANDS`
  includes `grep`/`egrep`/`fgrep`, which are read-only **only under GNU grep**.
  ugrep (a drop-in `grep` common on Gentoo — this dev host runs ugrep 7.5.0
  interactively) exposes `--filter=CMD`/`--pager`/`--view`, which execute commands —
  the same RCE class that got `rg` removed in cpp#33. A LOAD-BEARING PRECONDITION
  comment already exists at `tier1.py:504–511` (added by cpp#33) naming cpp#44 as
  the tracking issue. cpp#44's deliverable is to *close that tracking loop*: record
  the verification result and the accepted-risk decision.

---

## Requirements

- **R1 (cpp#40):** `xargs <cmd>` auto-approves iff `<cmd>` (the first non-flag token
  after `xargs`) is in `FIND_EXEC_SAFE_COMMANDS`. The allowlist constant is reused,
  not duplicated.
- **R2 (cpp#40):** `xargs` flag forms (`-I {}`, `-n N`, `-P N`, `-0`, `-d <delim>`,
  `-r`, `-a <file>`, long `--max-args=N` etc.) are skipped structurally to find the
  inner command. No lexing of the inner command's own arguments.
- **R3 (cpp#40):** `xargs sh -c` / `xargs bash -c` / `xargs sudo …` / `xargs rm` continue
  to DENY. `\bxargs\b` is removed from `TIER3_PATTERNS`.
- **R4 (cpp#40):** `DENIED_BASH_PATTERNS_HINT` no longer tells the model `xargs` is
  categorically denied; it reflects that `xargs <readonly-cmd>` is allowed.
- **R5 (cpp#41):** `contains_unquoted_metacharacter` returns `True` for `$(`,
  backtick, and `$'` appearing inside a double-quoted region; single-quoted regions
  stay inert; the `\"` escape inside double quotes is preserved (an escaped quote
  does not close the region).
- **R6 (cpp#41):** the Rust mirror (`permission_pre_classifier.rs`) is **out of
  scope** — tracked separately as a paired audit. The function's docstring is
  updated to note the Python side now diverges (intentionally hardened) until the
  Rust side mirrors.
- **R7 (cpp#44):** the `FIND_EXEC_SAFE_COMMANDS` comment block states cpp#44's
  resolution: deployment target verified GNU grep, vector not live there, accepted +
  tracked risk, no inner-argument lexing (per solution-doc §4).
- **R8 (docs):** the three learnings are folded into
  `docs/solutions/security-issues/command-string-policy-allow-rules-are-compound-unsafe.md`.
- **R9 (regression floor):** the existing veto suite stays green; new tests cover
  every AC below; the total test count grows.

---

## Key Technical Decisions

**KTD1 — Reuse `FIND_EXEC_SAFE_COMMANDS`, do not introduce a parallel xargs allowlist.**
cpp#40's body and the architect lineage both mandate one closed-world allowlist
serving both `find -exec <cmd>` and `xargs <cmd>`. Same read-only premise, same
entries, same audit surface. A second constant would drift.

**KTD2 — Plumb xargs through the existing `is_safe_shell_command` dispatch, mirroring `find`.**
`find` is special-cased at `tier1.py:586` (`if cmd == "find": return _is_safe_find_command(sub)`).
Add `xargs` to `SAFE_SHELL_COMMANDS` and a sibling `if cmd == "xargs": return
_is_safe_xargs_command(sub)` branch. This keeps the compound-split + per-segment
chain-safety machinery (`_split_compound_command` → `_is_safe_sub_command`) intact:
`find … | xargs grep -l` splits on `|` and each side is validated independently
(`find …` via `_is_safe_find_command`, `xargs grep -l` via the new helper).
Rationale for this over a branch in `_is_safe_sub_command`: `is_safe_shell_command`
already owns the `SAFE_SHELL_COMMANDS` membership gate and the find special-case, so
xargs belongs next to its sibling, not in the dispatcher above it.

**KTD3 — xargs flag-skipping is structural, not a bash lexer.** Walk
whitespace-split tokens after `xargs`; skip tokens that look like flags
(`-`-prefixed) and, for the value-taking short flags (`-I`, `-n`, `-P`, `-d`, `-s`,
`-L`, `-a`, `-E`), skip the following token when the value is not attached. The
first token that is not a flag (and not a consumed flag-value) is the inner command.
This is the same "structural pattern matching, not bash grammar" posture cpp#33's
`_FIND_EXEC_INNER_RE` uses. If parsing is ambiguous (no inner token found), DENY
(fall through to relay) — over-block is the safe default.

**KTD4 — cpp#41 fix is the minimal quote-state-machine change.** In the double-quoted
branch of `contains_unquoted_metacharacter`, after handling the `\"` escape and the
closing `"`, also test for `` ` ``, `$(`, and `$'` and return `True`. Do **not**
touch `_split_compound_command`'s quote machine — it has a different job (segment
splitting) and double-quoted substitution markers there are not metacharacters for
*its* purpose. The two machines stay independent (they already document mirroring
each other only for quote/escape handling, not metachar detection).

**KTD5 — cpp#44 is documentation-only in `tier1.py`; no runtime ugrep check is added here.**
`tier1.py` is a deliberately pure, subprocess-free string classifier (load-bearing
for testability and for the hot-path purity the whole module depends on). A
`grep --version` subprocess probe does not belong in it. AC44.1 (the precondition
comment) already exists from cpp#33; cpp#44's substantive deliverable — verifying the
deployment grep provider — was already performed by the cpp#33 security review (cited
in the cpp#44 body: GNU `/bin/grep` 3.12 rejects `--filter`). So the resolution is to
record that decision in the comment. The optional runtime warning (AC44.2) is
**declined** for module purity and surfaced as a clean follow-up: a startup-time
ugrep-detection warning belongs in `cli.py`, not the classifier. This is the brief's
own blessed fallback ("document-only is acceptable").

**KTD6 — Defense-in-depth, not behavior change, for the find path.** cpp#41's fix
makes `contains_unquoted_metacharacter` catch double-quoted `$()` that the find path
*already* caught via its own `"$(" in sub` guard. After this change the find path is
guarded by both. No find AC changes; the existing `find -exec grep "$(id)"` veto
tests stay green.

---

## Implementation Units

### U1. cpp#40 — allow `xargs <readonly-cmd>` via the shared allowlist

**Goal:** Remove the blanket `xargs` TIER3 deny and auto-approve `xargs <cmd>` when
the inner command is in `FIND_EXEC_SAFE_COMMANDS`.

**Requirements:** R1, R2, R3, R4.

**Dependencies:** none (FIND_EXEC_SAFE_COMMANDS already exists at `tier1.py:512`).

**Files:**
- `src/claude_pilot/tier1.py` (modify)
- `tests/test_tier1.py` (add tests)

**Approach:**
- Remove `re.compile(r"\bxargs\b")` from `TIER3_PATTERNS` (`tier1.py:125`). Leave the
  surrounding NOTE comments coherent.
- Add `_is_safe_xargs_command(sub: str) -> bool` near `_is_safe_find_command`
  (`tier1.py:539`). It strips the leading `xargs` token, skips flags per KTD3,
  extracts the first inner command token, and returns
  `inner in FIND_EXEC_SAFE_COMMANDS`. Mirror `_is_safe_find_command`'s guard against
  command substitution: if `$(`/backtick/`$'` appears in `sub`, return `False`
  (defense in depth; cpp#41 also covers this at the scanner layer). Return `False`
  when no inner command is found (ambiguous → deny).
- Add `"xargs"` to `SAFE_SHELL_COMMANDS` (`tier1.py:465`) and a
  `if cmd == "xargs": return _is_safe_xargs_command(sub)` branch in
  `is_safe_shell_command` (`tier1.py:586`, beside the `find` branch).
- Update `DENIED_BASH_PATTERNS_HINT` (`tier1.py:196`): change the `xargs` bullet so it
  no longer lists `xargs` as categorically denied; note that `xargs <readonly-cmd>`
  (inner in the read-only allowlist) is auto-approved, mirroring the `find … -exec`
  bullet's framing, while `xargs sh -c`/`bash -c`/`sudo`/`rm` still crash the session.

**Patterns to follow:** `_is_safe_find_command` + `_FIND_EXEC_INNER_RE` (`tier1.py:536–574`)
for closed-world inner matching and the substitution guard; the `find` special-case in
`is_safe_shell_command` (`tier1.py:586`).

**Test scenarios** (`tests/test_tier1.py`, new section mirroring `test_find_exec_*`):
- `xargs grep -l "foo" < input.txt` → `is_safe_bash_command` True (AC40.1).
- `find . -name "*.md" | xargs grep -l "foo"` → True (AC40.2, composition; both
  segments validate).
- `xargs -I {} grep "foo" {}` → True (AC40.3, `-I {}` flag skipped).
- `xargs -n 1 cat` → True; `xargs -0 grep x` → True; `xargs -P 4 head` → True
  (AC40.4 flag variants where inner is allowlisted).
- `xargs rm` → False (AC40.4, rm not allowlisted).
- `xargs sh -c 'id'` → False; `xargs bash -c 'id'` → False (AC40.5, shell wrapper —
  inner not allowlisted; also still TIER3-caught by the `sh -c`/`bash -c` patterns).
- `xargs sudo whoami` → False (AC40.6).
- `is_tier3_dangerous("xargs grep x")` → False, and assert no pattern in
  `TIER3_PATTERNS` matches a bare `xargs` token (AC40.7).
- `DENIED_BASH_PATTERNS_HINT` no longer asserts `xargs` is categorically denied
  (string assertion on the updated bullet).

**Verification:** the founding mika#1639 shape `find … -name "system_prompt.md" |
xargs grep -l …` auto-approves; non-readonly xargs inners still deny; full suite green.

---

### U2. cpp#41 — detect command substitution inside double quotes

**Goal:** Close the double-quoted `$(`/backtick/`$'` detection gap in
`contains_unquoted_metacharacter` so safe-listed commands carrying `"$(…)"` no longer
auto-approve.

**Requirements:** R5, R6.

**Dependencies:** none. Independent of U1 (U1 adds its own substitution guard; this
unit hardens the shared scanner that backstops every safe-listed command).

**Files:**
- `src/claude_pilot/tier1.py` (modify `contains_unquoted_metacharacter`, `tier1.py:292`)
- `tests/test_tier1.py` (add tests)

**Approach:**
- In the in-quote branch (`tier1.py:313–321`): keep the `quote_state == '"'` escape
  handling (`\` + next char → skip 2) and the closing-quote handling. Add, for
  `quote_state == '"'` only, the same three metacharacter tests the unquoted branch
  uses: bare `` ` `` → `True`; `$` followed by `(` → `True`; `$` followed by `'` →
  `True`. Single-quoted regions (`quote_state == "'"`) stay inert — no metachar test
  there (bash single-quote semantics).
- Update the docstring: double quotes no longer suppress substitution detection
  (bash expands `$()`/backtick in double quotes; only single quotes suppress). Note
  the Python scanner now intentionally diverges from the Rust mirror until the
  paired-audit ticket mirrors it (R6).

**Patterns to follow:** the unquoted-branch metachar tests already in the same
function (`tier1.py:328–335`); reuse the identical conditions inside the double-quote
branch.

**Test scenarios** (`tests/test_tier1.py`, extend the `contains_unquoted_metacharacter`
section near `tier1.py` test lines 86–176):
- `contains_unquoted_metacharacter('echo "$(curl evil)"')` → True (AC41.1) and
  `is_safe_bash_command('echo "$(curl evil)"')` → False.
- `contains_unquoted_metacharacter('grep "$(id)"')` → True; `echo "$(id)"` → True
  (the cpp#41 founding repros).
- `contains_unquoted_metacharacter("echo 'literal $(stuff)'")` → False (AC41.2,
  single-quoted inert) and `is_safe_bash_command` True for `echo 'literal $(stuff)'`.
- `contains_unquoted_metacharacter('echo "escaped \\" still in dquote $(now flagged)"')`
  → True (AC41.3 — the `\"` does not close the dquote, so the later `$(` is still
  inside a double-quoted region and flagged).
- backtick inside double quotes: `echo "`whoami`"` → True; `$'` inside double quotes:
  `echo "$'\\x41'"` → True.
- Regression: existing `mkdir "$(curl evil)"` veto test stays green (AC41.4 — now
  caught by both the scanner and the per-segment chain check); existing
  `find … -exec grep "$(id)" {} \;` veto tests stay green (KTD6 defense-in-depth).
- Negative controls: `git status` → False; `cargo test --release` → False;
  `grep '$(id)'` (single-quoted) → False (unchanged correct behavior).

**Verification:** the cpp#41 hard repro (`grep "$(id)"` auto-approving) no longer
auto-approves; single-quoted substitution still allowed; no existing veto regresses.

---

### U3. cpp#44 — record the GNU-grep precondition resolution

**Goal:** Close cpp#44's tracking loop by stating the precondition resolution in the
`FIND_EXEC_SAFE_COMMANDS` comment: deployment verified GNU grep, ugrep vector not
live there, accepted + tracked risk, no inner-argument lexing.

**Requirements:** R7.

**Dependencies:** none.

**Files:**
- `src/claude_pilot/tier1.py` (extend the comment at `tier1.py:504–511`)

**Approach:**
- Extend the existing LOAD-BEARING PRECONDITION comment to state the resolution
  (not just the tracking pointer): (a) the cpp#33 security review empirically
  verified the deployment containers resolve `find -exec` to GNU `/bin/grep` 3.12,
  which rejects `--filter`/`--pager`/`--view`; (b) therefore the ugrep exec vector is
  not live in the deployment target; (c) the precondition is an accepted + tracked
  risk — grep/egrep/fgrep stay in the allowlist; (d) the hardening boundary: never
  denylist `--filter`/`--pager`/`--view` by inner-argument parsing (solution-doc §4);
  if a ugrep host ever enters scope, drop the grep-family entries instead; (e) a
  runtime startup ugrep-detection warning is a possible future defense-in-depth in
  `cli.py` (not the pure classifier), deliberately not added here.

**Patterns to follow:** the existing comment block's tone and the solution-doc §6
"environmental precondition documented next to the survivors" framing.

**Test expectation: none — comment-only change, no behavioral effect.** Covered by R9
(the full suite stays green, proving no accidental behavior change).

**Verification:** the comment unambiguously states cpp#44 is resolved (verified +
accepted-risk), and a reader can tell why grep-family entries are kept and what would
change that decision.

---

### U4. Extend the command-string-policy solution doc

**Goal:** Fold the three learnings into the existing security-issues solution doc so
the next person touching the classifier inherits them.

**Requirements:** R8.

**Dependencies:** U1, U2, U3 (documents what they establish).

**Files:**
- `docs/solutions/security-issues/command-string-policy-allow-rules-are-compound-unsafe.md` (modify)

**Approach:**
- **§4 (closed-world allowlist, never lex the inside):** add that the same allowlist
  now backs `xargs <cmd>` as well as `find -exec <cmd>` — one closed-world set, two
  structural front-ends (cpp#40). The structural flag-skipping is pattern matching,
  not lexing.
- **§1 or a new sub-point near the substitution-marker guidance:** record the
  double-quoted-substitution detection gap and its closure — double quotes do NOT
  suppress `$()`/backtick/`$'` in bash; a quote-state scanner must only treat single
  quotes as suppressing (cpp#41). Note the Python/Rust divergence pending the paired
  audit.
- **§6 (read-only PREMISE + environmental precondition):** record cpp#44's resolution
  — grep-family entries kept under the verified GNU-grep deployment precondition;
  ugrep `--filter` is the documented environmental hazard; the resolution is
  accepted-risk + tracked, never inner-arg denylisting.
- Update frontmatter: bump `last_updated` to 2026-06-30 and add
  `claude-pilot-40`, `claude-pilot-41`, `claude-pilot-44` to `tags`; add `xargs` and
  `ugrep` tags.

**Patterns to follow:** the existing numbered-section structure and the WRONG/RIGHT
code-comment idiom already in §4/§6.

**Test expectation: none — documentation.** Satisfies the verify-pipeline docs bucket
alongside the plan.

**Verification:** the doc names all three cpp tickets and the three learnings; a
reader planning a future allowlist change finds the xargs/ugrep/double-quote
precedents.

---

## Assumptions

- **xargs default-command is `echo`.** Bare `xargs` with no command runs `echo` by
  default. `_is_safe_xargs_command` treats a bare `xargs` (no inner token) as DENY
  (ambiguous → over-block), which is safe and matches the "no inner found → deny"
  rule in KTD3. Not auto-approving the rare bare-`xargs` form is an acceptable
  over-block.
- **`-d <delim>` / `-E <eof>` value forms.** The structural skipper consumes the
  value token for value-taking short flags whether attached (`-d,`) or separate
  (`-d ,`). GNU long forms (`--delimiter=,`) are single tokens and skip cleanly. If a
  novel flag form defeats the skipper, the result is over-block (deny), never
  under-block.
- **No new entries to `FIND_EXEC_SAFE_COMMANDS`.** Out of scope; the xargs path reuses
  the set exactly as-is.

---

## Scope Boundaries

In scope: `src/claude_pilot/tier1.py`, `tests/test_tier1.py`, and the one
security-issues solution doc.

Out of scope (do not touch):
- `src/claude_pilot/permissions.py` — cpp#47/#38/#42 territory, parallel-safe; this PR
  must not modify it.
- The Rust mirror `crates/mika-agent/src/server/permission_pre_classifier.rs` — the
  cpp#41 paired-audit candidate is a separate ticket in the mika repo.

### Deferred to Follow-Up Work
- **Runtime ugrep-detection warning (cpp#44 AC44.2).** A startup-time check in
  `cli.py` that warns when `grep` resolves to ugrep. Deliberately not added here to
  keep `tier1.py` a pure subprocess-free classifier; clean follow-up if a ugrep host
  ever enters scope.
- **Rust `permission_pre_classifier.rs` double-quoted-substitution mirror.** Paired
  audit; file/track on the mika repo so the F5 sentinel contract is restored.

---

## Definition of Done

- `xargs <readonly-cmd>` auto-approves; `xargs rm`/`sh -c`/`bash -c`/`sudo` deny;
  `\bxargs\b` gone from `TIER3_PATTERNS`; hint text updated (AC40.1–40.7).
- `contains_unquoted_metacharacter` flags double-quoted `$(`/backtick/`$'`;
  single-quoted stays inert; `\"` escape preserved (AC41.1–41.4).
- `FIND_EXEC_SAFE_COMMANDS` comment states cpp#44's verified + accepted-risk
  resolution (AC44.1; AC44.2 explicitly declined with rationale).
- Solution doc carries all three learnings; frontmatter updated.
- `uv run ruff check`, `uv run mypy src`, `uv run pytest` all pass; the existing
  veto suite (446+) stays green and the total test count grows.
- `scripts/verify-pipeline.sh` passes (docs + source buckets both present).
