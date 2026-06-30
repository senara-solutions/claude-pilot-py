---
title: "fix: Allow `git show <SHA>:<path> > <relative-path>` in the dev-pilot permission policy"
date: 2026-06-30
type: fix
issue: senara-solutions/claude-pilot-py#35
module: claude_pilot.policy
component: permission-classifier
artifact_contract: ce-unified-plan/v1
artifact_readiness: implementation-ready
execution: code
product_contract_source: ce-plan-bootstrap
plan_depth: standard
severity: high
tags: [permissions, policy, bash, regex, git-show, redirect, allow-list, claude-pilot-35]
architect_session: 783d4a04
---

# fix: Allow `git show <SHA>:<path> > <relative-path>` in the dev-pilot permission policy

## Summary

The dev-pilot permission policy denies `git show <commit>:<path> > <local-path>`
— the canonical dispatch-lib pattern for re-importing a grooming plan from its
source commit into a fresh worktree. The data source is read-only (a git object)
and the destination is a worktree-relative file, but the classifier judges by
**bash syntax shape**: the `>` redirect trips the wholesale tier3 redirect ban,
and the chain-safety guard vetoes the otherwise-allowed `git show`. This plan
adds a single narrow sanctioned exception — `git show <SHA>:<path> > <relative>`
— with the source restricted to immutable hex commit SHAs and the redirect
target restricted by structural shape (no absolute path, no `..`, no `~`, no
shell expansion). Everything outside that exact shape stays denied.

---

## Problem Frame

**WHY (evidence).** On 2026-06-30 ~07:04 UTC, mika-dev's claude-pilot dispatch
for mika#1617 (session c292d46e) was halted when this command was denied:

```bash
git show e95a9d8f:docs/plans/2026-06-28-005-fix-1617-dispatch-lib-find-issue-plan-regex-plan.md > docs/plans/2026-06-28-005-fix-1617-dispatch-lib-find-issue-plan-regex-plan.md
```

The deny fired with policy ID `bash-git-readonly` (cpp#35 body). Mechanism,
confirmed by reading the code:

- `tier1.py` `is_tier3_dangerous` (`TIER3_PATTERNS`, the `(?<!<)>{1,2}(?!\(|&[\d-])`
  pattern) flags **any** `>` / `>>` redirect as dangerous. So the command is not
  tier1-safe.
- `policy.evaluate` (`src/claude_pilot/policy.py`) matches the
  `bash-git-readonly` rule (`src/claude_pilot/policies/permissions.yaml`, pattern
  `^git\s+(status|log|diff|show|...)`) → decision `allow`.
- `permissions.py` `_bash_allow_is_chain_safe` then vetoes that allow: the single
  segment is neither tier1-safe nor a clean (non-tier3) policy allow, because
  `is_tier3_dangerous(seg)` is `True` for the redirect. The handler converts the
  veto to `PermissionResultDeny(interrupt=True)` and the pilot dies.

This is the **third** confirmed instance of the "syntactic classifier doesn't
reason semantically" class (siblings: cpp#34 `$()` ban, mika#1639 make-verify
allowlist). cpp#35 is the **tactical Option A** unblock; the architectural Option
B (semantic classifier) is routed to mika-arch separately and is out of scope
here.

**Architect verdict (mika-arch session 783d4a04, GROOMED).** Prescribed patch
shape:

```yaml
bash-git-show-redirect:
  pattern: '^git show [a-f0-9]+:'
  allow_redirect_to: 'worktree'
  deny_redirect_if: 'absolute_path|../'
```

> Rationale: explicit pattern for the safe case (`SHA:path`, not `branch:path`),
> with literal path constraints (no `..`).

The YAML above is a **sketch**, not the literal schema — it must be translated to
the actual `permissions.yaml` rule schema and the `permissions.py` chain-safety
logic (per the cpp#35 brief, §"Architect's exact patch shape is a sketch").

**Load-bearing constraints (from the architect + cpp#35 brief):**

1. **SHA-only source.** Anchor `^git show [a-f0-9]+:` — hex commit SHAs only, not
   branch or tag names. A SHA names an immutable git object; branch refs are
   movable and tag refs are force-pushable. This closes bypass surface B3
   (TOCTOU on ref mutability).
2. **Literal-path destination.** The check uses the **literal redirect-target
   string**, never `realpath()` — `realpath()` is TOCTOU-vulnerable (a symlink
   target can change between check and execution). No absolute paths, no `..`,
   no `~`.
3. **No bash lexing of the redirect.** Match by simple structural shape: `>`
   then a token containing none of `..`, leading `/`, `~`, `$`, `$(`, backtick.
   If any appear → deny. Do not parse the path; reject anything compositional.

This is consistent with the load-bearing learning in
`docs/solutions/security-issues/command-string-policy-allow-rules-are-compound-unsafe.md`:
match a sanctioned shape by full-line-anchored structure (as
`_is_sanctioned_pure_heredoc` already does for `<<`), don't lex shell grammar in
a security gate, and back the allow with the existing allow-list guard.

---

## Requirements

- **R1 — Allow the safe shape.** `git show <SHA>:<path> > <relative-path>`, where
  `<SHA>` is `[a-f0-9]+` and `<relative-path>` is a worktree-relative literal
  token (no absolute, no `..`, no `~`, no shell expansion), is ALLOWED. (cpp#35
  AC1)
- **R2 — Keep every unsafe variant denied.** Absolute target, `..` traversal,
  command substitution, `$`-expansion, and non-SHA refs (branch/tag/`HEAD`) all
  stay DENIED. (cpp#35 AC2)
- **R3 — No realpath / no path lexing.** Validation is on the literal command
  string by structural shape only; no filesystem resolution. (architect
  constraint 2–3)
- **R4 — Single regex source of truth.** The sanctioned shape is encoded once;
  drift between the YAML rule and the guard must fail **closed** (deny), never
  open. (solutions-doc principle: divergence is the recurring failure mode)
- **R5 — Regression coverage.** The shipped-policy test suite proves the positive
  trigger allows and all seven brief-listed negatives deny. (cpp#35 file list)

---

## Key Technical Decisions

### KTD1 — Encode the sanctioned shape as a full-line-anchored YAML rule, placed before `bash-git-readonly`

Add rule `bash-git-show-redirect` to `permissions.yaml` **before**
`bash-git-readonly` (first-match-wins, so it must precede the broader read-only
rule to claim its own `rule_id`). The pattern matches the entire sanctioned
command:

```
^git\s+show\s+[a-f0-9]+:[\w./-]+\s*>\s*(?!/)(?!~)(?!.*\.\.)[\w./-]+\s*$
```

- `[a-f0-9]+:` — SHA-only source (R1, constraint 1).
- source `[\w./-]+` — git object path; the char class structurally excludes `$`,
  backtick, `(`, space, `>`, so a substitution-laden source (`abc:$(evil)`)
  cannot match this rule and falls through to normal handling.
- `(?!/)(?!~)(?!.*\.\.)[\w./-]+` — redirect target: reject leading absolute,
  leading `~`, and any `..`; the char class excludes `$`, `~`, space, `>`
  (R2–R3, constraints 2–3).
- `^...$` anchors are **required** because `policy.evaluate` uses `re.search`
  (not `match`/`fullmatch`). With no `re.MULTILINE` flag, `$` honors only a
  single *trailing* newline, so a multi-line injection (`> foo\nrm -rf /`) does
  **not** match this rule and falls through to the chain-safety guard, which
  splits on `\n` and vetoes the dangerous segment.

**Rationale.** This mirrors the existing `_SANCTIONED_HEREDOC_OPENER_RE` design
(full-line anchor, no lexer) blessed by the solutions doc. The regex is the
single source of truth (R4).

**Alternative rejected — match only the source `^git show [a-f0-9]+:` and do all
target validation in Python.** This splits the security constraint across two
layers and risks the exact drift the solutions doc warns against. Keeping the
full shape in one anchored regex is simpler and auditable.

### KTD2 — Honor the rule by `rule_id` in the chain-safety guard, after the universal vetoes

In `permissions.py` `_bash_allow_is_chain_safe`, add a sanctioned-exception
branch: re-evaluate the policy and, when the matched rule is
`bash-git-show-redirect` with an `allow` decision, return `True`.

**Placement (load-bearing): after** the existing `<<<` / `<<` / substitution-marker
/ bare-`&` universal vetoes, **before** the compound-segment loop. Ordering after
the substitution-marker veto means a command like `git show abc:x > $(evil)` — or
any `$(`/backtick/`$'` anywhere — is rejected *before* the exception is even
considered. This is defense-in-depth on top of the regex's own char-class
exclusions.

**Coupling fails closed (R4).** The guard trusts `rule_id == "bash-git-show-redirect"`.
If the YAML rule is renamed or removed, the exception simply never fires and the
command routes to the normal veto (deny) — the safe direction. A comment in both
files documents the coupling.

**Rationale.** This re-uses the established sanctioned-exception pattern
(`_is_sanctioned_pure_heredoc` is the sibling for `<<`). The guard is the
enforcement point that the redirect ban runs through, so the exception must live
there; trusting the YAML `rule_id` keeps the regex un-duplicated.

### KTD3 — Follow the architect's `[a-f0-9]+` verbatim, accepting the short-all-hex-branch edge

`[a-f0-9]+` (1+ hex chars) will also match a branch literally named with only
hex characters (e.g. a branch `abcdef`). The architect chose this pattern
knowingly: it rejects the *common* movable refs (`main`, `master`, `HEAD`,
`develop`, `feature/*`) that carry the TOCTOU risk in practice, and a hex-only
branch name is a pathological edge. We follow the GROOMED verdict verbatim
rather than inventing a stricter min-length the architect did not specify. The
edge is documented in a code comment for the next reader.

---

## High-Level Technical Design

Decision flow for a Bash command reaching Tier 2 (policy), showing where the new
exception sits. Authoritative for this change.

```mermaid
flowchart TD
    A[Bash command] --> B{tier1 auto-approve?}
    B -- yes --> ALLOW1[ALLOW]
    B -- no --> C[policy.evaluate first-match-wins]
    C --> D{decision}
    D -- deny/escalate --> DENY1[DENY interrupt=True]
    D -- allow --> E[_bash_allow_is_chain_safe]
    E --> F{universal vetoes:\n<<< / <<-non-heredoc /\n$( ` $' / bare &}
    F -- veto --> DENY2[DENY]
    F -- pass --> G{rule_id ==\nbash-git-show-redirect?}
    G -- yes --> ALLOW2[ALLOW - sanctioned redirect]
    G -- no --> H[compound-segment\nallow-list loop]
    H -- all segments safe --> ALLOW3[ALLOW]
    H -- any segment unsafe --> DENY3[DENY]
```

The `bash-git-show-redirect` rule (placed before `bash-git-readonly`) is what
makes the `rule_id` check at node **G** reachable for the sanctioned shape; every
unsafe variant either fails the rule's own regex (falls to `bash-git-readonly` →
node **H** → veto) or trips a universal veto at node **F**.

---

## Implementation Units

### U1. Add the `bash-git-show-redirect` policy rule

**Goal:** Introduce the sanctioned-shape allow rule so the safe command earns its
own `rule_id`.

**Requirements:** R1, R2, R3, KTD1, KTD3.

**Dependencies:** none.

**Files:**
- `src/claude_pilot/policies/permissions.yaml` (modify)

**Approach:** Insert a new rule **immediately before** `bash-git-readonly` (the
`# ---- Git operations ----` block). Pattern per KTD1. The `reason` field must
state the security intent (SHA-only source = immutable object; literal redirect
target = no absolute/`~`/`..`) and explicitly cross-reference that the
chain-safe guard in `permissions.py` honors this rule's `rule_id` as a sanctioned
redirect exception. Add a short comment above the rule noting the
`[a-f0-9]+` short-all-hex-branch edge (KTD3) and the `^...$` / `re.search`
anchoring requirement.

**Patterns to follow:** the lookahead-guarded relative-path rules already in this
file (`bash-mkdir`, `bash-cp-mv` at the `# ---- Dev-pilot phase ----` block) use
the same `(?!/)(?!~)(?!.*\.\.)` idiom — mirror their structure and comment
density.

**Test scenarios:** covered end-to-end in U3 against the shipped policy (this
unit ships no standalone test; the YAML rule is data validated by the U3 suite).
`Test expectation: none -- data rule, behavior asserted in U3.`

**Verification:** `bash-git-show-redirect` appears before `bash-git-readonly` in
the rules list; `uv run python -c "import yaml; yaml.safe_load(open('src/claude_pilot/policies/permissions.yaml'))"`
parses cleanly; the `PolicyRule` regex validator (load-time `re.compile`) accepts
the pattern.

### U2. Add the sanctioned-redirect exception to `_bash_allow_is_chain_safe`

**Goal:** Make the chain-safety guard return `True` for the sanctioned shape,
lifting the wholesale `>` veto for this one rule only.

**Requirements:** R1, R3, R4, KTD2.

**Dependencies:** U1 (the guard trusts the rule's `rule_id`).

**Files:**
- `src/claude_pilot/permissions.py` (modify)

**Approach:** In `_bash_allow_is_chain_safe`, after the existing `<<<` / `<<` /
`_SUBSTITUTION_MARKERS` / `_BARE_AMP_RE` checks and **before** the
`_split_compound_command` loop, evaluate the policy and short-circuit:

```text
pd = evaluate(policy, tool_name, tool_input)
if pd.decision == "allow" and pd.rule_id == "bash-git-show-redirect":
    return True
```

(directional — exact local-variable wiring is the implementer's call). Add a
doc-comment explaining: source is read-only (immutable git object), target
validated by the rule's anchored regex, universal vetoes already ran (so no
substitution/here-string can reach here), and the coupling fails closed on
rule rename. Keep the existing module narrative comment block in sync — note the
new sanctioned exception alongside the heredoc one.

**Patterns to follow:** `_is_sanctioned_pure_heredoc` and its call-site in the
`if "<<" in command:` branch — same "sanctioned exception to a wholesale veto"
shape and comment discipline.

**Test scenarios:**
- Happy path: `_bash_allow_is_chain_safe(POLICY, "Bash", {"command": "git show e95a9d8f:docs/plans/X.md > docs/plans/X.md"})` is `True`. (Covers AC1)
- Edge — trailing chain breaks the anchor: `git show e95a9d8f:a > b ; rm -rf /` is `False` (the `;` defeats `$`, rule doesn't match, segment loop vetoes `rm -rf /`).
- Edge — substitution in source vetoed before the exception: `git show e95a9d8f:$(curl evil) > b` is `False` (substitution-marker veto fires first).
- Error path — non-SHA ref: `git show HEAD:file > foo` and `git show main:file > foo` are `False`.

**Verification:** the four guard-unit assertions above pass; no change to any
existing guard-unit test in `tests/test_policy_devpilot.py`.

### U3. Lock production behavior with shipped-policy tests

**Goal:** Prove, against the **bundled** `permissions.yaml` + guard, that the
positive trigger allows and all seven brief-listed negatives deny — and that
unrelated denials are untouched.

**Requirements:** R5, R1, R2.

**Dependencies:** U1, U2.

**Files:**
- `tests/test_policy_devpilot.py` (modify)

**Approach:** Use the existing `_effective(cmd)` helper (evaluates the shipped
policy + chain guard, returns the effective `allow`/`deny`). Add:
- A positive case asserting `_effective("git show e95a9d8f:docs/plans/X.md > docs/plans/X.md") == "allow"` (new parametrized test or an entry alongside `test_bundled_allows_dev_pilot_footprint`).
- All seven negatives into the `test_bundled_denies_unsafe` parametrize list (or a new sibling), each asserting `deny`.
- One or two guard-unit tests (from U2's scenarios) next to the existing
  `test_guard_*` functions, to pin the guard behavior directly (not only through
  the shipped policy).

**Patterns to follow:** `_effective`, `test_bundled_allows_dev_pilot_footprint`,
`test_bundled_denies_unsafe`, and the `test_guard_*` unit tests already in the
file. Reuse `_bash(...)` and `_POLICY`.

**Test scenarios (the seven negatives — each must be `deny`):**
- `git show main:file > /etc/cron.d/pwn` — absolute target (non-SHA ref too). (Covers AC2)
- `git show main:file > ../escape` — `..` traversal.
- `git show main:file > $(readlink escape)` — command substitution.
- `git show abc123:file > worktree/../escape` — `..` embedded (valid SHA, unsafe target).
- `git show abc123:file > $HOME/anything` — `$`-expansion (valid SHA, unsafe target).
- `git show HEAD:file > foo` — branch/`HEAD` ref, not SHA (TOCTOU).
- `git show main:file > foo` — branch ref, not SHA (TOCTOU).
- Positive control: `git show e95a9d8f:docs/plans/X.md > docs/plans/X.md` — `allow`. (Covers AC1)
- Regression control: at least one pre-existing entry in `test_bundled_denies_unsafe` (e.g. `git status && rm -rf ~`) still `deny`, confirming the new rule didn't widen the readonly path.

**Verification:** `uv run pytest tests/test_policy_devpilot.py` green; the new
positive case fails if U1/U2 are reverted (proves the test exercises the fix, per
the verify-pipeline-passes-without-the-fix learning).

---

## Scope Boundaries

**In scope:** the `git show <SHA>:<path> > <relative-path>` sanctioned exception
(rule + guard + tests) in claude-pilot-py.

**Out of scope (do not touch):**
- cpp#34 — closed-world `$()` substitution allowlist (separate PR, spawn e126f9e5).
- mika#1639 — `make verify-bundled-skills` allowlist (mika-side classifier, autonomous loop).
- Option B — semantic (data-source/destination) classifier refactor (routed to mika-arch separately).
- Other `git` subcommands with redirects (`git diff > x`, `git log > x`) — only on hard evidence of need.
- The existing wholesale `>` ban for all unrelated rules — unchanged.

---

## Risks & Dependencies

- **Risk: a regex bypass admits an unsafe write.** Mitigation: full-line anchor +
  char-class exclusions + the universal substitution/here-string/bare-`&` vetoes
  running first + the seven-negative regression suite. Per the solutions doc,
  permission-classifier changes warrant **executed-exploit review** — the
  `/ce:review` step and PR review (AC4: not author-self-merged) provide it.
- **Risk: `rule_id` coupling drift.** Mitigation: fails closed (deny) by design;
  documented in both files; a U3 guard-unit test pins the coupling.
- **Dependency:** none external. Single-repo change in claude-pilot-py.
- **Deploy note:** `permissions.yaml` is bundled into the cpp package; the fix
  takes effect after `uv tool install --reinstall --force --editable ./claude-pilot-py`
  (the `make deploy` cpp step). Runtime override path `MIKA_PILOT_POLICY_PATH`
  is unaffected.

---

## Verification Contract

1. `uv run ruff check` — clean.
2. `uv run mypy src` — clean.
3. `uv run pytest` — all green, including the new U3 cases.
4. Manual proof the positive trigger now allows and the seven negatives deny
   (the U3 parametrized suite IS this proof, run against the shipped policy).
5. The new positive test fails when U1+U2 are reverted (fix-exercising check).

---

## Definition of Done

- `bash-git-show-redirect` rule added before `bash-git-readonly` (U1).
- `_bash_allow_is_chain_safe` honors the rule as a sanctioned exception, placed
  after the universal vetoes (U2).
- Shipped-policy tests: positive trigger allows; all seven negatives deny;
  pre-existing denials unaffected (U3).
- `ruff` + `mypy` + `pytest` green.
- PR opened with `Closes #35`; **not** author-self-merged (AC4 — security
  boundary, per Mika Prime).

---

## Sources & Research

- cpp#35 issue body (root-cause analysis, n=3 class finding, ACs).
- `/tmp/spawn-brief-cpp35-mika-pipeline.md` — architect-prescribed patch + hard
  constraints + concrete trigger/regression list.
- mika-arch session 783d4a04 — GROOMED verdict (prescribed YAML sketch +
  rationale).
- `docs/solutions/security-issues/command-string-policy-allow-rules-are-compound-unsafe.md`
  — don't lex shell grammar; full-line-anchored sanctioned shapes; allow-list
  backstop; executed-exploit review.
- Code read at plan time: `permissions.yaml` (`bash-git-readonly` at the git
  block), `permissions.py` (`_bash_allow_is_chain_safe`,
  `_is_sanctioned_pure_heredoc`, handler veto path), `tier1.py`
  (`is_tier3_dangerous` / `TIER3_PATTERNS` redirect ban), `policy.py`
  (`evaluate` uses `re.search`), `tests/test_policy_devpilot.py` (`_effective`,
  `test_bundled_*`, `test_guard_*`).
