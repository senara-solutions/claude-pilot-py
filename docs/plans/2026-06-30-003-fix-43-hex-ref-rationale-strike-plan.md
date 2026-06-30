---
artifact_contract: ce-unified-plan/v1
artifact_readiness: implementation-ready
execution: code
product_contract_source: ce-plan-bootstrap
title: "fix(permissions): strike source-immutability claim from bash-git-show-redirect rationale (cpp#43)"
date: 2026-06-30
issue: senara-solutions/claude-pilot-py#43
---

# fix: Strike source-immutability claim from `bash-git-show-redirect` rationale

## Summary

The deployed `bash-git-show-redirect` allow-rule justifies its safety with a claim
that is **empirically false**: that the `git show <ref>:<path>` source is an
"immutable git object." A peer-Claude adversarial review of cpp#PR39 proved on real
git that `git show deadbeef:file.txt` resolves `deadbeef` as a **hex-named branch**
(mutable, force-pushable), not as an abbreviated SHA — git's ref resolution does not
prefer a SHA over an identically-shaped ref name. The rule's regex `[a-f0-9]+:`
matches full SHAs, abbreviated SHAs, **and** hex-named branches/tags alike.

The rule's actual safety has never rested on source-immutability — it rests entirely
on the **destination validator** (no absolute path, no `~`, no `..`, no
shell-expansion). This is a rationale/comment defect, not a behavior defect: the
guard catches the practical exploit regardless. The fix corrects the rationale in the
two code locations that overstate it, and records the lesson in the solutions doc.

This is the same "overstated rationale" anti-pattern the solutions doc already warns
about in §5 (destination/symlink residual). §5 covers the **destination** side; this
adds the **source** side.

## Problem Frame

**Why now:** cpp#43 was filed with hard evidence (a real-git repro in the issue body).
A future reviewer reading "immutable git object" will trust a guarantee the regex does
not enforce and may compound on it (e.g. loosening the destination guard "because the
source is trusted"). The honest framing must be in the code before that happens.

**Decision (Option B, not Option A).** Do **not** tighten the regex to require a
full-length SHA. The founding cpp#35 use case — dispatch-lib's plan-import, which runs
`git show <8-char-abbrev-SHA>:...` — would regress. Abbreviated SHAs are legitimate and
in active use. The correct fix is to make the rationale honest: the source is *any
hex-shaped ref*, and safety rests on destination validation (plus the control-plane
denylist tracked in cpp#42).

## Scope Boundaries

**In scope:**
- Correct the `reason:` field of the `bash-git-show-redirect` rule in `permissions.yaml`.
- Correct the inline comment in `permissions.py` that repeats "immutable-object source."
- Add a solutions-doc subsection documenting the empirical finding and the lesson.

**Out of scope (hard constraints):**
- **No regex change.** `pattern: '^git\s+show\s+[a-f0-9]+:...'` stays byte-for-byte.
- **No behavior change.** The rule must match exactly the same command strings as before.
- **No widening** of `[a-f0-9]+` to other ref shapes.

### Deferred to Follow-Up Work
- cpp#42 (control-plane denylist) is the load-bearing co-defense referenced by the
  corrected rationale; it ships in parallel and is not implemented here.

## Key Technical Decisions

- **KTD1 — Option B (rationale, not regex).** Tightening to `{40}` would break
  abbreviated-SHA dispatch (cpp#35's founding trigger). The source genuinely *can* be
  any hex-shaped ref; the rule was always a destination guard. Document reality.
- **KTD2 — Correct both code copies, not just the YAML.** The immutability claim is
  duplicated: `permissions.yaml:122` (`reason:`) and `permissions.py:234` (branch
  comment). Leaving either uncorrected leaves the false claim live. Both must change.
- **KTD3 — No new behavior test.** Per the issue's Option B framing and the dispatch
  brief, this is rationale-only. The existing `bash-git-show-redirect` test suite
  already pins the allowed/denied byte sequences; those must stay green and unchanged,
  which *is* the regression guard for "no behavior change."

## Implementation Units

### U1. Strike the immutability claim in `permissions.yaml`

**Goal:** The `bash-git-show-redirect` rule's `reason:` field no longer asserts the
source is immutable; it states the source is any hex-shaped ref and that safety rests
on destination validation. (AC1, AC2)

**Files:**
- `src/claude_pilot/policies/permissions.yaml` (modify — `reason:` on the
  `bash-git-show-redirect` rule, currently line 122)

**Approach:** Replace the parenthetical "(immutable git object, no movable-ref TOCTOU)"
with honest framing: source is any hex-shaped ref (full SHA, abbreviated SHA, or
hex-named branch/tag); safety rests on the literal destination constraint, not source
immutability; cross-reference cpp#42. Keep the field a single readable line consistent
with the surrounding YAML `reason:` style. Do **not** touch `pattern:` or the comment
block above the rule (lines 111-117 do not claim immutability).

**Test scenarios:** `Test expectation: none — comment/metadata-only change to a YAML
`reason:` field; no code path reads `reason` for control flow. Behavior is pinned by
U3's existing-tests-green check.`

**Verification:** `reason:` field contains no "immutable" language; names "hex-shaped
ref" and destination validation; references cpp#42. `pattern:` byte-identical to origin.

### U2. Correct the duplicated claim in `permissions.py`

**Goal:** The inline comment at the `bash-git-show-redirect` honoring branch no longer
says "SHA-only (immutable-object) source." (AC1, AC2)

**Files:**
- `src/claude_pilot/permissions.py` (modify — comment near line 234, inside
  `_bash_allow_is_chain_safe`)

**Approach:** Reword "SHA-only (immutable-object) source" to "hex-shaped-ref source
(any ref the `[a-f0-9]+` shape matches — full/abbrev SHA or hex-named branch/tag;
NOT immutable)" while preserving the rest of the comment's load-bearing content (the
literal-target constraint, the fail-closed rule_id coupling, the symlink residual).
Comment text only — no code statements change. Optionally note line 96's reference
needs no change (it cites the rule by id, makes no immutability claim) — verify during
work, leave untouched if so.

**Test scenarios:** `Test expectation: none — comment-only change; no executable line
is modified.`

**Verification:** No "immutable" claim remains in `permissions.py`; the surrounding
logic (`evaluate` → `rule_id == "bash-git-show-redirect"` → `return True`) is unchanged.

### U3. Record the lesson in the solutions doc

**Goal:** A new subsection documents the empirical finding (hex-named refs resolve to
ref content, not abbreviated-SHA lookup) and the general lesson: when a regex's
syntactic intent diverges from what the matched bytes can refer to at runtime, document
the runtime semantics, not the shape. (AC3, AC4)

**Files:**
- `docs/solutions/security-issues/command-string-policy-allow-rules-are-compound-unsafe.md`
  (modify — add subsection after §6; extend frontmatter `tags` with `claude-pilot-43`)

**Approach:** Add `### 7. A regex's syntactic shape is not a runtime-identity guarantee
— document what the matched bytes can REFER TO, not what they look like`. Include the
`git show deadbeef:file.txt` repro and the ref-resolution note (git prefers the ref;
genuinely-ambiguous names emit `refname is ambiguous`). State the lesson and that this
was caught post-merge by friend-Claude adversarial review of cpp#PR39, corrected by
cpp#43. Update the §5 / "Accepted residuals" cross-references only if needed for
coherence (the source-side claim is now documented separately). The doc's
`last_updated` is already 2026-06-30.

**Test scenarios:** `Test expectation: none — documentation file.`

**Verification:** New subsection present with the empirical proof and lesson; frontmatter
`tags` includes `claude-pilot-43`; markdown renders (heading level consistent with §1–§6).

## Verification Contract

- `uv run ruff check` — clean (no Python behavior touched; comment edit only).
- `uv run mypy src` — clean.
- `uv run pytest` — all green, **including** the existing `bash-git-show-redirect`
  tests, with **no test file modified**. Green-unchanged tests are the regression proof
  that the rationale edit changed no behavior.
- Manual: `git diff` shows changes confined to `permissions.yaml` (`reason:` only),
  `permissions.py` (comment only), and the solutions doc. No `pattern:` line in the diff.

## Definition of Done

- AC1 — neither `permissions.yaml` nor `permissions.py` claims source-immutability.
- AC2 — rationale explicitly names "any hex-shaped ref" and destination-validation as
  the safety basis.
- AC3 — solutions doc has the new subsection with the empirical `deadbeef` proof.
- AC4 — no behavior change; existing tests green and unmodified.
- AC5 — PR body credits the friend-Claude post-merge finding (cpp#PR39 harness,
  orchestrator-CC session bba3bcac, 2026-06-30) and cross-references cpp#42.
- Quality gates (ruff, mypy, pytest) pass.

## Sources & Research

- Issue: senara-solutions/claude-pilot-py#43 (real-git repro in body).
- Dispatch brief: `/tmp/spawn-brief-cpp43-hex-ref-rationale.md` (orchestrator-CC bba3bcac).
- Existing rule: `src/claude_pilot/policies/permissions.yaml` `bash-git-show-redirect`.
- Existing honoring branch + symlink residual: `src/claude_pilot/permissions.py`
  `_bash_allow_is_chain_safe`.
- Prior learning (destination side, §5): `docs/solutions/security-issues/command-string-policy-allow-rules-are-compound-unsafe.md`.
