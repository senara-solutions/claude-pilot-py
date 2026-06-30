---
artifact_contract: ce-unified-plan/v1
artifact_readiness: implementation-ready
execution: code
product_contract_source: ce-plan-bootstrap
origin: cpp#37
plan_depth: lightweight
---

# fix: Veto bash 5.3 K-style funsub `${ ...; }` in the command-substitution chain-safety gate

**Target repo:** claude-pilot-py
**Issue:** senara-solutions/claude-pilot-py#37
**Branch:** `fix/37/k-style-funsub-bash-5-3-not-in-substitution`

---

## Summary

The chain-safety gate `_bash_allow_is_chain_safe` (`src/claude_pilot/permissions.py`) vetoes
every command-substitution form that could smuggle execution into a policy-allowed command —
backtick, `$'…'`, and any un-allowlisted `$(…)`. bash 5.3 added a **fourth** substitution form,
K-style command substitution `${ command; }` / `${| command; }`, with the same injection power as
`$(…)`. It is not vetoed, so `gh pr list --base ${ evil }` reaches the allow path. This plan adds
one structural veto for the funsub opening token, matching the closed-world syntactic-marker shape
the architect ratified for cpp#34/#35 (mika-arch session `783d4a04`).

## Problem Frame (WHY)

- **Evidence — code:** `permissions.py:220` vetoes `` ` `` and `$'`; `permissions.py:222` routes
  `$(` to the closed-world allowlist; **nothing** handles `${`. (The cpp#37 issue body references a
  stale `_SUBSTITUTION_MARKERS` tuple — that constant no longer exists post-cpp#34; the live checks
  are the inline string tests at `permissions.py:220-225`.)
- **Evidence — bash 5.3 grammar (verified on this host, GNU bash 5.3.9):** K-style funsub opens with
  `${` immediately followed by whitespace (space / tab / newline) or `|`. Parameter expansion
  (`${HOME}`, `${PATH}`, `${#arr[@]}`, `${VAR:-default}`) requires `${` immediately followed by an
  identifier or special-parameter char — **never** whitespace or `|`. The two token shapes are
  cleanly separable by the byte after `${`. Confirmed: `${ HOME}` (space after `${`) is parsed by
  bash 5.3 as a funsub opener, not as parameter expansion — so vetoing the whitespace form is correct,
  not a false positive.
- **Evidence — exploit shape (cpp#37 body):** `gh pr list --base ${ evil }` has no internal `;`, so it
  does not trip `_split_compound_command` segmentation and currently reaches the allow path. Reliance
  on segment-splitting is incidental defense, exactly what `docs/solutions/security-issues/command-string-policy-allow-rules-are-compound-unsafe.md`
  warns against.
- **Architecture lineage:** mika-arch session `783d4a04` (cpp#34 verdict) — keep syntactic crudeness via
  literal/structural markers; never lex the substitution body. This change is a marker-set expansion of
  the same shape (adding a deny marker, the mirror of cpp#34's allow-allowlist).

## Requirements

- **R1.** `_bash_allow_is_chain_safe` returns `False` for any command containing a K-style funsub opener
  (`${` followed by whitespace or `|`). (cpp#37 AC1)
- **R2.** `${name}`-style parameter expansion — including the braced `${HOME}` form — continues to be
  honored where the rest of the command is allow-safe. (cpp#37 AC2)
- **R3.** Detection is by **opening-token shape only** — no lexing or parsing of the funsub body.
  (cpp#37 hard rule; architect `783d4a04`)
- **R4.** Tests cover both funsub-veto and parameter-expansion-allow, including cpp#37's adversarial
  harness rows. (cpp#37 AC3, AC4)

## Key Technical Decisions

- **KTD1 — Veto `${` + (whitespace | `|`), via a compiled regex.** Add a module-level
  `_FUNSUB_OPENER_RE = re.compile(r"\$\{[\s|]")` and veto on `.search()` match, placed alongside the
  existing backtick / `$'` veto at `permissions.py:220`. This is cpp#37's option (c) refined to the
  exact bash 5.3 discriminator.
  - *Why not option (a) "add `${` to a marker list":* over-blocks — kills every `${HOME}` parameter
    expansion. Rejected.
  - *Why not option (b) "match `${ ` literal with trailing space":* misses the tab, newline, and `|`
    funsub forms. Rejected.
  - *Why regex over a few `in` substring checks:* the funsub opener is a *class* of bytes after `${`
    (space, tab, newline, `|`), not a fixed string. A single anchored regex expresses the class exactly
    and reads as one structural marker. `\s` covers space/tab/newline/CR/FF/VT — a superset of bash's
    funsub-delimiter set; over-matching here only ever *vetoes* (the safe direction) and never blocks a
    legitimate `${name}` (which never has whitespace after `${`).
- **KTD2 — Ordering: funsub veto runs in the same early block as backtick / `$'`, before the `$(`
  allowlist redaction.** It is an unconditional veto (no allowlist), so it belongs with the other
  unconditional substitution vetoes and must run before any `git show` redirect exception (mirroring the
  existing comment at `permissions.py:236-238` that substitution vetoes precede the redirect rule).
- **KTD3 — No funsub allowlist.** Unlike `$(`, there is no closed-world allowlist for `${…}` funsubs.
  Per cpp#34 discipline and cpp#37 out-of-scope, any future safe-funsub allowance is a separate
  evidence-gated ticket, not part of this change.

## Implementation Units

### U1. Add the K-style funsub veto to the chain-safety gate

- **Goal:** Veto any command whose substitution surface contains a bash 5.3 funsub opener, without
  touching parameter expansion.
- **Requirements:** R1, R3
- **Dependencies:** none
- **Files:**
  - `src/claude_pilot/permissions.py` (modify)
- **Approach:**
  - Add module-level `_FUNSUB_OPENER_RE = re.compile(r"\$\{[\s|]")` near the other substitution
    constants (`_SUBSTITUTION_ALLOWLIST` block, ~`permissions.py:116`), with a comment block
    explaining the bash 5.3 grammar discriminator (`${` + whitespace/`|` = funsub opener; `${` +
    identifier = parameter expansion) and citing cpp#37 + architect `783d4a04`.
  - In `_bash_allow_is_chain_safe`, extend the early veto at `permissions.py:220` so the funsub opener
    is rejected together with backtick / `$'`: `if "`" in command or "$'" in command or _FUNSUB_OPENER_RE.search(command): return False`.
  - Update the explanatory comment at `permissions.py:213-220` to name the funsub form alongside
    backtick / `$'` as a never-allowlistable substitution.
- **Patterns to follow:** the existing backtick / `$'` veto line and the `_BARE_AMP_RE` /
  `_SANCTIONED_HEREDOC_OPENER_RE` compiled-regex-constant convention already in this file.
- **Technical design (directional, not spec):** the discriminator is purely the byte after `${` —
  `[\s|]` → veto; identifier/`#`/`!`/`:` etc. → leave for the normal allow path. No body parsing.
- **Test scenarios:** covered by U2 (tests live in a separate unit/file).
- **Verification:** `uv run ruff check` and `uv run mypy src` clean; the new constant is referenced in
  the gate; manual `python -c` spot-check that `${ evil }` vetoes and `${HOME}` does not.

### U2. Test funsub veto + parameter-expansion regression

- **Goal:** Lock in R1/R2/R4 with the cpp#37 adversarial harness rows plus the braced-`${HOME}`
  positive regression.
- **Requirements:** R1, R2, R4
- **Dependencies:** U1
- **Files:**
  - `tests/test_policy_devpilot.py` (modify)
- **Approach:** Add tests mirroring the existing
  `test_guard_vetoes_command_substitution_even_double_quoted` (loop over cmd strings, assert
  `_bash_allow_is_chain_safe(...) is False`) and `test_guard_no_false_positive_on_var_expansion` styles.
  Note the existing positive regression at `tests/test_policy_devpilot.py:106` uses the **unbraced**
  `$HOME` form, which the new `${`-keyed check never touches — so a new **braced** `${HOME}` positive
  case is the one that actually guards against over-blocking and must be added.
- **Patterns to follow:** the `_bash(cmd)` helper and `_POLICY` fixture already used throughout the file;
  the cpp#34 test cluster (`permissions.py` import block at `tests/test_policy_devpilot.py:20`).
- **Test scenarios:**
  - *Funsub veto (R1, R4) — new `test_guard_vetoes_kstyle_funsub`:* assert `is False` for each of —
    - `gh pr list --head ${ git branch --show-current; }` (Covers cpp#37 AC harness row 1 — space + `;`)
    - `gh pr list --head ${ evil\n}` (Covers cpp#37 AC harness row 2 — space + newline terminator)
    - `gh pr list --base ${ evil }` (Covers cpp#37 AC1 / harness row 3 — no internal delimiter; the
      one that currently slips through)
    - `echo ${| REPLY=evil; }` (pipe form — the `${|` funsub variant)
    - `echo ${	evil; }` (tab-after-`${` form; use an actual `\t` in the literal)
  - *Parameter-expansion allow (R2) — new `test_guard_allows_braced_param_expansion`:* assert `is True`
    for `export PATH="${HOME}/.local/bin:$PATH" && which npm` (braced `${HOME}`, the at-risk form). A
    second positive row `echo ${PATH}` may be included for clarity.
  - *Edge — `${` with no following byte / end of string:* `echo ${` should not crash the gate
    (regex `.search` simply does not match → command proceeds to the normal path). Assert it does not
    raise; behavior is allow-path (no funsub opener present).
- **Verification:** `uv run pytest tests/test_policy_devpilot.py` green, including all new rows; full
  `uv run pytest` green.

### U3. Extend the substitution solution doc with the funsub marker-set expansion

- **Goal:** Record the bash 5.3 funsub surface and the discriminator in the canonical solution doc so
  the next reviewer of `permissions.py` sees it.
- **Requirements:** none (compounding hygiene; cpp#37 file list)
- **Dependencies:** U1
- **Files:**
  - `docs/solutions/security-issues/command-string-policy-allow-rules-are-compound-unsafe.md` (modify)
- **Approach:** Add a short subsection under the substitution discussion (and/or the "When to Apply"
  list) noting: bash 5.3 introduced `${ command; }` / `${| command; }`; it is vetoed structurally by the
  `${` + whitespace/`|` opener marker; parameter expansion (`${name}`) is distinguished by the byte after
  `${`; no funsub allowlist exists (closed-world, evidence-gated). Cross-reference cpp#37 and the
  symmetric `permission_pre_classifier.rs` paired-audit candidate already listed in "Related".
- **Test scenarios:** Test expectation: none — documentation only.
- **Verification:** doc renders; the new content references cpp#37 and the discriminator rule.

## Scope Boundaries

**In scope:** the funsub-opener veto, its tests, and the solution-doc note.

### Deferred to Follow-Up Work / Out of scope

- Process substitution `<(` / `>(` — already covered defense-in-depth at `tier1.py:130-131` (cpp#37
  out-of-scope; no-op here).
- Allowlisting any safe `${…}` funsub — closed-world; future evidence-gated ticket only (KTD3).
- Policy-wide symlink/TOCTOU traversal containment — cpp#38, a separate ticket.

## Verification Contract

- `uv run ruff check` — clean.
- `uv run mypy src` — clean.
- `uv run pytest` — all tests green, including the new funsub-veto and braced-param-expansion rows.
- Manual bash 5.3 evidence (already gathered on GNU bash 5.3.9): funsub forms veto; `${HOME}` /
  `${PATH}` / `${#arr[@]}` / `${VAR:-default}` allow.

## Definition of Done

- R1–R4 satisfied; all four cpp#37 acceptance criteria met.
- `_bash_allow_is_chain_safe` vetoes `gh pr list --base ${ evil }` and the full cpp#37 harness; honors
  `${HOME}` braced parameter expansion.
- Solution doc extended.
- Pipeline gates (ruff, mypy, pytest) green. PR opened with `Closes #37`.

## Sources & Research

- cpp#37 issue body (spec + adversarial harness AC).
- `src/claude_pilot/permissions.py:116-260` (live substitution-handling code; the stale
  `_SUBSTITUTION_MARKERS` name in the issue body does not exist post-cpp#34).
- `tests/test_policy_devpilot.py:101-165` (existing substitution test cluster; param-expansion
  regression at line 106 uses unbraced `$HOME`).
- bash 5.3 grammar verified empirically on GNU bash 5.3.9 (this host).
- mika-arch session `783d4a04` (cpp#34 syntactic-marker verdict).
- `docs/solutions/security-issues/command-string-policy-allow-rules-are-compound-unsafe.md`.
