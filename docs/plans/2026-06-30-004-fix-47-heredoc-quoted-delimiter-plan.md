---
artifact_contract: ce-unified-plan/v1
artifact_readiness: implementation-ready
execution: code
product_contract_source: ce-plan-bootstrap
origin: cpp#47
plan_depth: lightweight
---

# fix: Restrict the sanctioned cat-heredoc to a quoted delimiter so the body can never execute substitutions

**Target repo:** claude-pilot-py
**Issue:** senara-solutions/claude-pilot-py#47
**Branch:** `fix/47/sanctioned-cat-heredoc-body-executes`

---

## Summary

The chain-safety gate `_bash_allow_is_chain_safe` routes a `<<` command to `_is_sanctioned_pure_heredoc`
and returns **before** the substitution-marker veto. The sanctioned-heredoc opener regex admits an
**unquoted** `EOF` delimiter (`<<EOF`), and with an unquoted delimiter bash **expands** the heredoc body —
so `$(…)`, backtick, and `${ …; }` funsub in the body execute (during heredoc expansion) while the gate
auto-approves the command. This plan tightens the opener regex to admit **only a quoted delimiter**
(`<<'EOF'` / `<<"EOF"`), which makes the body provably inert. One regex token, its comment, and the test
that currently blesses the vulnerable form.

## Problem Frame (WHY)

- **Evidence — code:** `_bash_allow_is_chain_safe` (`src/claude_pilot/permissions.py`) handles `<<` by
  `return _is_sanctioned_pure_heredoc(command)` — an early return **before** the backtick/`$'`/`$(`
  substitution veto. `_SANCTIONED_HEREDOC_OPENER_RE` ends in `(?:'EOF'|"EOF"|EOF)`; the bare `EOF`
  alternative admits an unquoted delimiter.
- **Evidence — bash 5.3.9 (verified on this host):** with `<<EOF` (unquoted) the body is expanded —
  `cat > /tmp/x <<EOF\nval=$(echo X)\nEOF` writes `val=X` (the substitution ran). With `<<'EOF'` **or**
  `<<"EOF"` the body stays literal (`val=$(echo X)` verbatim, no execution). Any quoting of the heredoc
  delimiter disables all body expansion; only the bare unquoted delimiter expands.
- **Evidence — no legitimate caller:** searched `mika-skills/` (dispatch-lib) and `claude-pilot-py/src/`
  for the sanctioned `cat > /tmp/<token>` heredoc emitter — zero runtime callers (only an unrelated CI
  `$GITHUB_OUTPUT` heredoc and the permissions.py comments). Writing literal `$(…)` *content* to a file
  requires a quoted delimiter anyway, so a quoted-only restriction breaks no real use.
- **Evidence — a test blesses the bug:** `tests/test_policy_devpilot.py::test_guard_allows_heredoc_body_with_substitution_text`
  asserts `cat > /tmp/x.txt <<EOF\nfoo=$(date)\n…\nEOF` (unquoted) is **allowed**, on the false premise
  "the heredoc BODY is inert data." It is not inert under an unquoted delimiter.
- **Lineage:** this completes the cpp#34/#35 "inert sanctioned write" intent and the §2 no-lexing
  discipline (mika-arch session `783d4a04`). Surfaced by the cpp#37 (#49) security review.

## Requirements

- **R1.** A sanctioned heredoc with an **unquoted** delimiter (`<<EOF` / `<<-EOF`) whose body contains
  `$(…)`, backtick, `$'…'`, or a `${ …; }` funsub is vetoed by `_bash_allow_is_chain_safe`. (cpp#47 AC1)
- **R2.** A sanctioned heredoc with a **quoted** delimiter (`<<'EOF'` / `<<"EOF"`) and an arbitrary literal
  body (including substitution *text*) continues to be honored — the body is provably inert. (cpp#47 AC2)
- **R3.** All existing heredoc tests stay green. (cpp#47 AC3)
- **R4.** Detection adds no body lexing — the change is a tightening of the opener-token regex only.

## Key Technical Decisions

- **KTD1 — Drop the bare `EOF` alternative from the opener regex (option a).** Change the delimiter group
  `(?:'EOF'|"EOF"|EOF)` → `(?:'EOF'|"EOF")` in `_SANCTIONED_HEREDOC_OPENER_RE`. A quoted delimiter makes
  bash treat the entire body as literal text (verified on bash 5.3.9 for both `'EOF'` and `"EOF"`), so the
  body can no longer execute any substitution — without scanning or lexing the body.
  - *Why not option (b) "scan the heredoc body for substitution markers":* re-introduces a body lexer (the
    exact thing §2/§4 of the solution doc says to remove) for no benefit — no caller needs the unquoted
    form, and the quoted-delimiter restriction is strictly simpler and closes the gap completely. Rejected.
- **KTD2 — The closing terminator stays unquoted `EOF`.** `_HEREDOC_TERMINATOR = "EOF"` and the body
  close-line match are unchanged: bash's *closing* delimiter line is always the bare word (never quoted),
  regardless of how the *opener* quoted it. Only the opener's delimiter quoting controls body expansion.

## Implementation Units

### U1. Tighten the sanctioned-heredoc opener to a quoted delimiter

- **Goal:** Admit the sanctioned `cat > /tmp/<token>` heredoc only with a quoted delimiter, so the body
  is inert.
- **Requirements:** R1, R2, R4
- **Dependencies:** none
- **Files:**
  - `src/claude_pilot/permissions.py` (modify)
- **Approach:**
  - In `_SANCTIONED_HEREDOC_OPENER_RE`, change the trailing delimiter alternation
    `(?:'EOF'|"EOF"|EOF)` → `(?:'EOF'|"EOF")` (drop the bare unquoted `EOF`).
  - Update the comment block above the regex and the `_is_sanctioned_pure_heredoc` docstring to state the
    quoted-delimiter requirement and **why**: an unquoted delimiter makes bash expand the body (executing
    `$(…)`/backtick/`${ …; }`), so the "inert file write" guarantee holds only for a quoted delimiter.
    Cross-reference cpp#47 and the §2 heredoc lesson.
  - Leave `_HEREDOC_TERMINATOR` and the body close-line logic untouched (KTD2).
- **Patterns to follow:** the existing full-line-anchored opener regex and its comment style; the §2
  hard-coded-`EOF` discipline already documented in the file.
- **Test scenarios:** covered by U2.
- **Verification:** `uv run ruff check` / `uv run mypy src` clean; manual spot-check that an unquoted-`<<EOF`
  sanctioned heredoc with `$(date)` in the body now vetoes and a quoted-`<<'EOF'` one still allows.

### U2. Re-point the heredoc-body test from "blesses the bug" to "quoted inert, unquoted vetoes"

- **Goal:** Replace the test that asserts the vulnerable unquoted form is allowed with one that pins the
  fixed contract.
- **Requirements:** R1, R2, R3
- **Dependencies:** U1
- **Files:**
  - `tests/test_policy_devpilot.py` (modify)
- **Approach:** Rewrite `test_guard_allows_heredoc_body_with_substitution_text` (the current body asserts
  unquoted `<<EOF` with `$(date)` is allowed — that is the bug). Split into two assertions, mirroring the
  existing `_bash`/`_POLICY` helpers and the heredoc test cluster:
  - **Quoted → allow (R2):** `cat > /tmp/x.txt <<'EOF'\nfoo=$(date)\nrm -rf /tmp/build\nEOF` and the
    `<<"EOF"` variant, each `is True` — the body is literal text, provably inert.
  - **Unquoted → veto (R1):** `cat > /tmp/x.txt <<EOF\nfoo=$(date)\nEOF`, plus body variants carrying a
    backtick (`` `id` ``) and a `${ id; }` funsub, each `is False`.
- **Patterns to follow:** the `_bash(cmd)` helper, `_POLICY` fixture, and the existing heredoc tests
  (`test_guard_exempts_sole_command_heredoc` uses `<<'EOF'`).
- **Test scenarios:**
  - *Quoted-delimiter inert body allows (R2):* `<<'EOF'` body with `$(date)` + `rm -rf …` → True; `<<"EOF"`
    body with `$(date)` → True.
  - *Unquoted-delimiter body with substitution vetoes (R1):* `<<EOF` body with `$(date)` → False;
    `<<EOF` body with `` `id` `` → False; `<<EOF` body with `${ id; }` → False.
  - *Regression — other heredoc tests unaffected (R3):* running the full file leaves
    `test_guard_exempts_sole_command_heredoc`, `test_guard_closes_heredoc_trailing_chain_residual`,
    `test_guard_vetoes_heredoc_leading_edge_chain`, `test_guard_vetoes_heredoc_delimiter_desync`,
    `test_guard_heredoc_token_cannot_smuggle_a_chain`, `test_guard_vetoes_herestring_desync` all green.
- **Verification:** `uv run pytest tests/test_policy_devpilot.py` green; full `uv run pytest` green.

### U3. Record the fix in the substitution solution doc

- **Goal:** Update the canonical solution doc so the heredoc lesson reflects the quoted-delimiter
  requirement and the cpp#47 gap is marked closed.
- **Requirements:** none (compounding hygiene; cpp#47 file list)
- **Dependencies:** U1
- **Files:**
  - `docs/solutions/security-issues/command-string-policy-allow-rules-are-compound-unsafe.md` (modify)
- **Approach:** In §2 (the heredoc lesson), add that the sanctioned heredoc requires a **quoted** delimiter
  because an unquoted delimiter expands the body (executing substitutions) — the close-point fix (§2) made
  the *terminator* safe, but body expansion is a separate axis the quoted delimiter closes. Update the
  cpp#47 "known-open gap" bullet in **Related** to record the fix landed (quoted-delimiter restriction).
  Add `claude-pilot-47` to the tags if not present.
- **Test scenarios:** Test expectation: none — documentation only.
- **Verification:** doc renders; §2 + Related reflect the landed fix.

## Scope Boundaries

**In scope:** the opener-regex tightening, its test re-point, and the solution-doc update.

### Deferred to Follow-Up Work / Out of scope

- cpp#38 — policy-wide symlink/TOCTOU traversal containment (different mechanism).
- Any funsub / `$(` allowlist for heredoc bodies — not needed; the quoted-delimiter restriction makes the
  body inert wholesale.

## Verification Contract

- `uv run ruff check` — clean.
- `uv run mypy src` — clean.
- `uv run pytest` — all green, including the re-pointed heredoc-body test and the unchanged heredoc cluster.
- Manual bash 5.3.9 evidence (already gathered): `<<EOF` expands the body; `<<'EOF'`/`<<"EOF"` keep it literal.

## Definition of Done

- R1–R4 satisfied; all four cpp#47 acceptance criteria met.
- `_bash_allow_is_chain_safe` vetoes an unquoted-delimiter sanctioned heredoc whose body carries a
  substitution; honors the quoted-delimiter form with an inert literal body.
- Solution doc updated.
- ruff / mypy / pytest green. PR opened with `Closes #47`.

## Sources & Research

- cpp#47 issue body + groomed comment (resolved design, evidence).
- `src/claude_pilot/permissions.py` — `_SANCTIONED_HEREDOC_OPENER_RE`, `_is_sanctioned_pure_heredoc`,
  `_bash_allow_is_chain_safe` (the `<<` early-return path).
- `tests/test_policy_devpilot.py` heredoc cluster (the `test_guard_allows_heredoc_body_with_substitution_text`
  test currently blesses the unquoted form).
- bash 5.3.9 delimiter-quoting expansion behavior verified empirically on this host.
- `docs/solutions/security-issues/command-string-policy-allow-rules-are-compound-unsafe.md` §2 / Related.
- mika-arch session `783d4a04` (cpp#34/#35 sanctioned-heredoc + no-lexing discipline).
