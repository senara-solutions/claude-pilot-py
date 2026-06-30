---
artifact_contract: ce-unified-plan/v1
artifact_readiness: implementation-ready
execution: code
product_contract_source: ce-plan-bootstrap
issue: senara-solutions/claude-pilot-py#45
branch: fix/45-make-verify-allowlist
architect_session: 783d4a04
---

# fix: tier1 closed-world `make verify-bundled-skills` allowlist

## Summary

Add a closed-world `make`-target allowlist to claude-pilot's tier1 deterministic
classifier so `make verify-bundled-skills` auto-approves, mirroring the existing
`cargo`/`npm` build-command handling. Only that one target is enumerated; every
other `make` target (notably `make deploy`) stays denied. This is the primary
(claude-pilot-py) half of mika#1639.

## Problem frame (WHY)

`src/claude_pilot/tier1.py` auto-approves `cargo {check,test,clippy,fmt,build,…}`
via `SAFE_CARGO_SUBCOMMANDS` / `is_safe_build_command`, but has **no `make`
handling at all**. When a headless pilot session runs `make verify-bundled-skills`
— the bundled-skill pre-merge gate introduced in mika#1575, which CI runs on every
PR via `.github/workflows/ci.yml` — during the `/ce:work` verification step, tier1
does not match it. The command falls through to the relay, which denies it, and the
session halts in an implementation-complete-but-unverified state with the PR stuck
in draft.

`make verify-bundled-skills` is the same operation class tier1 already trusts for
cargo/npm: read-only verification, no side effects beyond stdout and exit code.

**Hard evidence:** mika-dev's autonomous callback on mika PR #1638 (~09:51Z
2026-06-29) named the policy-deny on `make verify-bundled-skills` as a recurring
substrate blocker that left the PR in draft. Full write-up: mika#1639 (primary
section) and cpp#45.

**Architect verdict (on file — do not re-route):** mika-arch session `783d4a04`
(n=3 `permission-policy-errs-strict` class) ruled: keep syntactic crudeness as
defense-in-depth; expand per-rule allowlists by **closed-world enumeration**.
Sibling deliverables merged this morning under the same verdict — cpp#36
(substitution-inner allowlist, PR #36) and cpp#39 (`git show <SHA>:<path>` redirect,
PR #39). This is the third deliverable.

## Scope boundaries

**In scope:** a single enumerated make target (`verify-bundled-skills`) in cpp
`tier1.py`, with tests.

**Out of scope / deferred:**
- The **secondary** half of mika#1639 — the `## Acceptance criteria` case-sensitivity
  fix in mika's `scripts/verify-pipeline.sh` (`grep -q` → `grep -qi`). That code lives
  in the **mika** repo and is tracked there, not here.
- Any other `make` target (`make check`, `make lint`, etc.). Each future target needs
  its own evidence-gated ticket per the cpp#34 closed-world discipline. Do not
  generalize to "any read-only make target."

## Key technical decisions

**KTD1 — Full-string anchor, stricter than cargo.** The make matcher anchors the
whole sub-command: `^\s*make\s+(\S+)\s*$`. Cargo's `^\s*cargo\s+(\S+)` deliberately
allows trailing flags (`cargo build --release`), but `make` arguments can override
variables and change behavior, so the closed-world rule forbids *any* trailing token.
This is what makes AC4 hold.

**KTD2 — Chain safety is inherited, not re-implemented.** `is_safe_bash_command`
already splits compound commands (`_split_compound_command`) and requires
`all(_is_safe_sub_command(sub) for sub in sub_commands)` (`tier1.py:337`). So
`make verify-bundled-skills && rm -rf ~` denies because the `rm` sub-command is not
safe — not because of any anchoring in the make regex. Do **not** add redundant
single-regex chain guarding; the splitter owns chain safety (AC2).

**KTD3 — Case-sensitivity is free.** The regex matches the literal lowercase token
`make`, so `MAKE verify-bundled-skills` never matches (AC3). No extra logic.

## Implementation units

### U1. Add `is_safe_make_command` closed-world allowlist to tier1

**Goal:** auto-approve `make verify-bundled-skills` (and only that target) at tier1.

**Requirements:** AC1, AC4, AC5.

**Dependencies:** none.

**Files:**
- `src/claude_pilot/tier1.py` (modify)

**Approach:** In the "Safe build/test commands" region (near `SAFE_CARGO_SUBCOMMANDS`
/ `is_safe_build_command`, ~line 385-420), add:
- `SAFE_MAKE_TARGETS: frozenset[str] = frozenset({"verify-bundled-skills"})`
- `_MAKE_RE = re.compile(r"^\s*make\s+(\S+)\s*$")` — full-anchored, no trailing tokens
- `def is_safe_make_command(sub: str) -> bool:` returning
  `bool(m := _MAKE_RE.match(sub)) and m.group(1) in SAFE_MAKE_TARGETS` (written
  without the walrus if it reads cleaner; mirror `is_safe_build_command`'s style).

Then OR it into `_is_safe_sub_command` (`tier1.py:340-347`), alongside
`is_safe_build_command`. Add a short comment citing cpp#45 / mika#1639 / architect
783d4a04 and the closed-world rationale, mirroring the cpp#27 comment style already
in the file.

**Patterns to follow:** `is_safe_build_command` (the immediately-adjacent sibling)
for structure; the cpp#27 awk/sed comment block for the rationale-comment style.

**Test expectation:** covered by U2 (kept as a separate unit only for narration;
implementer may land both in one commit).

**Verification:** `is_safe_bash_command("make verify-bundled-skills")` returns True;
`make deploy` and unenumerated targets still return False.

### U2. Tests for the make allowlist (AC1–AC5)

**Goal:** lock the closed-world behavior against regression.

**Requirements:** AC1, AC2, AC3, AC4, AC5.

**Dependencies:** U1.

**Files:**
- `tests/test_tier1.py` (modify)

**Approach:** Add a small `make`-specific test section mirroring the existing
git/shell-specific blocks (e.g. `test_git_push_to_main_denied`,
`test_find_with_exec_denied`). Assert against `is_safe_bash_command(...)` (the public
entry) so the compound-split + all-subs-safe path is exercised end to end. Optionally
add `make verify-bundled-skills` to the existing `test_safe_commands` parametrize list
for the positive case.

**Test scenarios:**
- `is_safe_bash_command("make verify-bundled-skills")` is True. *(Covers AC1)*
- `is_safe_bash_command("make verify-bundled-skills && rm -rf ~")` is False. *(Covers AC2)*
- `is_safe_bash_command("MAKE verify-bundled-skills")` is False. *(Covers AC3)*
- `is_safe_bash_command("make verify-bundled-skills extra-arg")` is False. *(Covers AC4)*
- `is_safe_bash_command("make deploy")` is False. *(Covers AC5)*
- A pre-existing cargo/npm safe command (e.g. `cargo build --release`) still returns
  True — guards against allowlist-ordering regression. *(Covers AC5)*

**Verification:** `uv run pytest tests/test_tier1.py` passes; the five new
assertions are present and green.

## Acceptance criteria

- AC1 — `make verify-bundled-skills` is tier1 auto-approved (no operator confirmation).
- AC2 — `make verify-bundled-skills && rm -rf ~` is DENIED (compound-split + all-subs-safe; the `rm` sub fails).
- AC3 — `MAKE verify-bundled-skills` is DENIED (case-sensitive literal `make`).
- AC4 — `make verify-bundled-skills extra-arg` is DENIED (full-string anchor rejects trailing tokens).
- AC5 — `make deploy` remains DENIED; existing cargo/npm/shell allowlists unchanged (pure addition, no regression).

## Verification contract

1. `uv run ruff check`
2. `uv run mypy src`
3. `uv run pytest` (all green, including the five new `make` assertions)

## Definition of done

- `is_safe_make_command` added to `tier1.py`, OR'd into `_is_safe_sub_command`, closed-world (`verify-bundled-skills` only).
- Five AC tests in `tests/test_tier1.py`, all green.
- Lint + type + test gates pass.
- PR cites architect session `783d4a04`, references mika#1639, and `Closes #45`.

## Sources & research

- cpp#45 — this ticket (primary half of mika#1639).
- mika#1639 — coupled parent; secondary half (`scripts/verify-pipeline.sh`) lives in the mika repo.
- mika#1575 — `make verify-bundled-skills` introduction.
- cpp#36 (PR #36), cpp#39 (PR #39) — sibling closed-world allowlist expansions under architect 783d4a04.
- `src/claude_pilot/tier1.py:337` — `all(_is_safe_sub_command(...))` chain-safety invariant.
- `src/claude_pilot/tier1.py:404` — `is_safe_build_command` (pattern to mirror).
