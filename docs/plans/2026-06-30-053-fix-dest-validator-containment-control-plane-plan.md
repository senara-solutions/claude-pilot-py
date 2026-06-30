---
artifact_contract: ce-unified-plan/v1
artifact_readiness: implementation-ready
execution: code
product_contract_source: ce-plan-bootstrap
title: "fix(permissions): destination-validator — worktree containment + control-plane denylist (cpp#38 + cpp#42)"
date: 2026-06-30
type: fix
issues: [38, 42]
branch: fix/dest-validator-38-42-containment-and-control-plane
origin: /tmp/spawn-brief-cpp-destination-validator.md
---

# fix(permissions): destination-validator — worktree containment + control-plane denylist

> **Target repo:** claude-pilot-py
> Closes cpp#38 and cpp#42 in one PR — both close residuals on the *same* set of
> write-capable structural permission rules and share one destination-validation
> code path. Splitting them would duplicate the operand-extraction plumbing.

---

## Summary

claude-pilot's deterministic permission policy admits three write-capable Bash
rules — `bash-git-show-redirect`, `bash-cp-mv`, `bash-mkdir` — purely by
**command-string shape**. The string check has no view of the filesystem, so two
empirically-confirmed bypasses survive it:

1. **cpp#38 — symlink traversal (out-of-worktree write).** A committed symlink
   `esc -> ../OUTSIDE` turns `git show <SHA>:payload > esc/passwd` (and the
   `cp`/`mv`/`mkdir` variants) into a write *outside* the worktree. The static
   regex rejects literal `../` but is blind to a symlinked intermediate
   component.
2. **cpp#42 — control-plane overwrite (in-worktree, higher severity).**
   `git show <SHA>:payload > .git/hooks/post-checkout` resolves to a *genuinely
   in-worktree* path, so even a containment check passes it — yet writing there
   executes code on next checkout / in CI / rewrites the agent's own slash
   commands and bundled skills. No symlink pre-plant required.

This plan adds a single **destination validator** invoked at the one chokepoint
every write-capable allow already flows through — `_bash_allow_is_chain_safe` in
`src/claude_pilot/permissions.py`. The validator runs two ordered checks on the
destination operand(s) of each write-capable rule: **(1) worktree containment
first** (load-bearing safety, closes cpp#38), **(2) control-plane denylist
second** (layered policy, closes cpp#42). Either failure vetoes the allow and
the pilot halts honestly via the existing `interrupt=True` path.

The plan does **not** harden against TOCTOU (symlink swapped between check and
exec). `pathlib.Path.resolve()` carries the same TOCTOU residual the Write tool's
`is_within_project` already accepts; that residual is documented, not closed
(out of scope, per architect verdict).

---

## Problem Frame

### Why the chokepoint is singular

`cp`/`mv`/`mkdir` are **not** in `SAFE_SHELL_COMMANDS` (`tier1.py`), and
`git show … > dest` is rejected by the Tier-1 metacharacter/danger scan because
of the `>`. So none of the three rules can be auto-approved at Tier 1. They reach
an `allow` **only** through the Tier-2 policy path:
`create_permission_handler.handler` → `evaluate(...) == allow` →
`_bash_allow_is_chain_safe(...)` (permissions.py:366). Inside that guard:

- `bash-git-show-redirect` short-circuits to `return True` via its `rule_id`
  (permissions.py:290).
- `bash-cp-mv` / `bash-mkdir` are honored in the per-segment loop
  (permissions.py:293–303): each segment is a clean policy allow and not
  tier3-dangerous, so the loop `continue`s.

This is confirmed by the existing learning doc: *"policy.evaluate … no compound
splitting, no danger scan (those live only in tier1.py, already bypassed by the
time the policy evaluator runs)."* Putting the destination validator inside
`_bash_allow_is_chain_safe` therefore gates **all three rules in one place** —
no per-rule duplication, and no second entry point to miss.

### What "destination" means per rule

| Rule | Command shape | Destination operand(s) to validate |
|------|---------------|-------------------------------------|
| `bash-git-show-redirect` | `git show <SHA>:<src> > <dest>` | the single redirect target after `>` |
| `bash-cp-mv` | `cp [flags] <src>… <dest>` / `mv …` | the **last** operand (and `-t <dir>` target if present) |
| `bash-mkdir` | `mkdir [-p] <dir>…` | **every** directory operand (mkdir takes N targets) |

Operand extraction is the fiddly core of this work: multi-source `cp`, multi-dir
`mkdir`, the `cp -t <dir> <src>…` target-flag form, and `>` whitespace variants
(`>x`, `> x`, `>  x`) all have to land on the right token(s).

---

## Scope Boundaries

### In scope
- Worktree-containment check on the destination operand of all three
  write-capable structural rules (cpp#38).
- Control-plane denylist check on the same operands (cpp#42).
- One shared validator code path; AC test matrices for both tickets.
- Extending the existing security learning doc with the static-shape-vs-runtime
  -containment crystallization.

### Out of scope (do not pull in)
- `tier1.py` `FIND_EXEC_SAFE_COMMANDS` — already shipped (cpp#57).
- Refactoring the native Write tool's `is_within_project` — this work *mirrors*
  its semantics for shell rules; it does not touch Write.
- Adding control-plane paths beyond the 6 enumerated — evidence-gated future
  tickets only.
- `O_NOFOLLOW` / `openat` TOCTOU hardening — `Path.resolve()` residual is
  accepted (architect verdict; Write tool accepts the identical residual).
- `bash-cat-heredoc-tmp` — already `/tmp`-pinned by its anchored rule; not a
  worktree-relative destination. (Note it in the doc as audited-and-excluded.)

---

## Key Technical Decisions

### KTD-1 — Single validator at `_bash_allow_is_chain_safe`, not per-rule call sites
The chokepoint argument above. One insertion point gates all three rules and any
future write-capable rule that flows through the same allow-honoring guard.
Rationale: the brief's "one helper, four call sites" intent is best served by
*one* guard function at the *one* place allows are honored, rather than literally
sprinkling calls at each `rule_id` branch.

### KTD-2 — Thread `cwd` (worktree root) into the validation
Both checks are filesystem-relative and need the worktree root. `cwd` lives in
`create_permission_handler`'s closure but `_bash_allow_is_chain_safe` does not
currently receive it. Decision: pass `cwd` into the destination-validation path
(extend `_bash_allow_is_chain_safe`'s signature, or factor the destination check
into a sibling guard called from the handler with `cwd` in scope — implementer's
call at `ce-work` time; both keep `cwd` flowing from the handler). The containment
helper reuses `tier1.is_within_project`'s resolution semantics
(`Path.resolve(strict=False)`).

### KTD-3 — Containment FIRST, control-plane SECOND
Containment is the load-bearing safety boundary; control-plane is layered policy
on an already-contained path. Order is observable: an out-of-worktree symlinked
control-plane-looking path must be denied as *containment* failure (cpp#38), not
mislabeled. Implement as: resolve → assert within worktree (else deny) → compute
canonical worktree-relative path → literal-prefix match against denylist (else
deny) → allow.

### KTD-4 — Control-plane denylist: anchored literal-prefix on the *resolved*
worktree-relative path
Match the canonical relative path (post-resolve, via `.relative_to(worktree_root)`),
not the raw string — this makes the denylist robust to `./` prefixes and to a
symlink that lands inside the worktree but inside the control plane. Patterns
(each with inline rationale in code):

```
^\.git/                                       # hooks/config exec on checkout
^\.github/workflows/                          # runs in CI, broad token access
^\.claude/                                    # agent's own slash commands
^skills/bundled/                              # bundled skills the pilot trusts
^crates/mika-agent/src/well_known_agents\.rs$ # mika agent identities
^\.mika/                                       # runtime config
```

`.gitignore` (top-level) must NOT match — anchor `^\.git/` with the trailing
slash so a sibling dotfile passes. Use a symbolic constant tuple so audits are
one-stop.

### KTD-5 — No regex on inner content; structural shape only
Canonicalization is `Path.resolve()`; denylist is literal-prefix. No parsing of
file contents, no source-side inspection. Consistent with the whole-file
learning doc: the gate is a pre-exec shape filter, not a runtime sandbox.

### KTD-6 — Fail closed
If operand extraction is ambiguous/unparseable for a write-capable rule, deny
(do not allow an un-validated destination). Mirrors the existing rule_id
fail-closed coupling: when in doubt, route to deny, the safe direction.

---

## High-Level Technical Design

Decision flow for a write-capable rule's policy `allow`, inside the chain-safety
guard:

```mermaid
flowchart TD
    A[policy evaluate == allow<br/>rule is write-capable] --> B[extract destination operand(s)]
    B -->|extraction ambiguous| DENY[veto allow → interrupt=True halt]
    B --> C{for each dest:<br/>resolve + within worktree?}
    C -->|no — escapes worktree| DENY
    C -->|yes| D{resolved rel-path<br/>matches control-plane denylist?}
    D -->|yes| DENY
    D -->|no| E[next dest]
    E -->|all dests clean| ALLOW[honor allow]
```

Non-write-capable rules and non-Bash tools bypass the validator unchanged
(current `_bash_allow_is_chain_safe` behavior preserved).

---

## Implementation Units

### U1. Destination-operand extraction helpers
**Goal:** Pure functions that pull the destination operand(s) out of each
write-capable command shape, fail-closed on ambiguity.
**Requirements:** cpp#38 AC38.1–38.4, cpp#42 AC42.1–42.6 all depend on correct
operand extraction.
**Dependencies:** none.
**Files:**
- `src/claude_pilot/permissions.py` (new private helpers, e.g.
  `_extract_write_destinations(rule_id, command) -> list[str] | None`)
- `tests/test_policy_devpilot.py` (extraction unit tests)
**Approach:** One extractor keyed on `rule_id`. For `bash-git-show-redirect`,
split on the redirect operator and take the post-`>` token (reuse the anchored
YAML pattern's structure for the target group rather than re-lexing). For
`bash-cp-mv`, return the last positional operand; also handle `-t <dir>` /
`--target-directory=<dir>`. For `bash-mkdir`, return all non-flag operands.
Return `None` on anything that doesn't cleanly parse → caller denies.
**Patterns to follow:** existing anchored-regex rule shapes in
`permissions.yaml`; fail-closed `rule_id` coupling at permissions.py:290.
**Test scenarios:**
- `git show abc123:payload > esc/passwd` → `["esc/passwd"]`.
- `git show abc123:legit > docs/plans/X-plan.md` → `["docs/plans/X-plan.md"]`.
- `>x`, `> x`, `>  x` whitespace variants all extract `x`.
- `cp a b` → `["b"]`; `cp a b c dest/` → `["dest/"]`; `cp -t out/ a b` →
  `["out/"]`.
- `mv src esc/passwd` → `["esc/passwd"]`.
- `mkdir esc/newdir` → `["esc/newdir"]`; `mkdir -p a/b c/d` → `["a/b", "c/d"]`.
- Unparseable/empty destination → `None` (fail closed).
- Edge: `cp` with only one operand (no dest) → `None`.

### U2. Worktree-containment check (cpp#38)
**Goal:** Reject any destination that resolves outside the worktree root,
including via committed symlink.
**Requirements:** cpp#38 AC38.1–38.6.
**Dependencies:** U1.
**Files:**
- `src/claude_pilot/permissions.py` (e.g.
  `_check_destination_within_worktree(dest, cwd) -> bool`)
- `tests/test_policy_devpilot.py`
**Approach:** Mirror `tier1.is_within_project` semantics —
`Path.resolve(strict=False)` resolves symlinks on existing components and leaves
the non-existent tail as-is; then `.relative_to(resolved_cwd)`; `ValueError` →
outside → deny. Import/reuse `is_within_project` directly if its signature fits,
rather than reimplementing.
**Patterns to follow:** `tier1.py:825 is_within_project`.
**Test scenarios (build a real worktree via `tmp_path`, plant a symlink
`esc -> ../OUTSIDE`):**
- Covers AC38.1: resolved `esc/passwd` (symlink → outside) → not within → False.
- Covers AC38.5/38.6: `docs/plans/X-plan.md`, `docs/plans/copy.md` (real
  in-worktree paths) → within → True.
- Absolute path `/etc/passwd` → False.
- Non-existent-but-in-worktree tail `docs/plans/new.md` → True (tail left as-is).
- `cwd` does not resolve (bad root) → False (mirror `is_within_project` OSError
  guard).

### U3. Control-plane denylist check (cpp#42)
**Goal:** Reject an in-worktree destination that lands on the agent's control
plane.
**Requirements:** cpp#42 AC42.1–42.7.
**Dependencies:** U1, U2 (operates on the post-containment resolved rel-path).
**Files:**
- `src/claude_pilot/permissions.py` (denylist constant +
  `_is_control_plane_path(dest, cwd) -> bool`)
- `tests/test_policy_devpilot.py`
**Approach:** Compute the canonical worktree-relative path (resolve, then
`relative_to(worktree_root)`), normalize to POSIX, literal-prefix match against
the symbolic denylist tuple. Each entry carries an inline rationale comment.
**Patterns to follow:** anchored-pattern + per-entry rationale style already used
across `permissions.yaml` rules.
**Test scenarios:**
- Covers AC42.1: `.git/hooks/post-checkout` → True (deny).
- Covers AC42.2: `.github/workflows/ci.yml` → True.
- Covers AC42.3: `.claude/commands/mika.md` → True.
- Covers AC42.4: `skills/bundled/_shared/dispatch-lib.sh` → True.
- Covers AC42.7: `.gitignore` (top-level) → False (allow).
- `well_known_agents.rs` at the exact path → True; a same-named file elsewhere →
  False (anchored `$`).
- `.mika/config` → True.
- `docs/.claude-test/x` → False (not the real control plane — prefix is
  `docs/`, not `^\.claude/`).

### U4. Wire the validator into the allow-honoring guard
**Goal:** Invoke extraction → containment → control-plane for every
write-capable rule allow, before the guard returns `True` / `continue`s.
**Requirements:** all ACs (integration seam).
**Dependencies:** U1, U2, U3.
**Files:**
- `src/claude_pilot/permissions.py` (`_bash_allow_is_chain_safe` and/or the
  handler call site; thread `cwd` per KTD-2)
- `tests/test_policy_devpilot.py` (end-to-end through the handler / guard)
**Approach:** At the `bash-git-show-redirect` short-circuit (permissions.py:290)
and the cp/mv/mkdir segment-loop `continue` (293–303), gate on
`_destination_is_safe(rule_id, command, cwd)` = extract (deny on `None`) →
containment (deny on escape) → control-plane (deny on match). A veto returns the
same `PermissionResultDeny(interrupt=True)` shape the chain-danger guard already
uses, with a clear reason string. Preserve all existing positive paths.
**Patterns to follow:** the existing chained-danger veto at permissions.py:366–373.
**Test scenarios (full AC matrices, exercised through the public guard/handler):**
- Covers AC38.1–38.4: symlink-escape `git show / cp / mv / mkdir` variants →
  DENY (`interrupt=True`).
- Covers AC38.5–38.6: legit in-worktree `git show` redirect + `cp` → ALLOW.
- Covers AC42.1–42.6: each control-plane destination across `git show` and `cp`
  → DENY.
- Covers AC42.7: `.gitignore` write → ALLOW.
- Regression: the existing `test_bundled_allows_git_show_redirect_trigger` and
  `test_bundled_allows_dev_pilot_footprint` cases stay green.
- Order check: an out-of-worktree symlink that *also* looks control-plane is
  denied — assert the deny fires (containment-first means it's caught before the
  denylist would even see a rel-path).

### U5. Extend the security learning doc + YAML rule comments
**Goal:** Crystallize the static-shape-vs-runtime-containment learning where the
next implementer will find it.
**Requirements:** brief's "Files" item; doc-audit gate.
**Dependencies:** U1–U4 (document what shipped).
**Files:**
- `docs/solutions/security-issues/command-string-policy-allow-rules-are-compound-unsafe.md`
  (extend; bump `last_updated`, add `claude-pilot-38`, `claude-pilot-42` tags)
- `src/claude_pilot/policies/permissions.yaml` (comment block on the three
  write-capable rules citing the new validator; rule logic stays in
  permissions.py)
**Approach:** Add a section: the policy is a pre-exec **shape filter**, not a
runtime sandbox; worktree containment + control-plane denial are the runtime-
adjacent checks that the shape filter structurally cannot do, now layered at the
allow-honoring chokepoint. Record the accepted TOCTOU residual and the
`bash-cat-heredoc-tmp` audited-and-excluded note.
**Test expectation:** none — documentation + comments only.

---

## Verification Contract

- `uv run pytest` — all pass; new AC tests present (count grows from 516 toward
  530+).
- `uv run ruff check` — clean.
- `uv run mypy src` — clean.
- Every write-capable structural rule (`bash-git-show-redirect`, `bash-cp-mv`,
  `bash-mkdir`) demonstrably routes through the validator — asserted by the U4
  matrix, and stated explicitly in the PR body.
- Both AC matrices (cpp#38 AC38.1–38.6, cpp#42 AC42.1–42.7) pass.

---

## Definition of Done

- One PR on branch `fix/dest-validator-38-42-containment-and-control-plane`,
  `Closes #38` and `Closes #42`.
- Containment-first / control-plane-second ordering implemented and asserted.
- Single validator chokepoint; no per-rule duplication; fail-closed on ambiguous
  extraction.
- Learning doc + YAML comments updated.
- All quality gates green.
- **Not author-self-merged** — security boundary; adversarial / executed-exploit
  review required before merge (handled at merge time, outside this plan).
- PR body lists every write-capable rule and confirms each routes through the
  validator; surfaces both AC matrices; notes the accepted `Path.resolve` TOCTOU
  residual and any substrate tickets for residual gaps.

---

## Risks & Residuals

- **TOCTOU (accepted).** `Path.resolve()` resolves symlinks at check time; a
  concurrent attacker could swap a symlink between check and exec. Theoretical
  under the single-sequential-model execution model; identical to the residual
  the Write tool already accepts. Documented, not closed.
- **Operand-extraction completeness.** `cp`/`mkdir` have many flag forms. The
  fail-closed default (deny on unparseable) bounds the blast radius: a missed
  form denies (safe), it does not silently allow. New legitimate forms that get
  denied are evidence-gated follow-ups.
- **Denylist completeness.** Six entries by design; broadening is evidence-gated.
  A control-plane path not yet listed remains writable if it passes containment —
  call this out in the doc so the boundary is loud.

---

## Sources & Research

- Spawn brief: `/tmp/spawn-brief-cpp-destination-validator.md` (architectural
  lineage, hard rules, AC matrices).
- cpp#38 body (symlink-traversal PoC, accepted-residual classification).
- cpp#42 body (control-plane PoC, peer-Claude harness on cpp#PR39).
- `src/claude_pilot/permissions.py:223–303` (`_bash_allow_is_chain_safe`,
  rule_id short-circuit, segment loop), `:358–386` (Tier-2 handler).
- `src/claude_pilot/tier1.py:825` (`is_within_project` reference semantics),
  `:392–413` (Tier-1 allowlist confirms cp/mv/mkdir excluded).
- `docs/solutions/security-issues/command-string-policy-allow-rules-are-compound-unsafe.md`
  (the "no danger scan at policy layer" statement that proves the chokepoint).
- mika-arch sessions `fe891012` (cpp#35 symlink-residual ratification at parity),
  `783d4a04` (no-realpath constraint context).
