# Plan — mika#1409: prevent policy-denied Bash calls from crashing pilot sessions (prevention-only)

> - **Issue:** senara-solutions/mika#1409 (milestone-30 Loop Trustworthiness, p1-important)
> - **Branch:** `fix/1409/claude-pilot-policy-denied-bash-tool`
> - **Scope:** Prevention-only (Approach #2) per Mika Prime's 2026-06-05 scope-ruling. Approach #1 (recoverable denials) is DEFERRED to mika#1410.
> - **Hard constraint:** `permissions.py` UNCHANGED — cpp#20 joint-2 `interrupt=True` honest-halt contract preserved.

## WHY (problem + evidence)

When the headless claude-pilot model requests a Bash command the permission policy denies, the SDK returns `PermissionResultDeny(interrupt=True)` (cpp#20 joint 2) and the session **dies** with `error_during_execution` — no recovery, no plan, manual rescue required. This is correct policy enforcement meeting a model that didn't know the command was forbidden.

**n=2 hard evidence (2026-06-05):**

1. **`find -exec` crashed the mika#1381 groom.** claude-pilot log `6f97dc72-fcf4-4e1a-87c9-8cbc25a923fc.log:5`:
   > `[tool:request] Bash: find /data/.../mika-agent/src -name "*.rs" -exec grep -l "INTENT_GUARD\|EndTurn\|..."`
   > `[policy:deny] Bash: find ... [bash-find]`
   > `[error] error_during_execution`

   The model reached for `find … -exec` (RCE-class, always denied — `tier1.py:115`, `_FIND_DANGEROUS_RE:316`) to search code. It could have used the **Grep** tool, which is Tier-1 auto-approved (`tier1.py:29`). The groom produced no plan; task `5df7cb79` blocked.

2. **Cross-worktree `md5sum` crashed mika#1255 AC verification** (log `548191b8`): a path outside the worktree boundary, denied. The **Read** tool is not worktree-bounded (`tier1.py:29` — Read always Tier-1) and would have served the same goal.

The model has no preflight visibility into the deny-list, so it reaches for forbidden shell idioms when an equivalent native tool (Grep/Glob/Read/Edit/Write) is auto-approved.

## WHAT (the change — prevention-only)

Surface the most-commonly-denied Bash patterns and their auto-approved substitutes to the model **in the system prompt**, so it avoids reaching for them.

1. **`tier1.py`** — add `DENIED_BASH_PATTERNS_HINT: str`, a prose hint living next to the deny-list patterns it describes (single source of truth → no drift between enforcement and documentation). Names: `find … -exec/-delete` → Grep/Glob; paths outside the worktree → Read; `sed -i` → Edit; `>`/`>>` redirects → Write; `xargs`/`eval`/`bash -c`/`sh -c` → native tools.

2. **`agent.py`** — wire the hint into `ClaudeAgentOptions` via
   `system_prompt={"type": "preset", "preset": "claude_code", "append": DENIED_BASH_PATTERNS_HINT}`.
   The **preset+append** form is load-bearing: it preserves the Claude Code preset system prompt (the headless `/mika` + `/ce:*` pipeline depends on it) and only *appends* the hint. A plain-string `system_prompt` would replace the preset and break the pipeline.

**NOT touched:** `permissions.py` / cpp#20 joint-2 contract / recoverable-denial paths.

## Verification bar (not "tests pass")

- **Denial is real (deterministic):** unit test asserts the exact failing `find … -exec` command from the #1381 log is `is_safe_bash_command(...) == False` — i.e. the thing the hint steers around genuinely crashes a session.
- **Hint ships & is wired (deterministic):** unit tests assert `DENIED_BASH_PATTERNS_HINT` names find→Grep and outside-worktree→Read, and that `run_agent` passes it through `system_prompt` as a preset-append.
- **Behavioral (best-effort):** run a headless `claude` code-search turn with the appended hint mirroring the #1381 groom step; observe it uses Grep rather than `find -exec`. Reported honestly — prevention is probabilistic.

## Honest closure (mandatory)

Prevention reduces the *rate* of denied reaches; it does **not** close the session-fatality *class*. A novel denied pattern the hint didn't anticipate still crashes the session. The PR body and the mika#1409 close-comment must name this unshipped half and link **mika#1410** (the cpp#20 joint-2 contract-revision follow-up that closes the class).
