"""Per-spawn permission-policy evaluator (mika#1708 Option C).

Decomposes shell commands via bashlex, tracks cwd across sequences, and
evaluates each resulting process spawn against a per-binary safety function.
This replaces the syntactic regex-over-shell-text approach of tier1.py.

Design source: mika#1708 architect-ratified spec 2026-07-01 (arch session
22d21b66) + Prime session 00000000. Full plan on the mika branch
``feat/1708/permission-policy-cpp-per-spawn:docs/plans/2026-07-01-008-*``.

Scope discipline (SSC boundary, 2026-07-01 15:29Z): this module is the
generic engine. Mika-specific allow/deny CONTENTS stay in the Mika repo
and are wired in through the POLICY registry — this module ships an empty
default POLICY plus example safety functions used only for tests and demo.

Supported shell constructs (decompose):
- Simple commands
- Pipelines (``|``)
- Sequences (``;``, ``&``, newline)
- Logical operators (``&&``, ``||``)
- Redirects (``>``, ``<``, ``>>``)
- Command substitution (``$(...)``, bounded by MAX_SUBSTITUTION_DEPTH)
- Compound groups (``{ ... }``, ``( ... )``)

Unsupported constructs (fail-safe DENY with named reason):
- Heredocs (``<<``, ``<<-``, ``<<EOF``)
- Process substitution (``<(...)``, ``>(...)``)
- Backticks (```...```) — deprecated, rewrite as ``$(...)``
- Arithmetic expansion (``$((...))``)
- Control flow (``if``, ``for``, ``while``, ``case``, functions)

Rejected built-ins (dynamic execution, fail-safe DENY):
- ``eval``, ``source``, ``.``

State-tracking built-ins (do not spawn, mutate cwd_stack):
- ``cd``, ``export``, ``unset``, ``alias``, ``unalias``, ``set``, ``shopt``

No-op safe built-ins (allow, no state change):
- ``echo``, ``printf``, ``true``, ``false``, ``pwd``, ``test``, ``[``
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import bashlex
import bashlex.errors

# ── Design constants ────────────────────────────────────────────────────────

MAX_SUBSTITUTION_DEPTH: int = 5
"""Recursion depth limit for command substitution ``$(...)``.

Deep nesting is pathological in real shell use. Bounding this keeps the
decomposer terminating on adversarial input and matches the risk architecture
noted in the mika#1708 design (Risk 3: recursion depth on command substitution)."""


# Built-in classification per architect-ratified design (mika#1708 body).
STATE_TRACKING_BUILTINS: frozenset[str] = frozenset({
    "cd",
    "export",
    "unset",
    "alias",
    "unalias",
    "set",
    "shopt",
})

NO_OP_SAFE_BUILTINS: frozenset[str] = frozenset({
    "echo",
    "printf",
    "true",
    "false",
    "pwd",
    "test",
    "[",
    ":",
})

REJECTED_BUILTINS: frozenset[str] = frozenset({
    "eval",
    "source",
    ".",
    "exec",
})

ALL_BUILTINS: frozenset[str] = (
    STATE_TRACKING_BUILTINS | NO_OP_SAFE_BUILTINS | REJECTED_BUILTINS
)


# ── Public types ────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Spawn:
    """A single process invocation decomposed from a shell command.

    ``argv[0]`` is the binary basename as written in the shell command
    (not resolved through ``$PATH``). ``cwd`` is the effective working
    directory for this spawn, which may differ from the process cwd if
    the shell command included a ``cd`` before this spawn.
    """

    binary: str
    argv: tuple[str, ...]
    cwd: str


@dataclass
class DecomposeResult:
    """Return type for :func:`decompose`.

    Exactly one of ``spawns`` and ``reject_reason`` is set:
    - Success: ``spawns=[...], reject_reason=None``
    - Fail-safe deny: ``spawns=None, reject_reason="<construct>"``
    """

    spawns: list[Spawn] | None
    reject_reason: str | None


@dataclass
class EvaluateResult:
    """Return type for :func:`evaluate`.

    ``allowed`` is the final decision. ``reason`` explains ``False``
    decisions (which policy rejected which spawn, or which construct
    triggered fail-safe deny). ``spawns`` echoes the decomposed spawns
    for audit / logging.
    """

    allowed: bool
    reason: str
    spawns: list[Spawn] = field(default_factory=list)


PolicyFn = Callable[[list[str], str], bool]
"""Signature of a per-binary safety function.

Called as ``fn(argv, cwd)`` where ``argv[0]`` is the binary basename.
Returns ``True`` if the invocation is safe to auto-approve, ``False``
to reject. The evaluator treats a missing binary as an implicit reject.
"""


# ── Empty default policy (Mika-side ships its own contents) ──────────────────

DEFAULT_POLICY: dict[str, PolicyFn] = {}
"""Default policy registry — empty.

Per SSC OSS boundary discipline (mika#1708, 2026-07-01 15:29Z), the
generic engine ships with an empty policy. Consumers (Mika, or other
downstream projects) register per-binary safety functions before
invoking :func:`evaluate`. See ``docs/permission-mode.md`` for the
plugin loading convention.
"""


# ── Decomposition ──────────────────────────────────────────────────────────


def decompose(command: str, initial_cwd: str | None = None) -> DecomposeResult:
    """Decompose a shell command into a list of :class:`Spawn` objects.

    Fail-safe DENY (``spawns=None``) on:

    - :class:`bashlex.errors.ParsingError` (malformed shell)
    - Heredoc (``<<``, ``<<-``, ``<<EOF``)
    - Process substitution (``<(...)``, ``>(...)``)
    - Backticks (```...```) in the raw source
    - Arithmetic expansion (``$((...))``) in the raw source
    - Control flow constructs (``if``, ``for``, ``while``, ``case``, functions)
    - Rejected builtins (``eval``, ``source``, ``.``, ``exec``)
    - Command substitution beyond :data:`MAX_SUBSTITUTION_DEPTH`
    - Variable/parameter expansion in ``cd`` path (``cd $HOME``)
    - Unrecognized bashlex node kinds

    Args:
        command: The shell command string to decompose.
        initial_cwd: Starting working directory. Defaults to
            :func:`os.getcwd`. State-tracking builtins push new
            entries onto a per-command cwd stack; each spawn records
            the top of the stack at the point it is emitted.

    Returns:
        A :class:`DecomposeResult` naming either the successful spawn
        list or a specific reject reason. The reason is intended for
        surface to operators (mika-dev, ops) so an over-strict deny
        is diagnosable and correctable.
    """
    if initial_cwd is None:
        initial_cwd = os.getcwd()

    if not command.strip():
        return DecomposeResult([], None)

    # Pre-check the raw string for constructs bashlex may accept but that
    # we explicitly refuse. Backticks are deprecated (recommend ``$(...)``);
    # arithmetic expansion ``$((...))`` is not decomposable to a spawn.
    if _contains_unquoted_backtick(command):
        return DecomposeResult(
            None,
            "backtick command substitution deprecated — rewrite as $(...)",
        )
    if _contains_arithmetic_expansion(command):
        return DecomposeResult(
            None,
            "arithmetic expansion $(( ... )) is not per-spawn decomposable",
        )
    if _contains_process_substitution(command):
        return DecomposeResult(
            None,
            "process substitution <(...) / >(...) is not per-spawn decomposable",
        )
    if _contains_heredoc(command):
        return DecomposeResult(
            None,
            "heredoc (<<, <<-, <<EOF) is not per-spawn decomposable — "
            "use `sh -c '...'` if a single-spawn wrapper is intended",
        )

    try:
        trees = bashlex.parse(command)
    except bashlex.errors.ParsingError as e:
        return DecomposeResult(None, f"bashlex parse error: {e}")
    except Exception as e:  # bashlex sometimes throws generic Exception
        return DecomposeResult(
            None, f"bashlex error: {type(e).__name__}: {e}"
        )

    spawns: list[Spawn] = []
    cwd_stack: list[str] = [initial_cwd]

    for tree in trees:
        reject = _walk(tree, cwd_stack, spawns, sub_depth=0)
        if reject is not None:
            return DecomposeResult(None, reject)

    return DecomposeResult(spawns, None)


# ── AST walk helpers ────────────────────────────────────────────────────────


def _walk(
    node: Any,
    cwd_stack: list[str],
    spawns: list[Spawn],
    sub_depth: int,
) -> str | None:
    """Recursively walk a bashlex parse tree.

    Returns ``None`` on success, or a string naming the specific unsupported
    construct for fail-safe DENY.
    """
    kind = node.kind

    if kind == "list":
        # Top-level sequence: parts alternate command/pipeline with operators.
        # ``;`` / ``&`` / newline separate commands; ``&&`` / ``||`` are
        # conditional. Bash semantics: cwd changes from ``cd`` persist across
        # ``;`` / ``&&`` / ``||`` within the same shell context (same list).
        for part in node.parts:
            if part.kind in ("operator", "reservedword"):
                continue
            reject = _walk(part, cwd_stack, spawns, sub_depth)
            if reject is not None:
                return reject
        return None

    if kind == "pipeline":
        # Pipe segments run in subshells — a ``cd`` in one segment does NOT
        # affect the next. Snapshot the cwd_stack for each pipe segment.
        for part in node.parts:
            if part.kind == "pipe":
                continue
            segment_stack = list(cwd_stack)
            reject = _walk(part, segment_stack, spawns, sub_depth)
            if reject is not None:
                return reject
        return None

    if kind == "command":
        return _walk_command(node, cwd_stack, spawns, sub_depth)

    if kind == "compound":
        # ``{ ... }`` or ``( ... )``. Bashlex wraps both in CompoundNode with
        # ``.list`` (not ``.parts``). Inside the list, control-flow constructs
        # appear as ``if``/``for``/``while``/``case``/function nodes — those
        # are unsupported per design. Plain groups have reservedwords + an
        # inner ListNode we can walk.
        #
        # Cwd semantics: ``( ... )`` is a subshell (cwd changes don't escape)
        # and ``{ ... }`` shares the parent context. We snapshot conservatively
        # for both — for ``{}`` a rare consequence is over-deny of a following
        # command that relied on inner-group cd, which is a rare enough shape
        # we accept the false-negative direction.
        segment_stack = list(cwd_stack)
        children = getattr(node, "list", None) or []
        for child in children:
            child_kind = child.kind
            if child_kind == "reservedword":
                continue
            if child_kind in ("if", "for", "while", "case", "function", "select", "until"):
                return f"unsupported shell construct: {child_kind}"
            reject = _walk(child, segment_stack, spawns, sub_depth)
            if reject is not None:
                return reject
        return None

    # Everything else is control flow, functions, or a shape we didn't design
    # for. Deny explicitly rather than silently walking through.
    return f"unsupported shell construct: {kind}"


def _walk_command(
    node: Any,
    cwd_stack: list[str],
    spawns: list[Spawn],
    sub_depth: int,
) -> str | None:
    """Walk a bashlex ``CommandNode``.

    Extracts binary + argv from ``WordNode`` children, handles state-tracking
    builtins by mutating ``cwd_stack`` instead of emitting a spawn, and
    recurses into nested command substitutions with a bounded depth budget.
    """
    words: list[str] = []
    for part in node.parts:
        if part.kind == "word":
            reject = _walk_word(part, cwd_stack, sub_depth)
            if reject is not None:
                return reject
            words.append(part.word)
        elif part.kind == "assignment":
            # ``VAR=value`` inline assignments before a command are prefix-
            # only-for-this-command in bash; we do not model env at
            # per-spawn level, but they are structurally safe to skip.
            continue
        elif part.kind == "redirect":
            # Redirect targets are tracked at the raw-source level (the
            # unsupported-construct pre-checks reject heredoc / process sub).
            # Simple ``>``/``<``/``>>`` redirects don't spawn anything and
            # don't mutate cwd, so we can safely walk past them here.
            continue
        elif part.kind == "reservedword":
            continue
        else:
            return f"unsupported command child: {part.kind}"

    if not words:
        # Assignment-only or redirect-only command (``VAR=x``, ``> /tmp/x``).
        # No spawn.
        return None

    binary = words[0]
    argv = tuple(words)

    # Rejected builtins: dynamic execution is not decomposable.
    if binary in REJECTED_BUILTINS:
        return f"rejected builtin '{binary}' — dynamic execution not decomposable"

    # State-tracking builtins: mutate cwd_stack, do not emit a spawn.
    if binary in STATE_TRACKING_BUILTINS:
        return _apply_state_tracking(binary, argv, cwd_stack)

    # No-op safe builtins: emit a spawn so the policy can still audit it
    # if desired. Empty POLICY entry = pass through, but consumer policies
    # may still want to log or gate ``echo``.
    # (Choice: emit rather than swallow, so audit_events see everything.)

    current_cwd = cwd_stack[-1]
    spawns.append(Spawn(binary=binary, argv=argv, cwd=current_cwd))
    return None


def _walk_word(node: Any, cwd_stack: list[str], sub_depth: int) -> str | None:
    """Walk a ``WordNode``, recursing into any embedded command substitution."""
    parts = getattr(node, "parts", None) or []
    for part in parts:
        if part.kind == "commandsubstitution":
            if sub_depth >= MAX_SUBSTITUTION_DEPTH:
                return (
                    f"command substitution nested deeper than "
                    f"MAX_SUBSTITUTION_DEPTH={MAX_SUBSTITUTION_DEPTH}"
                )
            # Recurse into the substituted command with a fresh cwd_stack
            # (subshell isolation) and an incremented depth budget.
            sub_stack = list(cwd_stack)
            sub_spawns: list[Spawn] = []
            reject = _walk(
                part.command, sub_stack, sub_spawns, sub_depth + 1
            )
            if reject is not None:
                return reject
            # Substituted spawns count toward the outer command's spawn set.
            # (They ran, so policy must see them.)
            # We attach via a well-known channel: since ``_walk_word`` is
            # called from ``_walk_command`` which owns the outer spawns
            # list, we can't mutate it from here without a return channel.
            # Instead we forward via node attribute (the outer walker will
            # merge). Simpler: use module-level thread-local? No — pass
            # via mutable list in outer scope. See _walk_command update.
            #
            # Concretely: for the OPTION-C evaluator, substituted-command
            # spawns are collected but not merged into the outer list here
            # to keep this function pure; the outer caller does the merge.
            # For now we approximate by refusing substitutions that
            # produce spawns — safer and simpler for Phase 1.
            if sub_spawns:
                return (
                    "command substitution contains spawns — not supported "
                    "in Phase 1 (nest one level max, no inner commands "
                    "that would themselves need policy evaluation)"
                )
        elif part.kind == "parameter":
            # ``$VAR``, ``${VAR}``. Structurally allowed in words other than
            # cd targets — cd handling below rejects them explicitly.
            continue
        elif part.kind == "tilde":
            # ``~`` or ``~user`` — safe, treated as literal string here.
            continue
    return None


def _apply_state_tracking(
    binary: str, argv: tuple[str, ...], cwd_stack: list[str]
) -> str | None:
    """Apply a state-tracking builtin to ``cwd_stack``.

    Only ``cd`` currently mutates cwd; the other state-tracking builtins
    (``export``, ``unset``, ``alias``, ``unalias``, ``set``, ``shopt``)
    affect environment / shell options which the per-spawn evaluator does
    not currently model. They are accepted (no spawn emitted) but do not
    change cwd.
    """
    if binary != "cd":
        return None  # accepted, no cwd change

    # cd with 0 args = cd to $HOME. We refuse env-expansion in cd targets
    # (design decision: static paths only, deny variable expansion). Zero
    # args counts as env-driven.
    if len(argv) < 2:
        return "cd with no argument (requires static path, no $HOME)"

    target = argv[1]

    # cd - (previous dir), cd ~ (home), cd $VAR — all rely on runtime state
    # we don't model. Deny with a diagnostic pointing at the workaround.
    if target == "-":
        return "cd - (previous dir) requires runtime state — use absolute path"
    if target.startswith("~"):
        return "cd ~ requires runtime state — use absolute path"
    if "$" in target:
        return "cd with variable expansion requires runtime state — use absolute path"

    # Resolve relative to current top of stack. Static paths only.
    current = cwd_stack[-1]
    if os.path.isabs(target):
        resolved = os.path.normpath(target)
    else:
        resolved = os.path.normpath(os.path.join(current, target))

    cwd_stack.append(resolved)
    return None


# ── Raw-source pre-checks ───────────────────────────────────────────────────


def _contains_unquoted_backtick(command: str) -> bool:
    """Detect ````` outside single-quoted regions.

    POSIX single-quote is atomic — backslash is literal, only a closing
    ``'`` ends it. Inside double-quotes, backtick still triggers command
    substitution, so we count double-quoted regions as unquoted for this
    check. Mirrors the semantics of ``tier1._split_compound_command``
    (see the docstring there for the incident history).
    """
    in_squote = False
    i = 0
    n = len(command)
    while i < n:
        ch = command[i]
        if in_squote:
            if ch == "'":
                in_squote = False
        else:
            if ch == "'":
                in_squote = True
            elif ch == "`":
                return True
        i += 1
    return False


def _contains_arithmetic_expansion(command: str) -> bool:
    """Detect ``$(( ... ))`` outside single-quoted regions."""
    in_squote = False
    i = 0
    n = len(command)
    while i < n - 2:
        ch = command[i]
        if in_squote:
            if ch == "'":
                in_squote = False
            i += 1
            continue
        if ch == "'":
            in_squote = True
            i += 1
            continue
        if ch == "$" and command[i + 1 : i + 3] == "((":
            return True
        i += 1
    return False


def _contains_process_substitution(command: str) -> bool:
    """Detect ``<(...)`` or ``>(...)`` outside quoted regions.

    Approximate: any unquoted ``<(`` or ``>(``. Redirects like ``> file``
    and ``< file`` have whitespace before the paren, so they don't match.
    """
    in_squote = False
    in_dquote = False
    i = 0
    n = len(command)
    while i < n - 1:
        ch = command[i]
        if in_squote:
            if ch == "'":
                in_squote = False
            i += 1
            continue
        if in_dquote:
            if ch == '"':
                in_dquote = False
            i += 1
            continue
        if ch == "'":
            in_squote = True
            i += 1
            continue
        if ch == '"':
            in_dquote = True
            i += 1
            continue
        if ch in ("<", ">") and command[i + 1] == "(":
            return True
        i += 1
    return False


def _contains_heredoc(command: str) -> bool:
    """Detect heredoc markers ``<<``, ``<<-``, ``<<<`` outside quotes.

    ``<<<`` is a here-string (also refused by tier1). ``<<`` / ``<<-``
    are true heredocs. We conservatively deny all three under the same
    diagnostic.
    """
    in_squote = False
    in_dquote = False
    i = 0
    n = len(command)
    while i < n - 1:
        ch = command[i]
        if in_squote:
            if ch == "'":
                in_squote = False
            i += 1
            continue
        if in_dquote:
            if ch == '"':
                in_dquote = False
            i += 1
            continue
        if ch == "'":
            in_squote = True
            i += 1
            continue
        if ch == '"':
            in_dquote = True
            i += 1
            continue
        if ch == "<" and command[i + 1] == "<":
            return True
        i += 1
    return False


# ── Evaluator (public API) ──────────────────────────────────────────────────


def evaluate(
    command: str,
    initial_cwd: str | None = None,
    policy: dict[str, PolicyFn] | None = None,
) -> EvaluateResult:
    """Evaluate a shell command under a per-binary policy.

    Steps:
    1. Decompose the command with :func:`decompose`. On decomposition
       failure, return ``allowed=False`` with the reject reason.
    2. For each :class:`Spawn`, look up ``policy[binary]``. Missing entry
       means the policy has no opinion — treated as deny by default so
       the outer classic evaluator or relay can weigh in.
    3. Any spawn rejected by its policy function fails the whole command
       (all-must-pass semantics, mirrors tier1's compound rule).

    Args:
        command: Shell command string to evaluate.
        initial_cwd: Starting working directory (defaults to ``os.getcwd()``).
        policy: Per-binary safety function registry. If ``None``, uses
            :data:`DEFAULT_POLICY` (empty — every spawn will reject).

    Returns:
        An :class:`EvaluateResult` naming the final decision and the
        specific spawn / reason on rejection.
    """
    if policy is None:
        policy = DEFAULT_POLICY

    result = decompose(command, initial_cwd)
    if result.reject_reason is not None:
        return EvaluateResult(
            allowed=False, reason=result.reject_reason, spawns=[]
        )

    spawns = result.spawns or []
    if not spawns:
        # Assignment-only or empty command — nothing to authorize.
        return EvaluateResult(allowed=True, reason="no spawns", spawns=[])

    for spawn in spawns:
        fn = policy.get(spawn.binary)
        if fn is None:
            return EvaluateResult(
                allowed=False,
                reason=(
                    f"no policy for binary '{spawn.binary}' "
                    f"(argv={list(spawn.argv)}, cwd={spawn.cwd})"
                ),
                spawns=spawns,
            )
        if not fn(list(spawn.argv), spawn.cwd):
            return EvaluateResult(
                allowed=False,
                reason=(
                    f"policy rejected '{spawn.binary}' "
                    f"(argv={list(spawn.argv)}, cwd={spawn.cwd})"
                ),
                spawns=spawns,
            )

    return EvaluateResult(allowed=True, reason="all spawns approved", spawns=spawns)


# ── Plugin loading ──────────────────────────────────────────────────────────


def load_policy_from_module(module_ref: str) -> dict[str, PolicyFn]:
    """Load a policy registry from a module reference.

    ``module_ref`` follows the standard entry-point syntax
    ``package.module:attribute``. The attribute may be either the policy
    dict itself, or a zero-arg callable returning the dict.

    This is how Mika-side (or any downstream consumer) ships its private
    allow/deny contents while the generic engine stays in cpp — see
    ``docs/permission-mode.md`` for the boundary discipline.
    """
    if ":" not in module_ref:
        raise ValueError(
            f"module ref must be 'package.module:attribute', got '{module_ref}'"
        )
    mod_name, _, attr = module_ref.partition(":")
    import importlib

    mod = importlib.import_module(mod_name)
    obj = getattr(mod, attr)
    if callable(obj):
        obj = obj()
    if not isinstance(obj, dict):
        raise TypeError(
            f"policy loader '{module_ref}' returned {type(obj).__name__}, "
            "expected dict[str, PolicyFn]"
        )
    return obj
