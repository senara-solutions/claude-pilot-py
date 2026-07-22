"""Unit tests for the per-spawn permission-policy evaluator (mika#1708).

Covers AC1 (decomposition + fail-safe deny), AC2 (state-tracking builtins),
AC3 (per-binary safety functions) from the mika#1708 issue body.

No real subprocess execution — everything is string-in, decision-out.
"""

from __future__ import annotations

from claude_pilot import per_spawn
from claude_pilot.per_spawn import (
    MAX_SUBSTITUTION_DEPTH,
    DecomposeResult,
    Spawn,
    decompose,
    evaluate,
)

# ── Synthetic policy fixtures ────────────────────────────────────────────────
#
# Per SSC boundary discipline (mika#1708 landing shape), cpp ships an empty
# DEFAULT_POLICY. These fixtures use synthetic patterns unrelated to Mika's
# actual deployment — they only exist to exercise the engine.


def _always_ok(argv: list[str], cwd: str) -> bool:
    return True


def _always_no(argv: list[str], cwd: str) -> bool:
    return False


def _permissive_policy() -> dict[str, per_spawn.PolicyFn]:
    """Every binary allowed. Used to isolate decomposition tests from policy."""

    class _Perm(dict):
        def get(self, key, default=None):
            return _always_ok

    return _Perm()


def _grep_only_readonly(argv: list[str], cwd: str) -> bool:
    # Synthetic: allow grep only when no --exec-like flag is present.
    return not any(a.startswith("--exec") for a in argv[1:])


# ── AC1 — decomposition ─────────────────────────────────────────────────────


class TestDecompositionSuccess:
    """Supported shell constructs decompose into a Spawn list."""

    def test_empty_command(self):
        r = decompose("", initial_cwd="/tmp")
        assert r == DecomposeResult(spawns=[], reject_reason=None)

    def test_whitespace_only(self):
        r = decompose("   ", initial_cwd="/tmp")
        assert r == DecomposeResult(spawns=[], reject_reason=None)

    def test_simple_command(self):
        r = decompose("grep -r foo .", initial_cwd="/tmp")
        assert r.reject_reason is None
        assert r.spawns == [
            Spawn(binary="grep", argv=("grep", "-r", "foo", "."), cwd="/tmp")
        ]

    def test_pipeline(self):
        r = decompose("ls | grep foo", initial_cwd="/tmp")
        assert r.reject_reason is None
        binaries = [s.binary for s in r.spawns or []]
        assert binaries == ["ls", "grep"]

    def test_sequence_semicolon(self):
        r = decompose("ls; pwd", initial_cwd="/tmp")
        assert r.reject_reason is None
        assert [s.binary for s in r.spawns or []] == ["ls", "pwd"]

    def test_logical_and(self):
        r = decompose("cd /etc && ls", initial_cwd="/tmp")
        assert r.reject_reason is None
        # cd doesn't spawn (state-tracking), only ls does.
        assert len(r.spawns or []) == 1
        assert r.spawns[0].binary == "ls"
        # AC2 in action: cd propagated across the && boundary.
        assert r.spawns[0].cwd == "/etc"

    def test_logical_or(self):
        r = decompose("false || echo fallback", initial_cwd="/tmp")
        assert r.reject_reason is None
        assert [s.binary for s in r.spawns or []] == ["false", "echo"]

    def test_grep_with_awk_pipe(self):
        """Regression case: the exact class of over-deny that motivated mika#1708.

        ``grep ... | awk '$1 > N'`` — pipe-to-awk with conditional. Classic
        classifier denied. Per-spawn: two safe spawns.
        """
        cmd = "grep -n foo file.txt | awk '$1 > 700 && $1 < 2540'"
        r = decompose(cmd, initial_cwd="/tmp")
        assert r.reject_reason is None
        binaries = [s.binary for s in r.spawns or []]
        assert binaries == ["grep", "awk"]

    def test_cd_chain_then_grep(self):
        """Regression: ``cd /path; grep ...`` — the mika#1671 blocked shape."""
        cmd = 'cd /data/x; echo "hi"; grep -n foo bar.rs'
        r = decompose(cmd, initial_cwd="/tmp")
        assert r.reject_reason is None
        binaries = [s.binary for s in r.spawns or []]
        assert binaries == ["echo", "grep"]
        # AC2: grep sees /data/x cwd after cd propagated across ;
        assert r.spawns[-1].cwd == "/data/x"

    def test_redirect_out(self):
        r = decompose("ls -la > /tmp/list.txt", initial_cwd="/tmp")
        assert r.reject_reason is None
        assert len(r.spawns or []) == 1
        assert r.spawns[0].binary == "ls"


class TestDecompositionFailSafeDeny:
    """Unsupported constructs must return ``spawns=None, reject_reason=<str>``.

    AC1: the specific unsupported construct is named in the reason so
    operators can diagnose the deny.
    """

    def test_heredoc_denied(self):
        r = decompose("cat << EOF\nfoo\nEOF", initial_cwd="/tmp")
        assert r.spawns is None
        assert "heredoc" in r.reject_reason.lower()

    def test_here_string_denied(self):
        r = decompose("grep foo <<< 'input'", initial_cwd="/tmp")
        assert r.spawns is None
        assert "heredoc" in r.reject_reason.lower()

    def test_process_substitution_denied(self):
        r = decompose("diff <(ls a) <(ls b)", initial_cwd="/tmp")
        assert r.spawns is None
        assert "process substitution" in r.reject_reason.lower()

    def test_backticks_denied(self):
        r = decompose("echo `date`", initial_cwd="/tmp")
        assert r.spawns is None
        assert "backtick" in r.reject_reason.lower()

    def test_arithmetic_expansion_denied(self):
        r = decompose("echo $((1 + 2))", initial_cwd="/tmp")
        assert r.spawns is None
        assert "arithmetic" in r.reject_reason.lower()

    def test_backticks_inside_squote_not_flagged(self):
        # POSIX single-quote is atomic — a backtick inside is a literal,
        # not command substitution. Must NOT trigger the raw-string check.
        r = decompose("echo 'hi `not-a-sub` bye'", initial_cwd="/tmp")
        assert r.reject_reason is None
        assert (r.spawns or [])[0].binary == "echo"

    def test_eval_rejected(self):
        r = decompose("eval 'echo hi'", initial_cwd="/tmp")
        assert r.spawns is None
        assert "eval" in r.reject_reason.lower()

    def test_source_rejected(self):
        r = decompose("source /tmp/script.sh", initial_cwd="/tmp")
        assert r.spawns is None
        assert "source" in r.reject_reason.lower()

    def test_dot_rejected(self):
        r = decompose(". /tmp/script.sh", initial_cwd="/tmp")
        assert r.spawns is None
        assert "dynamic execution" in r.reject_reason.lower()

    def test_control_flow_if_denied(self):
        r = decompose("if true; then echo hi; fi", initial_cwd="/tmp")
        assert r.spawns is None
        # Named as some unsupported kind; specific label is bashlex-dependent.
        assert "unsupported" in r.reject_reason.lower()

    def test_malformed_command_returns_deny(self):
        # An unbalanced quote is a parse error — fail-safe deny.
        r = decompose("echo 'unterminated", initial_cwd="/tmp")
        assert r.spawns is None
        # Message content varies by bashlex version; the shape is stable.
        assert r.reject_reason


class TestCommandSubstitution:
    """``$(...)`` is decomposable but bounded by MAX_SUBSTITUTION_DEPTH."""

    def test_shallow_sub_with_no_inner_spawn(self):
        # ``echo $(pwd)`` — inner produces a spawn, which Phase 1 refuses
        # (see per_spawn.py inline note). Deny with a diagnostic.
        r = decompose("echo $(pwd)", initial_cwd="/tmp")
        assert r.spawns is None
        assert "command substitution" in r.reject_reason.lower()

    def test_max_depth_constant_is_five(self):
        # Sanity: the design constant is explicit and matches the plan doc.
        assert MAX_SUBSTITUTION_DEPTH == 5


# ── AC2 — state-tracking builtins ──────────────────────────────────────────


class TestStateTrackingBuiltins:
    def test_bare_cd_denied(self):
        r = decompose("cd", initial_cwd="/tmp")
        assert r.spawns is None
        assert "no argument" in r.reject_reason.lower()

    def test_cd_with_var_denied(self):
        r = decompose("cd $HOME", initial_cwd="/tmp")
        assert r.spawns is None
        assert "variable" in r.reject_reason.lower()

    def test_cd_tilde_denied(self):
        r = decompose("cd ~", initial_cwd="/tmp")
        assert r.spawns is None
        assert "~" in r.reject_reason

    def test_cd_dash_denied(self):
        r = decompose("cd -", initial_cwd="/tmp")
        assert r.spawns is None
        assert "previous dir" in r.reject_reason.lower()

    def test_cd_absolute_updates_cwd(self):
        r = decompose("cd /etc; cat passwd", initial_cwd="/tmp")
        assert r.reject_reason is None
        assert r.spawns[-1].cwd == "/etc"
        # AC2 assertion from plan doc: ``cd /etc; cat passwd`` evaluates
        # cat against ``/etc/passwd`` — the argv[1] is the raw ``passwd``,
        # and the spawn.cwd is ``/etc`` so a downstream policy resolves
        # to /etc/passwd from those two facts.
        assert r.spawns[-1].argv == ("cat", "passwd")

    def test_cd_relative_updates_cwd(self):
        r = decompose("cd sub; cat f.txt", initial_cwd="/tmp")
        assert r.reject_reason is None
        assert r.spawns[-1].cwd == "/tmp/sub"

    def test_pipeline_cd_isolated(self):
        # cd in a subshell (pipe segment) does NOT propagate to the next.
        r = decompose("cd /etc | grep foo", initial_cwd="/tmp")
        # cd's pipe-isolated stack means the outer stack is untouched.
        assert r.reject_reason is None
        # grep runs in a subshell too; its cwd starts at the outer stack.
        assert (r.spawns or [])[0].cwd == "/tmp"

    def test_export_does_not_spawn_but_accepts(self):
        # export is state-tracking (env), no spawn. Command with only
        # export should return zero spawns and no reject reason.
        r = decompose("export FOO=bar", initial_cwd="/tmp")
        assert r.reject_reason is None
        assert r.spawns == []


# ── AC3 — per-binary safety functions ──────────────────────────────────────


class TestEvaluatorPerBinary:
    def test_empty_policy_denies(self):
        # AC3 semantics: missing entry = deny.
        r = evaluate("grep foo bar", initial_cwd="/tmp")
        assert r.allowed is False
        assert "no policy" in r.reason.lower()

    def test_permissive_policy_allows(self):
        pol = {"grep": _always_ok}
        r = evaluate("grep foo bar", initial_cwd="/tmp", policy=pol)
        assert r.allowed is True

    def test_reject_from_safety_fn(self):
        pol = {"grep": _always_no}
        r = evaluate("grep foo bar", initial_cwd="/tmp", policy=pol)
        assert r.allowed is False
        assert "policy rejected" in r.reason.lower()

    def test_all_must_pass_semantics(self):
        # grep passes, but awk has no policy → whole command rejects.
        pol = {"grep": _always_ok}
        r = evaluate("grep foo bar | awk '{print}'", initial_cwd="/tmp", policy=pol)
        assert r.allowed is False
        assert "awk" in r.reason

    def test_safety_fn_receives_argv_and_cwd(self):
        seen: list[tuple[list[str], str]] = []

        def spy(argv: list[str], cwd: str) -> bool:
            seen.append((argv, cwd))
            return True

        pol = {"cat": spy}
        r = evaluate("cd /etc; cat passwd", initial_cwd="/tmp", policy=pol)
        assert r.allowed is True
        assert seen == [(["cat", "passwd"], "/etc")]

    def test_synthetic_readonly_grep_policy(self):
        pol = {"grep": _grep_only_readonly}
        r_ok = evaluate("grep -r foo .", initial_cwd="/tmp", policy=pol)
        assert r_ok.allowed is True
        # Synthetic denied flag.
        r_no = evaluate("grep --exec-hack foo .", initial_cwd="/tmp", policy=pol)
        assert r_no.allowed is False

    def test_empty_command_allowed(self):
        r = evaluate("", initial_cwd="/tmp")
        assert r.allowed is True
        assert r.reason == "no spawns"


# ── Plugin loading ─────────────────────────────────────────────────────────


class TestPolicyLoader:
    def test_bad_ref_format(self):
        try:
            per_spawn.load_policy_from_module("not-a-ref")
        except ValueError as e:
            assert "package.module:attribute" in str(e)
        else:
            raise AssertionError("expected ValueError")

    def test_load_module_dict(self, tmp_path, monkeypatch):
        # Create a tiny plugin module in a tmp path.
        pkg_dir = tmp_path / "plugin_pkg"
        pkg_dir.mkdir()
        (pkg_dir / "__init__.py").write_text("")
        (pkg_dir / "policy_mod.py").write_text(
            "def get_policy():\n"
            "    def _grep_ok(argv, cwd): return True\n"
            "    return {'grep': _grep_ok}\n"
        )
        monkeypatch.syspath_prepend(str(tmp_path))
        loaded = per_spawn.load_policy_from_module("plugin_pkg.policy_mod:get_policy")
        assert "grep" in loaded
        assert loaded["grep"](["grep", "foo"], "/tmp") is True

    def test_wrong_return_type_raises(self, tmp_path, monkeypatch):
        pkg_dir = tmp_path / "plugin_bad"
        pkg_dir.mkdir()
        (pkg_dir / "__init__.py").write_text("")
        (pkg_dir / "policy_mod.py").write_text("get_policy = 42\n")
        monkeypatch.syspath_prepend(str(tmp_path))
        try:
            per_spawn.load_policy_from_module("plugin_bad.policy_mod:get_policy")
        except TypeError as e:
            assert "expected dict" in str(e)
        else:
            raise AssertionError("expected TypeError")
