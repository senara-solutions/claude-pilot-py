---
title: "feat: Initial Python port of claude-pilot"
type: feat
status: active
date: 2026-04-14
tracks_issue: senara-solutions/mika-platform#31
---

# Initial Python port of claude-pilot

This plan is the **claude-pilot-py slice** of `senara-solutions/mika-platform#31`
(Port claude-pilot from TypeScript to Python). The canonical, cross-repo plan
lives in the meta-repo:

> [`senara-solutions/mika-platform` → `docs/plans/2026-04-14-001-feat-port-claude-pilot-to-python-plan.md`](https://github.com/senara-solutions/mika-platform/blob/feat/31/port-claude-pilot-to-python/docs/plans/2026-04-14-001-feat-port-claude-pilot-to-python-plan.md)

Refer to the meta-repo plan for rationale, cross-repo choreography (archive
`claude-pilot-ts` → create `claude-pilot-py` → meta-repo Makefile/sync
updates), preserved contracts, and phase sequencing.

## Scope of this PR (Phase 1.1–1.4 of the meta-plan)

- [x] `pyproject.toml` with `hatchling`, `[project.scripts] claude-pilot = "claude_pilot.cli:main"`, `requires-python = ">=3.11"`, pinned `claude-agent-sdk==0.1.59`
- [x] `.github/workflows/ci.yml` — ruff + mypy strict + pytest on Python 3.11
- [x] `CLAUDE.md` + `README.md` + `.env.example`
- [x] `.claude/commands/mika.md` (adapted from claude-pilot-ts, scoped to claude-pilot-py)
- [x] `.gitignore` covering `.venv/`, `.mypy_cache/`, `.ruff_cache/`, `.pytest_cache/`, `dist/`, `*.egg-info/`, `.env*` (keep `.env.example`)
- [x] Port 9 source modules with TS-parity contracts:
  - `types.py` — Pydantic models for PilotConfig, PilotEvent, PilotResponse, ResultJson, GuardrailConfig
  - `logger.py` — file + stderr sink with ANSI stripping, best-effort error handling
  - `ui.py` — stderr log renderer with ANSI colors
  - `tier1.py` — auto-approval filter (TIER1_SAFE_SKILLS, TIER3_PATTERNS, safe git/build/shell/gh)
  - `transport.py` — `asyncio.create_subprocess_exec` with env scrubbing, JSON extraction, 1MB buffer cap
  - `guardrails.py` — SessionGuardrails with pausable idle timer (asyncio.Task + asyncio.Event)
  - `permissions.py` — `can_use_tool` callback with tier1 short-circuit, retry, interactive fallback
  - `agent.py` — `ClaudeSDKClient` wrapper, message stream loop, ResultJson emission
  - `cli.py` — argparse with all 14 flags, dotenv load, signal handlers, `asyncio.run` entrypoint
- [x] Tests:
  - `test_types.py` — schema round-trip, defaults, discriminated union validation
  - `test_tier1.py` — deny-list coverage, safe command coverage, path containment, Skill pipeline allow-list
  - `test_cli.py` — `--help` enumerates all 14 flags, invalid flag combinations exit non-zero
- [x] `scripts/verify-pipeline.sh` (copied from mika-platform for pipeline parity)

## Quality gates

- [x] `uv run ruff check` — clean
- [x] `uv run mypy src` — clean under `strict = true`
- [x] `uv run pytest` — 88 tests pass
- [x] `uv tool install --force .` — installs `claude-pilot` binary on PATH
- [x] `claude-pilot --help` — renders all 14 flags with matching names

## Out of scope for this PR (follow-up)

- [ ] Port the full 597-line `test/tier1.test.ts` suite to pytest (this PR covers the highest-risk rules; full coverage follows)
- [ ] Port `test/guardrails.test.ts` (452 lines) — stall/empty/idle behavioral tests
- [ ] End-to-end integration test against a live SDK session
- [ ] Cutover acceptance test: real mika-dev sprint run end-to-end through claude-pilot-py

These are tracked in the meta-plan under Phase 1.3 remainder and Phase 3 validation.

## Preserved contracts (verified)

See the meta-plan for full details. Verified in this PR:

- CLI flag surface matches TS byte-for-byte (tested via `test_cli.py::test_help_lists_all_flags`)
- ResultJson schema unchanged (tested via `test_types.py::test_result_json_single_line_no_none_fields`)
- Relay payload prefix `[claude-pilot] ` preserved (see `transport.py:88` — the prefix is load-bearing; LLM-backed relay agents key on it)
- `.claude/claude-pilot.json` schema accepted as-is (tested via `test_types.py::test_pilot_config_full`)
- Env scrubbing patterns identical (KEY/SECRET/TOKEN/PASSWORD/CREDENTIAL/AUTH/PRIVATE/DATABASE_URL/DSN)
- Tier 1 pipeline skill allow-list identical to TS `TIER1_SAFE_SKILLS`

## Next steps

1. Merge this PR → `claude-pilot-py` has a working Python port on main.
2. Land meta-repo PR (senara-solutions/mika-platform#32) to complete the cutover (Makefile/sync/CLAUDE.md).
3. Install the Python binary on the host (`uv tool install --force ./claude-pilot-py` from meta-repo root, or `make deploy`).
4. Run a real mika-dev sprint ticket end-to-end (Phase 3 validation in meta-plan).
5. Follow up: full TS test suite port.
