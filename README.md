# claude-pilot (Python)

Python wrapper around [`claude-agent-sdk`](https://pypi.org/project/claude-agent-sdk/) that runs Claude Code headlessly and intercepts tool permission requests via the SDK's `can_use_tool` callback, forwarding them to an external agent (e.g. `mika --agent mika-dev ask`) for automated decision-making.

This is the Python port of the original TypeScript implementation (archived at [`senara-solutions/claude-pilot-ts`](https://github.com/senara-solutions/claude-pilot-ts)). CLI flags, relay protocol, config file shape, binary name, and stdout JSON contract are preserved byte-for-byte so downstream consumers (mika-skills handlers, committed `.claude/claude-pilot.json` configs) keep working unchanged. See `mika-platform#31` for the rationale (Node ESM toolchain failures).

## Install

```bash
uv tool install git+https://github.com/senara-solutions/claude-pilot-py.git
```

Or from a local clone:

```bash
uv tool install --force .
```

`pipx install .` works as a documented fallback.

## Usage

```bash
claude-pilot [options] <prompt>
```

### Options

| Flag | Purpose |
|------|---------|
| `--task-id <id>` | Task identifier for external agent tracking |
| `--no-relay` | Disable agent forwarding (answer all prompts locally) |
| `--relay-config <path>` | Explicit path to config JSON (overrides CWD discovery) |
| `--cwd <dir>` | Working directory for Claude Code (default: current) |
| `--log-dir [path]` | Enable file logging (default: `/var/log/claude-pilot`) |
| `--command <cmd>` | Slash command to prepend to the prompt (e.g. `/mika`) |
| `--verbose` | Show debug output |
| `--max-turns <n>` | Maximum agentic turns (default: 200) |
| `--max-budget <usd>` | Maximum cost in USD (default: disabled) |
| `--stall-threshold <n>` | Consecutive no-tool turns before termination (0=off, default: 5) |
| `--empty-threshold <n>` | Consecutive trivial responses before termination (0=off, default: 5) |
| `--idle-timeout <ms>` | Idle timeout in ms (0=off, max 3_600_000, default: 300_000) |
| `--min-detection-turns <n>` | Turns before stall/empty detection activates (default: 10) |
| `--no-guardrails` | Disable stall/empty/idle detection (`max_turns` still applies) |

## Configuration

Place `.claude/claude-pilot.json` in the target project:

```json
{
  "command": "mika",
  "args": ["--agent", "mika-dev", "ask"],
  "timeout": 120000,
  "guardrails": {
    "maxTurns": 200,
    "stallThreshold": 5,
    "emptyResponseThreshold": 5,
    "idleTimeoutMs": 300000,
    "minTurnsBeforeDetection": 10
  }
}
```

Guardrail fields are optional — defaults apply when omitted. CLI flags override config file values. Set a threshold to `0` to disable that specific guardrail.

## Permission-policy mode

`claude-pilot` ships two Bash permission-policy evaluators, selectable via
`MIKA_PERMISSION_POLICY_MODE`:

- `classic` *(default)* — syntactic pattern-matching over the shell text.
- `per_spawn` — bashlex decomposition + per-binary safety functions
  (Phase 1 opt-in, `mika#1708`).

Downstream projects register per-binary safety functions via a plugin
module referenced through `MIKA_PERMISSION_POLICY_MODULE=package.module:attribute`.
The generic engine ships with an empty `DEFAULT_POLICY`; every deployment
supplies its own contents.

Full mode-selection guide, migration path, and audit-event wire shape:
[`docs/permission-mode.md`](docs/permission-mode.md).

## IPython magics

Optional REPL surface: drive a Claude Code session from IPython (≥8) or Jupyter with the same permission chain as the headless pilot.

```bash
pip install 'claude-pilot[ipython]'
```

```python
%load_ext claude_pilot.ipython
%claude "Summarize the git log of this repo"
```

`%claude "prompt"` runs a single-turn exchange in a fresh session, streaming the response into the cell. `%%claude` uses the cell body as the prompt and keeps **one session alive across invocations** in the kernel, so follow-up cells continue the same conversation:

```python
%%claude
What does src/claude_pilot/tier1.py guard against?
```

Notes:

- **Permissions are inherited, not re-implemented** — the magics build their `can_use_tool` callback from the same Tier-1 filter → policy → relay chain as the CLI. A kernel has no TTY, so the interactive fallback auto-denies; being in a REPL grants no silent privilege widening.
- **Config discovery matches the CLI** — `.claude/claude-pilot.json` in the kernel's working directory enables the relay; without it the policy chain still applies.
- **No extra runtime** — same pure-Python path through `claude-agent-sdk` as the headless pilot; no Node.js required.

## Architecture

```
src/claude_pilot/cli.py          → Entry point: arg parsing, config loading, signal handling
src/claude_pilot/agent.py        → ClaudeSDKClient wrapper, message streaming, ResultJson emission
src/claude_pilot/permissions.py  → can_use_tool handler: tier1, relay, retry, interactive fallback
src/claude_pilot/tier1.py        → Tier 1 auto-approval filter: deny-list, safe patterns, path safety
src/claude_pilot/transport.py    → asyncio subprocess transport with env scrubbing + JSON extraction
src/claude_pilot/guardrails.py   → Session termination guardrails
src/claude_pilot/ui.py           → Stderr log renderer (ANSI colors)
src/claude_pilot/types.py        → PilotConfig, PilotEvent, PilotResponse, ResultJson (Pydantic)
src/claude_pilot/logger.py       → File + stderr sink with ANSI stripping for files
src/claude_pilot/ipython/        → Optional %claude / %%claude IPython magics ([ipython] extra)
```

## Development

```bash
uv sync --all-extras      # install dev deps
uv run pytest             # run tests
uv run ruff check         # lint
uv run mypy src           # type check
```

## SDK version

This release pins `claude-agent-sdk==0.1.59`. The SDK is 0.1.x — breaking changes possible. Bump + smoke-test before committing version upgrades.

## License

MIT
