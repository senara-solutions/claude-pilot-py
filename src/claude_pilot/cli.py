"""CLI entry point. Port of src/cli.ts.

Preserves exact flag surface and stdout JSON contract. Invoked as
`claude-pilot` via the `[project.scripts]` entry in pyproject.toml.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import signal
import sys
import traceback
from pathlib import Path
from typing import Any, NoReturn

from dotenv import dotenv_values
from pydantic import ValidationError

from .agent import run_agent
from .guardrails import SessionGuardrails, resolve_guardrail_defaults
from .logger import close_file_log, init_file_log
from .permissions import create_permission_handler
from .types import GuardrailConfig, PilotConfig, ResultJson
from .ui import log_config, log_env


def _usage(parser: argparse.ArgumentParser) -> NoReturn:
    parser.print_help(sys.stderr)
    sys.exit(1)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="claude-pilot",
        description="Run Claude Code headlessly with relay-based tool permission callbacks.",
        add_help=True,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--task-id", dest="task_id", default=None)
    p.add_argument("--no-relay", dest="relay", action="store_false", default=True)
    p.add_argument("--relay-config", dest="relay_config", default=None)
    p.add_argument("--cwd", dest="cwd", default=None)
    p.add_argument(
        "--log-dir",
        dest="log_dir",
        nargs="?",
        const="/var/log/claude-pilot",
        default=None,
    )
    p.add_argument("--command", dest="command", default=None)
    p.add_argument("--verbose", dest="verbose", action="store_true", default=False)

    p.add_argument("--max-turns", dest="max_turns", type=int, default=None)
    p.add_argument("--max-budget", dest="max_budget", type=float, default=None)
    p.add_argument("--stall-threshold", dest="stall_threshold", type=int, default=None)
    p.add_argument("--empty-threshold", dest="empty_threshold", type=int, default=None)
    p.add_argument("--idle-timeout", dest="idle_timeout", type=int, default=None)
    p.add_argument("--min-detection-turns", dest="min_detection_turns", type=int, default=None)
    p.add_argument("--no-guardrails", dest="no_guardrails", action="store_true", default=False)

    p.add_argument("prompt", nargs=argparse.REMAINDER, help="Prompt for Claude Code")
    return p


def _validate_args(ns: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    if ns.command is not None and not ns.command.startswith("/"):
        sys.stderr.write("Error: --command must start with / (e.g., /mika)\n")
        _usage(parser)
    if ns.max_turns is not None and ns.max_turns < 1:
        sys.stderr.write("Error: --max-turns requires a positive integer\n")
        _usage(parser)
    if ns.max_budget is not None and ns.max_budget < 0.01:
        sys.stderr.write("Error: --max-budget requires a positive number\n")
        _usage(parser)
    if ns.stall_threshold is not None and ns.stall_threshold < 0:
        sys.stderr.write("Error: --stall-threshold requires a non-negative integer (0 = disabled)\n")
        _usage(parser)
    if ns.empty_threshold is not None and ns.empty_threshold < 0:
        sys.stderr.write("Error: --empty-threshold requires a non-negative integer (0 = disabled)\n")
        _usage(parser)
    if ns.idle_timeout is not None and not (ns.idle_timeout == 0 or 1000 <= ns.idle_timeout <= 3_600_000):
        sys.stderr.write("Error: --idle-timeout must be 0 (disabled) or 1000-3600000 (ms)\n")
        _usage(parser)
    if ns.min_detection_turns is not None and ns.min_detection_turns < 0:
        sys.stderr.write("Error: --min-detection-turns requires a non-negative integer\n")
        _usage(parser)


def _collect_prompt(parser: argparse.ArgumentParser, ns: argparse.Namespace) -> str:
    # argparse.REMAINDER keeps `--` as a literal first element if present
    words = [w for w in ns.prompt if w != "--"]
    if not words:
        sys.stderr.write("Error: prompt is required\n")
        _usage(parser)
    return " ".join(words)


def _load_config(cwd: Path, explicit: str | None) -> PilotConfig | None:
    path = Path(explicit).resolve() if explicit else cwd / ".claude" / "claude-pilot.json"
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except OSError as err:
        sys.stderr.write(f"Error: cannot read {path}: {err}\n")
        sys.exit(1)

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as err:
        sys.stderr.write(f"Error: Invalid JSON in {path}: {err}\n")
        sys.exit(1)

    try:
        return PilotConfig.model_validate(parsed)
    except ValidationError as err:
        msgs = ", ".join(issue["msg"] for issue in err.errors())
        sys.stderr.write(f"Error: Invalid .claude/claude-pilot.json: {msgs}\n")
        sys.exit(1)


def _merge_guardrails(
    file_config: GuardrailConfig | None,
    cli_overrides: dict[str, Any],
    no_guardrails: bool,
) -> GuardrailConfig:
    merged_data = {**(file_config.model_dump(exclude_none=True) if file_config else {}), **cli_overrides}
    if no_guardrails:
        merged_data["stallThreshold"] = 0
        merged_data["emptyResponseThreshold"] = 0
        merged_data["idleTimeoutMs"] = 0
    return GuardrailConfig.model_validate(merged_data)


def _cli_overrides(ns: argparse.Namespace) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if ns.max_turns is not None:
        out["maxTurns"] = ns.max_turns
    if ns.max_budget is not None:
        out["maxBudgetUsd"] = ns.max_budget
    if ns.stall_threshold is not None:
        out["stallThreshold"] = ns.stall_threshold
    if ns.empty_threshold is not None:
        out["emptyResponseThreshold"] = ns.empty_threshold
    if ns.idle_timeout is not None:
        out["idleTimeoutMs"] = ns.idle_timeout
    if ns.min_detection_turns is not None:
        out["minTurnsBeforeDetection"] = ns.min_detection_turns
    return out


def _emit_fatal(message: str) -> None:
    result = ResultJson(
        status="error",
        subtype="fatal",
        turns=0,
        cost_usd=0.0,
        duration_ms=0,
        errors=[message],
    )
    sys.stdout.write(result.to_line() + "\n")
    sys.stdout.flush()
    sys.stderr.write(f"Fatal: {message}\n")


def main() -> None:
    # .env load from package root. Mirrors TS: does not override existing env.
    pkg_root = Path(__file__).resolve().parent.parent.parent
    env_path = pkg_root / ".env"
    loaded = False
    count = 0
    if env_path.is_file():
        parsed_env = dotenv_values(env_path)
        count = len(parsed_env)
        loaded = True
        for k, v in parsed_env.items():
            if v is not None and k not in os.environ:
                os.environ[k] = v

    parser = _build_parser()
    ns = parser.parse_args()
    _validate_args(ns, parser)
    prompt = _collect_prompt(parser, ns)

    if ns.verbose:
        log_env(str(env_path), loaded, count)

    cwd = Path(ns.cwd).resolve() if ns.cwd else Path.cwd()
    config = _load_config(cwd, ns.relay_config)
    config_path = (
        Path(ns.relay_config).resolve()
        if ns.relay_config
        else cwd / ".claude" / "claude-pilot.json"
    )

    if ns.log_dir:
        sanitized = _sanitize(ns.task_id) if ns.task_id else None
        log_name = f"{sanitized}.log" if sanitized else "session.log"
        init_file_log(str(Path(ns.log_dir) / log_name))

    log_config(str(cwd), str(config_path), config is not None, ns.relay and config is not None)

    relay = ns.relay
    if relay and config is None:
        if ns.relay_config:
            sys.stderr.write(f"Error: Config file not found: {ns.relay_config}\n")
            sys.exit(1)
        sys.stderr.write(
            "Warning: No .claude/claude-pilot.json found — running in no-relay mode.\n"
            'Create .claude/claude-pilot.json with {"command": "...", "args": [...]} '
            "to enable agent forwarding.\n\n"
        )
        relay = False

    if not relay and ns.relay_config:
        sys.stderr.write("Warning: --relay-config is ignored when --no-relay is active\n")

    guardrail_config = _merge_guardrails(
        config.guardrails if config else None,
        _cli_overrides(ns),
        ns.no_guardrails,
    )

    try:
        exit_code = asyncio.run(
            _run(
                prompt=(f"{ns.command} {prompt}" if ns.command else prompt),
                cwd=str(cwd),
                verbose=ns.verbose,
                task_id=ns.task_id or None,
                relay=relay,
                config=config,
                guardrail_config=guardrail_config,
            )
        )
    except KeyboardInterrupt:
        sys.stderr.write("\nShutting down...\n")
        close_file_log()
        sys.exit(130)
    except Exception as err:
        _emit_fatal(str(err))
        traceback.print_exc(file=sys.stderr)
        close_file_log()
        sys.exit(1)

    close_file_log()
    sys.exit(exit_code)


async def _run(
    *,
    prompt: str,
    cwd: str,
    verbose: bool,
    task_id: str | None,
    relay: bool,
    config: PilotConfig | None,
    guardrail_config: GuardrailConfig,
) -> int:
    # Install async signal handlers for clean shutdown.
    loop = asyncio.get_running_loop()
    shutdown_event = asyncio.Event()

    def _shutdown() -> None:
        sys.stderr.write("\nShutting down...\n")
        shutdown_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _shutdown)
        except NotImplementedError:
            # Windows; KeyboardInterrupt in main() covers SIGINT there.
            pass

    resolved = resolve_guardrail_defaults(guardrail_config)
    guardrails = SessionGuardrails(resolved)
    handler = create_permission_handler(
        config=config,
        relay=relay,
        verbose=verbose,
        cwd=cwd,
        guardrails=guardrails,
        task_id=task_id,
    )

    agent_task = asyncio.create_task(
        run_agent(
            prompt=prompt,
            cwd=cwd,
            verbose=verbose,
            task_id=task_id,
            permission_handler=handler,
            guardrails=guardrails,
        )
    )
    shutdown_task = asyncio.create_task(shutdown_event.wait())

    done, _pending = await asyncio.wait(
        {agent_task, shutdown_task},
        return_when=asyncio.FIRST_COMPLETED,
    )

    if shutdown_task in done and agent_task not in done:
        agent_task.cancel()
        try:
            await agent_task
        except (asyncio.CancelledError, Exception):
            pass
        return 130

    shutdown_task.cancel()
    return agent_task.result()


_SAFE_TASK_ID_RE = re.compile(r"[^a-zA-Z0-9_-]")


def _sanitize(task_id: str) -> str:
    return _SAFE_TASK_ID_RE.sub("_", task_id)


if __name__ == "__main__":
    main()
