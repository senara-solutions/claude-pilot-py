"""Subprocess transport for the external relay agent. Port of src/transport.ts.

Spawns the configured command with `-` as the last positional arg, writes a
`[claude-pilot] <PilotEvent JSON>` payload to stdin, reads JSON response from
stdout. Scrubs sensitive env vars before spawning. The prefix literal is
load-bearing: the relay agent keys on it to distinguish claude-pilot events
from user messages.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
from typing import Any

from pydantic import TypeAdapter, ValidationError

from .logger import write_file_log
from .types import PilotConfig, PilotEvent, PilotResponse, TransportError
from .ui import log_verbose

_SCRUB_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"KEY", re.IGNORECASE),
    re.compile(r"SECRET", re.IGNORECASE),
    re.compile(r"TOKEN", re.IGNORECASE),
    re.compile(r"PASSWORD", re.IGNORECASE),
    re.compile(r"CREDENTIAL", re.IGNORECASE),
    re.compile(r"^DATABASE_URL$", re.IGNORECASE),
    re.compile(r"DSN$", re.IGNORECASE),
    re.compile(r"AUTH", re.IGNORECASE),
    re.compile(r"PRIVATE", re.IGNORECASE),
)

_MAX_BUFFER = 1024 * 1024  # 1 MB

_response_adapter: TypeAdapter[PilotResponse] = TypeAdapter(PilotResponse)


def scrub_env(env: dict[str, str]) -> dict[str, str]:
    return {k: v for k, v in env.items() if not any(p.search(k) for p in _SCRUB_PATTERNS)}


async def invoke_command(
    config: PilotConfig,
    event: PilotEvent,
    verbose: bool,
    task_id: str | None = None,
) -> PilotResponse:
    """Invoke the configured relay subprocess and return its parsed response.

    Raises:
        TransportError: subprocess failed, produced no output, or returned
            unparseable/invalid JSON.
        asyncio.CancelledError: caller aborted (SIGINT, timeout at caller level).
    """
    timeout = (config.timeout or 120_000) / 1000.0  # ms → seconds

    args = list(config.args or [])
    args.append("-")
    if config.model:
        args.extend(["--model", config.model])
    if task_id:
        args.extend(["--task-id", task_id])

    if verbose:
        log_verbose(f"invoking: {config.command} {' '.join(args)}")

    scrubbed = scrub_env(dict(os.environ))

    proc = await asyncio.create_subprocess_exec(
        config.command,
        *args,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=scrubbed,
    )

    if verbose:
        write_file_log(
            f"[relay:payload] type={event.type} tool={event.tool_name} id={event.tool_use_id}\n"
        )

    # Prefix is load-bearing — see transport.ts:101-109 for the incident history.
    # Without it, LLM-backed relay agents rationalize the JSON-only PilotResponse
    # contract onto plain prose messages (qwen3-coder, 2026-04-11).
    payload = f"[claude-pilot] {event.model_dump_json(exclude_none=True)}".encode()

    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(input=payload),
            timeout=timeout,
        )
    except TimeoutError as err:
        proc.kill()
        try:
            await proc.wait()
        except Exception:
            pass
        raise TransportError(f"Command timed out after {timeout}s") from err
    except asyncio.CancelledError:
        proc.kill()
        raise

    stdout = stdout_bytes.decode("utf-8", errors="replace")
    stderr = stderr_bytes.decode("utf-8", errors="replace")

    if len(stdout_bytes) > _MAX_BUFFER or len(stderr_bytes) > _MAX_BUFFER:
        raise TransportError("Command output exceeded 1MB buffer")

    if stdout.strip():
        try:
            value, extracted = _extract_json(stdout)
        except ValueError as err:
            raise TransportError(
                f"Invalid JSON from command: {stdout.strip()[:200]}"
            ) from err

        if verbose and extracted:
            log_verbose(f"extracted JSON from noisy stdout ({len(stdout)} bytes)")

        try:
            return _response_adapter.validate_python(value)
        except ValidationError as err:
            raise TransportError(f"Invalid response schema: {err.errors()}") from err

    if proc.returncode != 0:
        tail = stderr.strip()[:200]
        tail_str = f" — stderr: {tail}" if tail else ""
        raise TransportError(f"Command failed (exit {proc.returncode}){tail_str}")

    raise TransportError("Command produced no output")


def _extract_json(raw: str) -> tuple[Any, bool]:
    """Extract the first valid JSON object from a string that may contain
    surrounding text. Returns (value, extracted) where `extracted` is True iff
    the raw string was not directly parseable as JSON."""
    trimmed = raw.strip()
    try:
        return json.loads(trimmed), False
    except json.JSONDecodeError:
        pass

    start = raw.find("{")
    if start == -1:
        raise ValueError("no JSON object found in output")

    depth = 0
    in_string = False
    escape = False
    for i in range(start, len(raw)):
        ch = raw[i]
        if escape:
            escape = False
            continue
        if ch == "\\" and in_string:
            escape = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(raw[start : i + 1]), True
                except json.JSONDecodeError:
                    break

    raise ValueError("no JSON object found in output")
