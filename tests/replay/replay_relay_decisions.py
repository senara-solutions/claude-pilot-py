"""Replay historical mika-relay decisions against the local tier1 fast-path.

Operator-runnable script (not part of `pytest`). Reads `[claude-pilot] ` events
from the mika-relay agent's messages in `~/.mika/data/mika.db`, runs each
through the new tier1 / tier1.5 / tier3 classifier, and reports how many
would have been resolved locally without invoking the relay.

Usage::

    uv run python tests/replay/replay_relay_decisions.py --days 7
    uv run python tests/replay/replay_relay_decisions.py --days 7 --emit-latency

Output (single JSON object to stdout)::

    {
      "days": 7,
      "events_total": 42,
      "events_replayable": 38,
      "events_unreplayable": 4,
      "resolved_locally": 30,
      "still_needs_relay": 8,
      "local_resolution_pct": 78.9,
      "unreplayable_ratio": 0.095,
      "disagreement_vs_relay": [
        {"event_id": "...", "tool": "Bash", "input": "...", "local": "allow", "relay": "deny"}
      ]
    }

NF3 hard-floor (anti-vacuous-truth): if ``events_unreplayable / events_total``
exceeds 0.30, the script exits with status 2 and logs a "harness may be
broken" message on stderr. A-AC3 measures ``local_resolution_pct`` against the
**replayable** subset, but a broken harness that drops most events and
trivially passes the threshold on the surviving 1% would defeat the gate; the
hard-floor catches that case.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

# Make the local claude-pilot source importable when the script is run via
# `uv run python tests/replay/replay_relay_decisions.py` from the package
# root. `uv run` already places the package on sys.path, so this is a
# defense-in-depth for ad-hoc invocations from outside.
_REPO_ROOT = Path(__file__).resolve().parents[2]
if (_REPO_ROOT / "src").is_dir() and str(_REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "src"))

from claude_pilot.permissions import try_tier_1_5_auto_answer  # noqa: E402
from claude_pilot.tier1 import is_tier1_auto_approve, is_tier3_dangerous  # noqa: E402

DEFAULT_DB_PATH = Path.home() / ".mika" / "data" / "mika.db"
PROMPT_PREFIX = "[claude-pilot] "
UNREPLAYABLE_HARD_FLOOR = 0.30  # NF3


@dataclass
class ReplayCounters:
    days: int
    events_total: int = 0
    events_replayable: int = 0
    events_unreplayable: int = 0
    resolved_locally: int = 0
    still_needs_relay: int = 0
    disagreement_vs_relay: list[dict[str, Any]] = field(default_factory=list)
    latency_samples_ms_pre: list[int] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        unreplayable_ratio = (
            self.events_unreplayable / self.events_total if self.events_total else 0.0
        )
        local_resolution_pct = (
            (self.resolved_locally / self.events_replayable * 100)
            if self.events_replayable
            else 0.0
        )
        out: dict[str, Any] = {
            "days": self.days,
            "events_total": self.events_total,
            "events_replayable": self.events_replayable,
            "events_unreplayable": self.events_unreplayable,
            "resolved_locally": self.resolved_locally,
            "still_needs_relay": self.still_needs_relay,
            "local_resolution_pct": round(local_resolution_pct, 2),
            "unreplayable_ratio": round(unreplayable_ratio, 4),
            "disagreement_vs_relay": self.disagreement_vs_relay,
        }
        if self.latency_samples_ms_pre:
            sorted_samples = sorted(self.latency_samples_ms_pre)
            n = len(sorted_samples)
            p50 = sorted_samples[n // 2]
            p95 = sorted_samples[min(int(n * 0.95), n - 1)]
            out["latency_pre_change_ms"] = {
                "samples": n,
                "p50": p50,
                "p95": p95,
            }
        return out


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    db_path = Path(args.db).expanduser() if args.db else DEFAULT_DB_PATH

    if not db_path.exists():
        print(f"error: database not found at {db_path}", file=sys.stderr)
        return 1

    cutoff = datetime.now(UTC) - timedelta(days=args.days)
    counters = ReplayCounters(days=args.days)

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        relay_agent_id = _find_mika_relay_agent_id(conn)
        if relay_agent_id is None:
            print(
                "error: no agent named 'mika-relay' in agents table — nothing to replay",
                file=sys.stderr,
            )
            return 1

        for event_row in _iter_relay_user_events(conn, relay_agent_id, cutoff):
            counters.events_total += 1
            pilot_event = _parse_pilot_event(event_row["content"])
            if pilot_event is None:
                counters.events_unreplayable += 1
                continue

            assistant = _find_assistant_reply(
                conn,
                session_id=event_row["session_id"],
                after_id=event_row["id"],
            )
            relay_action = _extract_action(assistant["content"]) if assistant else None
            if relay_action is None:
                counters.events_unreplayable += 1
                continue

            counters.events_replayable += 1
            local_action = _classify_locally(pilot_event)

            if local_action in ("allow", "deny", "answer"):
                counters.resolved_locally += 1
            else:
                counters.still_needs_relay += 1

            if (
                local_action in ("allow", "deny", "answer")
                and local_action != relay_action
            ):
                counters.disagreement_vs_relay.append(
                    {
                        "event_id": event_row["id"],
                        "tool": pilot_event.get("tool_name"),
                        "input": _summarize_input(pilot_event),
                        "local": local_action,
                        "relay": relay_action,
                    }
                )

            if args.emit_latency and assistant is not None:
                latency_ms = _latency_between(event_row["created_at"], assistant["created_at"])
                if latency_ms is not None:
                    counters.latency_samples_ms_pre.append(latency_ms)

    payload = counters.to_dict()
    print(json.dumps(payload, indent=2, sort_keys=True))

    # NF3 anti-vacuous-truth hard floor.
    if (
        counters.events_total > 0
        and counters.events_unreplayable / counters.events_total >= UNREPLAYABLE_HARD_FLOOR
    ):
        print(
            f"\nerror: unreplayable_ratio "
            f"{counters.events_unreplayable}/{counters.events_total} "
            f"≥ {UNREPLAYABLE_HARD_FLOOR:.0%} — harness may be broken "
            "(schema drift, malformed payloads, or wrong cutoff window). "
            "Local-resolve threshold check is suspended.",
            file=sys.stderr,
        )
        return 2

    return 0


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else "")
    p.add_argument("--days", type=int, default=7, help="lookback window (default: 7)")
    p.add_argument("--db", type=str, default=os.environ.get("MIKA_DB"), help="path to mika.db")
    p.add_argument(
        "--emit-latency",
        action="store_true",
        help="compute pre-change p50/p95 from messages.created_at deltas (A-AC5)",
    )
    return p.parse_args(argv)


def _find_mika_relay_agent_id(conn: sqlite3.Connection) -> str | None:
    # Match by id (the stable role slug) OR by display name as a fallback —
    # `id='mika-relay'` is the convention for well-known agents while `name`
    # is the human-readable display label (e.g., 'Relay').
    row = conn.execute(
        """
        SELECT id FROM agents
        WHERE id = 'mika-relay' OR LOWER(name) = 'mika-relay'
        ORDER BY created_at DESC
        LIMIT 1
        """,
    ).fetchone()
    return row["id"] if row else None


def _iter_relay_user_events(
    conn: sqlite3.Connection,
    agent_id: str,
    cutoff: datetime,
):
    return conn.execute(
        """
        SELECT id, session_id, content, created_at
        FROM messages
        WHERE agent_id = ?
          AND role = 'user'
          AND created_at >= ?
          AND content LIKE ?
        ORDER BY created_at ASC
        """,
        (agent_id, cutoff.strftime("%Y-%m-%dT%H:%M:%SZ"), f"{PROMPT_PREFIX}%"),
    )


def _find_assistant_reply(
    conn: sqlite3.Connection,
    *,
    session_id: str,
    after_id: int,
) -> sqlite3.Row | None:
    return conn.execute(
        """
        SELECT id, content, created_at
        FROM messages
        WHERE session_id = ?
          AND role = 'assistant'
          AND id > ?
        ORDER BY id ASC
        LIMIT 1
        """,
        (session_id, after_id),
    ).fetchone()


def _parse_pilot_event(content: str) -> dict[str, Any] | None:
    if not content.startswith(PROMPT_PREFIX):
        return None
    payload = content[len(PROMPT_PREFIX):].strip()
    try:
        event = json.loads(payload)
    except json.JSONDecodeError:
        return None
    if not isinstance(event, dict):
        return None
    if not isinstance(event.get("tool_name"), str):
        return None
    if not isinstance(event.get("tool_input"), dict):
        return None
    return event


def _extract_action(content: str) -> str | None:
    """The relay's assistant content is a JSON object {"action": "..."}.
    Tolerate fenced code blocks or stray prose by scanning for the action
    keys in order — the relay is LLM-driven and occasionally adds prose.
    """
    text = content.strip()
    # Fast path — pure JSON.
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict) and parsed.get("action") in ("allow", "deny", "answer"):
            return parsed["action"]
    except json.JSONDecodeError:
        pass

    # Defensive parse — look for the action key inside the message body.
    for action in ("allow", "deny", "answer"):
        needle = f'"action": "{action}"'
        if needle in text or f'"action":"{action}"' in text:
            return action
    return None


def _classify_locally(event: dict[str, Any]) -> str | None:
    """Return the action this tier1/tier1.5 path would produce, or None
    (meaning: still needs the relay).

    Write/Edit tools are intentionally skipped: ``is_within_project`` requires
    the agent's original ``cwd`` at dispatch time, which the historical
    PilotEvent payload does not carry (see ``types.py:63-75``). Falling back
    to ``os.getcwd()`` would produce non-deterministic classifications and
    silently bias the resolved-locally count, so we mark them as "still needs
    relay" — A-AC3 measures local-resolution on the events we can correctly
    classify.
    """
    tool_name = event.get("tool_name", "")
    tool_input = event.get("tool_input", {})
    if not isinstance(tool_name, str) or not isinstance(tool_input, dict):
        return None

    if tool_name in ("Write", "Edit"):
        return None

    if is_tier1_auto_approve(tool_name, tool_input, os.getcwd()):
        return "allow"

    auto_answer = try_tier_1_5_auto_answer(tool_name, tool_input)
    if auto_answer is not None:
        return "answer"

    if tool_name == "Bash":
        command = tool_input.get("command", "")
        if isinstance(command, str) and is_tier3_dangerous(command):
            return "deny"

    return None


def _summarize_input(event: dict[str, Any]) -> str:
    tool_input = event.get("tool_input", {})
    if not isinstance(tool_input, dict):
        return ""
    if event.get("tool_name") == "Bash":
        return str(tool_input.get("command", ""))[:120]
    return json.dumps(tool_input, default=str)[:120]


def _latency_between(req_ts: str, resp_ts: str) -> int | None:
    try:
        req = datetime.fromisoformat(req_ts.replace("Z", "+00:00"))
        resp = datetime.fromisoformat(resp_ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    delta_ms = int((resp - req).total_seconds() * 1000)
    return delta_ms if delta_ms >= 0 else None


if __name__ == "__main__":
    sys.exit(main())
