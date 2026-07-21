"""Structured audit events emitted from claude-pilot for mika-side collection.

cpp does not own a database — the receiving side (mika-agent) reads
these events off stderr. The wire shape is one JSON object per line,
prefixed with the load-bearing tag ``[claude-pilot audit_event]`` so
mika-agent can distinguish audit lines from prose log output.

Introduced by mika#1708 (per-spawn permission-policy) — AC5 requires
``perm_policy_mode`` on every dispatch and ``perm_policy_rollback`` on
per_spawn block. Consumers of this module may add further event kinds
as new features need cross-process telemetry, but the wire shape and
tag are stable API.
"""

from __future__ import annotations

import json
import sys
import time
from typing import Any

AUDIT_TAG: str = "[claude-pilot audit_event]"
"""Load-bearing prefix on every audit line.

mika-agent parses cpp stderr for tool events (see ``crates/mika-agent/`` for
the parse); adding a distinct tag lets it split audit signal from prose
without changing the existing tool-event grammar.
"""


def emit(kind: str, detail: dict[str, Any] | None = None) -> None:
    """Emit a single audit event to stderr.

    Best-effort — a failed write must never affect the primary path
    (permission-callback returning to the SDK). All exceptions are
    swallowed here.

    Args:
        kind: Short event kind (e.g. ``perm_policy_mode``,
            ``perm_policy_rollback``). By convention kebab-case with
            underscores.
        detail: Arbitrary JSON-serializable payload. Sensitive values
            (tokens, secrets) must be scrubbed by the caller — this
            module writes ``detail`` verbatim.
    """
    payload: dict[str, Any] = {
        "kind": kind,
        "ts": _now_iso(),
    }
    if detail is not None:
        payload["detail"] = detail
    try:
        line = f"{AUDIT_TAG} {json.dumps(payload, default=str)}\n"
        sys.stderr.write(line)
        sys.stderr.flush()
    except Exception:
        # Never let audit-emit failure propagate to the caller.
        pass


def _now_iso() -> str:
    """UTC timestamp, ISO 8601 with seconds precision."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
