"""Orchestrator inbox writer (mika#1189).

Posts session-end handoff messages to the mika-gateway orchestrator inbox
endpoint, supplementing the existing filesystem-inbox protocol from
mika-platform#100. Dual-write semantics during the migration window — the
filesystem write is the canonical path; the HTTP post is a side channel that
fails open.

Gated by two env vars (both must be set):

- ``MIKA_ORCHESTRATOR_INBOX_ENABLED`` — case-insensitive `1`/`true` enables
  the writer. `2` (gateway-only cutover) is reserved for a future ticket and
  currently treated as disabled to prevent silent partial cutover.
- ``MIKA_ORCHESTRATOR_ID`` — orchestrator session id passed through by
  ``scripts/mika-platform-spawn``. Must be 1-128 chars matching the gateway's
  ``[A-Za-z0-9_-]`` regex.

Transport reads ``MIKA_GATEWAY_URL`` and ``MIKA_INTERNAL_TOKEN`` (same env
vars the agent SDK already consumes). Failures are logged via stderr and never
change the agent's exit code — canonical output remains the stdout
``ResultJson`` line.

See the plan for the full rationale:
``mika/docs/plans/2026-05-17-003-feat-1189-mika-gateway-orchestrator-inbox-v2-plan.md``.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any

from .types import ResultJson

# Module-level constants (tuneable by code edit) — match the gateway side so
# either edit is enough to discover the other.

# Per-request timeout for the inbox write. Side-channel; we never want to slow
# the agent's shutdown waiting on a slow gateway.
INBOX_POST_TIMEOUT_SECS: float = 5.0

# Max body size we'll send. Belt-and-braces against accidental payload growth;
# the gateway enforces 256KB with a 413 anyway.
INBOX_BODY_LIMIT_BYTES: int = 200 * 1024


def is_orchestrator_inbox_enabled(raw: str | None) -> bool:
    """Mirror of the gateway's ``orchestrator_inbox_is_enabled`` rule.

    ``1`` and ``true`` (case-insensitive, surrounding whitespace stripped) are
    on. Anything else — including ``0``, ``false``, empty, ``2`` — is off.
    """
    if raw is None:
        return False
    lower = raw.strip().lower()
    return lower in ("1", "true")


def _is_valid_orchestrator_id(value: str) -> bool:
    """Match the gateway's ``is_valid_orchestrator_id`` so we never POST an id
    the gateway will reject with 400. ASCII-alphanumeric plus hyphen /
    underscore, 1-128 chars.
    """
    if not value or len(value) > 128:
        return False
    return all(c.isalnum() or c in "-_" for c in value)


def post_handoff(
    result: ResultJson,
    *,
    spawn_id: str | None = None,
    extra_body: dict[str, Any] | None = None,
) -> bool:
    """Post a handoff message to the orchestrator inbox.

    Returns ``True`` on a 201 from the gateway, ``False`` on any skip /
    failure. Never raises.

    The function reads env vars at call time so the caller doesn't need to
    cache them. Disabling the writer is a single env-var flip with no code
    change.

    ``spawn_id`` defaults to ``$MIKA_SPAWN_ID`` for consistency with
    mika-platform#100's filesystem-inbox protocol; pass explicitly to override.
    """
    enabled_raw = os.environ.get("MIKA_ORCHESTRATOR_INBOX_ENABLED")
    if not is_orchestrator_inbox_enabled(enabled_raw):
        return False

    orchestrator_id = os.environ.get("MIKA_ORCHESTRATOR_ID")
    if not orchestrator_id or not _is_valid_orchestrator_id(orchestrator_id):
        if orchestrator_id:
            _warn(
                "MIKA_ORCHESTRATOR_ID does not match the gateway's id rule "
                f"(1-128 chars [A-Za-z0-9_-]); got {orchestrator_id!r} — skipping inbox post."
            )
        return False

    gateway_url = os.environ.get("MIKA_GATEWAY_URL")
    if not gateway_url:
        _warn("MIKA_GATEWAY_URL unset; skipping orchestrator inbox post.")
        return False

    internal_token = os.environ.get("MIKA_INTERNAL_TOKEN")
    if not internal_token:
        _warn("MIKA_INTERNAL_TOKEN unset; skipping orchestrator inbox post.")
        return False

    if spawn_id is None:
        spawn_id = os.environ.get("MIKA_SPAWN_ID") or None

    body: dict[str, Any] = {
        "result": json.loads(result.to_line()),
    }
    if extra_body:
        body.update(extra_body)

    envelope: dict[str, Any] = {
        "spawn_id": spawn_id,
        "kind": "handoff",
        "body": body,
    }
    payload = json.dumps(envelope).encode("utf-8")
    if len(payload) > INBOX_BODY_LIMIT_BYTES:
        _warn(
            f"orchestrator inbox payload {len(payload)} bytes exceeds "
            f"INBOX_BODY_LIMIT_BYTES={INBOX_BODY_LIMIT_BYTES}; skipping post."
        )
        return False

    url = _build_url(gateway_url, orchestrator_id)
    req = urllib.request.Request(
        url,
        data=payload,
        method="POST",
        headers={
            "authorization": f"Bearer {internal_token}",
            "content-type": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=INBOX_POST_TIMEOUT_SECS) as resp:
            status = resp.status
            if status == 201:
                return True
            if status == 404:
                # Gateway has the feature flag off — caller is dual-writing
                # ahead of cutover. Silent skip; filesystem inbox carries the
                # canonical message.
                return False
            _warn(
                f"orchestrator inbox post returned unexpected status {status}; "
                "filesystem inbox remains the canonical path."
            )
            return False
    except urllib.error.HTTPError as e:
        _warn(
            f"orchestrator inbox post got HTTP {e.code}: {e.reason}; "
            "filesystem inbox remains the canonical path."
        )
        return False
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        _warn(
            f"orchestrator inbox post failed to reach {url}: {e}; "
            "filesystem inbox remains the canonical path."
        )
        return False


def _build_url(gateway_url: str, orchestrator_id: str) -> str:
    """Join the gateway base URL with the inbox path, normalizing trailing /."""
    base = gateway_url.rstrip("/")
    return f"{base}/orchestrator/inbox/{orchestrator_id}/message"


def _warn(msg: str) -> None:
    """Best-effort stderr write; never raises. Mirrors ``ui.log_*`` style
    without the ANSI deps so this module stays import-cheap."""
    try:
        sys.stderr.write(f"[claude-pilot inbox] {msg}\n")
        sys.stderr.flush()
    except OSError:
        pass
