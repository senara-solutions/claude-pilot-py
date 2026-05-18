"""Best-effort operator notification via ``mika notify``."""

from __future__ import annotations

import logging
import os
import shlex
import shutil

logger = logging.getLogger(__name__)


def notify_escalation(text: str) -> None:
    """Fire-and-forget ``mika notify --text <text> --severity escalate``.

    Silent on failure -- this is a best-effort notification channel.
    Uses os.system for simplicity since this is fire-and-forget.
    """
    mika_bin = shutil.which("mika")
    if not mika_bin:
        logger.debug("notify: mika binary not found on PATH")
        return

    try:
        escaped_text = shlex.quote(text)
        escaped_bin = shlex.quote(mika_bin)
        os.system(f"{escaped_bin} notify --text {escaped_text} --severity escalate &")
    except Exception:
        logger.debug("notify: mika notify failed (best-effort)", exc_info=True)
