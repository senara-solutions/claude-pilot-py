"""Best-effort operator notification via ``mika notify``."""

from __future__ import annotations

import logging
import shutil
import subprocess

logger = logging.getLogger(__name__)


def notify_escalation(text: str) -> None:
    """Fire-and-forget ``mika notify --text <text> --severity escalate``.

    Silent on failure -- this is a best-effort notification channel.
    Uses subprocess.Popen with argv list to avoid shell injection.
    """
    mika_bin = shutil.which("mika")
    if not mika_bin:
        logger.debug("notify: mika binary not found on PATH")
        return

    try:
        subprocess.Popen(
            [mika_bin, "notify", "--text", text, "--severity", "escalate"],
            close_fds=True,
            start_new_session=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        logger.debug("notify: mika notify failed (best-effort)", exc_info=True)
