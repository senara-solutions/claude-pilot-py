"""File + stderr logging with ANSI stripping for the file sink.

Port of src/logger.ts. Single module-level file handle; first write failure
reports one warning and disables further file writes (best-effort sink, never
crashes the session).
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import IO

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

_file: IO[str] | None = None
_error_reported = False


def init_file_log(file_path: str) -> None:
    global _file, _error_reported
    _error_reported = False
    path = Path(file_path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        _file = path.open("a", encoding="utf-8")
        # Best-effort chmod; ignore if filesystem doesn't support it.
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    except OSError as err:
        _report_error(err)
        _file = None


def write_log(msg: str) -> None:
    """Write to stderr (with color) and to the file sink (without color)."""
    sys.stderr.write(msg)
    sys.stderr.flush()
    _write_file(msg)


def write_file_log(msg: str) -> None:
    """Write only to the file sink (skip stderr)."""
    _write_file(msg)


def close_file_log() -> None:
    global _file
    if _file is not None:
        try:
            _file.close()
        except OSError:
            pass
        _file = None


def _write_file(msg: str) -> None:
    global _file
    if _file is None:
        return
    try:
        _file.write(_ANSI_RE.sub("", msg))
        _file.flush()
    except OSError as err:
        _report_error(err)
        _file = None


def _report_error(err: OSError) -> None:
    global _error_reported
    if not _error_reported:
        _error_reported = True
        sys.stderr.write(f"Warning: log file write error: {err}\n")
