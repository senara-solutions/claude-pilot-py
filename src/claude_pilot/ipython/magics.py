"""`%claude` / `%%claude` magic definitions (claude-pilot#81).

One ``@line_cell_magic`` handles both spellings:

* ``%claude "prompt"`` — single-turn exchange in a fresh, throwaway session.
* ``%%claude`` — the cell body is the prompt; ONE persistent session per
  kernel carries multi-turn continuity across invocations.

Kept import-safe only under the ``ipython`` extra — the package
``__init__`` defers importing this module until ``%load_ext`` time.
"""

from __future__ import annotations

from typing import Any

from IPython.core.error import UsageError
from IPython.core.magic import Magics, line_cell_magic, magics_class

from .session import ClaudeKernelSession, SessionConfigError, ask_once

_LINE_USAGE = 'usage: %claude "prompt"'
_CELL_USAGE = "%%claude takes no arguments — the cell body is the prompt"


def parse_line_prompt(line: str) -> str:
    """Extract the prompt from a `%claude` argument line.

    Accepts both the quoted form from the issue (``%claude "prompt"``) and a
    bare unquoted tail (``%claude what is this repo?``). A single pair of
    matching outer quotes is stripped; inner quotes are preserved verbatim.
    """
    stripped = line.strip()
    if len(stripped) >= 2 and stripped[0] == stripped[-1] and stripped[0] in "'\"":
        return stripped[1:-1].strip()
    return stripped


@magics_class
class ClaudeMagics(Magics):
    """Magic container owning the kernel's persistent `%%claude` session."""

    def __init__(self, shell: Any) -> None:
        super().__init__(shell)
        self._session: ClaudeKernelSession | None = None

    @line_cell_magic
    def claude(self, line: str, cell: str | None = None) -> None:
        """Run a Claude Code exchange with the headless pilot's permission chain."""
        try:
            if cell is None:
                self._run_line(line)
            else:
                self._run_cell(line, cell)
        except SessionConfigError as err:
            raise UsageError(str(err)) from err

    def _run_line(self, line: str) -> None:
        prompt = parse_line_prompt(line)
        if not prompt:
            raise UsageError(_LINE_USAGE)
        ask_once(prompt)

    def _run_cell(self, line: str, cell: str) -> None:
        if line.strip():
            # No options exist yet; reject rather than silently swallow so a
            # future flag surface stays backward-compatible.
            raise UsageError(_CELL_USAGE)
        prompt = cell.strip()
        if not prompt:
            raise UsageError("%%claude: cell body is empty")
        if self._session is None:
            self._session = ClaudeKernelSession()
        self._session.ask(prompt)

    def shutdown(self) -> None:
        """Close the persistent session (called by `%unload_ext`)."""
        if self._session is not None:
            self._session.close()
            self._session = None
