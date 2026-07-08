"""IPython extension surface: `%claude` / `%%claude` magics (claude-pilot#81).

Load inside an IPython >= 8 kernel (terminal IPython or Jupyter) with::

    %load_ext claude_pilot.ipython

`%claude "prompt"` runs a single-turn exchange in a fresh session;
`%%claude` sends the cell body as the prompt and keeps one multi-turn
session alive across invocations within the kernel.

IPython itself is an OPTIONAL dependency (``pip install claude-pilot[ipython]``)
— this package must therefore never be imported by the base CLI modules, and
its own IPython imports are deferred into ``load_ipython_extension`` so a
missing extra fails with an actionable message instead of a bare ImportError.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover — typing-only, avoids hard IPython import
    from .magics import ClaudeMagics

_MAGICS: ClaudeMagics | None = None


def load_ipython_extension(ipython: Any) -> None:
    """Register the `%claude` / `%%claude` magics with the running shell."""
    global _MAGICS
    try:
        from .magics import ClaudeMagics
    except ImportError as err:
        raise ImportError(
            "claude-pilot's IPython surface requires the 'ipython' extra: "
            "pip install 'claude-pilot[ipython]'"
        ) from err
    _MAGICS = ClaudeMagics(ipython)
    ipython.register_magics(_MAGICS)


def unload_ipython_extension(ipython: Any) -> None:
    """Tear down the kernel-resident session (disconnect SDK client, stop the
    background loop thread). IPython has no public magic-deregistration API, so
    the magic names stay bound until the kernel exits — but they hold no live
    resources after this."""
    global _MAGICS
    if _MAGICS is not None:
        _MAGICS.shutdown()
        _MAGICS = None
