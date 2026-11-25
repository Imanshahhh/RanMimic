# killswitch.py
"""
Kill switch handler - registers SIGINT (Ctrl+C) so any in-progress
simulation can be cleanly aborted and auto-restored rather than left
in a half-encrypted state.
"""

import signal
from typing import Callable

_on_abort_callback: Callable[[], None] | None = None


def register(on_abort: Callable[[], None]) -> None:
    """
    Register the function to call when an abort signal (Ctrl+C) is received.
    Must be called once at program startup, before any file operations begin.
    """
    global _on_abort_callback
    _on_abort_callback = on_abort
    signal.signal(signal.SIGINT, _handle_signal)


def _handle_signal(signum, frame):
    if _on_abort_callback is not None:
        _on_abort_callback()
    else:
        raise SystemExit(1)