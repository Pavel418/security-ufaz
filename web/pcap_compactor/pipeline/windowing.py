"""
Windowing utilities.

The pipeline operates on fixed, tumbling hourly windows. This module provides
a minimal helper to check whether a packet timestamp falls within a given
window. All times are epoch seconds (UTC).
"""

from __future__ import annotations


def in_window(ts: float, window_start: int, window_end: int) -> bool:
    """
    Return True if ts is within [window_start, window_end), else False.

    Parameters
    ----------
    ts : float
        Packet/event timestamp (epoch seconds).
    window_start : int
        Inclusive lower bound (epoch seconds).
    window_end : int
        Exclusive upper bound (epoch seconds).

    Notes
    -----
    - We treat the upper bound as exclusive to avoid double-counting on boundaries.
    - Timestamps slightly outside due to clock skew should already be filtered
      at intake/orchestration; keep this predicate strict.
    """
    return float(window_start) <= ts < float(window_end)