"""
Emission queue (synchronous, minimal).

Purpose
-------
Forward finalized outputs from the pipeline to the downstream consumer (EventSinkPort)
while exposing a simple backpressure policy knob. This implementation is intentionally
synchronous and lean: by default it **forwards immediately** to the sink. The queue
and policy exist to keep the boundary stable if you later swap in an async/worker
consumer.

Behavior
--------
- `emit_group(record)`  -> calls `sink.on_group(record)`
- `emit_scan(summary)`  -> calls `sink.on_scan(summary)`
- `close()`             -> no-op hook (kept for symmetry/future async)

Backpressure
------------
Since calls are synchronous, the "queue" is effectively size 0. The policy
parameters are accepted to keep a stable API. If you later introduce an async
buffer, implement:
  - policy="block": producers wait when capacity reached
  - policy="drop_oldest": evict oldest before enqueue

This file keeps the single-responsibility: emission only.
"""

from __future__ import annotations

from typing import Literal

from ..dto import GroupRecord, ScanSummary
from ..ports import EventSinkPort


class EmissionQueue:
    """
    Minimal synchronous emitter.

    Parameters
    ----------
    sink : EventSinkPort
        Downstream consumer; must be callable from this thread.
    capacity : int
        Ignored in this synchronous implementation; kept for API stability.
    policy : Literal["block", "drop_oldest"]
        Ignored here; relevant only if/when a real bounded queue is introduced.
    """

    def __init__(
        self,
        *,
        sink: EventSinkPort,
        capacity: int = 50000,
        policy: Literal["block", "drop_oldest"] = "block",
    ) -> None:
        self._sink = sink
        self._capacity = int(capacity)
        self._policy = policy

    # --- emission ---

    def emit_group(self, record: GroupRecord) -> None:
        """Forward one GroupRecord to the sink."""
        self._sink.on_group(record)

    def emit_scan(self, summary: ScanSummary) -> None:
        """Forward one ScanSummary to the sink."""
        self._sink.on_scan(summary)

    def close(self) -> None:
        """Hook for symmetry; no buffered state to flush in the sync path."""
        return