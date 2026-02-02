"""
Hexagonal interfaces (Ports) for the compaction pipeline.

These define the boundary between core domain logic and I/O adapters.
Keep them small and implementation-agnostic so they’re easy to mock in tests.
"""

from __future__ import annotations

from typing import Dict, Iterable, Protocol

from .dto import GroupRecord, ScanSummary, SegmentHandle


class SegmentSourcePort(Protocol):
    """
    Supplies PCAP/PCAPNG segments overlapping a given hourly window.
    Implementations may read from local FS, object stores, or any catalog.
    """

    def fetch(self, hour_start: int, hour_end: int) -> Iterable[SegmentHandle]:
        """
        Return an iterable of SegmentHandle items for [hour_start, hour_end).
        Times are epoch seconds (UTC). Implementations MUST avoid yielding
        segments that are still being written (atomic rename or success marker).
        """
        ...


class EventSinkPort(Protocol):
    """
    Receives emitted records and metrics from the pipeline.
    Implementations might push to an in-process queue, call a callback,
    or publish to a bus—no persistence here by design.
    """

    def on_group(self, record: GroupRecord) -> None:
        """Receive one finalized GroupRecord."""
        ...

    def on_scan(self, summary: ScanSummary) -> None:
        """Receive one collapsed repetitive-scan summary."""
        ...

    def on_metrics(self, metrics: Dict[str, int]) -> None:
        """
        Receive a minimal metrics snapshot at the end of the run
        (e.g., packets_processed, groups_emitted, scans_collapsed, etc.).
        """
        ...