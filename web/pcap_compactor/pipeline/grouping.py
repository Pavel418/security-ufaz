"""
Grouping primitives and aggregate lifecycle.

Responsibilities (kept minimal, one thing each):
- Infer a coarse 'service' label from destination port (no deep parsing).
- Decide packet direction relative to a GroupKey (up: src→dst, down: dst→src).
- Maintain mutable GroupAggregate instances and roll them on idle gaps.

Notes
-----
- The five-tuple root key deliberately EXCLUDES the ephemeral source port.
- Idle rolling prevents unbounded aggregates for long-lived connections.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Literal, Tuple

from ..dto import GroupAggregate, GroupKey, PacketRecord, Transport

# ---- Service inference (single heuristic rule: dst_port -> service) ----

_PORT_SERVICE_MAP: Dict[int, str] = {
    80: "http",
    8080: "http",
    21: "ftp",
    445: "smb",
    22: "ssh",
    53: "dns",
}
_UNKNOWN: str = "unknown"


def infer_service(dst_port: int) -> str:
    """Map destination port to a coarse service label or 'unknown'."""
    return _PORT_SERVICE_MAP.get(int(dst_port), _UNKNOWN)


# ---- Direction decision ----

Direction = Literal["up", "dn"]


def group_direction(pkt: PacketRecord, key: GroupKey) -> Direction:
    """
    Determine direction of the packet relative to the GroupKey.

    - "up": from key.src_ip -> key.dst_ip (i.e., pkt src==key.src, dst==key.dst)
    - "dn": reverse traffic (key.dst_ip -> key.src_ip)
    - If neither matches (should be rare), default to "up" to keep counts consistent.
    """
    if pkt.src_ip == key.src_ip and pkt.dst_ip == key.dst_ip:
        return "up"
    if pkt.src_ip == key.dst_ip and pkt.dst_ip == key.src_ip:
        return "dn"
    # Fallback: default to up
    return "up"


# ---- Aggregation shard ----

@dataclass
class _Entry:
    agg: GroupAggregate


class AggregatorShard:
    """
    Manages GroupAggregate objects keyed by GroupKey and rolls them on idle gaps.

    Only one knob: idle_split_seconds (gap threshold to start a new aggregate slice).
    """

    def __init__(self, *, idle_split_seconds: int = 120) -> None:
        self._idle = float(idle_split_seconds)
        self._open: Dict[GroupKey, _Entry] = {}
        self._finalized: List[GroupAggregate] = []

    # --- lifecycle ---

    def get_or_create(self, key: GroupKey, ts: float) -> GroupAggregate:
        """
        Return the current mutable aggregate for `key`, rolling it if idle gap exceeded.

        Rolling rule:
        If there is an open aggregate for `key` and (ts - agg.last_ts) > idle_split_seconds,
        finalize the existing one and start a fresh aggregate with timestamps at `ts`.
        """
        entry = self._open.get(key)
        if entry is None:
            agg = self._new_aggregate(key, ts)
            self._open[key] = _Entry(agg=agg)
            return agg

        agg = entry.agg
        if ts - agg.last_ts > self._idle:
            # finalize current and open a new slice
            self._finalized.append(agg)
            agg = self._new_aggregate(key, ts)
            entry.agg = agg
        return agg

    def finalize_all(self, hour_end: int) -> Iterable[GroupAggregate]:
        """
        Close all open aggregates at hour end and yield finalized ones.

        The aggregates remain mutable inside but callers should treat them as closed and
        immediately convert to immutable GroupRecord via features.finalize_aggregate().
        """
        # Move open aggregates to finalized list
        for entry in self._open.values():
            self._finalized.append(entry.agg)
        self._open.clear()

        # Yield and clear finalized list
        out = self._finalized
        self._finalized = []
        return out

    # --- helpers ---

    @staticmethod
    def _new_aggregate(key: GroupKey, ts: float) -> GroupAggregate:
        """Create a fresh aggregate initialized with zero counters at timestamp ts."""
        return GroupAggregate(
            key=key,
            first_ts=float(ts),
            last_ts=float(ts),
            pkts_up=0,
            pkts_dn=0,
            bytes_up=0,
            bytes_dn=0,
            tcp_flags={"syn": 0, "ack": 0, "rst": 0, "fin": 0},
            http_uri_tokens=None,
            ftp_cmd_counts=None,
            smb_cmd_counts=None,
        )