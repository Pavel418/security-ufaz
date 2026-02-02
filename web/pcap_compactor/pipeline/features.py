"""
Feature construction for grouped traffic.

Responsibilities (kept minimal):
- Update a GroupAggregate with directional packet/byte counters and TCP flag counts.
- Stash a SMALL number of payload previews per direction for later enrichment.
- Finalize an aggregate into immutable primitives needed downstream
  (duration, counts dict, tcp flag dict).

Notes
-----
- Only the four primary TCP flags are tracked: SYN, ACK, RST, FIN.
- Direction is decided by grouping.group_direction and passed in explicitly.
"""

from __future__ import annotations

from typing import Dict, Tuple, List

from ..dto import GroupAggregate, PacketRecord
from .grouping import Direction

# TCP flag bitmasks (aligned with common stacks and dpkt constants)
_TCP_FIN = 0x01
_TCP_SYN = 0x02
_TCP_RST = 0x04
_TCP_ACK = 0x10

# Payload preview caps (per aggregate, per direction) to bound memory.
_MAX_PREVIEWS_PER_DIR = 12  # keep at most 12 short previews "up" and 12 "dn"


def update_aggregate(agg: GroupAggregate, pkt: PacketRecord, direction: Direction) -> None:
    """
    Update the rolling aggregate with a single packet.

    Parameters
    ----------
    agg : GroupAggregate
        Mutable aggregate for the packet's group.
    pkt : PacketRecord
        Minimal per-packet data (may include small payload_preview for TCP).
    direction : Literal["up", "dn"]
        Direction relative to the GroupKey (up = src->dst; dn = dst->src).
    """
    # Update time bounds
    if pkt.ts < agg.first_ts:
        agg.first_ts = float(pkt.ts)
    if pkt.ts > agg.last_ts:
        agg.last_ts = float(pkt.ts)

    # Directional counters
    if direction == "up":
        agg.pkts_up += 1
        agg.bytes_up += int(pkt.length)
    else:
        agg.pkts_dn += 1
        agg.bytes_dn += int(pkt.length)

    # TCP flag histogram (only if TCP)
    if pkt.tcp_flags is not None:
        flags = int(pkt.tcp_flags)
        if flags & _TCP_SYN:
            agg.tcp_flags["syn"] += 1
        if flags & _TCP_ACK:
            agg.tcp_flags["ack"] += 1
        if flags & _TCP_RST:
            agg.tcp_flags["rst"] += 1
        if flags & _TCP_FIN:
            agg.tcp_flags["fin"] += 1

    # Stash small payload previews (if present) for enrichers; bound memory tightly.
    if pkt.payload_preview:
        if direction == "up":
            buf: List[bytes] = getattr(agg, "_payload_up", [])
            if not buf:
                setattr(agg, "_payload_up", buf)
            if len(buf) < _MAX_PREVIEWS_PER_DIR:
                buf.append(pkt.payload_preview)
        else:
            buf: List[bytes] = getattr(agg, "_payload_dn", [])
            if not buf:
                setattr(agg, "_payload_dn", buf)
            if len(buf) < _MAX_PREVIEWS_PER_DIR:
                buf.append(pkt.payload_preview)


def finalize_aggregate(agg: GroupAggregate) -> Tuple[float, Dict[str, int], Dict[str, int]]:
    """
    Convert a mutable GroupAggregate into finalized primitive values.

    Returns
    -------
    duration_s : float
        Duration in seconds (last_ts - first_ts, floored at 0).
    counts : Dict[str, int]
        Keys: pkts_up, pkts_dn, bytes_up, bytes_dn
    flags : Dict[str, int]
        Keys: syn, ack, rst, fin (copied from aggregate)
    """
    duration_s = max(0.0, float(agg.last_ts) - float(agg.first_ts))

    counts = {
        "pkts_up": int(agg.pkts_up),
        "pkts_dn": int(agg.pkts_dn),
        "bytes_up": int(agg.bytes_up),
        "bytes_dn": int(agg.bytes_dn),
    }

    # copy to avoid accidental mutation by callers
    flags = {
        "syn": int(agg.tcp_flags.get("syn", 0)),
        "ack": int(agg.tcp_flags.get("ack", 0)),
        "rst": int(agg.tcp_flags.get("rst", 0)),
        "fin": int(agg.tcp_flags.get("fin", 0)),
    }

    return duration_s, counts, flags