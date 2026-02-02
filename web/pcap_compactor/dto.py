"""
Data Transfer Objects (DTOs) used across the compaction pipeline.

These are intentionally small, immutable (where sensible), and independent
of any I/O or parsing libraries.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Literal, Optional, Tuple

Transport = Literal["tcp", "udp", "other"]


# === Intake ===
@dataclass(frozen=True)
class SegmentHandle:
    """Represents one PCAP/PCAPNG segment to process within a window."""
    id: str                  # stable identifier (e.g., filename without path)
    sensor: str              # capture source identifier
    start_ts: float          # epoch seconds, first packet (approx/sidecar)
    end_ts: float            # epoch seconds, last packet (approx/sidecar)
    path: str                # filesystem/object path
    compressor: Literal["none", "gzip", "zstd"]


# === Normalized packet ===
@dataclass(frozen=True)
class PacketRecord:
    """Minimal per-packet view the pipeline needs; payload not stored (except tiny preview)."""
    ts: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    transport: Transport
    tcp_flags: Optional[int]  # bitmask if TCP, else None
    length: int               # L2/L3-dependent total length (consistent within project)
    # NEW: optional short application payload preview (e.g., first 256 bytes for TCP).
    # Used by enrichers to extract HTTP/FTP/SMB tokens without retaining full payloads.
    payload_preview: Optional[bytes] = None


# === Grouping key (hierarchical root) ===
@dataclass(frozen=True)
class GroupKey:
    """Five-tuple root (excludes ephemeral source port by design)."""
    src_ip: str
    dst_ip: str
    dst_port: int
    transport: Transport
    service: str  # inferred from dst_port or "unknown"


# === Rolling aggregate (mutable during build) ===
@dataclass
class GroupAggregate:
    """In-memory accumulator for one group within the hour (or idle-split slice)."""
    key: GroupKey
    first_ts: float
    last_ts: float
    pkts_up: int
    pkts_dn: int
    bytes_up: int
    bytes_dn: int
    tcp_flags: Dict[str, int]              # keys: syn, ack, rst, fin

    # Minimal protocol enrichments (set by enrichers if applicable)
    http_uri_tokens: Optional[List[str]] = None
    ftp_cmd_counts: Optional[Dict[str, int]] = None
    smb_cmd_counts: Optional[Dict[str, int]] = None

    # NOTE: payload previews are attached dynamically as private attrs by features.py:
    #   _payload_up: List[bytes]
    #   _payload_dn: List[bytes]


# === Final immutable record for emission ===
@dataclass(frozen=True)
class GroupRecord:
    key: GroupKey
    first_ts: float
    last_ts: float
    duration_s: float
    counts: Dict[str, int]                 # pkts_up, pkts_dn, bytes_up, bytes_dn
    tcp_flags: Dict[str, int]              # syn, ack, rst, fin
    tokens: Dict[str, int]                 # quantized bins (e.g., bytes_up_bin=10)
    http: Optional[Dict[str, List[str]]] = None   # {"uri_tokens": [...]}
    ftp: Optional[Dict[str, int]] = None           # {"USER": n, "PASS": m, ...}
    smb: Optional[Dict[str, int]] = None           # {"NEGOTIATE": n, ...}
    lineage_hour: Tuple[int, int] = (0, 0)         # (hour_start, hour_end) UTC


# === Scan summary (collapsed repetitive probes) ===
@dataclass(frozen=True)
class ScanSummary:
    src_ip: str
    window: Tuple[int, int]                # (hour_start, hour_end) UTC
    unique_dsts: int
    unique_ports: int
    syn_only_ratio: float
    sample_targets: List[Tuple[str, int]]  # [(dst_ip, dst_port), ...]