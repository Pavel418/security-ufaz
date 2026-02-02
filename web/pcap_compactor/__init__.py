"""
pcap_compactor: Hierarchical compression for NIDS traffic.

Public API (stable):
- PipelineConfig           (configuration)
- run_hour                 (orchestrates one hourly run)
- SegmentSourcePort        (input adapter interface)
- EventSinkPort            (output adapter interface)
- FilesystemSegmentSource  (filesystem-backed segment source)
- DTOs: GroupRecord, ScanSummary, GroupKey, SegmentHandle, PacketRecord

This package intentionally exposes a small surface area so the rest of
your application can wire sources/sinks without depending on internals.
"""

from __future__ import annotations

# Configuration
from .config import PipelineConfig

# Orchestration
from .orchestration.runner import run_hour

# Ports
from .ports import EventSinkPort, SegmentSourcePort

# Adapters
from .intake.segment_source_fs import FilesystemSegmentSource

# DTOs
from .dto import (
    GroupKey,
    GroupRecord,
    PacketRecord,
    ScanSummary,
    SegmentHandle,
)

__all__ = [
    "PipelineConfig",
    "run_hour",
    "EventSinkPort",
    "SegmentSourcePort",
    "FilesystemSegmentSource",
    "GroupKey",
    "GroupRecord",
    "PacketRecord",
    "ScanSummary",
    "SegmentHandle",
]