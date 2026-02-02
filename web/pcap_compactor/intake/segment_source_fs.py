"""
Filesystem-backed SegmentSource adapter.

It enumerates PCAP/PCAPNG segment files from a directory layout like:
  <root>/<sensor>/<YYYY>/<MM>/<DD>/<HH>/*.(pcap|pcapng)[.(zst|gz)]

This module is intentionally simple and robust:
- It relies on directory partitioning by hour (recommended).
- It does NOT open files; validation (magic bytes, etc.) happens later.
- It infers compression from filename suffix; validator will double-check.

If your layout differs, you can subclass or provide a different SegmentSourcePort.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator, Literal, Optional, Sequence, Tuple

from ..dto import SegmentHandle
from ..ports import SegmentSourcePort


# Accepted filename suffixes
PCAP_SUFFIXES = (".pcap", ".pcapng")
COMP_SUFFIXES: Tuple[Tuple[str, Literal["gzip", "zstd", "none"]], ...] = (
    (".pcap.zst", "zstd"),
    (".pcapng.zst", "zstd"),
    (".zst", "zstd"),
    (".pcap.gz", "gzip"),
    (".pcapng.gz", "gzip"),
    (".gz", "gzip"),
)


@dataclass(frozen=True)
class FilesystemSegmentSource(SegmentSourcePort):
    """
    Enumerate PCAP/PCAPNG segments from a filesystem tree.

    Parameters
    ----------
    root : str | os.PathLike
        Root directory under which segments are stored.
    sensors : Optional[Sequence[str]]
        If provided, only enumerate these sensor IDs (directory names under root).
        If None, enumerate all immediate subdirectories as sensors.
    """

    root: str | os.PathLike
    sensors: Optional[Sequence[str]] = None

    def fetch(self, hour_start: int, hour_end: int) -> Iterable[SegmentHandle]:
        """
        Yield SegmentHandle objects for files under:
          <root>/<sensor>/<YYYY>/<MM>/<DD>/<HH>/

        The start/end timestamps in the handle are **approximate** here (the hour bounds);
        exact per-packet times are enforced later during processing.
        """
        root_path = Path(self.root)

        if not root_path.exists():
            return []

        y, m, d, hh = _ymdh_from_epoch(hour_start)
        hour_dir_glob = f"{y:04d}/{m:02d}/{d:02d}/{hh:02d}"

        sensors = list(self.sensors) if self.sensors is not None else _list_sensors(root_path)

        def _iter() -> Iterator[SegmentHandle]:
            for sensor in sensors:
                sensor_dir = root_path / sensor / hour_dir_glob
                if not sensor_dir.exists() or not sensor_dir.is_dir():
                    continue

                for p in sorted(sensor_dir.iterdir()):
                    if not p.is_file():
                        continue
                    comp = _infer_compressor(p.name)
                    if comp == "none" and not p.suffix.lower() in PCAP_SUFFIXES:
                        # Not a recognizable segment file; skip silently.
                        continue

                    # ID is stable and human-readable: relative path from root.
                    seg_id = str(p.relative_to(root_path))
                    # Approximate timestamps: bound to the requested hour window.
                    handle = SegmentHandle(
                        id=seg_id,
                        sensor=sensor,
                        start_ts=float(hour_start),
                        end_ts=float(hour_end),
                        path=str(p),
                        compressor=comp,
                    )
                    yield handle

        return _iter()


# === Helpers ===


def _list_sensors(root_path: Path) -> list[str]:
    sensors: list[str] = []
    try:
        for child in root_path.iterdir():
            if child.is_dir():
                sensors.append(child.name)
    except FileNotFoundError:
        pass
    return sorted(sensors)


def _ymdh_from_epoch(ts: int) -> Tuple[int, int, int, int]:
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    return dt.year, dt.month, dt.day, dt.hour


def _infer_compressor(name: str) -> Literal["gzip", "zstd", "none"]:
    lower = name.lower()
    for suffix, comp in COMP_SUFFIXES:
        if lower.endswith(suffix):
            return comp
    # No explicit compression suffix; bare .pcap/.pcapng or other
    return "none"