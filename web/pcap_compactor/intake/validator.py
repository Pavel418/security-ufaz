"""
Basic segment validation.

Goal: fast, side-effect-free checks that a segment *looks* like a PCAP/PCAPNG
file (optionally compressed with gzip or zstd) before we spend CPU parsing it.

We DO NOT fully parse headers here—just magic bytes / size sanity—because the
decompressor and packet reader will do deeper checks later.
"""

from __future__ import annotations

import os
from typing import Final

from ..dto import SegmentHandle

# --- Magic numbers (big-endian byte order as they appear on disk) ---

# Uncompressed PCAP
MAGIC_PCAP_USEC_BE: Final[bytes] = bytes.fromhex("a1 b2 c3 d4".replace(" ", ""))
MAGIC_PCAP_USEC_LE: Final[bytes] = bytes.fromhex("d4 c3 b2 a1".replace(" ", ""))
MAGIC_PCAP_NSEC_BE: Final[bytes] = bytes.fromhex("a1 b2 3c 4d".replace(" ", ""))
MAGIC_PCAP_NSEC_LE: Final[bytes] = bytes.fromhex("4d 3c b2 a1".replace(" ", ""))

# PCAPNG
MAGIC_PCAPNG: Final[bytes] = bytes.fromhex("0a 0d 0d 0a".replace(" ", ""))

# Compression
MAGIC_GZIP: Final[bytes] = bytes.fromhex("1f 8b")
MAGIC_ZSTD: Final[bytes] = bytes.fromhex("28 b5 2f fd")


def _read_head(path: str, n: int) -> bytes:
    with open(path, "rb") as f:
        return f.read(n)


def _looks_like_uncompressed_pcap(head: bytes) -> bool:
    if len(head) < 4:
        return False
    sig4 = head[:4]
    if sig4 in (MAGIC_PCAP_USEC_BE, MAGIC_PCAP_USEC_LE, MAGIC_PCAP_NSEC_BE, MAGIC_PCAP_NSEC_LE):
        return True
    if sig4 == MAGIC_PCAPNG:
        return True
    return False


def _looks_like_gzip(head: bytes) -> bool:
    return len(head) >= 2 and head[:2] == MAGIC_GZIP


def _looks_like_zstd(head: bytes) -> bool:
    return len(head) >= 4 and head[:4] == MAGIC_ZSTD


def validate_segment(seg: SegmentHandle) -> bool:
    """
    Quick validation of a SegmentHandle path.

    Checks:
    - File exists and has non-trivial size (> 24 bytes).
    - If compressor == none: magic bytes match PCAP or PCAPNG.
    - If compressor == gzip/zstd: magic bytes match the compressor.

    Returns True if basic checks pass, False otherwise.
    """
    try:
        st = os.stat(seg.path)
    except FileNotFoundError:
        return False
    except OSError:
        return False

    # Minimal size sanity (pcap global header ~24 bytes; pcapng SHB 32 bytes+)
    if st.st_size < 24:
        return False

    # Read a small prefix for magic checks
    head = _read_head(seg.path, 16)

    if seg.compressor == "none":
        return _looks_like_uncompressed_pcap(head)

    if seg.compressor == "gzip":
        return _looks_like_gzip(head)

    if seg.compressor == "zstd":
        return _looks_like_zstd(head)

    # Unknown compressor label (shouldn't happen)
    return False