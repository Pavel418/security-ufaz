"""
Compressed segment opener.

Provides a single entry point `open_segment_stream(seg)` that returns a
binary file-like object for reading the segment's raw bytes, regardless
of whether the underlying file is uncompressed, gzip-compressed, or
zstd-compressed.

This module does not parse PCAP/PCAPNG; it only handles decompression.
"""

from __future__ import annotations

import gzip
from contextlib import contextmanager
from typing import Generator, IO

import zstandard  # type: ignore

from ..dto import SegmentHandle


@contextmanager
def open_segment_stream(seg: SegmentHandle) -> Generator[IO[bytes], None, None]:
    """
    Context manager yielding a readable binary stream for the given segment.

    - seg.compressor == "none": open() in 'rb'
    - seg.compressor == "gzip": gzip.open(..., 'rb')
    - seg.compressor == "zstd": zstd stream reader over the file

    The caller is responsible for consuming bytes and closing the context.
    """
    if seg.compressor == "none":
        f = open(seg.path, "rb")
        try:
            yield f
        finally:
            f.close()
        return

    if seg.compressor == "gzip":
        f = gzip.open(seg.path, "rb")
        try:
            yield f  # gzip.GzipFile is file-like
        finally:
            f.close()
        return

    if seg.compressor == "zstd":
        raw = open(seg.path, "rb")
        dctx = zstandard.ZstdDecompressor()
        stream = dctx.stream_reader(raw)
        try:
            yield stream  # has .read(), acts like a file object
        finally:
            try:
                stream.close()
            finally:
                raw.close()
        return

    # Fallback: treat as plain file (should not happen if validator is correct)
    f = open(seg.path, "rb")
    try:
        yield f
    finally:
        f.close()