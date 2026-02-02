"""
Quantization of numeric features into compact integer tokens.

We convert high-cardinality numeric features (counts, bytes, duration)
into small integers using logarithmic binning, and small integer flags
into linear bins. This keeps payloads tiny while preserving orders of
magnitude and relative shape, enabling the "283,491 → 312 tokens" style
compression.

Public API:
- quantize_tokens(counts, duration_s, flags, count_log_base, duration_log_base) -> Dict[str, int]
"""

from __future__ import annotations

import math
from typing import Dict


def quantize_tokens(
    *,
    counts: Dict[str, int],
    duration_s: float,
    flags: Dict[str, int],
    count_log_base: float = 2.0,
    duration_log_base: float = 2.0,
) -> Dict[str, int]:
    """
    Produce integer tokens from numeric primitives.

    Parameters
    ----------
    counts : dict
        Expected keys: pkts_up, pkts_dn, bytes_up, bytes_dn
    duration_s : float
        Session/group duration in seconds.
    flags : dict
        Expected keys: syn, ack, rst, fin
    count_log_base : float
        Log base for packet/byte counts (default 2).
    duration_log_base : float
        Log base for duration (default 2).

    Returns
    -------
    Dict[str, int]
        Keys: pkts_up_bin, pkts_dn_bin, bytes_up_bin, bytes_dn_bin,
              dur_bin, syn_bin, ack_bin, rst_bin, fin_bin
    """
    pkts_up = int(counts.get("pkts_up", 0))
    pkts_dn = int(counts.get("pkts_dn", 0))
    bytes_up = int(counts.get("bytes_up", 0))
    bytes_dn = int(counts.get("bytes_dn", 0))

    syn = int(flags.get("syn", 0))
    ack = int(flags.get("ack", 0))
    rst = int(flags.get("rst", 0))
    fin = int(flags.get("fin", 0))

    tokens: Dict[str, int] = {
        "pkts_up_bin": _log_bin(pkts_up, count_log_base),
        "pkts_dn_bin": _log_bin(pkts_dn, count_log_base),
        "bytes_up_bin": _log_bin(bytes_up, count_log_base),
        "bytes_dn_bin": _log_bin(bytes_dn, count_log_base),
        "dur_bin": _log_bin_float(max(0.0, float(duration_s)), duration_log_base),
        # Flags are typically small; linear bins preserve exact small counts.
        "syn_bin": _linear_bin(syn),
        "ack_bin": _linear_bin(ack),
        "rst_bin": _linear_bin(rst),
        "fin_bin": _linear_bin(fin),
    }
    return tokens


# === helpers ===


def _log_bin(x: int, base: float) -> int:
    """Logarithmic binning for non-negative integers."""
    if x <= 0:
        return 0
    if base <= 1.0:
        base = 2.0
    # floor(log_base(x)); clamp to int
    return int(math.floor(math.log(x, base)))


def _log_bin_float(x: float, base: float) -> int:
    """Logarithmic binning for non-negative floats (e.g., duration seconds)."""
    if x <= 0.0:
        return 0
    if base <= 1.0:
        base = 2.0
    return int(math.floor(math.log(x, base)))


def _linear_bin(x: int) -> int:
    """
    Linear bin for small integers (flags). This is effectively identity
    but enforces non-negativity and integer type.
    """
    return max(0, int(x))