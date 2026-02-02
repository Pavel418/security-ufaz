"""
Configuration schema for the PCAP compaction pipeline.

Keep this lean and opinionated: only the knobs needed by the
current minimal feature set (five-tuple grouping, behavioral
features, scan splitting with Isolation Forest, and binomial
sampling for HTTP URI tokens).
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class PipelineConfig(BaseModel):
    """
    Centralized, validated configuration for one hourly run.
    All times are UTC seconds since epoch unless otherwise noted.
    """

    # === Windowing ===
    window_seconds: int = Field(
        default=3600,
        description="Tumbling window length; fixed at 1 hour by design.",
    )
    idle_split_seconds: int = Field(
        default=120,
        description="Split a group if no packets observed for this many seconds.",
    )

    # === Service inference ===
    unknown_service_label: Literal["unknown"] = Field(
        default="unknown",
        description="Label to use when dst_port does not map to a known service.",
    )

    # Minimal, opinionated port → service mapping (no deep parsing)
    service_port_map: dict[int, str] = Field(
        default_factory=lambda: {
            80: "http",
            8080: "http",
            21: "ftp",
            445: "smb",
            22: "ssh",
            53: "dns",
        },
        description="Heuristic mapping used to label the 'service' from dst_port.",
    )

    # === Scan handling (rule + Isolation Forest) ===
    scan_unique_dsts_threshold: int = Field(
        default=50,
        description="If a source IP contacts more than this many distinct destinations "
        "within the window, treat it as a scan-candidate.",
    )
    iforest_contamination: float = Field(
        default=0.14,
        ge=0.0,
        le=0.5,
        description="Target fraction of repetitive probes to filter.",
    )
    iforest_estimators: int = Field(
        default=256,
        ge=32,
        description="Number of trees for the Isolation Forest.",
    )
    iforest_random_state: int | None = Field(
        default=42,
        description="Seed for deterministic behavior; set None to randomize.",
    )

    # === Quantization (turn numerics into compact tokens) ===
    count_log_base: float = Field(
        default=2.0,
        gt=1.0,
        description="Log base for binning packet/byte counts.",
    )
    duration_log_base: float = Field(
        default=2.0,
        gt=1.0,
        description="Log base for binning session duration (seconds).",
    )

    # === Sampling (HTTP URI tokens) ===
    http_uri_token_budget: int = Field(
        default=40,
        ge=1,
        description="Maximum expected kept tokens per HTTP group after binomial sampling.",
    )
    http_always_keep_lexicon: tuple[str, ...] = Field(
        default=(
            "or",
            "and",
            "union",
            "select",
            "sleep",
            "benchmark",
            "'",
            '"',
            "--",
            ";",
            "/*",
            "*/",
            "%27",
            "%20or%20",
            "..",
        ),
        description="Security-critical tokens that bypass sampling.",
    )

    # === Backpressure / emission ===
    emitter_queue_capacity: int = Field(
        default=50000,
        ge=1024,
        description="Bounded queue size between pipeline and sink.",
    )
    emitter_backpressure_policy: Literal["block", "drop_oldest"] = Field(
        default="block",
        description="When the sink is slow: block producers or drop oldest records.",
    )

    class Config:
        frozen = True  # make instances hashable / safe to share across threads