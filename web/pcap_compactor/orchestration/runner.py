"""
Orchestrates one hourly compaction run.

This module wires together the intake (segment enumeration → packet stream)
and the core pipeline stages (windowing → grouping → features → quantize →
scan handling → enrichment → sampling → emission).

It intentionally keeps the control flow simple and each stage focused on
a single responsibility. Concrete stage implementations live in their
respective submodules.
"""

from __future__ import annotations

from typing import Dict, Iterable, Tuple

from ..config import PipelineConfig
from ..dto import GroupAggregate, GroupKey, GroupRecord, PacketRecord, ScanSummary
from ..ports import EventSinkPort, SegmentSourcePort

# === Stage imports (to be implemented in their own modules) ===
from ..intake.validator import validate_segment  # type: ignore
from ..intake.decompress import open_segment_stream  # type: ignore
from ..intake.packet_reader import iter_packets  # type: ignore

from ..pipeline.windowing import in_window  # type: ignore
from ..pipeline.grouping import (
    infer_service,
    group_direction,
    AggregatorShard,
)  # type: ignore
from ..pipeline.features import update_aggregate, finalize_aggregate  # type: ignore
from ..pipeline.quantize import quantize_tokens  # type: ignore
from ..pipeline.scan import ScanGate  # type: ignore
from ..pipeline.enrichers import enrich_group  # type: ignore
from ..pipeline.sampling import apply_http_binomial_sampling  # type: ignore
from ..pipeline.emitter import EmissionQueue  # type: ignore


def run_hour(
    *,
    source: SegmentSourcePort,
    sink: EventSinkPort,
    cfg: PipelineConfig,
    hour_start: int,
    hour_end: int,
) -> None:
    """
    Execute one hourly pipeline run over [hour_start, hour_end).

    This function owns orchestration only:
    - discovers segments via the SegmentSourcePort
    - validates and streams packets
    - routes packets through pipeline stages
    - flushes, finalizes, and emits GroupRecords / ScanSummaries
    - reports minimal metrics
    """
    metrics: Dict[str, int] = {
        "segments_seen": 0,
        "segments_valid": 0,
        "packets_processed": 0,
        "groups_emitted": 0,
        "scan_candidates": 0,
        "scans_collapsed": 0,
        "scan_outliers_kept": 0,
        "http_enriched": 0,
        "ftp_enriched": 0,
        "smb_enriched": 0,
        "sampling_applied": 0,
    }

    # Emission queue handles backpressure and forwards to the sink.
    emitter = EmissionQueue(
        sink=sink,
        capacity=cfg.emitter_queue_capacity,
        policy=cfg.emitter_backpressure_policy,
    )

    # Aggregation is sharded by hash(GroupKey) internally; keep the interface small.
    aggregator = AggregatorShard(idle_split_seconds=cfg.idle_split_seconds)

    # Scan gate handles the rule (>50 unique dsts) and IF split on syn_only_ratio.
    scan_gate = ScanGate(
        threshold_unique_dsts=cfg.scan_unique_dsts_threshold,
        iforest_contamination=cfg.iforest_contamination,
        iforest_estimators=cfg.iforest_estimators,
        iforest_random_state=cfg.iforest_random_state,
    )

    # === Intake & processing ===
    for seg in source.fetch(hour_start, hour_end):
        metrics["segments_seen"] += 1
        if not validate_segment(seg):
            # Invalid segments are skipped silently; real systems would log.
            continue
        metrics["segments_valid"] += 1

        # Open the (possibly compressed) segment as a byte stream and iterate packets.
        with open_segment_stream(seg) as bytestream:
            for pkt in iter_packets(bytestream, seg):
                # Window guard: keep state bounded strictly to [hour_start, hour_end).
                if not in_window(pkt.ts, hour_start, hour_end):
                    continue

                metrics["packets_processed"] += 1

                # Grouping key: five-tuple root (exclude src_port), service by dst_port heuristic.
                service = infer_service(pkt.dst_port)
                key = GroupKey(
                    src_ip=pkt.src_ip,
                    dst_ip=pkt.dst_ip,
                    dst_port=pkt.dst_port,
                    transport=pkt.transport,
                    service=service,
                )

                # Direction for counters: from src→dst is "up"; reverse is "down".
                direction = group_direction(pkt, key)

                # Update rolling aggregate in the appropriate shard.
                agg = aggregator.get_or_create(key, pkt.ts)
                update_aggregate(agg, pkt, direction)

                # Forward packet to the scan gate for per-source fanout tracking.
                scan_gate.observe_packet(pkt, key)

    # === Close hour: finalize aggregates, perform scan splitting and emit ===
    # 1) Identify scan candidates and split into repetitive vs. outliers.
    #    - repetitive -> collapsed ScanSummary and (optionally) drop their groups
    #    - outliers -> keep their groups for enrichment/emit
    candidates = scan_gate.candidates()
    metrics["scan_candidates"] = len(candidates)

    repetitive, outlier_sources = scan_gate.split_repetitive_vs_outliers()
    for summary in repetitive:
        emitter.emit_scan(summary)
        metrics["scans_collapsed"] += 1

    # 2) Finalize aggregates (close idle/open groups at hour end) and emit groups
    for agg in aggregator.finalize_all(hour_end):
        # If this aggregate belongs to a repetitive scan source, skip emission.
        if agg.key.src_ip in repetitive.source_ips:
            continue

        # Minimal enrichment: exactly one field per protocol as specified.
        enr_flags = enrich_group(agg)  # returns flags like {"http": True, "ftp": False, ...}
        metrics["http_enriched"] += int(bool(enr_flags.get("http")))
        metrics["ftp_enriched"] += int(bool(enr_flags.get("ftp")))
        metrics["smb_enriched"] += int(bool(enr_flags.get("smb")))

        # Apply binomial sampling to HTTP URI tokens if present.
        if agg.http_uri_tokens:
            applied = apply_http_binomial_sampling(
                agg, budget=cfg.http_uri_token_budget, always_keep=cfg.http_always_keep_lexicon
            )
            metrics["sampling_applied"] += int(applied)

        # Produce immutable GroupRecord with quantized tokens.
        record = _finalize_record(agg, (hour_start, hour_end), cfg)
        emitter.emit_group(record)
        metrics["groups_emitted"] += 1

    # Drain/close emitter queues and publish metrics to sink.
    emitter.close()
    sink.on_metrics(metrics)


# === Helpers ===


def _finalize_record(
    agg: GroupAggregate, lineage_hour: Tuple[int, int], cfg: PipelineConfig
) -> GroupRecord:
    """Convert a mutable aggregate into an immutable GroupRecord."""
    duration_s, counts, flags = finalize_aggregate(agg)

    tokens = quantize_tokens(
        counts=counts,
        duration_s=duration_s,
        flags=flags,
        count_log_base=cfg.count_log_base,
        duration_log_base=cfg.duration_log_base,
    )

    http = {"uri_tokens": list(agg.http_uri_tokens)} if agg.http_uri_tokens else None
    ftp = dict(agg.ftp_cmd_counts) if agg.ftp_cmd_counts else None
    smb = dict(agg.smb_cmd_counts) if agg.smb_cmd_counts else None

    return GroupRecord(
        key=agg.key,
        first_ts=agg.first_ts,
        last_ts=agg.last_ts,
        duration_s=duration_s,
        counts=counts,
        tcp_flags=flags,
        tokens=tokens,
        http=http,
        ftp=ftp,
        smb=smb,
        lineage_hour=lineage_hour,
    )