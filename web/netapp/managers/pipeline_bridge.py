from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Dict, List, Tuple

from pcap_compactor import PipelineConfig, run_hour
from pcap_compactor.ports import EventSinkPort, SegmentSourcePort
from pcap_compactor.dto import SegmentHandle, GroupRecord, ScanSummary

from detector.utils.prompt_loader import load_config, get_prompts
from detector.pipelines.pipeline import run_pipeline
from detector.llm_clients.openai_client import OpenAIClient


# --- Minimal SegmentSource for a single file ---------------------------------
class SingleFileSegmentSource(SegmentSourcePort):
    def __init__(self, pcap_path: str) -> None:
        self._p = str(pcap_path)

    def fetch(self, hour_start: int, hour_end: int):
        yield SegmentHandle(
            id=Path(self._p).name,
            sensor="web",
            start_ts=float(hour_start),
            end_ts=float(hour_end),
            path=self._p,
            compressor="none",
        )


# --- Collecting sink ----------------------------------------------------------
class CollectingSink(EventSinkPort):
    def __init__(self) -> None:
        self.groups: List[GroupRecord] = []
        self.scans: List[ScanSummary] = []
        self.metrics: Dict[str, int] = {}

    def on_group(self, record: GroupRecord) -> None:
        self.groups.append(record)

    def on_scan(self, summary: ScanSummary) -> None:
        self.scans.append(summary)

    def on_metrics(self, metrics: Dict[str, int]) -> None:
        self.metrics = dict(metrics)


# --- Public bridge ------------------------------------------------------------
def run_compactor_and_detector(
    pcap_path: Path,
    *,
    detector_config_path: Path,
    compactor_cfg: PipelineConfig | None = None,
) -> Dict[str, object]:
    """
    Returns:
      {
        "groups": <int>,
        "scans": <int>,
        "metrics": {...},
        "final_answer": [ {...}, ... ]   # from detector
      }
    """
    cfg = compactor_cfg or PipelineConfig()
    source = SingleFileSegmentSource(str(pcap_path))
    sink = CollectingSink()

    # Run compactor over a wide window to include entire pcap
    run_hour(
        source=source,
        sink=sink,
        cfg=cfg,
        hour_start=0,
        hour_end=2_147_483_647,  # ~2038; acts as 'include all'
    )

    # Build a **single** compact JSON doc for the detector
    compact_groups = []
    for g in sink.groups:
        compact_groups.append(
            {
                "src_ip": g.key.src_ip,
                "dst_ip": g.key.dst_ip,
                "dst_port": g.key.dst_port,
                "transport": g.key.transport,
                "service": g.key.service,
                "first_ts": g.first_ts,
                "last_ts": g.last_ts,
                "duration_s": g.duration_s,
                "counts": g.counts,
                "tcp_flags": g.tcp_flags,
                "tokens": g.tokens,
                "http": g.http or {},
                "ftp": g.ftp or {},
                "smb": g.smb or {},
            }
        )

    detector_input = {
        "pcap_file": pcap_path.name,
        "groups": compact_groups,
        "scan_summaries": [asdict(s) for s in sink.scans],
        "metrics": sink.metrics,
    }
    detector_input_str = json.dumps(detector_input, ensure_ascii=False)

    # Detector: load config/prompts, call pipeline once on the combined doc
    config = load_config(str(detector_config_path))
    prompts = get_prompts(config)
    llm_client = OpenAIClient()

    output_obj = run_pipeline(
        llm_client,
        detector_input_str,
        prompts,
        pbar=None,
        exist_msg=None,
    )

    final_answer = output_obj.get("final_answer", []) if isinstance(output_obj, dict) else []

    return {
        "groups": len(sink.groups),
        "scans": len(sink.scans),
        "metrics": sink.metrics,
        "final_answer": final_answer,
    }