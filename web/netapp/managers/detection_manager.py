"""
Detection manager.

Runs the compactor + detector pipeline on-demand (e.g., “Run Detection Now”)
and exposes a snapshot of the latest results for the UI. Each successful run
is also persisted to disk as a timestamped JSON file under `log_dir/detections/`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional, Union
import json
import threading
import time
from datetime import datetime

from pcap_compactor import PipelineConfig
from .pipeline_bridge import run_compactor_and_detector


@dataclass
class DetectionManager:
    """
    Manual detection orchestrator.

    Attributes:
        log_dir: Directory containing captured PCAP files.
        detector_config_path: Path to the detector configuration file.

    State (protected by _lock):
        last_run_at: UNIX timestamp of the last successful run.
        last_results: Latest results payload returned by the pipeline.
        last_error: Last error message (if any).
        last_results_path: Path to the most recent persisted results JSON.
    """
    log_dir: Path
    detector_config_path: Path

    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    last_run_at: Optional[float] = None
    last_results: Dict[str, object] = field(default_factory=dict)
    last_error: Optional[str] = None
    last_results_path: Optional[Path] = None

    # --------------------------- Private helpers ---------------------------

    def _find_latest_pcap(self) -> Optional[Path]:
        """Return the most recent 'capture_*.pcap' under log_dir, or None."""
        if not self.log_dir.exists():
            return None
        pcaps = sorted(self.log_dir.glob("capture_*.pcap"))
        return pcaps[-1] if pcaps else None

    def _persist_results(self, payload: Dict[str, object], pcap_path: Path) -> Path:
        """
        Persist detection payload to `log_dir/detections/detect_YYYYmmdd_HHMMSS.json`.
        Adds minimal metadata for traceability.
        """
        detections_dir = self.log_dir / "detections"
        detections_dir.mkdir(parents=True, exist_ok=True)

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = detections_dir / f"detect_{ts}.json"

        enriched = {
            "ran_at": datetime.now().isoformat(timespec="seconds"),
            "pcap_file": pcap_path.name,
            "results": payload,
        }
        with out_path.open("w", encoding="utf-8") as f:
            json.dump(enriched, f, indent=2)

        return out_path

    # ---------------------------- Public methods ---------------------------

    def run_once_now(self, pcap_path: Optional[Path] = None) -> Dict[str, object]:
        """
        Run compactor + detector once and persist the results JSON.

        Args:
            pcap_path: Explicit PCAP path (optional). If not provided, uses
                       the latest 'capture_*.pcap' in self.log_dir.

        Returns:
            The raw results dict from `run_compactor_and_detector`. The caller
            can retrieve the persisted filename via `self.last_results_path`.
        """
        target = pcap_path or self._find_latest_pcap()
        if not target:
            raise FileNotFoundError("No PCAP found")

        res = run_compactor_and_detector(
            target,
            detector_config_path=self.detector_config_path,
            compactor_cfg=PipelineConfig(),
        )

        saved_path = self._persist_results(res, target)

        with self._lock:
            self.last_results = res
            self.last_error = None
            self.last_run_at = time.time()
            self.last_results_path = saved_path

        return res

    def snapshot(self) -> Dict[str, object]:
        """Return a thread-safe snapshot of the latest detection state for the API."""
        with self._lock:
            return {
                "last_run_at": self.last_run_at,
                "error": self.last_error,
                "results": self.last_results,
                "results_file": self.last_results_path.name if self.last_results_path else None,
            }

    def record_external_result(self, payload: Dict[str, object], source_file: Union[str, Path]) -> Path:
        """
        Persist an externally-produced detection payload (e.g., from /analyze)
        and update the manager snapshot so /report/build can find it.
        """
        src = Path(source_file)
        if not src.exists():
            raise FileNotFoundError(f"Source file not found: {src}")

        out_path = self._persist_results(payload, src)
        with self._lock:
            self.last_results = payload
            self.last_error = None
            self.last_run_at = time.time()
            self.last_results_path = out_path
        return out_path