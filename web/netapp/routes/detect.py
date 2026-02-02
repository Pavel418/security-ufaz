"""
Detection routes.

Workflow:
  1) Capture a short snapshot PCAP on the requested interface.
  2) Run compactor + detector synchronously on that PCAP.
  3) Persist the results JSON to logs and return both data and filename.
"""

from __future__ import annotations

from pathlib import Path
from flask import Blueprint, current_app, jsonify, request

from netapp.managers.detection_manager import DetectionManager

bp = Blueprint("detect", __name__, url_prefix="/detect")


@bp.record_once
def _on_load(state):
    """Initialize the detection manager and register it on app.extensions."""
    app = state.app
    log_dir = Path(app.config["LOG_FOLDER"])
    detector_cfg = Path(app.config.get("DETECTOR_CONFIG", "detector/config.yaml"))
    # Use a single, consistent key everywhere
    app.extensions["detect_mgr"] = DetectionManager(
        log_dir=log_dir,
        detector_config_path=detector_cfg,
    )


@bp.route("/run-now", methods=["POST"])
def run_now():
    """
    Capture a fresh snapshot PCAP and run compactor+detector on it.

    Body (JSON, optional):
      {
        "duration": 10,       # seconds, default from DETECT_SNAPSHOT_SECONDS or 10
        "interface": "eth0"   # default from DEFAULT_INTERFACE
      }
    """
    try:
        body = request.get_json(silent=True) or {}
        duration = int(
            body.get("duration", current_app.config.get("DETECT_SNAPSHOT_SECONDS", 10))
        )
        iface = body.get("interface", current_app.config.get("DEFAULT_INTERFACE"))

        # 1) Create a snapshot PCAP
        sniffer_mgr = current_app.extensions["sniffer_mgr"]
        if not hasattr(sniffer_mgr, "capture_snapshot"):
            return jsonify({"success": False, "error": "Snapshot capture not supported by sniffer manager"}), 500

        snapshot_path: Path = sniffer_mgr.capture_snapshot(
            duration=duration, interface=iface
        )

        # 2) Run detection (also persists results JSON via DetectionManager)
        det_mgr: DetectionManager = current_app.extensions["detect_mgr"]
        out = det_mgr.run_once_now(snapshot_path)

        return jsonify({
            "success": True,
            "pcap": snapshot_path.name,
            "data": out,
            "results_file": det_mgr.last_results_path.name if det_mgr.last_results_path else None,
        })
    except Exception as e:
        current_app.logger.exception("run-now failed")
        return jsonify({"success": False, "error": str(e)}), 500
