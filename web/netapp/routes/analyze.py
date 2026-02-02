from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from flask import Blueprint, current_app, jsonify, render_template, session

from netapp.managers.pipeline_bridge import run_compactor_and_detector

bp = Blueprint("analyze", __name__, url_prefix="/")


@bp.route("/")
@bp.route("/home")
def home():
    """Render homepage (template optional)."""
    return render_template("home.html")


@bp.route("/analyze", methods=["POST"])
def analyze():
    """
    Run detection on the last uploaded PCAP:
      - compacts traffic into GroupRecords
      - feeds compact JSON to the detector
      - returns detector.final_answer (tactics/techniques/reasons) + counters

    Expects `session["uploaded_file"]` to point to a .pcap saved by your upload flow.
    """
    path_str = session.get("uploaded_file")
    if not path_str:
        return jsonify({"success": False, "error": "No file uploaded"}), 400

    pcap_path = Path(path_str)
    if not pcap_path.exists():
        return jsonify({"success": False, "error": "Uploaded file not found"}), 400

    if pcap_path.suffix.lower() != ".pcap":
        return jsonify({
            "success": False,
            "error": "Only PCAP files are supported for detection at /analyze."
        }), 400

    try:
        detector_cfg = Path(current_app.config.get("DETECTOR_CONFIG", "detector/config.yaml"))
        results: Dict[str, Any] = run_compactor_and_detector(
            pcap_path=pcap_path,
            detector_config_path=detector_cfg,
        )

        # Shape a UI-friendly payload
        payload: Dict[str, Any] = {
            "pcap_file": pcap_path.name,
            "groups": results.get("groups", 0),
            "scans": results.get("scans", 0),
            "metrics": results.get("metrics", {}),
            # list[{tactic_name, technique_id, technique_name, reason, ...}]
            "final_answer": results.get("final_answer", []),
        }

        # Persist into DetectionManager so /report/build can find it.
        try:
            detect_mgr = current_app.extensions.get("detect_mgr")
            if detect_mgr is not None:
                detect_mgr.record_external_result(payload, pcap_path)
        except Exception:
            current_app.logger.exception("Failed to persist analysis to DetectionManager snapshot")

        return jsonify({"success": True, "analysis": payload})
    except Exception as e:
        current_app.logger.exception("Detection failed")
        return jsonify({"success": False, "error": f"Detection error: {e}"}), 500