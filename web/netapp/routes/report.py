from __future__ import annotations
from datetime import datetime
from pathlib import Path
from flask import Blueprint, current_app, jsonify, send_file, send_from_directory, request
from werkzeug.utils import secure_filename

from ..report import build_pdf  # adjust import path if needed

bp = Blueprint("report", __name__, url_prefix="/report")


@bp.route("/generate", methods=["POST"])
def generate_report_latest():
    """
    Generate a PDF from the latest detection result JSON (Mode A).
    Does NOT re-run detection. Returns a URL for download.
    """
    detect_mgr = current_app.extensions.get("detect_mgr")
    if not detect_mgr:
        return jsonify({"success": False, "error": "Detection manager unavailable"}), 500

    snap = detect_mgr.snapshot()
    results_file = snap.get("results_file")
    if not results_file:
        return jsonify({"success": False, "error": "No detection result available"}), 400

    # Resolve the persisted JSON path
    detections_dir = detect_mgr.log_dir / "detections"
    src_path = detections_dir / results_file
    if not src_path.exists():
        return jsonify({"success": False, "error": "Latest detection JSON not found"}), 404

    # Report destination: <log_dir>/reports/report_YYYYmmdd_HHMMSS.pdf
    reports_dir = detect_mgr.log_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_name = f"report_{ts}.pdf"
    out_path = reports_dir / out_name

    # Title param is optional; allow override via JSON if provided
    body = request.get_json(silent=True) or {}
    title = body.get("title") or "NDIS Detection Report"
    landscape = bool(body.get("landscape") or False)

    try:
        build_pdf(str(src_path), str(out_path), title, use_landscape=landscape)
    except Exception as e:
        current_app.logger.exception("PDF build failed")
        return jsonify({"success": False, "error": f"PDF generation failed: {e}"}), 500

    # Expose a download route
    url = f"/report/download/{out_name}"
    return jsonify({"success": True, "url": url, "file": out_name})

@bp.route("/download/<path:filename>", methods=["GET"])
def download_report(filename: str):
    """
    Serve generated PDFs from <root>/logs/reports (configurable via LOG_DIR).
    """
    # Prefer explicit config/env; otherwise infer "<root>/logs" from app root
    app_root = Path(current_app.root_path)          # .../root/app
    logs_dir = Path(current_app.config.get(
        "LOG_DIR",
        app_root.parent / "logs"                    # -> .../root/logs
    )).resolve()

    reports_dir = (logs_dir / "reports").resolve()
    file_path = (reports_dir / filename).resolve()

    current_app.logger.info("Report download requested: %s", file_path)

    # Path traversal / outside-of-reports defense
    if not str(file_path).startswith(str(reports_dir)):
        current_app.logger.warning("Illegal report path: %s", file_path)
        return jsonify({"success": False, "error": "Invalid path"}), 400

    if not file_path.exists():
        current_app.logger.warning("Report download missing: %s", file_path)
        return jsonify({"success": False, "error": "Report not found"}), 404
    else:
        current_app.logger.info("Report download found: %s", file_path)

    return send_file(
        str(file_path),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=secure_filename(Path(filename).name),
        conditional=True,   # ETag/Range
        max_age=0           # dev: avoid stale caching
    )