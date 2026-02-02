"""
Streaming routes: start/stop capture, telemetry, interface list, and PCAP analysis.
"""

from __future__ import annotations
from datetime import datetime

from flask import Blueprint, current_app, jsonify, render_template, request

from netapp.packet_sniffer import PacketSniffer
from netapp.managers.sniffer_manager import SnifferManager

bp = Blueprint("stream", __name__, url_prefix="/stream")


@bp.route("")
def stream_page():
    """Render streaming page (front-end polls /stream/data)."""
    return render_template("stream.html")


@bp.route("/interfaces")
def get_interfaces():
    """Return available interfaces (as seen by Scapy)."""
    try:
        interfaces = PacketSniffer.list_interfaces()
        return jsonify({"success": True, "interfaces": interfaces})
    except Exception as e:
        current_app.logger.exception("Error getting interfaces")
        return jsonify({"success": False, "error": str(e), "interfaces": []}), 500


@bp.route("/start", methods=["POST"])
def start_stream():
    """
    Start background capture.

    Body (JSON, optional):
      { "interface": "eth0" }
    """
    data = request.get_json(silent=True) or {}
    iface = data.get("interface", current_app.config["DEFAULT_INTERFACE"])
    mgr: SnifferManager = current_app.extensions["sniffer_mgr"]

    ok, msg = mgr.start(interface=iface)
    status = 200 if ok else 400
    current_app.logger.info("Start stream: %s", msg)
    return jsonify({"success": ok, "message": msg}), status


@bp.route("/data")
def stream_data():
    """Return current capture telemetry (or error/inactive status)."""
    mgr: SnifferManager = current_app.extensions["sniffer_mgr"]
    return jsonify(mgr.telemetry_snapshot())


@bp.route("/stop", methods=["POST"])
def stop_stream():
    """Stop capture, persist history JSON, and return session analysis."""
    mgr: SnifferManager = current_app.extensions["sniffer_mgr"]
    final_count = mgr.stop()
    analysis = mgr.summarize_and_persist()
    analysis["total_packets_captured"] = final_count or analysis.get(
        "total_packets_captured", 0
    )
    return jsonify({"success": True, "analysis": analysis})


@bp.route("/analyze-pcap", methods=["POST"])
def analyze_pcap():
    """Analyze the most recent captured PCAP and return basic stats."""
    mgr: SnifferManager = current_app.extensions["sniffer_mgr"]
    last = mgr.last_pcap_file
    if not last or not last.exists():
        return (
            jsonify({"success": False, "error": "No pcap file available to analyze"}),
            400,
        )

    try:
        stats = mgr.basic_pcap_analysis(last)
        result = {
            **stats,
            "pcap_file": last.name,
            "analyzed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        return jsonify({"success": True, "analysis": result})
    except Exception as e:
        current_app.logger.exception("Error analyzing pcap")
        return jsonify({"success": False, "error": f"Error analyzing pcap: {e}"}), 500