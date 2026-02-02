"""
Flask app factory: registers config, logging, blueprints, and error handlers.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Type

from flask import Flask, jsonify
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge

from netapp.config import Config, DevelopmentConfig, ProductionConfig
from netapp.utils import ensure_dirs, init_logging
from netapp.managers.sniffer_manager import SnifferManager
from netapp.routes import analyze as analyze_bp
from netapp.routes import upload as upload_bp
from netapp.routes import stream as stream_bp
from netapp.routes import detect as detect_bp
from netapp.routes import report as report_bp

# NEW: Detection manager import
from netapp.managers.detection_manager import DetectionManager  # adjust path if different


def create_app(config_class: Type[Config] | None = None) -> Flask:
    """Create and configure the Flask application."""
    app = Flask(__name__, static_folder="static", template_folder="templates")

    # Config selection
    cfg: Type[Config]
    env = os.getenv("FLASK_ENV", "production").lower()
    if config_class is not None:
        cfg = config_class
    elif env.startswith("dev"):
        cfg = DevelopmentConfig
    else:
        cfg = ProductionConfig
    app.config.from_object(cfg)

    # Ensure folders
    upload_dir = Path(app.config["UPLOAD_FOLDER"])
    log_dir = Path(app.config["LOG_FOLDER"])
    ensure_dirs(upload_dir, log_dir)

    (log_dir / "detections").mkdir(parents=True, exist_ok=True)
    (log_dir / "reports").mkdir(parents=True, exist_ok=True)

    # Sessions
    app.secret_key = app.config["SECRET_KEY"]

    # Logging
    logger = init_logging(app)
    app.logger = logger  # align Flask's logger with ours

    # Thread-safe sniffer manager stored in extensions registry
    app.extensions["sniffer_mgr"] = SnifferManager(
        logger=logger,
        log_dir=log_dir,
        default_iface=app.config["DEFAULT_INTERFACE"],
        max_duration=app.config["MAX_CAPTURE_SECONDS"],
    )

    # If your config class doesn't define DETECTOR_CONFIG, set a sensible default.
    detector_cfg_path = Path(app.config.get("DETECTOR_CONFIG", "detector/config.yaml"))
    app.extensions["detect_mgr"] = DetectionManager(
        log_dir=log_dir,
        detector_config_path=detector_cfg_path,
    )

    # Security-ish headers
    @app.after_request
    def set_security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-XSS-Protection"] = "1; mode=block"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "img-src 'self' data:; "
            "script-src 'self' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline'; "
            "connect-src 'self' https://cdn.jsdelivr.net"
        )
        return resp

    # Error handlers
    @app.errorhandler(RequestEntityTooLarge)
    def handle_file_too_large(_e):
        return jsonify({"success": False, "error": "File too large"}), 413

    @app.errorhandler(HTTPException)
    def handle_http_exception(e: HTTPException):
        return jsonify({"success": False, "error": e.description}), e.code

    @app.errorhandler(Exception)
    def handle_unexpected_exception(e: Exception):
        app.logger.exception("Unhandled error")
        return jsonify({"success": False, "error": "Internal server error"}), 500

    # Blueprints
    app.register_blueprint(analyze_bp.bp)
    app.register_blueprint(upload_bp.bp)
    app.register_blueprint(stream_bp.bp)
    app.register_blueprint(detect_bp.bp)
    app.register_blueprint(report_bp.bp)

    # Health
    @app.route("/healthz")
    def healthz():
        return jsonify({"status": "ok"}), 200

    return app