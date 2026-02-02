"""
Utility helpers: directory setup, logging config, simple validators, and time utils.
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from datetime import datetime
from flask import Flask


def ensure_dirs(*paths: Path) -> None:
    """Ensure each directory exists."""
    for p in paths:
        p.mkdir(parents=True, exist_ok=True)


def init_logging(app: Flask) -> logging.Logger:
    """Configure a console logger + rotating file handler."""
    log_level = getattr(logging, app.config["LOG_LEVEL"].upper(), logging.INFO)
    logger = logging.getLogger("netapp")
    logger.setLevel(log_level)
    logger.propagate = False  # avoid duplicate logs if root has handlers

    # Console
    ch = logging.StreamHandler()
    ch.setLevel(log_level)
    ch.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(ch)

    # File (rotating)
    log_file = Path(app.config["LOG_FILE"])
    ensure_dirs(log_file.parent)
    fh = RotatingFileHandler(log_file, maxBytes=1_000_000, backupCount=5)
    fh.setLevel(log_level)
    fh.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(fh)

    if app.config["SECRET_KEY"] == "dev-unsafe-change-this":
        logger.warning("Using default SECRET_KEY. Set FLASK_SECRET_KEY for production.")

    return logger


def allowed_file(filename: str, allowed: set[str]) -> bool:
    """Return True if the filename has an allowed extension."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed


def utcnow_iso() -> str:
    """Return current UTC timestamp in RFC3339-ish ISO format."""
    return datetime.utcnow().isoformat() + "Z"