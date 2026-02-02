"""
Configuration objects for the Flask application.

Override via environment variables or a .env file (when using python-dotenv).
"""

from __future__ import annotations
import os


class Config:
    """Base configuration (safe defaults)."""

    # Security
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "dev-unsafe-change-this")

    # Storage
    UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", "uploads")
    LOG_FOLDER = os.getenv("LOG_FOLDER", "logs")

    # Requests / uploads
    MAX_CONTENT_LENGTH = int(os.getenv("MAX_CONTENT_LENGTH", str(16 * 1024 * 1024)))  # 16 MiB

    # File types
    ALLOWED_EXTENSIONS = set(
        (os.getenv("ALLOWED_EXTENSIONS", "txt,log,csv,json,pcap")).split(",")
    )

    # Logging
    LOG_FILE = os.getenv("APP_LOG_FILE", "logs/app.log")
    LOG_LEVEL = os.getenv("APP_LOG_LEVEL", "INFO")

    # Packet capture
    DEFAULT_INTERFACE = os.getenv("DEFAULT_INTERFACE", "eth0")
    MAX_CAPTURE_SECONDS = int(os.getenv("MAX_CAPTURE_SECONDS", "3600"))  # 1 hour


class ProductionConfig(Config):
    """Production overrides."""
    LOG_LEVEL = os.getenv("APP_LOG_LEVEL", "INFO")


class DevelopmentConfig(Config):
    """Development overrides."""
    LOG_LEVEL = os.getenv("APP_LOG_LEVEL", "DEBUG")