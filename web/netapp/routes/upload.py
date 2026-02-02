"""
Upload routes: file validation + saving. Stores path in session.
"""

from __future__ import annotations
from datetime import datetime
from pathlib import Path
from flask import Blueprint, current_app, jsonify, request, session
from werkzeug.utils import secure_filename

from netapp.utils import allowed_file

bp = Blueprint("upload", __name__, url_prefix="/")


@bp.route("/upload", methods=["POST"])
def upload_file():
    """Upload a file (validated by extension) into UPLOAD_FOLDER."""
    if "file" not in request.files:
        return jsonify({"success": False, "error": "No file part"}), 400

    file = request.files["file"]
    if not file or file.filename == "":
        return jsonify({"success": False, "error": "No selected file"}), 400

    if not allowed_file(file.filename, current_app.config["ALLOWED_EXTENSIONS"]):
        return jsonify({"success": False, "error": "Invalid file type"}), 400

    upload_dir = Path(current_app.config["UPLOAD_FOLDER"])
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{ts}_{secure_filename(file.filename)}"
    dest = upload_dir / filename
    file.save(dest)

    session["uploaded_file"] = str(dest)

    return jsonify(
        {"success": True, "filename": filename, "message": "File uploaded successfully"}
    )