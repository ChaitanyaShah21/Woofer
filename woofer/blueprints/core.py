"""Core blueprint: health check endpoint and error handlers."""
from flask import Blueprint, current_app, jsonify, render_template
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from woofer.extensions import db

core_bp = Blueprint("core", __name__)


@core_bp.route("/health", methods=["GET"])
def health():
    """Service health check that validates database connectivity."""
    try:
        db.session.execute(text("SELECT 1"))
        return jsonify({
            "status": "healthy",
            "database": "connected",
        }), 200
    except Exception as e:  # noqa: BLE001
        return jsonify({
            "status": "unhealthy",
            "database": "disconnected",
            "error": str(e),
        }), 503


@core_bp.app_errorhandler(400)
def bad_request(error):
    return render_template("layout.html", error_message="Bad Request"), 400


@core_bp.app_errorhandler(403)
def forbidden(error):
    return render_template("layout.html", error_message="Forbidden"), 403


@core_bp.app_errorhandler(404)
def not_found(error):
    return render_template("layout.html", error_message="Page Not Found"), 404


@core_bp.app_errorhandler(500)
def internal_server_error(error):
    return render_template("layout.html", error_message="Internal Server Error"), 500


@core_bp.app_errorhandler(OperationalError)
def handle_db_operational_error(error):
    current_app.logger.critical("Database operational failure: %s", error)
    return (
        render_template(
            "layout.html",
            error_message="The database is temporarily unavailable. Please retry in a moment.",
        ),
        503,
    )
