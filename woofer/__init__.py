"""Application factory for Woofer."""
import contextlib
import logging
import os

from flask import Flask, render_template
from werkzeug.middleware.proxy_fix import ProxyFix

from woofer.blueprints.auth import auth_bp
from woofer.blueprints.core import core_bp
from woofer.blueprints.user import user_bp
from woofer.blueprints.woofs import woofs_bp
from woofer.config import config_by_name
from woofer.extensions import csrf, db, limiter, mail, migrate


def create_app(config_name: str | None = None) -> Flask:
    """Create and configure an instance of the Flask application."""
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    template_dir = os.path.join(root_dir, "templates")
    static_dir = os.path.join(root_dir, "static")

    app = Flask(
        __name__,
        template_folder=template_dir,
        static_folder=static_dir,
    )

    if not config_name:
        env_name = os.getenv("APP_ENV", "development").lower()
        config_name = "production" if env_name == "production" else "development"

    config_class = config_by_name.get(config_name, config_by_name["default"])
    app.config.from_object(config_class)

    # Configure reverse proxy headers for Render/Nginx
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=1,
        x_proto=1,
        x_host=1,
        x_port=1,
        x_prefix=1,
    )

    # Initialize extensions
    db.init_app(app)
    mail.init_app(app)
    csrf.init_app(app)
    migrate.init_app(app, db)
    limiter.init_app(app)

    # Custom 429 handler
    @app.errorhandler(429)
    def ratelimit_exceeded(e):
        return (
            render_template(
                "layout.html",
                error_message="Too many requests. Please slow down and try again later.",
            ),
            429,
        )

    # Security and cache control headers
    @app.after_request
    def add_security_headers(response):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Expires"] = "0"
        response.headers["Pragma"] = "no-cache"

        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        if app.config.get("SESSION_COOKIE_SECURE"):
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net; "
            "img-src 'self' data:; "
            "connect-src 'self';"
        )
        response.headers["Content-Security-Policy"] = csp

        return response

    # Register blueprints
    app.register_blueprint(core_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(woofs_bp)
    app.register_blueprint(user_bp)

    # Configure structured logging
    if not app.debug and not app.testing:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] in %(module)s: %(message)s",
        )

    # Ensure database schema is synchronized across migrations and legacy databases
    sync_database_schema(app)

    return app


def sync_database_schema(app: Flask) -> None:
    """Synchronize database schema defensively on startup to support legacy databases."""
    if app.config.get("TESTING"):
        return

    with app.app_context():
        # 1. Attempt standard Flask-Migrate upgrade
        try:
            from flask_migrate import upgrade
            upgrade()
            app.logger.info("Alembic database migrations applied successfully.")
        except Exception as exc:  # noqa: BLE001
            app.logger.warning("Flask-Migrate upgrade bypassed or failed: %s", exc)
            with contextlib.suppress(Exception):
                db.session.rollback()

        # 2. Defensive schema alignment for production databases
        try:
            from sqlalchemy import inspect, text
            inspector = inspect(db.engine)
            tables = inspector.get_table_names()

            if "users" not in tables:
                db.create_all()
                tables = inspector.get_table_names()

            if "users" in tables:
                cols = {c["name"] for c in inspector.get_columns("users")}
                is_pg = "postgres" in str(db.engine.url)

                with db.engine.begin() as conn:
                    if "session_token" not in cols:
                        sql = (
                            "ALTER TABLE users ADD COLUMN IF NOT EXISTS session_token VARCHAR(64) DEFAULT 'legacy_initial_token'"
                            if is_pg
                            else "ALTER TABLE users ADD COLUMN session_token VARCHAR(64) DEFAULT 'legacy_initial_token'"
                        )
                        conn.execute(text(sql))
                        app.logger.info("Successfully added session_token to users table.")

                    if "reset_token_used" not in cols:
                        sql = (
                            "ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token_used BOOLEAN DEFAULT FALSE"
                            if is_pg
                            else "ALTER TABLE users ADD COLUMN reset_token_used BOOLEAN DEFAULT 0"
                        )
                        conn.execute(text(sql))

                    if "is_verified" not in cols:
                        sql = (
                            "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_verified BOOLEAN DEFAULT FALSE"
                            if is_pg
                            else "ALTER TABLE users ADD COLUMN is_verified BOOLEAN DEFAULT 0"
                        )
                        conn.execute(text(sql))

                    if "created_at" not in cols:
                        sql = (
                            "ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP"
                            if is_pg
                            else "ALTER TABLE users ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
                        )
                        conn.execute(text(sql))

                    if "followers" not in cols:
                        sql = (
                            "ALTER TABLE users ADD COLUMN IF NOT EXISTS followers INTEGER DEFAULT 0"
                            if is_pg
                            else "ALTER TABLE users ADD COLUMN followers INTEGER DEFAULT 0"
                        )
                        conn.execute(text(sql))

                    if "following" not in cols:
                        sql = (
                            "ALTER TABLE users ADD COLUMN IF NOT EXISTS following INTEGER DEFAULT 0"
                            if is_pg
                            else "ALTER TABLE users ADD COLUMN following INTEGER DEFAULT 0"
                        )
                        conn.execute(text(sql))

            if "woofs" in tables:
                woof_cols = {c["name"] for c in inspector.get_columns("woofs")}
                is_pg = "postgres" in str(db.engine.url)
                if "timestamp" not in woof_cols:
                    sql = (
                        "ALTER TABLE woofs ADD COLUMN IF NOT EXISTS timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP"
                        if is_pg
                        else "ALTER TABLE woofs ADD COLUMN timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
                    )
                    with db.engine.begin() as conn:
                        conn.execute(text(sql))

        except Exception as exc:  # noqa: BLE001
            app.logger.warning("Defensive schema sync encountered an issue: %s", exc)
            with contextlib.suppress(Exception):
                db.session.rollback()
