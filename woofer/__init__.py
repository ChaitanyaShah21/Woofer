"""Application factory for Woofer."""
import logging
import os

from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix

from woofer.blueprints.auth import auth_bp
from woofer.blueprints.core import core_bp
from woofer.blueprints.user import user_bp
from woofer.blueprints.woofs import woofs_bp
from woofer.config import config_by_name
from woofer.extensions import csrf, db, mail, migrate


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

    # Cache control headers
    @app.after_request
    def add_security_headers(response):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Expires"] = "0"
        response.headers["Pragma"] = "no-cache"
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

    return app
