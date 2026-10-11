"""Application entrypoint for local development and WSGI servers (Gunicorn)."""
import os

from woofer import create_app

app = create_app()

if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port)
