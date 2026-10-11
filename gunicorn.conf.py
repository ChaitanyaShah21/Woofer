"""Production Gunicorn configuration for Woofer."""
import os

bind = f"0.0.0.0:{os.getenv('PORT', '5000')}"
workers = int(os.getenv("WEB_CONCURRENCY", "2"))
threads = int(os.getenv("GUNICORN_THREADS", "2"))
worker_class = "gthread"
timeout = 30
keepalive = 2
accesslog = "-"
errorlog = "-"
loglevel = os.getenv("LOG_LEVEL", "info")
max_requests = 1000
max_requests_jitter = 50

