"""
Cyber Mistake Detector - Production WSGI Entry Point.

Compatible with Gunicorn, Waitress, and any WSGI application server.
Provides high-throughput multi-threaded request processing,
ML model pre-warming for zero latency, and cross-platform support.
"""

import logging
import os
import sys

from app import app

logger = logging.getLogger("wsgi")

# Preload ML models during worker startup for instant evaluation
try:
    from ml_engine import load_ml_models
    load_ml_models()
except Exception as exc:
    logger.warning("ML model warm-up skipped: %s", exc)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    host = os.environ.get("HOST", "0.0.0.0")

    try:
        from waitress import serve
        print("=" * 60)
        print(" Cyber Mistake Detector - Waitress Production Server")
        print(f" Production WSGI Server listening on http://{host}:{port}/")
        print(" High-concurrency multi-threaded engine active (threads=4).")
        print(" Press Ctrl+C to stop the server.")
        print("=" * 60)
        serve(app, host=host, port=port, threads=4)
    except ImportError:
        print(f"Waitress not installed; falling back to Flask development server on http://{host}:{port}/")
        app.run(host=host, port=port, debug=False)
