"""
Cyber Mistake Detector - Flask Web Application.

Educational local web dashboard for inspecting selected Windows security
configurations, identifying common security misconfigurations, and learning
safe defensive best practices.
Supports both Quick Baseline Audits and Hard / Deep System Vulnerability Audits.
"""

import json
import logging
import os
import platform
from typing import Any, Dict, Optional
from flask import Flask, redirect, render_template, request, send_file, session, url_for

from scanner import scan_system

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "cyber-sage-demo-secret-key-2026")

# Temporary in-memory storage for the latest scan report.
# Note: Designed for single-user local educational sessions.
latest_report: Optional[Dict[str, Any]] = None


@app.route("/", methods=["GET"])
def home():
    """Renders the main educational dashboard."""
    is_cloud = platform.system() != "Windows"
    return render_template("index.html", is_cloud=is_cloud)


@app.route("/scan", methods=["POST"])
def scan():
    """
    Executes the security configuration checks and redirects to results.
    Accepts 'mode' from form data: 'deep' (default Hard Scan) or 'quick' (Baseline).
    """
    global latest_report
    mode = request.form.get("mode", "deep").strip().lower()
    if mode not in ("quick", "deep", "hard", "demo"):
        mode = "deep"
    session["scan_mode"] = mode

    logger.info("Starting security configuration scan (mode: %s)...", mode)
    try:
        latest_report = scan_system(mode=mode)
        logger.info(
            "Scan completed: %d total checks, %d safe, %d warnings, %d unknown (mode: %s).",
            latest_report.get("total_checks", 0),
            latest_report.get("safe_count", 0),
            latest_report.get("warning_count", 0),
            latest_report.get("unknown_count", 0),
            mode,
        )
    except Exception as exc:
        logger.exception("Unexpected error during system scan: %s", exc)
        latest_report = {
            "results": [
                {
                    "name": "Scanner Engine",
                    "category": "Scanner System",
                    "status": "ERROR",
                    "details": f"Scanner encountered an unexpected error: {exc}",
                    "severity": "High",
                    "checked_at": "",
                    "recommendation": {
                        "summary": "The scanner engine encountered an unexpected error.",
                        "what_checked": "Overall system scan execution.",
                        "what_it_means": "An internal exception prevented the scan from finishing.",
                        "why_it_matters": "System errors prevent automated validation of your security settings.",
                        "next_steps": [
                            "Ensure Python is running with normal user permissions.",
                            "Review application logs in the terminal console.",
                            "Try initiating the scan again from the dashboard."
                        ],
                    },
                }
            ],
            "scan_mode": mode,
            "scan_mode_label": "System Scan (Error State)",
            "total_checks": 1,
            "safe_count": 0,
            "warning_count": 0,
            "high_severity_count": 0,
            "unknown_count": 1,
            "evaluated_count": 0,
            "hygiene_percentage": None,
            "scanned_at": "N/A",
            "coverage_note": "Scan failed due to an unexpected internal error.",
            "disclaimer": "This educational tool does not guarantee complete security.",
            "is_simulated": platform.system() != "Windows",
            "environment_label": "Error State",
        }

    return redirect(url_for("results"))


@app.route("/results", methods=["GET"])
def results():
    """
    Renders the most recent scan findings.
    If no scan has been performed in this session, redirects to the dashboard
    unless mode parameter is provided (supports stateless serverless instances).
    """
    global latest_report
    mode = request.args.get("mode") or session.get("scan_mode")
    if latest_report is None:
        if mode in ("quick", "deep", "hard", "demo"):
            logger.info("Stateless/cloud request detected with mode '%s'; generating report.", mode)
            latest_report = scan_system(mode=mode)
        elif platform.system() != "Windows":
            logger.info("Cloud host detected without prior session; defaulting to deep audit simulation.")
            latest_report = scan_system(mode="deep")
        else:
            logger.info("No prior scan found; redirecting user to home.")
            return redirect(url_for("home"))
    elif mode and latest_report.get("scan_mode") != mode:
        logger.info("Switching report mode from '%s' to '%s'.", latest_report.get("scan_mode"), mode)
        latest_report = scan_system(mode=mode)

    return render_template("results.html", report=latest_report)


@app.route("/upload", methods=["POST"])
def upload_report():
    """
    Accepts an exported audit_report.json from a physical Windows host
    and renders its actual findings on this web dashboard.
    """
    global latest_report
    file = request.files.get("report_file")
    if not file or not file.filename:
        return redirect(url_for("home"))

    try:
        data = json.load(file)
        if "results" in data and isinstance(data["results"], list):
            from recommendations import get_recommendation
            findings = [get_recommendation(item) for item in data["results"]]
            data["results"] = findings
            data["is_simulated"] = False
            data["environment_label"] = "Local Physical Windows PC (Uploaded Audit)"
            latest_report = data
            session["scan_mode"] = data.get("scan_mode", "deep")
            logger.info("Successfully loaded uploaded audit report with %d checks.", len(findings))
            return redirect(url_for("results"))
    except Exception as exc:
        logger.error("Failed to parse uploaded audit report: %s", exc)

    return redirect(url_for("home"))


@app.route("/download-auditor", methods=["GET"])
def download_auditor():
    """Serves the standalone 1-click batch script to audit local Windows PCs."""
    script_path = os.path.join(app.root_path, "CyberSage_Scanner.bat")
    if not os.path.exists(script_path):
        script_path = os.path.join(app.root_path, "audit_pc.bat")
    if os.path.exists(script_path):
        return send_file(script_path, as_attachment=True, download_name="CyberSage_Scanner.bat")
    return redirect(url_for("home"))


@app.errorhandler(404)
def page_not_found(e):
    """Custom 404 error page."""
    return (
        render_template(
            "error.html",
            error_code=404,
            error_title="Page Not Found",
            error_message="The requested page could not be found. Please return to the dashboard.",
        ),
        404,
    )


@app.errorhandler(500)
def internal_server_error(e):
    """Custom 500 error page."""
    logger.error("Internal Server Error: %s", e)
    return (
        render_template(
            "error.html",
            error_code=500,
            error_title="Internal Server Error",
            error_message="An unexpected server error occurred. Please check the terminal logs.",
        ),
        500,
    )


if __name__ == "__main__":
    print("=" * 60)
    print(" Cyber Mistake Detector - Educational Security Dashboard")
    print(" Running locally at: http://127.0.0.1:5000/")
    print(" Press Ctrl+C in this terminal to stop the server.")
    print("=" * 60)
    app.run(host="127.0.0.1", port=5000, debug=False)
