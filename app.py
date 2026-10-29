"""
CyberSage - Enterprise Windows Security & Vulnerability Auditor.
Flask Application Controller.
"""

import json
import logging
import os
import platform
import uuid
from typing import Any, Dict, Optional
from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)

from recommendations import get_recommendation
from scanner import (
    get_system_metadata,
    scan_system,
    verify_single_control,
)
from scoring import calculate_audit_score
from storage import (
    get_latest_scan_for_session,
    get_scan,
    init_db,
    record_verification,
    save_scan,
    update_scan,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "cyber-sage-enterprise-key-2026")

# Initialize SQLite database schema on startup
init_db()


@app.before_request
def ensure_session_identity():
    """Guarantees every connecting visitor has a unique, isolated session ID."""
    if "session_id" not in session:
        session["session_id"] = str(uuid.uuid4())


@app.route("/", methods=["GET"])
def home():
    """Renders the primary educational security dashboard."""
    sys_meta = get_system_metadata()
    latest_scan = get_latest_scan_for_session(session["session_id"])
    return render_template(
        "index.html",
        is_cloud=not sys_meta["is_windows"],
        sys_meta=sys_meta,
        latest_scan=latest_scan,
    )


@app.route("/scan", methods=["POST"])
def scan():
    """
    Executes an on-demand security configuration scan.
    Generates a unique scan record isolated to the current user's session.
    """
    mode = request.form.get("mode", "deep").strip().lower()
    if mode not in ("quick", "deep", "hard", "demo"):
        mode = "deep"
    session["scan_mode"] = mode

    logger.info("Executing on-demand security scan (mode: %s, session: %s)...", mode, session["session_id"])
    try:
        report = scan_system(mode=mode)
    except Exception as exc:
        logger.exception("Unexpected error during system scan execution: %s", exc)
        report = {
            "scan_id": str(uuid.uuid4()),
            "scan_mode": mode,
            "scan_mode_label": "System Scan (Execution Failed)",
            "scan_source": "local_host",
            "target_host": "Local Host",
            "results": [
                {
                    "control_id": "scanner_engine",
                    "name": "Scanner Engine",
                    "category": "Scanner System",
                    "status": "ERROR",
                    "details": f"Scanner encountered an unexpected internal error: {exc}",
                    "severity": "High",
                    "checked_at": "",
                    "recommendation": {
                        "summary": "The scanner engine encountered an unexpected error.",
                        "what_checked": "Overall system scan execution.",
                        "what_it_means": "An internal exception prevented the scan from completing.",
                        "why_it_matters": "System errors prevent automated validation of defensive controls.",
                        "next_steps": [
                            "Ensure Python is running with standard user permissions.",
                            "Review application logs in the terminal console.",
                            "Initiate the scan again from the dashboard."
                        ],
                    },
                }
            ],
            "total_checks": 1,
            "applicable_count": 1,
            "safe_count": 0,
            "warning_count": 0,
            "unknown_count": 1,
            "not_applicable_count": 0,
            "high_severity_count": 0,
            "is_complete": False,
            "hygiene_percentage": None,
            "score_label": "Score Unavailable (Execution Error)",
            "score_status": "ERROR",
            "scanned_at": "N/A",
            "coverage_note": "Scan failed due to an unexpected internal error.",
            "disclaimer": "Defensive auditor does not guarantee absolute security.",
            "is_simulated": False,
            "environment_label": "Execution Error",
        }

    # Enrich findings with machine learning risk evaluation if available
    try:
        from ml_engine import predict_endpoint_risk
        report["ml_prediction"] = predict_endpoint_risk(report.get("results", []))
    except Exception as exc:
        logger.warning("Could not compute ML risk prediction: %s", exc)

    # Persist the isolated scan record in SQLite
    scan_id = save_scan(report, session["session_id"])
    session["current_scan_id"] = scan_id

    return redirect(url_for("results", id=scan_id))


@app.route("/results", methods=["GET"])
def results():
    """
    Renders audit findings for a specific scan ID.
    If no scan ID is specified in URL query, falls back to the current session's latest scan.
    """
    scan_id = request.args.get("id") or session.get("current_scan_id")
    report = None

    if scan_id:
        report = get_scan(scan_id)

    if not report:
        # Fall back to latest scan owned by this session
        report = get_latest_scan_for_session(session["session_id"])

    if not report:
        sys_meta = get_system_metadata()
        if not sys_meta["is_windows"]:
            # On cloud sandbox with no prior scan, create an explicit demo sample
            logger.info("Cloud host accessed without prior scan; generating demonstration sample.")
            report = scan_system(mode="deep", force_simulation=True)
            scan_id = save_scan(report, session["session_id"])
            session["current_scan_id"] = scan_id
        else:
            logger.info("No prior scan record found for session %s; redirecting to home.", session["session_id"])
            return redirect(url_for("home"))

    # Re-evaluate ML prediction on display if missing
    if "ml_prediction" not in report and "results" in report:
        try:
            from ml_engine import predict_endpoint_risk
            report["ml_prediction"] = predict_endpoint_risk(report.get("results", []))
        except Exception as exc:
            logger.warning("Could not calculate ML prediction: %s", exc)

    return render_template("results.html", report=report)


@app.route("/api/verify-control", methods=["POST"])
def api_verify_control():
    """
    Authoritative remediation verification API endpoint.
    Performs a fresh, read-only live probe on the target endpoint.
    Prevents false remediation claims:
    - If condition is truly resolved: Marks SAFE, recalculates authoritative score.
    - If condition is still insecure: Leaves WARNING, score DOES NOT increase.
    """
    try:
        data = request.get_json(force=True, silent=True) or {}
    except Exception:
        data = {}

    scan_id = data.get("scan_id")
    control_id = data.get("control_id")

    if not scan_id or not control_id:
        return jsonify({
            "success": False,
            "outcome": "INVALID_REQUEST",
            "message": "Both scan_id and control_id must be provided."
        }), 400

    report = get_scan(scan_id)
    if not report:
        return jsonify({
            "success": False,
            "outcome": "SCAN_NOT_FOUND",
            "message": f"Scan record '{scan_id}' could not be located."
        }), 404

    scan_source = report.get("scan_source", "local_host")

    # If the report is from uploaded telemetry or demo simulation, live probes on the server cannot reach remote client
    if scan_source == "demo_sample":
        return jsonify({
            "success": False,
            "outcome": "DEMO_MODE",
            "message": "This is a demonstration sample running in the cloud. Live re-verification requires running CyberSage_Scanner directly on your physical Windows computer."
        }), 400

    if scan_source == "uploaded_telemetry":
        return jsonify({
            "success": False,
            "outcome": "REMOTE_TELEMETRY",
            "message": "This report represents uploaded remote endpoint telemetry. To verify fixes on that remote machine, re-run CyberSage_Scanner on that endpoint and upload the updated audit_report.json."
        }), 400

    # For local_host scans on Windows, execute the fresh, dedicated probe
    if platform.system() != "Windows":
        return jsonify({
            "success": False,
            "outcome": "NOT_WINDOWS",
            "message": "Live endpoint verification is only supported when the CyberSage server is running natively on Windows."
        }), 400

    logger.info("Executing live verification probe for control '%s' on scan '%s'...", control_id, scan_id)
    fresh_finding = verify_single_control(control_id)
    if not fresh_finding:
        return jsonify({
            "success": False,
            "outcome": "UNKNOWN_CONTROL",
            "message": f"No verification probe registered for control '{control_id}'."
        }), 400

    new_status = fresh_finding.get("status", "UNKNOWN").upper()
    results_list = report.get("results", [])

    # Find the corresponding control finding in the stored scan
    target_idx = None
    old_finding = None
    for idx, item in enumerate(results_list):
        if item.get("control_id") == control_id or item.get("name") == fresh_finding.get("name"):
            target_idx = idx
            old_finding = item
            break

    if target_idx is None:
        return jsonify({
            "success": False,
            "outcome": "CONTROL_NOT_IN_SCAN",
            "message": f"Control '{control_id}' was not evaluated in this scan scope."
        }), 400

    previous_status = old_finding.get("status", "UNKNOWN")
    control_name = fresh_finding.get("name", control_id)

    # Record the verification audit log in SQLite
    if new_status == "SAFE":
        outcome = "VERIFIED_SAFE"
        # Update finding in report
        results_list[target_idx] = fresh_finding
        report["results"] = results_list

        # Recalculate authoritative score on backend
        score_data = calculate_audit_score(results_list, scan_mode=report.get("scan_mode", "deep"))
        report["hygiene_percentage"] = score_data["score"]
        report["score_label"] = score_data["score_label"]
        report["score_status"] = score_data["score_status"]
        report["safe_count"] = score_data["safe_count"]
        report["warning_count"] = score_data["warning_count"]
        report["unknown_count"] = score_data["unknown_count"]
        report["coverage_note"] = score_data["summary_note"]

        # Recalculate ML prediction
        try:
            from ml_engine import predict_endpoint_risk
            report["ml_prediction"] = predict_endpoint_risk(results_list)
        except Exception:
            pass

        update_scan(report, session["session_id"])
        record_verification(
            scan_id=scan_id,
            control_id=control_id,
            control_name=control_name,
            previous_status=previous_status,
            new_status="SAFE",
            outcome=outcome,
            details=fresh_finding.get("details", "")
        )

        return jsonify({
            "success": True,
            "outcome": outcome,
            "previous_status": previous_status,
            "new_status": "SAFE",
            "score": score_data["score"],
            "score_label": score_data["score_label"],
            "safe_count": score_data["safe_count"],
            "warning_count": score_data["warning_count"],
            "details": fresh_finding.get("details", ""),
            "message": f"Verification successful: {control_name} is confirmed SAFE on this machine."
        })
    else:
        # Check still failing or inconclusive; score MUST NOT increase
        outcome = "STILL_FAILING" if new_status == "WARNING" else "INCONCLUSIVE"
        # Update the observed details without flipping the status to SAFE
        old_finding["details"] = f"[Verification Re-check] {fresh_finding.get('details', '')}"
        old_finding["checked_at"] = fresh_finding.get("checked_at")
        results_list[target_idx] = old_finding
        report["results"] = results_list

        update_scan(report, session["session_id"])
        record_verification(
            scan_id=scan_id,
            control_id=control_id,
            control_name=control_name,
            previous_status=previous_status,
            new_status=new_status,
            outcome=outcome,
            details=fresh_finding.get("details", "")
        )

        return jsonify({
            "success": False,
            "outcome": outcome,
            "previous_status": previous_status,
            "new_status": new_status,
            "score": report.get("hygiene_percentage"),
            "details": fresh_finding.get("details", ""),
            "message": f"Verification failed: {control_name} is still insecure ({fresh_finding.get('details', '')}). Score remains unchanged."
        })


@app.route("/upload", methods=["POST"])
def upload_report():
    """
    Accepts an exported audit_report.json from a physical Windows host,
    validates its schema, calculates authoritative score, and stores the isolated report.
    """
    file = request.files.get("report_file")
    if not file or not file.filename:
        return redirect(url_for("home"))

    try:
        data = json.load(file)
        if not isinstance(data, dict) or "results" not in data or not isinstance(data["results"], list):
            logger.warning("Uploaded JSON file does not contain valid 'results' schema.")
            return redirect(url_for("home"))

        # Validate findings schema and sanitize
        sanitized_results = []
        for item in data["results"]:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", "Unknown Control")).strip()
            raw_status = str(item.get("status", "UNKNOWN")).strip().upper()
            valid_statuses = ("SAFE", "WARNING", "UNKNOWN", "ERROR", "TIMEOUT", "NOT_APPLICABLE")
            status = raw_status if raw_status in valid_statuses else "UNKNOWN"
            details = str(item.get("details", "Uploaded telemetry")).strip()
            severity = str(item.get("severity", "Low")).strip().capitalize()
            category = str(item.get("category", "Endpoint Hardening")).strip()
            cid = str(item.get("control_id", "")).strip()

            sanitized_finding = {
                "control_id": cid,
                "name": name,
                "category": category,
                "status": status,
                "details": details,
                "severity": severity,
                "observed_value": item.get("observed_value", details),
                "evidence_source": item.get("evidence_source", "Uploaded Host Telemetry (audit_report.json)"),
                "scope_limitations": item.get("scope_limitations", "Exported telemetry snapshot."),
                "checked_at": item.get("checked_at", ""),
            }
            sanitized_results.append(get_recommendation(sanitized_finding))

        scan_mode = str(data.get("scan_mode", "deep")).lower()
        score_data = calculate_audit_score(sanitized_results, scan_mode=scan_mode)

        scan_id = str(uuid.uuid4())
        endpoint_host = str(data.get("environment_label") or data.get("target_host") or "Uploaded Windows Endpoint")

        report = {
            "scan_id": scan_id,
            "scan_mode": scan_mode,
            "scan_mode_label": f"Uploaded Endpoint Telemetry ({len(sanitized_results)} Controls)",
            "scan_source": "uploaded_telemetry",
            "target_host": endpoint_host,
            "results": sanitized_results,
            "hygiene_percentage": score_data["score"],
            "score_label": score_data["score_label"],
            "score_status": score_data["score_status"],
            "total_checks": score_data["total_checks"],
            "applicable_count": score_data["applicable_count"],
            "safe_count": score_data["safe_count"],
            "warning_count": score_data["warning_count"],
            "unknown_count": score_data["unknown_count"],
            "not_applicable_count": score_data["not_applicable_count"],
            "high_severity_count": score_data["high_severity_count"],
            "is_complete": score_data["is_complete"],
            "scanned_at": data.get("scanned_at") or "",
            "coverage_note": score_data["summary_note"],
            "disclaimer": "This audit reflects exported telemetry collected locally by CyberSage_Scanner on the target host.",
            "is_simulated": False,
            "environment_label": f"Remote Endpoint: {endpoint_host}",
        }

        try:
            from ml_engine import predict_endpoint_risk
            report["ml_prediction"] = predict_endpoint_risk(sanitized_results)
        except Exception:
            pass

        save_scan(report, session["session_id"])
        session["current_scan_id"] = scan_id
        logger.info("Successfully ingested uploaded telemetry scan %s for session %s.", scan_id, session["session_id"])
        return redirect(url_for("results", id=scan_id))

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


@app.route("/train-model", methods=["GET", "POST"])
def train_model_endpoint():
    """Renders ML model analytics or triggers retraining on cybersecurity dataset."""
    meta_path = os.path.join(app.root_path, "models", "model_metadata.json")
    if request.method == "POST":
        try:
            from train_model import train
            metadata = train()
            return redirect(url_for("train_model_endpoint", retrained="true"))
        except Exception as exc:
            logger.error("Failed to retrain ML model: %s", exc)

    metadata = {}
    if os.path.exists(meta_path):
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                metadata = json.load(f)
        except Exception as exc:
            logger.warning("Could not read model metadata: %s", exc)

    return render_template("train.html", metadata=metadata)


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
