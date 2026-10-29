"""
CyberSage Scoring Engine.

Provides transparent, mathematically consistent, and tamper-proof security
score calculations for Quick Baseline and Hard System Vulnerability Audits.
"""

from typing import Any, Dict, List, Optional, Tuple

QUICK_SCAN_CONTROLS = {
    "firewall_profiles",
    "defender_realtime",
    "threat_signatures",
    "windows_update",
    "uac_policy",
    "guest_account",
}

DEEP_SCAN_CONTROLS = QUICK_SCAN_CONTROLS.union({
    "smb1_protocol",
    "rdp_nla",
    "restrict_anonymous",
    "pua_protection",
    "controlled_folder_access",
    "script_block_logging",
})

# Weight definitions per control (can be customized, defaults to 1.0 per applicable control)
DEFAULT_WEIGHTS = {cid: 1.0 for cid in DEEP_SCAN_CONTROLS}


def calculate_audit_score(
    findings: List[Dict[str, Any]],
    scan_mode: str = "deep"
) -> Dict[str, Any]:
    """
    Computes an authoritative audit score and breakdown from findings.

    Rules:
    1. Only applicable controls in scope contribute to the score.
    2. SAFE (PASS) contributes positive score credit.
    3. WARNING (FAIL) receives zero credit.
    4. UNKNOWN, ERROR, TIMEOUT receive zero credit and count toward the incomplete threshold.
    5. NOT_APPLICABLE controls are excluded from both numerator and denominator.
    6. If inconclusive checks exceed 33% of applicable scope, the score is reported as None (Incomplete Scan).

    Args:
        findings: List of finding dictionaries.
        scan_mode: "quick" for baseline audit, or "deep" for hard audit.

    Returns:
        Dictionary with score metrics, counts, and status label.
    """
    is_deep = scan_mode.lower() in ("deep", "hard", "comprehensive")
    scope_controls = DEEP_SCAN_CONTROLS if is_deep else QUICK_SCAN_CONTROLS
    audit_label = "Hard Audit Score" if is_deep else "Baseline Audit Score"

    # Normalize findings and map by control_id or normalized name
    safe_items: List[Dict[str, Any]] = []
    warning_items: List[Dict[str, Any]] = []
    unknown_items: List[Dict[str, Any]] = []
    not_applicable_items: List[Dict[str, Any]] = []
    high_severity_items: List[Dict[str, Any]] = []

    for item in findings:
        status = str(item.get("status", "UNKNOWN")).upper()
        severity = str(item.get("severity", "Low")).capitalize()

        if status == "SAFE":
            safe_items.append(item)
        elif status == "WARNING":
            warning_items.append(item)
            if severity == "High":
                high_severity_items.append(item)
        elif status == "NOT_APPLICABLE":
            not_applicable_items.append(item)
        else: # UNKNOWN, ERROR, TIMEOUT, NOT SUPPORTED
            unknown_items.append(item)

    total_checks = len(findings)
    safe_count = len(safe_items)
    warning_count = len(warning_items)
    unknown_count = len(unknown_items)
    na_count = len(not_applicable_items)
    high_severity_count = len(high_severity_items)

    applicable_count = total_checks - na_count
    if applicable_count <= 0:
        return {
            "score": None,
            "score_label": f"{audit_label} (Not Applicable)",
            "score_status": "NOT_APPLICABLE",
            "is_complete": False,
            "total_checks": total_checks,
            "applicable_count": 0,
            "safe_count": safe_count,
            "warning_count": warning_count,
            "unknown_count": unknown_count,
            "not_applicable_count": na_count,
            "high_severity_count": high_severity_count,
            "summary_note": "No applicable security controls were evaluated for this environment."
        }

    # Incompleteness check: If more than 33% of applicable checks are UNKNOWN/ERROR/TIMEOUT
    max_unknown_allowed = applicable_count // 3
    if unknown_count > max_unknown_allowed:
        return {
            "score": None,
            "score_label": f"{audit_label} (Incomplete Scan)",
            "score_status": "INCOMPLETE_SCAN",
            "is_complete": False,
            "total_checks": total_checks,
            "applicable_count": applicable_count,
            "safe_count": safe_count,
            "warning_count": warning_count,
            "unknown_count": unknown_count,
            "not_applicable_count": na_count,
            "high_severity_count": high_severity_count,
            "summary_note": f"Insufficient conclusive evidence ({unknown_count} of {applicable_count} checks failed or returned unknown state). Score is withheld."
        }

    # Authoritative hygiene score: passed applicable controls over total applicable controls
    score = round((safe_count / applicable_count) * 100)

    summary_note = (
        f"{safe_count} of {applicable_count} applicable configuration parameters passed defensive best practices. "
        f"{warning_count} potential weaknesses were confirmed."
    )
    if unknown_count > 0:
        summary_note += f" ({unknown_count} checks were inconclusive)."

    return {
        "score": score,
        "score_label": f"{audit_label}: {score}%",
        "score_status": "VALID",
        "is_complete": True,
        "total_checks": total_checks,
        "applicable_count": applicable_count,
        "safe_count": safe_count,
        "warning_count": warning_count,
        "unknown_count": unknown_count,
        "not_applicable_count": na_count,
        "high_severity_count": high_severity_count,
        "summary_note": summary_note
    }
