"""Explainable security-alert scoring and recommendation engine."""

from typing import Any, Dict, List

SEVERITY_POINTS = {"critical": 25, "high": 18, "medium": 10, "low": 3}
ASSET_POINTS = {"critical": 25, "high": 20, "medium": 12, "low": 5}

EVENT_GUIDANCE = {
    "brute_force": {
        "mitre": "T1110 - Brute Force",
        "actions": [
            "Review authentication logs for the affected account and source IP.",
            "Check whether any login succeeded after repeated failures.",
            "Consider a password reset or temporary account lock after validation.",
        ],
    },
    "malware": {
        "mitre": "T1204 - User Execution (possible)",
        "actions": [
            "Isolate the affected endpoint according to your incident procedure.",
            "Collect endpoint detection and response (EDR) evidence.",
            "Scan related systems and review persistence indicators.",
        ],
    },
    "phishing": {
        "mitre": "T1566 - Phishing",
        "actions": [
            "Preserve the message and inspect sender, links, and attachments.",
            "Search mailboxes for matching messages and remove confirmed malicious mail.",
            "Check whether the recipient clicked a link or submitted credentials.",
        ],
    },
    "data_exfiltration": {
        "mitre": "T1041 - Exfiltration Over C2 Channel (possible)",
        "actions": [
            "Review outbound traffic, destination, volume, and time window.",
            "Preserve relevant network and cloud audit logs.",
            "Escalate to the data owner and incident-response lead before blocking business traffic.",
        ],
    },
    "privilege_escalation": {
        "mitre": "TA0004 - Privilege Escalation",
        "actions": [
            "Review recent privilege, group-membership, and role changes.",
            "Confirm the change was approved by the system owner.",
            "Revoke unauthorized privileges after evidence is preserved.",
        ],
    },
    "suspicious_process": {
        "mitre": "T1059 - Command and Scripting Interpreter (possible)",
        "actions": [
            "Inspect process command line, parent process, hash, and execution user.",
            "Check endpoint telemetry for related child processes and network connections.",
            "Compare the binary and behavior with your approved software baseline.",
        ],
    },
}

def _normalise(value: Any, default: str = "unknown") -> str:
    return str(value if value is not None else default).strip().lower()


def triage_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Score one alert and return an analyst-friendly triage record."""
    score = 0
    reasons: List[str] = []

    severity = _normalise(alert.get("severity"))
    points = SEVERITY_POINTS.get(severity, 0)
    if points:
        score += points
        reasons.append(f"{severity.title()} alert severity (+{points})")

    criticality = _normalise(alert.get("asset_criticality"))
    points = ASSET_POINTS.get(criticality, 0)
    if points:
        score += points
        reasons.append(f"{criticality.title()} asset criticality (+{points})")

    if alert.get("known_malicious_ip") is True:
        score += 25
        reasons.append("Source marked as known malicious (+25)")

    try:
        failed_logins = int(alert.get("failed_logins", 0) or 0)
    except (TypeError, ValueError):
        failed_logins = 0
    if failed_logins >= 20:
        score += 20
        reasons.append(f"Very high failed-login count ({failed_logins}) (+20)")
    elif failed_logins >= 10:
        score += 12
        reasons.append(f"Elevated failed-login count ({failed_logins}) (+12)")
    elif failed_logins >= 5:
        score += 6
        reasons.append(f"Repeated failed logins ({failed_logins}) (+6)")

    if alert.get("successful_login_after_failures") is True:
        score += 25
        reasons.append("Successful login after repeated failures (+25)")

    event_type = _normalise(alert.get("event_type"))
    event_bonus = {
        "data_exfiltration": 20,
        "privilege_escalation": 15,
        "malware": 15,
        "phishing": 10,
        "brute_force": 8,
        "suspicious_process": 8,
    }.get(event_type, 0)
    if event_bonus:
        score += event_bonus
        reasons.append(f"Sensitive event type: {event_type} (+{event_bonus})")

    score = min(score, 100)
    if score >= 80:
        priority = "Critical"
    elif score >= 60:
        priority = "High"
    elif score >= 30:
        priority = "Medium"
    else:
        priority = "Low"

    guidance = EVENT_GUIDANCE.get(event_type, {})
    actions = guidance.get("actions", [
        "Validate the alert against source-system logs and known-good activity.",
        "Identify the affected user, host, and business owner.",
        "Document findings and escalate if suspicious activity is confirmed.",
    ])

    if not reasons:
        reasons.append("No configured risk signals matched; validate the alert context.")

    return {
        "id": alert.get("id", "UNASSIGNED"),
        "timestamp": alert.get("timestamp", ""),
        "title": alert.get("title", "Untitled alert"),
        "event_type": event_type,
        "risk_score": score,
        "priority": priority,
        "reasons": reasons,
        "mitre_mapping": guidance.get("mitre", "Not mapped"),
        "recommended_actions": actions,
        "source_ip": alert.get("source_ip", ""),
        "asset": alert.get("asset", ""),
        "analyst_status": "Needs review",
    }


def triage_alerts(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Triage a list of alerts, highest risk first."""
    return sorted(
        (triage_alert(alert) for alert in alerts),
        key=lambda item: item["risk_score"],
        reverse=True,
    )
