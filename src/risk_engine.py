import logging

logger = logging.getLogger(__name__)


def calculate_risk(alert_severity, vt_result):
    """
    Calculate final risk based on:
    - Local alert severity
    - VirusTotal enrichment result

    Returns:
        risk_level, action
    """

    severity = str(alert_severity).lower()

    malicious = int(vt_result.get("malicious", 0))
    suspicious = int(vt_result.get("suspicious", 0))

    # Highest priority: malicious VT detections
    if malicious > 0:
        return "HIGH", "ALERT_AND_RESPOND"

    # Suspicious VT detections
    if suspicious > 0:
        return "MEDIUM", "ALERT_AND_INVESTIGATE"

    # Local alert severity
    if severity == "high":
        return "HIGH", "ALERT_AND_RESPOND"

    if severity == "medium":
        return "MEDIUM", "ALERT_AND_INVESTIGATE"

    return "LOW", "LOG_ONLY"

