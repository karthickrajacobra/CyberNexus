import hashlib
import json
from datetime import datetime, timezone


def _hash_data(data):
    """
    Create a stable hash for correlation data.
    """
    text = json.dumps(
        data,
        sort_keys=True,
        default=str
    )

    return hashlib.sha256(
        text.encode("utf-8")
    ).hexdigest()


def correlate_security_signals(
    url_result=None,
    file_result=None,
    email_result=None
):
    """
    Correlate URL, File and Email security signals
    into a single cybersecurity incident.
    """

    signals = []

    # -----------------------------
    # URL SIGNAL
    # -----------------------------
    if url_result:
        signals.append({
            "source": "URL",
            "risk_score": url_result.get("risk_score", 0),
            "risk_level": url_result.get("risk_level", "LOW"),
            "details": url_result
        })

    # -----------------------------
    # FILE SIGNAL
    # -----------------------------
    if file_result:
        signals.append({
            "source": "FILE",
            "risk_score": file_result.get("risk_score", 0),
            "risk_level": file_result.get("risk_level", "LOW"),
            "details": file_result
        })

    # -----------------------------
    # EMAIL SIGNAL
    # -----------------------------
    if email_result:
        signals.append({
            "source": "EMAIL",
            "risk_score": email_result.get("risk_score", 0),
            "risk_level": email_result.get("risk_level", "LOW"),
            "details": email_result
        })

    # -----------------------------
    # NO SIGNALS
    # -----------------------------
    if not signals:
        return {
            "success": True,
            "incident_id": None,
            "incident_level": "LOW",
            "correlation_score": 0,
            "signal_count": 0,
            "signals": [],
            "reasons": [
                "No security signals available for correlation."
            ]
        }

    # -----------------------------
    # BASIC METRICS
    # -----------------------------
    scores = [
        signal["risk_score"]
        for signal in signals
    ]

    highest_score = max(scores)

    average_score = round(
        sum(scores) / len(scores)
    )

    source_count = len(signals)

    # -----------------------------
    # CORRELATION BONUS
    # -----------------------------
    correlation_bonus = 0

    if source_count >= 2:
        correlation_bonus += 10

    if source_count >= 3:
        correlation_bonus += 10

    # -----------------------------
    # CROSS-SIGNAL RELATIONSHIPS
    # -----------------------------
    reasons = []

    sources = {
        signal["source"]
        for signal in signals
    }

    if "EMAIL" in sources and "URL" in sources:
        correlation_bonus += 10

        reasons.append(
            "Email and URL security signals are present together."
        )

    if "EMAIL" in sources and "FILE" in sources:
        correlation_bonus += 10

        reasons.append(
            "Email and file security signals are present together."
        )

    if "URL" in sources and "FILE" in sources:
        correlation_bonus += 10

        reasons.append(
            "URL and file security signals are present together."
        )

    # -----------------------------
    # HIGH-RISK SIGNALS
    # -----------------------------
    high_risk_count = sum(
        1
        for signal in signals
        if signal["risk_score"] >= 45
    )

    if high_risk_count >= 2:
        correlation_bonus += 15

        reasons.append(
            "Multiple high-risk security signals detected."
        )

    # -----------------------------
    # FINAL CORRELATION SCORE
    # -----------------------------
    correlation_score = round(
        (average_score * 0.5)
        + (highest_score * 0.3)
        + (correlation_bonus * 0.2)
    )

    correlation_score = min(
        correlation_score,
        100
    )

    # -----------------------------
    # INCIDENT LEVEL
    # -----------------------------
    if correlation_score >= 70:
        incident_level = "CRITICAL"

    elif correlation_score >= 45:
        incident_level = "HIGH"

    elif correlation_score >= 20:
        incident_level = "MEDIUM"

    else:
        incident_level = "LOW"

    # -----------------------------
    # DEFAULT REASON
    # -----------------------------
    if not reasons:
        reasons.append(
            "Security signals were correlated into a unified assessment."
        )

    # -----------------------------
    # INCIDENT ID
    # -----------------------------
    timestamp = datetime.now(
        timezone.utc
    ).isoformat()

    incident_seed = {
        "timestamp": timestamp,
        "sources": sorted(sources),
        "scores": scores
    }

    incident_hash = _hash_data(
        incident_seed
    )

    incident_id = (
        "CNX-"
        + incident_hash[:12].upper()
    )

    # -----------------------------
    # RESULT
    # -----------------------------
    return {
        "success": True,
        "incident_id": incident_id,
        "timestamp": timestamp,
        "incident_level": incident_level,
        "correlation_score": correlation_score,
        "signal_count": source_count,
        "high_risk_signal_count": high_risk_count,
        "correlation_bonus": correlation_bonus,
        "signals": signals,
        "reasons": reasons
    }