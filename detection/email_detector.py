import re
from urllib.parse import urlparse


URGENCY_WORDS = [
    "urgent",
    "immediately",
    "act now",
    "verify",
    "verification",
    "suspended",
    "suspension",
    "expire",
    "expired",
    "confirm",
    "account locked",
    "security alert",
]

SENSITIVE_WORDS = [
    "password",
    "otp",
    "pin",
    "credit card",
    "debit card",
    "bank account",
    "cvv",
    "login",
]

SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly",
]


def extract_urls(text):
    pattern = r'https?://[^\s<>"\']+'
    return re.findall(pattern, text, re.IGNORECASE)


def analyze_email(email_text, sender=None):

    text = email_text or ""
    lower_text = text.lower()

    score = 0
    findings = []

    # Urgency indicators
    matched_urgency = [
        word for word in URGENCY_WORDS
        if word in lower_text
    ]

    if matched_urgency:
        score += min(len(matched_urgency) * 8, 24)
        findings.append(
            "Urgency indicators: " +
            ", ".join(matched_urgency)
        )

    # Sensitive information requests
    matched_sensitive = [
        word for word in SENSITIVE_WORDS
        if word in lower_text
    ]

    if matched_sensitive:
        score += min(len(matched_sensitive) * 10, 30)
        findings.append(
            "Sensitive-data indicators detected"
        )

    # URL analysis
    urls = extract_urls(text)

    if urls:
        score += min(len(urls) * 5, 15)

        findings.append(
            f"{len(urls)} URL(s) detected"
        )

    suspicious_domains = []

    for url in urls:

        try:
            hostname = urlparse(url).hostname or ""

            if hostname in SHORTENERS:
                suspicious_domains.append(hostname)

            if "@" in url:
                score += 15
                findings.append(
                    "URL contains @ character"
                )

        except Exception:
            continue

    if suspicious_domains:

        score += 15

        findings.append(
            "URL shortener detected: " +
            ", ".join(suspicious_domains)
        )

    # Sender analysis
    if sender:

        sender_lower = sender.lower()

        if "@" not in sender:
            score += 20
            findings.append(
                "Sender address format is invalid"
            )

        else:

            domain = sender_lower.split("@")[-1]

            if domain in {
                "gmail.com",
                "outlook.com",
                "yahoo.com"
            }:
                findings.append(
                    "Consumer email provider detected"
                )

    score = min(score, 100)

    if score >= 70:
        risk_level = "CRITICAL"
    elif score >= 45:
        risk_level = "HIGH"
    elif score >= 20:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "urls": urls,
        "sender": sender,
        "findings": findings,
    }