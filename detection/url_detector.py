from urllib.parse import urlparse
import re


SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "account",
    "secure",
    "update",
    "password",
    "signin",
    "bank",
    "wallet",
]


def analyze_url(url):

    findings = []
    score = 0

    # ---------------------------------------------------------
    # 1. BASIC URL VALIDATION
    # ---------------------------------------------------------

    try:
        parsed = urlparse(url)

        if parsed.scheme not in ("http", "https"):
            findings.append("Unsupported URL scheme")
            score += 20

        if not parsed.netloc:
            findings.append("Invalid or incomplete URL")
            score += 30

    except Exception:

        return {
            "url": url,
            "risk_score": 100,
            "risk_level": "CRITICAL",
            "findings": [
                "Malformed URL"
            ],
        }

    hostname = parsed.hostname or ""
    url_lower = url.lower()

    # ---------------------------------------------------------
    # 2. IP ADDRESS INSTEAD OF DOMAIN
    # ---------------------------------------------------------

    if re.fullmatch(
        r"\d{1,3}(\.\d{1,3}){3}",
        hostname
    ):

        findings.append(
            "URL uses an IP address"
        )

        score += 25

    # ---------------------------------------------------------
    # 3. SUSPICIOUS KEYWORDS
    # ---------------------------------------------------------

    matched_keywords = [
        word
        for word in SUSPICIOUS_KEYWORDS
        if word in url_lower
    ]

    if matched_keywords:

        findings.append(
            "Suspicious keywords: "
            + ", ".join(matched_keywords)
        )

        score += min(
            len(matched_keywords) * 10,
            30
        )

    # ---------------------------------------------------------
    # 4. HTTP WITHOUT HTTPS
    # ---------------------------------------------------------

    if parsed.scheme == "http":

        findings.append(
            "URL uses unencrypted HTTP"
        )

        score += 10

    # ---------------------------------------------------------
    # 5. LOGIN / AUTHENTICATION PATH
    # ---------------------------------------------------------

    authentication_paths = [
        "/login",
        "/signin",
        "/sign-in",
        "/verify",
        "/authentication",
        "/auth",
        "/account",
        "/password",
    ]

    if any(
        path in url_lower
        for path in authentication_paths
    ):

        findings.append(
            "Authentication-related URL path"
        )

        score += 15

    # ---------------------------------------------------------
    # 6. VERY LONG URL
    # ---------------------------------------------------------

    if len(url) > 100:

        findings.append(
            "Unusually long URL"
        )

        score += 15

    # ---------------------------------------------------------
    # 7. EXCESSIVE SUBDOMAINS
    # ---------------------------------------------------------

    if hostname.count(".") >= 4:

        findings.append(
            "Excessive subdomain depth"
        )

        score += 15

    # ---------------------------------------------------------
    # 8. @ SYMBOL
    # ---------------------------------------------------------

    if "@" in url:

        findings.append(
            "URL contains @ character"
        )

        score += 25

    # ---------------------------------------------------------
    # 9. SUSPICIOUS PORT
    # ---------------------------------------------------------

    try:

        if parsed.port not in (
            None,
            80,
            443
        ):

            findings.append(
                "URL uses a non-standard port"
            )

            score += 15

    except ValueError:

        findings.append(
            "Invalid URL port"
        )

        score += 25

    # ---------------------------------------------------------
    # 10. URL ENCODING / OBFUSCATION
    # ---------------------------------------------------------

    encoded_count = len(
        re.findall(
            r"%[0-9a-fA-F]{2}",
            url
        )
    )

    if encoded_count >= 5:

        findings.append(
            "URL contains excessive encoded characters"
        )

        score += 15

    # ---------------------------------------------------------
    # 11. DOUBLE SLASH PATH
    # ---------------------------------------------------------

    path = parsed.path or ""

    if "//" in path:

        findings.append(
            "URL contains suspicious double-slash path"
        )

        score += 10

    # ---------------------------------------------------------
    # FINAL SCORE
    # ---------------------------------------------------------

    score = min(
        score,
        100
    )

    # ---------------------------------------------------------
    # RISK LEVEL
    # ---------------------------------------------------------

    if score >= 70:

        level = "CRITICAL"

    elif score >= 45:

        level = "HIGH"

    elif score >= 20:

        level = "MEDIUM"

    else:

        level = "LOW"

    # ---------------------------------------------------------
    # RESULT
    # ---------------------------------------------------------

    return {

        "url": url,

        "risk_score": score,

        "risk_level": level,

        "findings": findings,

    }