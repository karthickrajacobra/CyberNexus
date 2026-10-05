from datetime import datetime, timezone


class BehaviourAgent:
    """
    CyberNexus Ω - Behaviour Agent

    Responsibilities:
    - Analyze suspicious behaviour signals
    - Calculate behaviour risk
    - Identify behaviour patterns
    - Classify attacker behaviour
    - Generate investigation priority
    """

    AGENT_NAME = "CyberNexus Behaviour Agent"
    AGENT_VERSION = "1.0"

    def __init__(self):
        self.status = "READY"

    def _timestamp(self):
        return datetime.now(timezone.utc).isoformat()

    # ---------------------------------------------------------
    # RISK CLASSIFICATION
    # ---------------------------------------------------------

    def _classify(self, score):

        if score >= 80:
            return {
                "risk_level": "CRITICAL",
                "classification": "MALICIOUS BEHAVIOUR",
                "priority": "IMMEDIATE"
            }

        if score >= 60:
            return {
                "risk_level": "HIGH",
                "classification": "SUSPICIOUS BEHAVIOUR",
                "priority": "HIGH"
            }

        if score >= 35:
            return {
                "risk_level": "MEDIUM",
                "classification": "ANOMALOUS BEHAVIOUR",
                "priority": "MEDIUM"
            }

        return {
            "risk_level": "LOW",
            "classification": "NORMAL BEHAVIOUR",
            "priority": "LOW"
        }

    # ---------------------------------------------------------
    # BEHAVIOUR ANALYSIS
    # ---------------------------------------------------------

    def analyze(self, signals):
        """
        Analyze behaviour from security signals.

        Supported signal fields:

        failed_logins
        unusual_login
        privilege_escalation
        suspicious_url
        suspicious_file
        suspicious_email
        rapid_requests
        unknown_device
        data_exfiltration
        command_execution
        """

        if not isinstance(signals, dict):
            return {
                "success": False,
                "agent": self.AGENT_NAME,
                "status": "ERROR",
                "message": "Behaviour signals must be provided as a dictionary.",
                "timestamp": self._timestamp()
            }

        score = 0
        findings = []
        indicators = []

        # -----------------------------------------------------
        # FAILED LOGIN ACTIVITY
        # -----------------------------------------------------

        failed_logins = signals.get("failed_logins", 0)

        try:
            failed_logins = int(failed_logins)
        except (TypeError, ValueError):
            failed_logins = 0

        if failed_logins >= 10:
            score += 20
            indicators.append("Excessive failed login attempts")
            findings.append(
                f"{failed_logins} failed login attempts detected."
            )

        elif failed_logins >= 5:
            score += 10
            indicators.append("Repeated failed login attempts")
            findings.append(
                f"{failed_logins} failed login attempts detected."
            )

        # -----------------------------------------------------
        # UNUSUAL LOGIN
        # -----------------------------------------------------

        if signals.get("unusual_login", False):
            score += 15
            indicators.append("Unusual login behaviour")
            findings.append(
                "Login activity differs from the expected behaviour."
            )

        # -----------------------------------------------------
        # PRIVILEGE ESCALATION
        # -----------------------------------------------------

        if signals.get("privilege_escalation", False):
            score += 25
            indicators.append("Privilege escalation")
            findings.append(
                "Privilege escalation behaviour detected."
            )

        # -----------------------------------------------------
        # SUSPICIOUS URL
        # -----------------------------------------------------

        if signals.get("suspicious_url", False):
            score += 10
            indicators.append("Suspicious URL activity")
            findings.append(
                "Suspicious URL activity is associated with the behaviour."
            )

        # -----------------------------------------------------
        # SUSPICIOUS FILE
        # -----------------------------------------------------

        if signals.get("suspicious_file", False):
            score += 15
            indicators.append("Suspicious file activity")
            findings.append(
                "Suspicious file activity is associated with the behaviour."
            )

        # -----------------------------------------------------
        # SUSPICIOUS EMAIL
        # -----------------------------------------------------

        if signals.get("suspicious_email", False):
            score += 10
            indicators.append("Suspicious email activity")
            findings.append(
                "Suspicious email activity is associated with the behaviour."
            )

        # -----------------------------------------------------
        # RAPID REQUESTS
        # -----------------------------------------------------

        rapid_requests = signals.get("rapid_requests", 0)

        try:
            rapid_requests = int(rapid_requests)
        except (TypeError, ValueError):
            rapid_requests = 0

        if rapid_requests >= 100:
            score += 20
            indicators.append("High-volume rapid requests")
            findings.append(
                f"{rapid_requests} rapid requests detected."
            )

        elif rapid_requests >= 50:
            score += 10
            indicators.append("Elevated request frequency")
            findings.append(
                f"{rapid_requests} rapid requests detected."
            )

        # -----------------------------------------------------
        # UNKNOWN DEVICE
        # -----------------------------------------------------

        if signals.get("unknown_device", False):
            score += 10
            indicators.append("Unknown device")
            findings.append(
                "Activity originated from an unknown device."
            )

        # -----------------------------------------------------
        # DATA EXFILTRATION
        # -----------------------------------------------------

        if signals.get("data_exfiltration", False):
            score += 30
            indicators.append("Possible data exfiltration")
            findings.append(
                "Possible unauthorized data transfer detected."
            )

        # -----------------------------------------------------
        # COMMAND EXECUTION
        # -----------------------------------------------------

        if signals.get("command_execution", False):
            score += 20
            indicators.append("Suspicious command execution")
            findings.append(
                "Suspicious command execution behaviour detected."
            )

        # -----------------------------------------------------
        # MULTI-SIGNAL CORRELATION BONUS
        # -----------------------------------------------------

        indicator_count = len(indicators)

        if indicator_count >= 5:
            score += 20
            findings.append(
                "Multiple independent suspicious behaviour indicators "
                "are present."
            )

        elif indicator_count >= 3:
            score += 10
            findings.append(
                "Multiple suspicious behaviour indicators are present."
            )

        score = min(score, 100)

        classification = self._classify(score)

        # -----------------------------------------------------
        # BEHAVIOUR PROFILE
        # -----------------------------------------------------

        profile = "NORMAL"

        if (
            signals.get("privilege_escalation")
            or signals.get("command_execution")
        ):
            profile = "INTRUSION"

        elif (
            signals.get("data_exfiltration")
            or signals.get("rapid_requests", 0) >= 50
        ):
            profile = "DATA_ABUSE"

        elif (
            signals.get("failed_logins", 0) >= 5
            or signals.get("unknown_device")
        ):
            profile = "ACCOUNT_ABUSE"

        elif (
            signals.get("suspicious_url")
            or signals.get("suspicious_email")
            or signals.get("suspicious_file")
        ):
            profile = "SOCIAL_ENGINEERING"

        return {
            "success": True,
            "agent": self.AGENT_NAME,
            "version": self.AGENT_VERSION,
            "status": "ANALYZED",
            "type": "BEHAVIOUR",
            "behaviour": {
                "risk_score": score,
                "risk_level": classification["risk_level"],
                "classification": classification["classification"],
                "priority": classification["priority"],
                "profile": profile
            },
            "indicators": indicators,
            "findings": findings,
            "signal_count": indicator_count,
            "signals": signals,
            "timestamp": self._timestamp()
        }


def run_behaviour_agent(signals):
    """
    Convenience function for other CyberNexus modules.
    """

    agent = BehaviourAgent()

    return agent.analyze(signals)


# =============================================================
# DIRECT TEST
# =============================================================

if __name__ == "__main__":

    print("\n" + "=" * 70)
    print("CYBERNEXUS Ω - BEHAVIOUR AGENT TEST")
    print("=" * 70)

    agent = BehaviourAgent()

    # ---------------------------------------------------------
    # SUSPICIOUS BEHAVIOUR TEST
    # ---------------------------------------------------------

    print("\n[1] SUSPICIOUS BEHAVIOUR TEST")
    print("-" * 70)

    test_signals = {
        "failed_logins": 12,
        "unusual_login": True,
        "privilege_escalation": True,
        "suspicious_url": True,
        "suspicious_file": True,
        "suspicious_email": True,
        "rapid_requests": 120,
        "unknown_device": True,
        "data_exfiltration": True,
        "command_execution": True
    }

    result = agent.analyze(test_signals)

    print("Agent        :", result.get("agent"))
    print("Status       :", result.get("status"))

    if result.get("success"):

        behaviour = result["behaviour"]

        print("Risk Score   :", behaviour["risk_score"])
        print("Risk Level   :", behaviour["risk_level"])
        print("Classification:", behaviour["classification"])
        print("Priority     :", behaviour["priority"])
        print("Profile      :", behaviour["profile"])
        print("Signal Count :", result["signal_count"])

        print("\nIndicators:")

        for indicator in result.get("indicators", []):
            print(" -", indicator)

        print("\nFindings:")

        for finding in result.get("findings", []):
            print(" -", finding)

    else:

        print("Error        :", result.get("message"))

    # ---------------------------------------------------------
    # NORMAL BEHAVIOUR TEST
    # ---------------------------------------------------------

    print("\n[2] NORMAL BEHAVIOUR TEST")
    print("-" * 70)

    normal_signals = {
        "failed_logins": 1,
        "unusual_login": False,
        "privilege_escalation": False,
        "suspicious_url": False,
        "suspicious_file": False,
        "suspicious_email": False,
        "rapid_requests": 5,
        "unknown_device": False,
        "data_exfiltration": False,
        "command_execution": False
    }

    normal_result = agent.analyze(normal_signals)

    print("Agent        :", normal_result.get("agent"))
    print("Status       :", normal_result.get("status"))

    if normal_result.get("success"):

        behaviour = normal_result["behaviour"]

        print("Risk Score   :", behaviour["risk_score"])
        print("Risk Level   :", behaviour["risk_level"])
        print("Classification:", behaviour["classification"])
        print("Priority     :", behaviour["priority"])
        print("Profile      :", behaviour["profile"])

    else:

        print("Error        :", normal_result.get("message"))

    # ---------------------------------------------------------
    # FINAL STATUS
    # ---------------------------------------------------------

    print("\n" + "=" * 70)
    print("BEHAVIOUR AGENT TEST COMPLETED")
    print("=" * 70)