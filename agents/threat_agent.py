from datetime import datetime, timezone

from detection.url_detector import analyze_url
from detection.email_detector import analyze_email
from detection.file_detector import analyze_file


class ThreatAgent:
    """
    CyberNexus Ω - Threat Agent

    Central threat-analysis agent.

    Responsibilities:
    - Analyze URL threats
    - Analyze email threats
    - Analyze file threats
    - Normalize detector results
    - Produce an agent-level threat assessment
    """

    AGENT_NAME = "CyberNexus Threat Agent"
    AGENT_VERSION = "1.0"

    def __init__(self):
        self.status = "READY"

    def _timestamp(self):
        return datetime.now(timezone.utc).isoformat()

    def _classify(self, score):
        if score >= 70:
            return {
                "classification": "CRITICAL THREAT",
                "priority": "IMMEDIATE"
            }

        if score >= 45:
            return {
                "classification": "HIGH THREAT",
                "priority": "HIGH"
            }

        if score >= 20:
            return {
                "classification": "SUSPICIOUS",
                "priority": "MEDIUM"
            }

        return {
            "classification": "LOW THREAT",
            "priority": "LOW"
        }

    def analyze_url(self, url):
        """
        Analyze a URL using the existing URL detector.
        """

        if not url or not isinstance(url, str):
            return {
                "success": False,
                "agent": self.AGENT_NAME,
                "type": "URL",
                "message": "A valid URL is required.",
                "timestamp": self._timestamp()
            }

        try:
            result = analyze_url(url.strip())

            score = result.get("risk_score", 0)
            classification = self._classify(score)

            return {
                "success": True,
                "agent": self.AGENT_NAME,
                "version": self.AGENT_VERSION,
                "type": "URL",
                "status": "ANALYZED",
                "input": {
                    "url": url.strip()
                },
                "threat": {
                    "risk_score": score,
                    "risk_level": result.get("risk_level", "LOW"),
                    "classification": classification["classification"],
                    "priority": classification["priority"]
                },
                "findings": result.get("findings", []),
                "detector_result": result,
                "timestamp": self._timestamp()
            }

        except Exception as error:
            return {
                "success": False,
                "agent": self.AGENT_NAME,
                "type": "URL",
                "status": "ERROR",
                "message": str(error),
                "timestamp": self._timestamp()
            }

    def analyze_email(self, email_text, sender=None):
        """
        Analyze an email using the existing email detector.
        """

        if not email_text or not isinstance(email_text, str):
            return {
                "success": False,
                "agent": self.AGENT_NAME,
                "type": "EMAIL",
                "message": "Email content is required.",
                "timestamp": self._timestamp()
            }

        try:
            result = analyze_email(
                email_text=email_text.strip(),
                sender=sender
            )

            score = result.get("risk_score", 0)
            classification = self._classify(score)

            return {
                "success": True,
                "agent": self.AGENT_NAME,
                "version": self.AGENT_VERSION,
                "type": "EMAIL",
                "status": "ANALYZED",
                "input": {
                    "sender": sender,
                    "email": email_text.strip()
                },
                "threat": {
                    "risk_score": score,
                    "risk_level": result.get("risk_level", "LOW"),
                    "classification": classification["classification"],
                    "priority": classification["priority"]
                },
                "findings": result.get("findings", []),
                "detector_result": result,
                "timestamp": self._timestamp()
            }

        except Exception as error:
            return {
                "success": False,
                "agent": self.AGENT_NAME,
                "type": "EMAIL",
                "status": "ERROR",
                "message": str(error),
                "timestamp": self._timestamp()
            }

    def analyze_file(self, file_path):
        """
        Analyze a file using the existing file detector.
        """

        if not file_path or not isinstance(file_path, str):
            return {
                "success": False,
                "agent": self.AGENT_NAME,
                "type": "FILE",
                "message": "A valid file path is required.",
                "timestamp": self._timestamp()
            }

        try:
            result = analyze_file(file_path)

            score = result.get("risk_score", 0)
            classification = self._classify(score)

            return {
                "success": True,
                "agent": self.AGENT_NAME,
                "version": self.AGENT_VERSION,
                "type": "FILE",
                "status": "ANALYZED",
                "input": {
                    "file_path": file_path
                },
                "threat": {
                    "risk_score": score,
                    "risk_level": result.get("risk_level", "LOW"),
                    "classification": classification["classification"],
                    "priority": classification["priority"]
                },
                "findings": result.get("findings", []),
                "detector_result": result,
                "timestamp": self._timestamp()
            }

        except FileNotFoundError:
            return {
                "success": False,
                "agent": self.AGENT_NAME,
                "type": "FILE",
                "status": "ERROR",
                "message": "File not found.",
                "timestamp": self._timestamp()
            }

        except Exception as error:
            return {
                "success": False,
                "agent": self.AGENT_NAME,
                "type": "FILE",
                "status": "ERROR",
                "message": str(error),
                "timestamp": self._timestamp()
            }

    def analyze(self, data_type, value, sender=None):
        """
        Generic agent entry point.

        Supported types:
        URL
        EMAIL
        FILE
        """

        normalized_type = str(data_type).upper().strip()

        if normalized_type == "URL":
            return self.analyze_url(value)

        if normalized_type == "EMAIL":
            return self.analyze_email(
                email_text=value,
                sender=sender
            )

        if normalized_type == "FILE":
            return self.analyze_file(value)

        return {
            "success": False,
            "agent": self.AGENT_NAME,
            "status": "ERROR",
            "message": (
                "Unsupported analysis type. "
                "Supported types: URL, EMAIL, FILE."
            ),
            "timestamp": self._timestamp()
        }


def run_threat_agent(data_type, value, sender=None):
    """
    Convenience function for other CyberNexus modules.
    """

    agent = ThreatAgent()

    return agent.analyze(
        data_type=data_type,
        value=value,
        sender=sender
    )


if __name__ == "__main__":

    print("\n" + "=" * 70)
    print("CYBERNEXUS Ω - THREAT AGENT TEST")
    print("=" * 70)

    agent = ThreatAgent()

    # ---------------------------------------------------------
    # URL TEST
    # ---------------------------------------------------------

    print("\n[1] URL THREAT TEST")
    print("-" * 70)

    url_result = agent.analyze_url(
        "http://192.168.1.20/login/verify/password"
    )

    print("Agent        :", url_result.get("agent"))
    print("Status       :", url_result.get("status"))

    if url_result.get("success"):
        threat = url_result["threat"]

        print("Risk Score   :", threat["risk_score"])
        print("Risk Level   :", threat["risk_level"])
        print("Classification:", threat["classification"])
        print("Priority     :", threat["priority"])

        print("\nFindings:")

        for finding in url_result.get("findings", []):
            print(" -", finding)

    else:
        print("Error        :", url_result.get("message"))

    # ---------------------------------------------------------
    # EMAIL TEST
    # ---------------------------------------------------------

    print("\n[2] EMAIL THREAT TEST")
    print("-" * 70)

    email_result = agent.analyze_email(
        email_text=(
            "URGENT! Your account is suspended. "
            "Verify your password and login immediately: "
            "https://bit.ly/example"
        ),
        sender="security@example.com"
    )

    print("Agent        :", email_result.get("agent"))
    print("Status       :", email_result.get("status"))

    if email_result.get("success"):
        threat = email_result["threat"]

        print("Risk Score   :", threat["risk_score"])
        print("Risk Level   :", threat["risk_level"])
        print("Classification:", threat["classification"])
        print("Priority     :", threat["priority"])

        print("\nFindings:")

        for finding in email_result.get("findings", []):
            print(" -", finding)

    else:
        print("Error        :", email_result.get("message"))

    # ---------------------------------------------------------
    # FINAL STATUS
    # ---------------------------------------------------------

    print("\n" + "=" * 70)
    print("THREAT AGENT TEST COMPLETED")
    print("=" * 70)