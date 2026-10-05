from datetime import datetime, timezone
from urllib.parse import urlparse
import re


class IntelligenceAgent:
    """
    CyberNexus Ω - Intelligence Agent

    Responsibilities:
    - Extract Indicators of Compromise (IOCs)
    - Analyze URL/domain intelligence
    - Analyze file hash intelligence
    - Analyze email intelligence
    - Correlate threat indicators
    - Generate intelligence confidence
    - Generate investigation recommendations
    """

    AGENT_NAME = "CyberNexus Intelligence Agent"
    AGENT_VERSION = "1.0"

    def __init__(self):
        self.status = "READY"

    def _timestamp(self):
        return datetime.now(timezone.utc).isoformat()

    # ---------------------------------------------------------
    # IOC EXTRACTION
    # ---------------------------------------------------------

    def extract_iocs(
        self,
        url_result=None,
        file_result=None,
        email_result=None
    ):
        """
        Extract useful Indicators of Compromise.
        """

        iocs = {
            "urls": [],
            "domains": [],
            "ip_addresses": [],
            "file_hashes": [],
            "email_addresses": []
        }

        # -----------------------------------------------------
        # URL RESULT
        # -----------------------------------------------------

        if isinstance(url_result, dict):

            url = url_result.get("url")

            if url:
                iocs["urls"].append(url)

                try:
                    parsed = urlparse(url)
                    hostname = parsed.hostname

                    if hostname:

                        if self._is_ip_address(hostname):
                            iocs["ip_addresses"].append(hostname)
                        else:
                            iocs["domains"].append(hostname)

                except Exception:
                    pass

        # -----------------------------------------------------
        # FILE RESULT
        # -----------------------------------------------------

        if isinstance(file_result, dict):

            file_hash = file_result.get("sha256")

            if file_hash:
                iocs["file_hashes"].append(file_hash)

        # -----------------------------------------------------
        # EMAIL RESULT
        # -----------------------------------------------------

        if isinstance(email_result, dict):

            sender = email_result.get("sender")

            if sender and isinstance(sender, str):
                if "@" in sender:
                    iocs["email_addresses"].append(sender)

            email_urls = email_result.get("urls", [])

            if isinstance(email_urls, list):

                for url in email_urls:

                    if url not in iocs["urls"]:
                        iocs["urls"].append(url)

                    try:

                        parsed = urlparse(url)
                        hostname = parsed.hostname

                        if hostname:

                            if self._is_ip_address(hostname):

                                if hostname not in iocs["ip_addresses"]:
                                    iocs["ip_addresses"].append(
                                        hostname
                                    )

                            else:

                                if hostname not in iocs["domains"]:
                                    iocs["domains"].append(
                                        hostname
                                    )

                    except Exception:
                        pass

        # -----------------------------------------------------
        # REMOVE DUPLICATES
        # -----------------------------------------------------

        for key in iocs:
            iocs[key] = list(dict.fromkeys(iocs[key]))

        return iocs

    # ---------------------------------------------------------
    # IP ADDRESS CHECK
    # ---------------------------------------------------------

    def _is_ip_address(self, value):
        """
        Basic IPv4 validation.
        """

        if not value:
            return False

        pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

        if not re.match(pattern, value):
            return False

        try:

            parts = value.split(".")

            return all(
                0 <= int(part) <= 255
                for part in parts
            )

        except ValueError:

            return False

    # ---------------------------------------------------------
    # THREAT LEVEL
    # ---------------------------------------------------------

    def _calculate_threat_score(
        self,
        url_result=None,
        file_result=None,
        email_result=None,
        behaviour_result=None
    ):
        """
        Calculate intelligence-level threat score.
        """

        scores = []

        results = [
            url_result,
            file_result,
            email_result
        ]

        if isinstance(behaviour_result, dict):

            behaviour = behaviour_result.get(
                "behaviour",
                {}
            )

            behaviour_score = behaviour.get(
                "risk_score"
            )

            if behaviour_score is not None:

                try:
                    scores.append(
                        int(behaviour_score)
                    )
                except (TypeError, ValueError):
                    pass

        for result in results:

            if isinstance(result, dict):

                score = result.get("risk_score")

                if score is None:

                    threat = result.get(
                        "threat",
                        {}
                    )

                    score = threat.get(
                        "risk_score"
                    )

                if score is not None:

                    try:
                        scores.append(
                            int(score)
                        )
                    except (TypeError, ValueError):
                        pass

        if not scores:
            return 0

        highest = max(scores)
        average = sum(scores) / len(scores)

        score = round(
            (highest * 0.6)
            + (average * 0.4)
        )

        return min(score, 100)

    # ---------------------------------------------------------
    # CONFIDENCE
    # ---------------------------------------------------------

    def _calculate_confidence(
        self,
        iocs,
        signal_count
    ):
        """
        Estimate intelligence confidence based on
        available independent evidence.

        This is an internal confidence measure,
        not an external threat-intelligence verdict.
        """

        evidence_count = 0

        for values in iocs.values():

            evidence_count += len(values)

        confidence = 30

        if evidence_count >= 1:
            confidence += 15

        if evidence_count >= 3:
            confidence += 15

        if evidence_count >= 5:
            confidence += 15

        if signal_count >= 2:
            confidence += 10

        if signal_count >= 3:
            confidence += 10

        return min(confidence, 95)

    # ---------------------------------------------------------
    # INTELLIGENCE CLASSIFICATION
    # ---------------------------------------------------------

    def _classify(self, score):

        if score >= 80:

            return {
                "level": "CRITICAL",
                "classification": "CRITICAL THREAT INTELLIGENCE",
                "priority": "IMMEDIATE"
            }

        if score >= 60:

            return {
                "level": "HIGH",
                "classification": "HIGH-RISK THREAT INTELLIGENCE",
                "priority": "HIGH"
            }

        if score >= 35:

            return {
                "level": "MEDIUM",
                "classification": "SUSPICIOUS THREAT INTELLIGENCE",
                "priority": "MEDIUM"
            }

        return {
            "level": "LOW",
            "classification": "LOW-RISK THREAT INTELLIGENCE",
            "priority": "LOW"
        }

    # ---------------------------------------------------------
    # RECOMMENDATIONS
    # ---------------------------------------------------------

    def _generate_recommendations(
        self,
        iocs,
        classification,
        behaviour_result=None
    ):
        """
        Generate defensive investigation recommendations.
        """

        recommendations = []

        if iocs["urls"]:

            recommendations.append(
                "Investigate identified URLs before allowing "
                "user interaction."
            )

        if iocs["domains"]:

            recommendations.append(
                "Review identified domains against approved "
                "organizational domain lists."
            )

        if iocs["ip_addresses"]:

            recommendations.append(
                "Review IP-based indicators in network logs "
                "and firewall telemetry."
            )

        if iocs["file_hashes"]:

            recommendations.append(
                "Compare identified file hashes with trusted "
                "malware-analysis or organizational records."
            )

        if iocs["email_addresses"]:

            recommendations.append(
                "Review sender identity and email authentication "
                "signals."
            )

        if isinstance(behaviour_result, dict):

            behaviour = behaviour_result.get(
                "behaviour",
                {}
            )

            profile = behaviour.get(
                "profile"
            )

            if profile == "INTRUSION":

                recommendations.append(
                    "Investigate possible unauthorized access "
                    "and privilege escalation activity."
                )

            elif profile == "DATA_ABUSE":

                recommendations.append(
                    "Review outbound data-transfer activity "
                    "for possible unauthorized exfiltration."
                )

            elif profile == "ACCOUNT_ABUSE":

                recommendations.append(
                    "Review authentication logs and account "
                    "access history."
                )

        if classification["level"] in {
            "CRITICAL",
            "HIGH"
        }:

            recommendations.append(
                "Prioritize the incident for security investigation."
            )

        if not recommendations:

            recommendations.append(
                "Continue monitoring the available security signals."
            )

        return recommendations

    # ---------------------------------------------------------
    # MAIN ANALYSIS
    # ---------------------------------------------------------

    def analyze(
        self,
        url_result=None,
        file_result=None,
        email_result=None,
        behaviour_result=None
    ):
        """
        Complete threat-intelligence analysis.
        """

        provided_results = [
            url_result,
            file_result,
            email_result,
            behaviour_result
        ]

        signal_count = sum(
            1
            for result in provided_results
            if isinstance(result, dict)
        )

        if signal_count == 0:

            return {
                "success": False,
                "agent": self.AGENT_NAME,
                "status": "NO_DATA",
                "message": (
                    "At least one security result is required."
                ),
                "timestamp": self._timestamp()
            }

        # -----------------------------------------------------
        # EXTRACT IOCs
        # -----------------------------------------------------

        iocs = self.extract_iocs(
            url_result=url_result,
            file_result=file_result,
            email_result=email_result
        )

        # -----------------------------------------------------
        # SCORE
        # -----------------------------------------------------

        threat_score = self._calculate_threat_score(
            url_result=url_result,
            file_result=file_result,
            email_result=email_result,
            behaviour_result=behaviour_result
        )

        classification = self._classify(
            threat_score
        )

        # -----------------------------------------------------
        # CONFIDENCE
        # -----------------------------------------------------

        confidence = self._calculate_confidence(
            iocs=iocs,
            signal_count=signal_count
        )

        # -----------------------------------------------------
        # RECOMMENDATIONS
        # -----------------------------------------------------

        recommendations = self._generate_recommendations(
            iocs=iocs,
            classification=classification,
            behaviour_result=behaviour_result
        )

        # -----------------------------------------------------
        # SUMMARY
        # -----------------------------------------------------

        intelligence_summary = (
            f"CyberNexus identified "
            f"{sum(len(v) for v in iocs.values())} "
            f"indicator(s) across "
            f"{signal_count} security signal(s). "
            f"Intelligence assessment is "
            f"{classification['level']}."
        )

        return {
            "success": True,
            "agent": self.AGENT_NAME,
            "version": self.AGENT_VERSION,
            "status": "ANALYZED",
            "type": "THREAT_INTELLIGENCE",
            "intelligence": {
                "risk_score": threat_score,
                "risk_level": classification["level"],
                "classification": classification[
                    "classification"
                ],
                "priority": classification["priority"],
                "confidence": confidence
            },
            "iocs": iocs,
            "signal_count": signal_count,
            "summary": intelligence_summary,
            "recommendations": recommendations,
            "timestamp": self._timestamp()
        }


def run_intelligence_agent(
    url_result=None,
    file_result=None,
    email_result=None,
    behaviour_result=None
):
    """
    Convenience function for other CyberNexus modules.
    """

    agent = IntelligenceAgent()

    return agent.analyze(
        url_result=url_result,
        file_result=file_result,
        email_result=email_result,
        behaviour_result=behaviour_result
    )


# =============================================================
# DIRECT TEST
# =============================================================

if __name__ == "__main__":

    print("\n" + "=" * 70)
    print("CYBERNEXUS Ω - INTELLIGENCE AGENT TEST")
    print("=" * 70)

    agent = IntelligenceAgent()

    # ---------------------------------------------------------
    # SAMPLE URL RESULT
    # ---------------------------------------------------------

    url_result = {
        "url": (
            "http://192.168.1.20/"
            "login/verify/password"
        ),
        "risk_score": 55,
        "risk_level": "HIGH",
        "findings": [
            "URL uses an IP address",
            "Suspicious keywords: login, verify, password"
        ]
    }

    # ---------------------------------------------------------
    # SAMPLE FILE RESULT
    # ---------------------------------------------------------

    file_result = {
        "file_name": "suspicious_test.txt",
        "sha256": (
            "eaf3695cb93a4b4da830cbc0a1d52f118eee11d0c43a972a951489dc257b1646"
        ),
        "risk_score": 40,
        "risk_level": "MEDIUM"
    }

    # ---------------------------------------------------------
    # SAMPLE EMAIL RESULT
    # ---------------------------------------------------------

    email_result = {
        "sender": "security@example.com",
        "urls": [
            "https://bit.ly/example"
        ],
        "risk_score": 64,
        "risk_level": "HIGH"
    }

    # ---------------------------------------------------------
    # SAMPLE BEHAVIOUR RESULT
    # ---------------------------------------------------------

    behaviour_result = {
        "behaviour": {
            "risk_score": 100,
            "risk_level": "CRITICAL",
            "classification": "MALICIOUS BEHAVIOUR",
            "priority": "IMMEDIATE",
            "profile": "INTRUSION"
        }
    }

    # ---------------------------------------------------------
    # RUN ANALYSIS
    # ---------------------------------------------------------

    print("\n[1] THREAT INTELLIGENCE ANALYSIS")
    print("-" * 70)

    result = agent.analyze(
        url_result=url_result,
        file_result=file_result,
        email_result=email_result,
        behaviour_result=behaviour_result
    )

    print("Agent        :", result.get("agent"))
    print("Status       :", result.get("status"))

    if result.get("success"):

        intelligence = result["intelligence"]

        print(
            "Risk Score   :",
            intelligence["risk_score"]
        )

        print(
            "Risk Level   :",
            intelligence["risk_level"]
        )

        print(
            "Classification:",
            intelligence["classification"]
        )

        print(
            "Priority     :",
            intelligence["priority"]
        )

        print(
            "Confidence   :",
            str(intelligence["confidence"]) + "%"
        )

        print(
            "Signal Count :",
            result["signal_count"]
        )

        # -----------------------------------------------------
        # IOC OUTPUT
        # -----------------------------------------------------

        print("\nIndicators of Compromise:")

        iocs = result.get("iocs", {})

        for category, values in iocs.items():

            print(
                f" - {category}:"
            )

            if values:

                for value in values:
                    print(
                        f"    • {value}"
                    )

            else:

                print(
                    "    • None"
                )

        # -----------------------------------------------------
        # SUMMARY
        # -----------------------------------------------------

        print("\nSummary:")
        print(
            " ",
            result.get("summary")
        )

        # -----------------------------------------------------
        # RECOMMENDATIONS
        # -----------------------------------------------------

        print("\nRecommendations:")

        for recommendation in result.get(
            "recommendations",
            []
        ):

            print(
                " -",
                recommendation
            )

    else:

        print(
            "Error        :",
            result.get("message")
        )

    # ---------------------------------------------------------
    # EMPTY INPUT TEST
    # ---------------------------------------------------------

    print("\n[2] EMPTY INPUT TEST")
    print("-" * 70)

    empty_result = agent.analyze()

    print(
        "Status       :",
        empty_result.get("status")
    )

    print(
        "Message      :",
        empty_result.get("message")
    )

    # ---------------------------------------------------------
    # FINAL STATUS
    # ---------------------------------------------------------

    print("\n" + "=" * 70)
    print("INTELLIGENCE AGENT TEST COMPLETED")
    print("=" * 70)