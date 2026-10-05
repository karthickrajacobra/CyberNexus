from datetime import datetime, timezone


class ResponseAgent:
    """
    CyberNexus Ω - Response Agent

    Responsibilities:
    - Interpret security incident severity
    - Generate defensive response actions
    - Prioritize containment
    - Generate investigation steps
    - Generate recovery and monitoring actions
    - Produce a structured incident response plan
    """

    AGENT_NAME = "CyberNexus Response Agent"
    AGENT_VERSION = "1.0"

    def __init__(self):
        self.status = "READY"

    def _timestamp(self):
        return datetime.now(timezone.utc).isoformat()

    # ---------------------------------------------------------
    # SEVERITY CLASSIFICATION
    # ---------------------------------------------------------

    def _classify(self, score):

        if score >= 80:
            return {
                "level": "CRITICAL",
                "priority": "IMMEDIATE",
                "response_time": "Immediate response"
            }

        if score >= 60:
            return {
                "level": "HIGH",
                "priority": "HIGH",
                "response_time": "Priority response"
            }

        if score >= 35:
            return {
                "level": "MEDIUM",
                "priority": "MEDIUM",
                "response_time": "Prompt investigation"
            }

        return {
            "level": "LOW",
            "priority": "LOW",
            "response_time": "Routine monitoring"
        }

    # ---------------------------------------------------------
    # CONTAINMENT ACTIONS
    # ---------------------------------------------------------

    def _containment_actions(
        self,
        threat_level,
        iocs=None,
        behaviour_profile=None
    ):
        """
        Generate defensive containment actions.
        """

        actions = []

        iocs = iocs or {}

        if threat_level in {"CRITICAL", "HIGH"}:

            actions.append(
                "Isolate affected systems from unnecessary "
                "network access."
            )

            actions.append(
                "Preserve relevant logs and security evidence "
                "before making destructive changes."
            )

        if iocs.get("urls"):

            actions.append(
                "Block or restrict confirmed malicious URLs "
                "after validation."
            )

        if iocs.get("domains"):

            actions.append(
                "Review and restrict suspicious domains "
                "through appropriate security controls."
            )

        if iocs.get("ip_addresses"):

            actions.append(
                "Review network traffic involving identified "
                "IP indicators."
            )

        if iocs.get("file_hashes"):

            actions.append(
                "Quarantine matching files where appropriate "
                "and preserve copies for forensic analysis."
            )

        if iocs.get("email_addresses"):

            actions.append(
                "Review messages from identified senders and "
                "remove confirmed malicious messages."
            )

        if behaviour_profile == "INTRUSION":

            actions.append(
                "Review privileged accounts and recent "
                "authentication activity."
            )

        elif behaviour_profile == "DATA_ABUSE":

            actions.append(
                "Review outbound data transfers and restrict "
                "unauthorized destinations."
            )

        elif behaviour_profile == "ACCOUNT_ABUSE":

            actions.append(
                "Review affected account activity and apply "
                "appropriate account-protection controls."
            )

        if not actions:

            actions.append(
                "Continue normal security monitoring."
            )

        return actions

    # ---------------------------------------------------------
    # INVESTIGATION ACTIONS
    # ---------------------------------------------------------

    def _investigation_actions(
        self,
        iocs=None,
        behaviour_profile=None
    ):
        """
        Generate investigation steps.
        """

        actions = []

        iocs = iocs or {}

        actions.append(
            "Review the complete incident timeline."
        )

        actions.append(
            "Correlate endpoint, authentication, network, "
            "and application logs."
        )

        if iocs.get("urls"):
            actions.append(
                "Investigate URL activity and related "
                "network requests."
            )

        if iocs.get("domains"):
            actions.append(
                "Investigate domain resolution and associated "
                "network connections."
            )

        if iocs.get("ip_addresses"):
            actions.append(
                "Search network telemetry for the identified "
                "IP indicators."
            )

        if iocs.get("file_hashes"):
            actions.append(
                "Search endpoints for matching file hashes."
            )

        if iocs.get("email_addresses"):
            actions.append(
                "Review email headers, sender information, "
                "and related messages."
            )

        if behaviour_profile == "INTRUSION":
            actions.append(
                "Investigate authentication and privilege "
                "escalation events."
            )

        if behaviour_profile == "DATA_ABUSE":
            actions.append(
                "Investigate outbound data-transfer events."
            )

        return actions

    # ---------------------------------------------------------
    # RECOVERY ACTIONS
    # ---------------------------------------------------------

    def _recovery_actions(
        self,
        threat_level,
        behaviour_profile=None
    ):
        """
        Generate recovery and monitoring actions.
        """

        actions = []

        if threat_level in {"CRITICAL", "HIGH"}:

            actions.append(
                "Restore affected systems only after "
                "security validation."
            )

            actions.append(
                "Reset or rotate potentially exposed "
                "credentials where appropriate."
            )

        if behaviour_profile == "INTRUSION":

            actions.append(
                "Review privileged access and strengthen "
                "access controls."
            )

        if behaviour_profile == "ACCOUNT_ABUSE":

            actions.append(
                "Review account security and authentication "
                "controls."
            )

        actions.append(
            "Increase monitoring for recurrence of the "
            "identified indicators."
        )

        actions.append(
            "Document investigation findings and preserve "
            "the final evidence trail."
        )

        return actions

    # ---------------------------------------------------------
    # MAIN ANALYSIS
    # ---------------------------------------------------------

    def analyze(
        self,
        incident_id,
        risk_score=0,
        risk_level=None,
        iocs=None,
        behaviour_profile=None,
        findings=None
    ):
        """
        Generate a complete defensive incident response plan.
        """

        if not incident_id:

            return {
                "success": False,
                "agent": self.AGENT_NAME,
                "status": "ERROR",
                "message": "Incident ID is required.",
                "timestamp": self._timestamp()
            }

        try:
            risk_score = int(risk_score)
        except (TypeError, ValueError):
            risk_score = 0

        risk_score = max(
            0,
            min(risk_score, 100)
        )

        classification = self._classify(
            risk_score
        )

        # -----------------------------------------------------
        # USE PROVIDED LEVEL OR CALCULATED LEVEL
        # -----------------------------------------------------

        if risk_level:

            normalized_level = str(
                risk_level
            ).upper().strip()

            if normalized_level in {
                "LOW",
                "MEDIUM",
                "HIGH",
                "CRITICAL"
            }:
                final_level = normalized_level
            else:
                final_level = classification["level"]

        else:

            final_level = classification["level"]

        # -----------------------------------------------------
        # GENERATE RESPONSE PHASES
        # -----------------------------------------------------

        containment = self._containment_actions(
            threat_level=final_level,
            iocs=iocs,
            behaviour_profile=behaviour_profile
        )

        investigation = self._investigation_actions(
            iocs=iocs,
            behaviour_profile=behaviour_profile
        )

        recovery = self._recovery_actions(
            threat_level=final_level,
            behaviour_profile=behaviour_profile
        )

        # -----------------------------------------------------
        # INCIDENT SUMMARY
        # -----------------------------------------------------

        summary = (
            f"Incident {incident_id} has a "
            f"{final_level} response priority "
            f"with a risk score of {risk_score}/100."
        )

        if behaviour_profile:

            summary += (
                f" Associated behaviour profile: "
                f"{behaviour_profile}."
            )

        # -----------------------------------------------------
        # RESPONSE PLAN
        # -----------------------------------------------------

        response_plan = {
            "phase_1_containment": containment,
            "phase_2_investigation": investigation,
            "phase_3_recovery": recovery
        }

        return {
            "success": True,
            "agent": self.AGENT_NAME,
            "version": self.AGENT_VERSION,
            "status": "RESPONSE_PLAN_GENERATED",
            "type": "INCIDENT_RESPONSE",
            "incident": {
                "incident_id": incident_id,
                "risk_score": risk_score,
                "risk_level": final_level,
                "priority": classification["priority"],
                "response_time": classification[
                    "response_time"
                ]
            },
            "response_plan": response_plan,
            "findings": findings or [],
            "iocs": iocs or {},
            "behaviour_profile": behaviour_profile,
            "summary": summary,
            "timestamp": self._timestamp()
        }


def run_response_agent(
    incident_id,
    risk_score=0,
    risk_level=None,
    iocs=None,
    behaviour_profile=None,
    findings=None
):
    """
    Convenience function for other CyberNexus modules.
    """

    agent = ResponseAgent()

    return agent.analyze(
        incident_id=incident_id,
        risk_score=risk_score,
        risk_level=risk_level,
        iocs=iocs,
        behaviour_profile=behaviour_profile,
        findings=findings
    )


# =============================================================
# DIRECT TEST
# =============================================================

if __name__ == "__main__":

    print("\n" + "=" * 70)
    print("CYBERNEXUS Ω - RESPONSE AGENT TEST")
    print("=" * 70)

    agent = ResponseAgent()

    # ---------------------------------------------------------
    # SAMPLE IOC DATA
    # ---------------------------------------------------------

    iocs = {
        "urls": [
            "http://192.168.1.20/login/verify/password",
            "https://bit.ly/example"
        ],
        "domains": [
            "bit.ly"
        ],
        "ip_addresses": [
            "192.168.1.20"
        ],
        "file_hashes": [
            "eaf3695cb93a4b4da830cbc0a1d52f118eee11d0c43a972a951489dc257b1646"
        ],
        "email_addresses": [
            "security@example.com"
        ]
    }

    # ---------------------------------------------------------
    # SAMPLE FINDINGS
    # ---------------------------------------------------------

    findings = [
        "Suspicious URL detected.",
        "Suspicious email activity detected.",
        "Suspicious file activity detected.",
        "Multiple security signals correlated."
    ]

    # ---------------------------------------------------------
    # RESPONSE TEST
    # ---------------------------------------------------------

    print("\n[1] INCIDENT RESPONSE TEST")
    print("-" * 70)

    result = agent.analyze(
        incident_id="CNX-RESPONSE-TEST-001",
        risk_score=86,
        risk_level="CRITICAL",
        iocs=iocs,
        behaviour_profile="INTRUSION",
        findings=findings
    )

    print("Agent        :", result.get("agent"))
    print("Status       :", result.get("status"))

    if result.get("success"):

        incident = result["incident"]

        print(
            "Incident ID  :",
            incident["incident_id"]
        )

        print(
            "Risk Score   :",
            incident["risk_score"]
        )

        print(
            "Risk Level   :",
            incident["risk_level"]
        )

        print(
            "Priority     :",
            incident["priority"]
        )

        print(
            "Response Time:",
            incident["response_time"]
        )

        print("\nSummary:")
        print(
            " ",
            result["summary"]
        )

        # -----------------------------------------------------
        # CONTAINMENT
        # -----------------------------------------------------

        print("\nPhase 1 - Containment:")

        for action in result[
            "response_plan"
        ]["phase_1_containment"]:

            print(
                " -",
                action
            )

        # -----------------------------------------------------
        # INVESTIGATION
        # -----------------------------------------------------

        print("\nPhase 2 - Investigation:")

        for action in result[
            "response_plan"
        ]["phase_2_investigation"]:

            print(
                " -",
                action
            )

        # -----------------------------------------------------
        # RECOVERY
        # -----------------------------------------------------

        print("\nPhase 3 - Recovery:")

        for action in result[
            "response_plan"
        ]["phase_3_recovery"]:

            print(
                " -",
                action
            )

    else:

        print(
            "Error        :",
            result.get("message")
        )

    # ---------------------------------------------------------
    # LOW-RISK TEST
    # ---------------------------------------------------------

    print("\n[2] LOW-RISK RESPONSE TEST")
    print("-" * 70)

    low_result = agent.analyze(
        incident_id="CNX-LOW-TEST-001",
        risk_score=10,
        risk_level="LOW"
    )

    print(
        "Status       :",
        low_result.get("status")
    )

    if low_result.get("success"):

        print(
            "Risk Level   :",
            low_result["incident"]["risk_level"]
        )

        print(
            "Priority     :",
            low_result["incident"]["priority"]
        )

    # ---------------------------------------------------------
    # EMPTY INPUT TEST
    # ---------------------------------------------------------

    print("\n[3] EMPTY INCIDENT TEST")
    print("-" * 70)

    empty_result = agent.analyze(
        incident_id=""
    )

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
    print("RESPONSE AGENT TEST COMPLETED")
    print("=" * 70)