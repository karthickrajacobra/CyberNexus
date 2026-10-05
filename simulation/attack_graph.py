from collections import OrderedDict


class AttackGraphSimulator:
    """
    CyberNexus Ω - Attack Graph Simulation Engine

    Defensive simulation engine for modeling a possible
    cyber-incident progression.

    This module does NOT execute attacks.
    It only models attack stages and defensive risk.
    """

    ENGINE_NAME = "CyberNexus Attack Graph Simulator"
    ENGINE_VERSION = "1.0"

    DEFAULT_STAGES = [
        "INITIAL_ACCESS",
        "CREDENTIAL_ACCESS",
        "EXECUTION",
        "PRIVILEGE_ESCALATION",
        "DISCOVERY",
        "COMMAND_AND_CONTROL",
        "DATA_EXFILTRATION"
    ]

    STAGE_WEIGHTS = {
        "INITIAL_ACCESS": 15,
        "CREDENTIAL_ACCESS": 15,
        "EXECUTION": 15,
        "PRIVILEGE_ESCALATION": 15,
        "DISCOVERY": 10,
        "COMMAND_AND_CONTROL": 15,
        "DATA_EXFILTRATION": 15
    }

    def __init__(self):
        self.status = "READY"

    # =========================================================
    # STAGE CREATION
    # =========================================================

    def _create_stages(self):
        stages = OrderedDict()

        for stage in self.DEFAULT_STAGES:
            stages[stage] = {
                "stage": stage,
                "active": False,
                "risk_score": 0,
                "evidence": []
            }

        return stages

    # =========================================================
    # ADD EVIDENCE
    # =========================================================

    def _activate_stage(
        self,
        stages,
        stage,
        score,
        evidence
    ):

        if stage not in stages:
            return

        stages[stage]["active"] = True

        current_score = stages[stage]["risk_score"]

        stages[stage]["risk_score"] = min(
            max(current_score, score),
            100
        )

        if evidence:
            stages[stage]["evidence"].append(
                evidence
            )

    # =========================================================
    # URL ANALYSIS
    # =========================================================

    def _analyze_url(
        self,
        stages,
        url_result
    ):

        if not url_result:
            return

        score = url_result.get(
            "risk_score",
            0
        )

        findings = url_result.get(
            "findings",
            []
        )

        if score > 0:

            self._activate_stage(
                stages,
                "INITIAL_ACCESS",
                min(score + 20, 100),
                "Suspicious URL activity detected."
            )

        url = url_result.get(
            "url",
            ""
        ).lower()

        if any(
            word in url
            for word in [
                "login",
                "signin",
                "verify",
                "password",
                "account"
            ]
        ):

            self._activate_stage(
                stages,
                "CREDENTIAL_ACCESS",
                min(score + 25, 100),
                "Credential-related URL indicators detected."
            )

        if any(
            "ip address" in str(item).lower()
            for item in findings
        ):

            self._activate_stage(
                stages,
                "INITIAL_ACCESS",
                min(score + 30, 100),
                "Direct IP-based URL activity detected."
            )

    # =========================================================
    # EMAIL ANALYSIS
    # =========================================================

    def _analyze_email(
        self,
        stages,
        email_result
    ):

        if not email_result:
            return

        score = email_result.get(
            "risk_score",
            0
        )

        findings = email_result.get(
            "findings",
            []
        )

        if score > 0:

            self._activate_stage(
                stages,
                "INITIAL_ACCESS",
                min(score + 15, 100),
                "Suspicious email activity detected."
            )

        if any(
            keyword in " ".join(
                str(item).lower()
                for item in findings
            )
            for keyword in [
                "password",
                "sensitive",
                "credential"
            ]
        ):

            self._activate_stage(
                stages,
                "CREDENTIAL_ACCESS",
                min(score + 20, 100),
                "Email contains potential credential-targeting indicators."
            )

        if email_result.get("urls"):

            self._activate_stage(
                stages,
                "INITIAL_ACCESS",
                min(score + 10, 100),
                "Email contains potentially suspicious URLs."
            )

    # =========================================================
    # FILE ANALYSIS
    # =========================================================

    def _analyze_file(
        self,
        stages,
        file_result
    ):

        if not file_result:
            return

        score = file_result.get(
            "risk_score",
            0
        )

        findings = file_result.get(
            "findings",
            []
        )

        if score > 0:

            self._activate_stage(
                stages,
                "EXECUTION",
                min(score + 25, 100),
                "Suspicious file activity detected."
            )

        suspicious_patterns = (
            file_result.get(
                "suspicious_patterns",
                []
            )
        )

        if suspicious_patterns:

            self._activate_stage(
                stages,
                "EXECUTION",
                min(score + 30, 100),
                "Execution-related patterns detected."
            )

        if any(
            keyword in " ".join(
                str(item).lower()
                for item in findings
            )
            for keyword in [
                "powershell",
                "cmd",
                "wscript",
                "cscript",
                "rundll32",
                "mshta",
                "createprocess"
            ]
        ):

            self._activate_stage(
                stages,
                "EXECUTION",
                min(score + 35, 100),
                "Command or script execution indicators detected."
            )

    # =========================================================
    # BEHAVIOUR ANALYSIS
    # =========================================================

    def _analyze_behaviour(
        self,
        stages,
        behaviour_result
    ):

        if not behaviour_result:
            return

        score = behaviour_result.get(
            "risk_score",
            0
        )

        indicators = behaviour_result.get(
            "indicators",
            []
        )

        findings = behaviour_result.get(
            "findings",
            []
        )

        combined_text = " ".join(
            str(item).lower()
            for item in (
                indicators + findings
            )
        )

        if score <= 0 and not combined_text:
            return

        # -----------------------------------------------------
        # PRIVILEGE ESCALATION
        # -----------------------------------------------------

        if (
            "privilege" in combined_text
            or "escalation" in combined_text
        ):

            self._activate_stage(
                stages,
                "PRIVILEGE_ESCALATION",
                min(score, 100),
                "Privilege escalation behaviour detected."
            )

        # -----------------------------------------------------
        # DISCOVERY
        # -----------------------------------------------------

        if (
            "request" in combined_text
            or "discovery" in combined_text
            or "high-volume" in combined_text
        ):

            self._activate_stage(
                stages,
                "DISCOVERY",
                min(score, 100),
                "Discovery or high-volume activity detected."
            )

        # -----------------------------------------------------
        # COMMAND AND CONTROL
        # -----------------------------------------------------

        if (
            "command" in combined_text
            or "rapid" in combined_text
        ):

            self._activate_stage(
                stages,
                "COMMAND_AND_CONTROL",
                min(score, 100),
                "Potential command-and-control behaviour detected."
            )

        # -----------------------------------------------------
        # DATA EXFILTRATION
        # -----------------------------------------------------

        if (
            "exfiltration" in combined_text
            or "data transfer" in combined_text
            or "unauthorized data" in combined_text
        ):

            self._activate_stage(
                stages,
                "DATA_EXFILTRATION",
                min(score, 100),
                "Potential unauthorized data transfer detected."
            )

    # =========================================================
    # INTELLIGENCE ANALYSIS
    # =========================================================

    def _analyze_intelligence(
        self,
        stages,
        intelligence_result
    ):

        if not intelligence_result:
            return

        score = intelligence_result.get(
            "risk_score",
            0
        )

        indicators = intelligence_result.get(
            "indicators",
            {}
        )

        if score <= 0 and not indicators:
            return

        if indicators.get("urls"):

            self._activate_stage(
                stages,
                "INITIAL_ACCESS",
                min(score, 100),
                "Threat intelligence contains URL indicators."
            )

        if indicators.get("domains"):

            self._activate_stage(
                stages,
                "COMMAND_AND_CONTROL",
                min(score, 100),
                "Threat intelligence contains domain indicators."
            )

        if indicators.get("ip_addresses"):

            self._activate_stage(
                stages,
                "COMMAND_AND_CONTROL",
                min(score, 100),
                "Threat intelligence contains IP indicators."
            )

        if indicators.get("file_hashes"):

            self._activate_stage(
                stages,
                "EXECUTION",
                min(score, 100),
                "Threat intelligence contains file-hash indicators."
            )

    # =========================================================
    # CALCULATE OVERALL RISK
    # =========================================================

    def _calculate_overall_risk(
        self,
        stages
    ):

        active_stages = [
            stage
            for stage, data in stages.items()
            if data["active"]
        ]

        if not active_stages:
            return 0

        weighted_total = 0
        weight_total = 0

        for stage in active_stages:

            stage_score = stages[
                stage
            ]["risk_score"]

            weight = self.STAGE_WEIGHTS.get(
                stage,
                10
            )

            weighted_total += (
                stage_score * weight
            )

            weight_total += weight

        if weight_total == 0:
            return 0

        base_score = round(
            weighted_total / weight_total
        )

        # Multiple-stage bonus
        stage_count = len(
            active_stages
        )

        if stage_count >= 3:
            base_score += 10

        if stage_count >= 5:
            base_score += 10

        if stage_count >= 7:
            base_score += 10

        return min(
            base_score,
            100
        )

    # =========================================================
    # CLASSIFICATION
    # =========================================================

    def _classify_attack(
        self,
        stages
    ):

        active = {
            stage
            for stage, data in stages.items()
            if data["active"]
        }

        if {
            "INITIAL_ACCESS",
            "CREDENTIAL_ACCESS"
        }.issubset(active):

            if "DATA_EXFILTRATION" in active:

                return "CREDENTIAL_COMPROMISE_WITH_EXFILTRATION"

            return "CREDENTIAL_ATTACK"

        if {
            "INITIAL_ACCESS",
            "EXECUTION"
        }.issubset(active):

            return "MALWARE_EXECUTION"

        if {
            "PRIVILEGE_ESCALATION",
            "DISCOVERY"
        }.issubset(active):

            return "INTRUSION_ACTIVITY"

        if {
            "COMMAND_AND_CONTROL",
            "DATA_EXFILTRATION"
        }.issubset(active):

            return "POTENTIAL_DATA_BREACH"

        if "INITIAL_ACCESS" in active:

            return "INITIAL_ACCESS_ACTIVITY"

        if active:

            return "MULTI_STAGE_SUSPICIOUS_ACTIVITY"

        return "NO_ATTACK_PATTERN"

    # =========================================================
    # RISK LEVEL
    # =========================================================

    def _risk_level(
        self,
        score
    ):

        if score >= 70:
            return "CRITICAL"

        if score >= 45:
            return "HIGH"

        if score >= 20:
            return "MEDIUM"

        return "LOW"

    # =========================================================
    # ATTACK PATH
    # =========================================================

    def _build_attack_path(
        self,
        stages
    ):

        path = []

        for stage in self.DEFAULT_STAGES:

            if stages[
                stage
            ]["active"]:

                path.append(stage)

        return path

    # =========================================================
    # RECOMMENDATIONS
    # =========================================================

    def _recommendations(
        self,
        stages
    ):

        recommendations = []

        active = {
            stage
            for stage, data in stages.items()
            if data["active"]
        }

        if "INITIAL_ACCESS" in active:

            recommendations.append(
                "Investigate and validate the suspected initial access vector."
            )

        if "CREDENTIAL_ACCESS" in active:

            recommendations.append(
                "Review authentication activity and potential credential exposure."
            )

        if "EXECUTION" in active:

            recommendations.append(
                "Investigate suspicious files and execution-related activity."
            )

        if "PRIVILEGE_ESCALATION" in active:

            recommendations.append(
                "Review privileged account activity and authorization changes."
            )

        if "DISCOVERY" in active:

            recommendations.append(
                "Review unusual discovery and high-volume activity."
            )

        if "COMMAND_AND_CONTROL" in active:

            recommendations.append(
                "Investigate suspicious network communication and destinations."
            )

        if "DATA_EXFILTRATION" in active:

            recommendations.append(
                "Investigate outbound data transfers for possible unauthorized activity."
            )

        if not recommendations:

            recommendations.append(
                "No significant attack-path indicators were identified."
            )

        return recommendations

    # =========================================================
    # MAIN SIMULATION
    # =========================================================

    def simulate(
        self,
        url_result=None,
        file_result=None,
        email_result=None,
        behaviour_result=None,
        intelligence_result=None
    ):

        all_results = [
            url_result,
            file_result,
            email_result,
            behaviour_result,
            intelligence_result
        ]

        if not any(
            result is not None
            for result in all_results
        ):

            return {
                "success": False,
                "engine": self.ENGINE_NAME,
                "status": "NO_DATA",
                "message": (
                    "At least one security result "
                    "is required for attack simulation."
                )
            }

        stages = self._create_stages()

        self._analyze_url(
            stages,
            url_result
        )

        self._analyze_email(
            stages,
            email_result
        )

        self._analyze_file(
            stages,
            file_result
        )

        self._analyze_behaviour(
            stages,
            behaviour_result
        )

        self._analyze_intelligence(
            stages,
            intelligence_result
        )

        overall_score = (
            self._calculate_overall_risk(
                stages
            )
        )

        risk_level = self._risk_level(
            overall_score
        )

        classification = (
            self._classify_attack(
                stages
            )
        )

        attack_path = (
            self._build_attack_path(
                stages
            )
        )

        active_stage_count = len(
            attack_path
        )

        recommendations = (
            self._recommendations(
                stages
            )
        )

        return {
            "success": True,
            "engine": self.ENGINE_NAME,
            "version": self.ENGINE_VERSION,
            "status": "SIMULATED",

            "simulation": {
                "attack_classification": classification,
                "risk_score": overall_score,
                "risk_level": risk_level,
                "active_stage_count": active_stage_count,
                "attack_path": attack_path
            },

            "stages": dict(
                stages
            ),

            "recommendations": recommendations
        }


def simulate_attack_graph(
    url_result=None,
    file_result=None,
    email_result=None,
    behaviour_result=None,
    intelligence_result=None
):

    simulator = AttackGraphSimulator()

    return simulator.simulate(
        url_result=url_result,
        file_result=file_result,
        email_result=email_result,
        behaviour_result=behaviour_result,
        intelligence_result=intelligence_result
    )


# =============================================================
# DIRECT TEST
# =============================================================

if __name__ == "__main__":

    print("\n" + "=" * 70)
    print("CYBERNEXUS Ω - ATTACK GRAPH SIMULATOR TEST")
    print("=" * 70)

    simulator = AttackGraphSimulator()

    # ---------------------------------------------------------
    # SAMPLE SECURITY RESULTS
    # ---------------------------------------------------------

    url_result = {
        "url": (
            "http://192.168.1.20/"
            "login/verify/password"
        ),
        "risk_score": 55,
        "risk_level": "HIGH",
        "findings": [
            "IP address used instead of domain name",
            "Suspicious keywords: login, verify, password"
        ]
    }

    email_result = {
        "risk_score": 64,
        "risk_level": "HIGH",
        "sender": "security@example.com",
        "urls": [
            "https://bit.ly/example"
        ],
        "findings": [
            "Urgency indicators detected",
            "Sensitive-data indicators detected"
        ]
    }

    file_result = {
        "file_name": "suspicious_test.txt",
        "risk_score": 40,
        "risk_level": "MEDIUM",
        "findings": [
            "Suspicious execution-related patterns detected"
        ],
        "suspicious_patterns": [
            "powershell",
            "createprocess",
            "invoke-expression"
        ]
    }

    behaviour_result = {
        "risk_score": 100,
        "risk_level": "CRITICAL",
        "indicators": [
            "Privilege escalation behaviour",
            "High-volume rapid requests",
            "Possible data exfiltration",
            "Suspicious command execution"
        ],
        "findings": [
            "Privilege escalation behaviour detected.",
            "120 rapid requests detected.",
            "Possible unauthorized data transfer detected.",
            "Suspicious command execution behaviour detected."
        ]
    }

    intelligence_result = {
        "risk_score": 86,
        "risk_level": "CRITICAL",
        "indicators": {
            "urls": [
                "http://192.168.1.20/login/verify/password"
            ],
            "domains": [
                "bit.ly"
            ],
            "ip_addresses": [
                "192.168.1.20"
            ],
            "file_hashes": [
                "eaf3695cb93a4b4da830cbc0a1d52f118eee11d0c43a972a951489dc257b1646"
            ]
        }
    }

    # ---------------------------------------------------------
    # SIMULATION
    # ---------------------------------------------------------

    print("\n[1] ATTACK GRAPH SIMULATION")
    print("-" * 70)

    result = simulator.simulate(
        url_result=url_result,
        file_result=file_result,
        email_result=email_result,
        behaviour_result=behaviour_result,
        intelligence_result=intelligence_result
    )

    print(
        "Engine       :",
        result["engine"]
    )

    print(
        "Status       :",
        result["status"]
    )

    simulation = result["simulation"]

    print(
        "Classification:",
        simulation["attack_classification"]
    )

    print(
        "Risk Score   :",
        simulation["risk_score"]
    )

    print(
        "Risk Level   :",
        simulation["risk_level"]
    )

    print(
        "Active Stages:",
        simulation["active_stage_count"]
    )

    # ---------------------------------------------------------
    # ATTACK PATH
    # ---------------------------------------------------------

    print("\n[2] SIMULATED ATTACK PATH")
    print("-" * 70)

    for index, stage in enumerate(
        simulation["attack_path"],
        start=1
    ):

        print(
            f"{index}. {stage}"
        )

    # ---------------------------------------------------------
    # STAGE ANALYSIS
    # ---------------------------------------------------------

    print("\n[3] STAGE ANALYSIS")
    print("-" * 70)

    for stage_name, stage_data in (
        result["stages"].items()
    ):

        status = (
            "ACTIVE"
            if stage_data["active"]
            else "INACTIVE"
        )

        print(
            f"{stage_name:<25} "
            f"{status:<10} "
            f"Risk: {stage_data['risk_score']}"
        )

        for evidence in stage_data[
            "evidence"
        ]:

            print(
                "  -",
                evidence
            )

    # ---------------------------------------------------------
    # RECOMMENDATIONS
    # ---------------------------------------------------------

    print("\n[4] DEFENSIVE RECOMMENDATIONS")
    print("-" * 70)

    for recommendation in (
        result["recommendations"]
    ):

        print(
            " -",
            recommendation
        )

    # ---------------------------------------------------------
    # EMPTY INPUT TEST
    # ---------------------------------------------------------

    print("\n[5] EMPTY INPUT TEST")
    print("-" * 70)

    empty_result = simulator.simulate()

    print(
        "Status       :",
        empty_result["status"]
    )

    print(
        "Message      :",
        empty_result["message"]
    )

    # ---------------------------------------------------------
    # FINAL
    # ---------------------------------------------------------

    print("\n" + "=" * 70)
    print("ATTACK GRAPH SIMULATOR TEST COMPLETED")
    print("=" * 70)