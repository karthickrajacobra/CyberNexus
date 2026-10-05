from datetime import datetime, timezone


class AttackDNA:
    """
    CyberNexus Ω - Attack DNA Engine

    Converts multiple security signals into a defensive
    attack-pattern profile.

    This module does NOT execute attacks.
    It only analyzes security evidence and classifies
    possible attack stages.
    """

    ENGINE_NAME = "CyberNexus Attack DNA Engine"
    ENGINE_VERSION = "1.0"

    def __init__(self):
        self.status = "READY"

    # =========================================================
    # UTILITY
    # =========================================================

    def _timestamp(self):
        return datetime.now(timezone.utc).isoformat()

    def _normalize_text(self, value):
        if value is None:
            return ""

        if isinstance(value, list):
            return " ".join(
                str(item) for item in value
            ).lower()

        return str(value).lower()

    # =========================================================
    # ATTACK STAGE DEFINITIONS
    # =========================================================

    def _empty_stages(self):

        return {
            "RECONNAISSANCE": [],
            "INITIAL_ACCESS": [],
            "CREDENTIAL_ACCESS": [],
            "EXECUTION": [],
            "PRIVILEGE_ESCALATION": [],
            "PERSISTENCE": [],
            "COMMAND_AND_CONTROL": [],
            "DISCOVERY": [],
            "LATERAL_MOVEMENT": [],
            "DATA_EXFILTRATION": [],
            "IMPACT": []
        }

    # =========================================================
    # URL ANALYSIS
    # =========================================================

    def _analyze_url(
        self,
        url_result,
        stages
    ):

        if not url_result:
            return

        score = url_result.get(
            "risk_score",
            0
        )

        findings = self._normalize_text(
            url_result.get(
                "findings",
                []
            )
        )

        url = self._normalize_text(
            url_result.get(
                "url",
                ""
            )
        )

        if score >= 20:

            stages[
                "INITIAL_ACCESS"
            ].append(
                "Suspicious URL activity detected."
            )

        if any(
            word in url
            for word in [
                "login",
                "signin",
                "verify",
                "account"
            ]
        ):

            stages[
                "CREDENTIAL_ACCESS"
            ].append(
                "Credential-related URL activity detected."
            )

        if (
            "ip address" in findings
            or "ip address" in url
        ):

            stages[
                "INITIAL_ACCESS"
            ].append(
                "Direct IP-based URL activity detected."
            )

        if (
            "shortener" in findings
            or "bit.ly" in url
            or "tinyurl" in url
        ):

            stages[
                "INITIAL_ACCESS"
            ].append(
                "URL redirection or shortening indicator detected."
            )

    # =========================================================
    # EMAIL ANALYSIS
    # =========================================================

    def _analyze_email(
        self,
        email_result,
        stages
    ):

        if not email_result:
            return

        score = email_result.get(
            "risk_score",
            0
        )

        findings = self._normalize_text(
            email_result.get(
                "findings",
                []
            )
        )

        if score >= 20:

            stages[
                "INITIAL_ACCESS"
            ].append(
                "Suspicious email activity may indicate an initial access vector."
            )

        if (
            "sensitive-data" in findings
            or "sensitive" in findings
            or "password" in findings
            or "otp" in findings
        ):

            stages[
                "CREDENTIAL_ACCESS"
            ].append(
                "Email contains indicators targeting sensitive credentials or data."
            )

        if (
            "url" in findings
            or email_result.get("urls")
        ):

            stages[
                "INITIAL_ACCESS"
            ].append(
                "Email contains potentially suspicious URL indicators."
            )

    # =========================================================
    # FILE ANALYSIS
    # =========================================================

    def _analyze_file(
        self,
        file_result,
        stages
    ):

        if not file_result:
            return

        score = file_result.get(
            "risk_score",
            0
        )

        extension = self._normalize_text(
            file_result.get(
                "extension",
                ""
            )
        )

        findings = self._normalize_text(
            file_result.get(
                "findings",
                []
            )
        )

        patterns = self._normalize_text(
            file_result.get(
                "suspicious_patterns",
                []
            )
        )

        if score >= 20:

            stages[
                "EXECUTION"
            ].append(
                "Suspicious file activity detected."
            )

        executable_extensions = [
            ".exe",
            ".dll",
            ".bat",
            ".cmd",
            ".ps1",
            ".vbs",
            ".js",
            ".jar",
            ".msi",
            ".scr"
        ]

        if extension in executable_extensions:

            stages[
                "EXECUTION"
            ].append(
                "Executable or script file type detected."
            )

        execution_words = [
            "powershell",
            "cmd.exe",
            "wscript",
            "cscript",
            "rundll32",
            "regsvr32",
            "mshta",
            "createprocess",
            "invoke-expression"
        ]

        combined = (
            findings
            + " "
            + patterns
        )

        for word in execution_words:

            if word in combined:

                stages[
                    "EXECUTION"
                ].append(
                    f"Execution-related indicator detected: {word}."
                )

        if (
            "base64" in combined
            or "high entropy" in combined
        ):

            stages[
                "EXECUTION"
            ].append(
                "Possible obfuscation or encoded content detected."
            )

    # =========================================================
    # BEHAVIOUR ANALYSIS
    # =========================================================

    def _analyze_behaviour(
        self,
        behaviour_result,
        stages
    ):

        if not behaviour_result:
            return

        indicators = behaviour_result.get(
            "indicators",
            []
        )

        findings = behaviour_result.get(
            "findings",
            []
        )

        combined = (
            self._normalize_text(indicators)
            + " "
            + self._normalize_text(findings)
        )

        if (
            "failed login" in combined
            or "login" in combined
        ):

            stages[
                "CREDENTIAL_ACCESS"
            ].append(
                "Abnormal authentication behaviour detected."
            )

        if (
            "privilege escalation" in combined
        ):

            stages[
                "PRIVILEGE_ESCALATION"
            ].append(
                "Privilege escalation behaviour detected."
            )

        if (
            "command execution" in combined
        ):

            stages[
                "EXECUTION"
            ].append(
                "Suspicious command execution behaviour detected."
            )

        if (
            "unknown device" in combined
        ):

            stages[
                "INITIAL_ACCESS"
            ].append(
                "Activity originated from an unknown device."
            )

        if (
            "rapid requests" in combined
        ):

            stages[
                "DISCOVERY"
            ].append(
                "High-volume request behaviour detected."
            )

        if (
            "data exfiltration" in combined
            or "data transfer" in combined
            or "unauthorized data" in combined
        ):

            stages[
                "DATA_EXFILTRATION"
            ].append(
                "Possible unauthorized data transfer detected."
            )

        if (
            "suspicious url" in combined
        ):

            stages[
                "INITIAL_ACCESS"
            ].append(
                "Suspicious URL behaviour detected."
            )

        if (
            "suspicious file" in combined
        ):

            stages[
                "EXECUTION"
            ].append(
                "Suspicious file behaviour detected."
            )

        if (
            "suspicious email" in combined
        ):

            stages[
                "INITIAL_ACCESS"
            ].append(
                "Suspicious email behaviour detected."
            )

    # =========================================================
    # INTELLIGENCE ANALYSIS
    # =========================================================

    def _analyze_intelligence(
        self,
        intelligence_result,
        stages
    ):

        if not intelligence_result:
            return

        classification = self._normalize_text(
            intelligence_result.get(
                "classification",
                ""
            )
        )

        iocs = intelligence_result.get(
            "iocs",
            {}
        )

        if (
            iocs.get("urls")
            or iocs.get("domains")
            or iocs.get("ip_addresses")
        ):

            stages[
                "INITIAL_ACCESS"
            ].append(
                "Network-based indicators of compromise identified."
            )

        if iocs.get("file_hashes"):

            stages[
                "EXECUTION"
            ].append(
                "File-based indicators of compromise identified."
            )

        if (
            "critical" in classification
            or "high" in classification
        ):

            stages[
                "COMMAND_AND_CONTROL"
            ].append(
                "Threat intelligence indicates elevated malicious activity."
            )

    # =========================================================
    # STAGE SCORING
    # =========================================================

    def _calculate_stage_scores(
        self,
        stages
    ):

        stage_scores = {}

        for stage, indicators in stages.items():

            count = len(indicators)

            if count == 0:

                score = 0

            elif count == 1:

                score = 35

            elif count == 2:

                score = 60

            elif count == 3:

                score = 80

            else:

                score = 95

            stage_scores[stage] = score

        return stage_scores

    # =========================================================
    # ATTACK DNA CLASSIFICATION
    # =========================================================

    def _classify_dna(
        self,
        stages,
        stage_scores
    ):

        active_stages = [
            stage
            for stage, indicators
            in stages.items()
            if indicators
        ]

        if not active_stages:

            return {
                "name": "NO_ATTACK_PATTERN",
                "classification": "NORMAL",
                "confidence": 0
            }

        # -----------------------------------------------------
        # PHISHING / CREDENTIAL THEFT
        # -----------------------------------------------------

        if (
            "INITIAL_ACCESS" in active_stages
            and "CREDENTIAL_ACCESS" in active_stages
        ):

            return {
                "name": "PHISHING_CREDENTIAL_ATTACK",
                "classification": "CREDENTIAL_ATTACK",
                "confidence": 92
            }

        # -----------------------------------------------------
        # MALWARE EXECUTION
        # -----------------------------------------------------

        if (
            "EXECUTION" in active_stages
            and "INITIAL_ACCESS" in active_stages
        ):

            return {
                "name": "MALWARE_EXECUTION_CHAIN",
                "classification": "MALWARE_ACTIVITY",
                "confidence": 90
            }

        # -----------------------------------------------------
        # INTRUSION
        # -----------------------------------------------------

        if (
            "INITIAL_ACCESS" in active_stages
            and "PRIVILEGE_ESCALATION" in active_stages
        ):

            return {
                "name": "INTRUSION_AND_PRIVILEGE_ESCALATION",
                "classification": "INTRUSION",
                "confidence": 94
            }

        # -----------------------------------------------------
        # DATA EXFILTRATION
        # -----------------------------------------------------

        if (
            "DATA_EXFILTRATION" in active_stages
        ):

            return {
                "name": "DATA_EXFILTRATION_PATTERN",
                "classification": "DATA_EXFILTRATION",
                "confidence": 91
            }

        # -----------------------------------------------------
        # COMMAND AND CONTROL
        # -----------------------------------------------------

        if (
            "COMMAND_AND_CONTROL" in active_stages
        ):

            return {
                "name": "COMMAND_AND_CONTROL_ACTIVITY",
                "classification": "C2_ACTIVITY",
                "confidence": 85
            }

        # -----------------------------------------------------
        # EXECUTION ONLY
        # -----------------------------------------------------

        if (
            "EXECUTION" in active_stages
        ):

            return {
                "name": "SUSPICIOUS_EXECUTION",
                "classification": "EXECUTION_ACTIVITY",
                "confidence": 78
            }

        # -----------------------------------------------------
        # INITIAL ACCESS ONLY
        # -----------------------------------------------------

        if (
            "INITIAL_ACCESS" in active_stages
        ):

            return {
                "name": "INITIAL_ACCESS_ACTIVITY",
                "classification": "INITIAL_ACCESS",
                "confidence": 75
            }

        return {
            "name": "MULTI_SIGNAL_SUSPICIOUS_ACTIVITY",
            "classification": "SUSPICIOUS_ACTIVITY",
            "confidence": 70
        }

    # =========================================================
    # MAIN ANALYSIS
    # =========================================================

    def analyze(
        self,
        url_result=None,
        email_result=None,
        file_result=None,
        behaviour_result=None,
        intelligence_result=None
    ):

        if not any([
            url_result,
            email_result,
            file_result,
            behaviour_result,
            intelligence_result
        ]):

            return {
                "success": False,
                "engine": self.ENGINE_NAME,
                "status": "NO_DATA",
                "message": (
                    "At least one security result "
                    "is required."
                ),
                "timestamp": self._timestamp()
            }

        stages = self._empty_stages()

        # -----------------------------------------------------
        # ANALYZE ALL SECURITY SIGNALS
        # -----------------------------------------------------

        self._analyze_url(
            url_result,
            stages
        )

        self._analyze_email(
            email_result,
            stages
        )

        self._analyze_file(
            file_result,
            stages
        )

        self._analyze_behaviour(
            behaviour_result,
            stages
        )

        self._analyze_intelligence(
            intelligence_result,
            stages
        )

        # -----------------------------------------------------
        # REMOVE DUPLICATES
        # -----------------------------------------------------

        for stage in stages:

            stages[stage] = list(
                dict.fromkeys(
                    stages[stage]
                )
            )

        # -----------------------------------------------------
        # STAGE SCORES
        # -----------------------------------------------------

        stage_scores = self._calculate_stage_scores(
            stages
        )

        # -----------------------------------------------------
        # CLASSIFY ATTACK DNA
        # -----------------------------------------------------

        dna = self._classify_dna(
            stages,
            stage_scores
        )

        # -----------------------------------------------------
        # OVERALL SCORE
        # -----------------------------------------------------

        active_scores = [
            score
            for score in stage_scores.values()
            if score > 0
        ]

        if active_scores:

            overall_score = max(
                active_scores
            )

        else:

            overall_score = 0

        # Multiple attack stages increase confidence
        active_stage_count = len(
            [
                stage
                for stage in stages.values()
                if stage
            ]
        )

        if active_stage_count >= 4:

            overall_score = min(
                overall_score + 10,
                100
            )

        elif active_stage_count >= 3:

            overall_score = min(
                overall_score + 5,
                100
            )

        # -----------------------------------------------------
        # RISK LEVEL
        # -----------------------------------------------------

        if overall_score >= 80:

            risk_level = "CRITICAL"

        elif overall_score >= 60:

            risk_level = "HIGH"

        elif overall_score >= 35:

            risk_level = "MEDIUM"

        else:

            risk_level = "LOW"

        # -----------------------------------------------------
        # ATTACK CHAIN
        # -----------------------------------------------------

        attack_chain = [
            stage
            for stage, indicators
            in stages.items()
            if indicators
        ]

        # -----------------------------------------------------
        # SUMMARY
        # -----------------------------------------------------

        if attack_chain:

            summary = (
                f"CyberNexus identified a "
                f"{dna['name']} pattern across "
                f"{len(attack_chain)} attack stage(s)."
            )

        else:

            summary = (
                "No significant attack pattern "
                "was identified."
            )

        # -----------------------------------------------------
        # RECOMMENDATIONS
        # -----------------------------------------------------

        recommendations = []

        if "INITIAL_ACCESS" in attack_chain:

            recommendations.append(
                "Investigate the suspected initial access vector."
            )

        if "CREDENTIAL_ACCESS" in attack_chain:

            recommendations.append(
                "Review authentication activity and "
                "potential credential exposure."
            )

        if "EXECUTION" in attack_chain:

            recommendations.append(
                "Investigate suspicious files and "
                "execution-related activity."
            )

        if "PRIVILEGE_ESCALATION" in attack_chain:

            recommendations.append(
                "Review privileged account activity "
                "and authorization changes."
            )

        if "DATA_EXFILTRATION" in attack_chain:

            recommendations.append(
                "Investigate outbound data transfers "
                "and affected destinations."
            )

        if "COMMAND_AND_CONTROL" in attack_chain:

            recommendations.append(
                "Investigate network communication "
                "associated with identified indicators."
            )

        if not recommendations:

            recommendations.append(
                "Continue routine security monitoring."
            )

        return {
            "success": True,
            "engine": self.ENGINE_NAME,
            "version": self.ENGINE_VERSION,
            "status": "ANALYZED",
            "timestamp": self._timestamp(),

            "attack_dna": {
                "name": dna["name"],
                "classification": dna["classification"],
                "confidence": dna["confidence"],
                "risk_score": overall_score,
                "risk_level": risk_level
            },

            "attack_chain": attack_chain,

            "stage_scores": stage_scores,

            "stages": stages,

            "active_stage_count": active_stage_count,

            "summary": summary,

            "recommendations": recommendations
        }


def analyze_attack_dna(
    url_result=None,
    email_result=None,
    file_result=None,
    behaviour_result=None,
    intelligence_result=None
):

    engine = AttackDNA()

    return engine.analyze(
        url_result=url_result,
        email_result=email_result,
        file_result=file_result,
        behaviour_result=behaviour_result,
        intelligence_result=intelligence_result
    )


# =============================================================
# DIRECT TEST
# =============================================================

if __name__ == "__main__":

    print("\n" + "=" * 70)
    print("CYBERNEXUS Ω - ATTACK DNA ENGINE TEST")
    print("=" * 70)

    # ---------------------------------------------------------
    # URL RESULT
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

    # ---------------------------------------------------------
    # EMAIL RESULT
    # ---------------------------------------------------------

    email_result = {
        "sender": "security@example.com",
        "risk_score": 64,
        "risk_level": "HIGH",
        "urls": [
            "https://bit.ly/example"
        ],
        "findings": [
            "Urgency indicators: urgent, immediately, verify",
            "Sensitive-data indicators detected",
            "1 URL(s) detected",
            "URL shortener detected: bit.ly"
        ]
    }

    # ---------------------------------------------------------
    # FILE RESULT
    # ---------------------------------------------------------

    file_result = {
        "file_name": "suspicious_test.txt",
        "extension": ".txt",
        "risk_score": 40,
        "risk_level": "MEDIUM",
        "findings": [
            "Suspicious execution-related patterns detected"
        ],
        "suspicious_patterns": [
            "powershell",
            "downloadstring",
            "invoke-expression",
            "createprocess"
        ]
    }

    # ---------------------------------------------------------
    # BEHAVIOUR RESULT
    # ---------------------------------------------------------

    behaviour_result = {
        "risk_score": 100,
        "risk_level": "CRITICAL",
        "classification": "MALICIOUS BEHAVIOUR",
        "profile": "INTRUSION",

        "indicators": [
            "Excessive failed login attempts",
            "Unusual login behaviour",
            "Privilege escalation",
            "Suspicious URL activity",
            "Suspicious file activity",
            "Suspicious email activity",
            "High-volume rapid requests",
            "Unknown device",
            "Possible data exfiltration",
            "Suspicious command execution"
        ],

        "findings": [
            "12 failed login attempts detected.",
            "Privilege escalation behaviour detected.",
            "120 rapid requests detected.",
            "Possible unauthorized data transfer detected.",
            "Suspicious command execution behaviour detected."
        ]
    }

    # ---------------------------------------------------------
    # INTELLIGENCE RESULT
    # ---------------------------------------------------------

    intelligence_result = {
        "risk_score": 86,
        "risk_level": "CRITICAL",
        "classification": (
            "CRITICAL THREAT INTELLIGENCE"
        ),

        "iocs": {
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
    }

    # ---------------------------------------------------------
    # RUN ENGINE
    # ---------------------------------------------------------

    engine = AttackDNA()

    result = engine.analyze(
        url_result=url_result,
        email_result=email_result,
        file_result=file_result,
        behaviour_result=behaviour_result,
        intelligence_result=intelligence_result
    )

    # ---------------------------------------------------------
    # DISPLAY RESULT
    # ---------------------------------------------------------

    print("\n[1] ATTACK DNA ANALYSIS")
    print("-" * 70)

    print(
        "Engine       :",
        result.get("engine")
    )

    print(
        "Status       :",
        result.get("status")
    )

    dna = result.get(
        "attack_dna",
        {}
    )

    print(
        "DNA Pattern  :",
        dna.get("name")
    )

    print(
        "Classification:",
        dna.get("classification")
    )

    print(
        "Confidence   :",
        f"{dna.get('confidence', 0)}%"
    )

    print(
        "Risk Score   :",
        dna.get("risk_score")
    )

    print(
        "Risk Level   :",
        dna.get("risk_level")
    )

    print(
        "Active Stages:",
        result.get("active_stage_count")
    )

    # ---------------------------------------------------------
    # ATTACK CHAIN
    # ---------------------------------------------------------

    print("\n[2] ATTACK CHAIN")
    print("-" * 70)

    for index, stage in enumerate(
        result.get("attack_chain", []),
        start=1
    ):

        print(
            f" {index}. {stage}"
        )

    # ---------------------------------------------------------
    # STAGE SCORES
    # ---------------------------------------------------------

    print("\n[3] STAGE SCORES")
    print("-" * 70)

    for stage, score in result.get(
        "stage_scores",
        {}
    ).items():

        if score > 0:

            print(
                f" {stage:<25} : {score}"
            )

    # ---------------------------------------------------------
    # STAGE INDICATORS
    # ---------------------------------------------------------

    print("\n[4] ATTACK INDICATORS")
    print("-" * 70)

    for stage, indicators in result.get(
        "stages",
        {}
    ).items():

        if indicators:

            print(f"\n{stage}:")

            for indicator in indicators:

                print(
                    " -",
                    indicator
                )

    # ---------------------------------------------------------
    # SUMMARY
    # ---------------------------------------------------------

    print("\n[5] SUMMARY")
    print("-" * 70)

    print(
        " ",
        result.get("summary")
    )

    # ---------------------------------------------------------
    # RECOMMENDATIONS
    # ---------------------------------------------------------

    print("\n[6] RECOMMENDATIONS")
    print("-" * 70)

    for recommendation in result.get(
        "recommendations",
        []
    ):

        print(
            " -",
            recommendation
        )

    # ---------------------------------------------------------
    # EMPTY INPUT TEST
    # ---------------------------------------------------------

    print("\n[7] EMPTY INPUT TEST")
    print("-" * 70)

    empty_result = engine.analyze()

    print(
        "Status       :",
        empty_result.get("status")
    )

    print(
        "Message      :",
        empty_result.get("message")
    )

    # ---------------------------------------------------------
    # FINAL
    # ---------------------------------------------------------

    print("\n" + "=" * 70)
    print("ATTACK DNA ENGINE TEST COMPLETED")
    print("=" * 70)