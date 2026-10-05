from datetime import datetime, timezone


class CyberRangeSimulator:
    """
    CyberNexus Ω - Cyber Range Simulator

    Defensive cyber-incident simulation engine.

    This module simulates an incident progression using
    predefined stages and defensive response actions.

    It does NOT execute real attacks, commands, exploits,
    network scans, malware, or destructive operations.
    """

    ENGINE_NAME = "CyberNexus Cyber Range Simulator"
    ENGINE_VERSION = "1.0"

    STAGES = [
        "INITIAL_ACCESS",
        "CREDENTIAL_ACCESS",
        "EXECUTION",
        "PRIVILEGE_ESCALATION",
        "DISCOVERY",
        "COMMAND_AND_CONTROL",
        "DATA_EXFILTRATION"
    ]

    STAGE_RISK = {
        "INITIAL_ACCESS": 45,
        "CREDENTIAL_ACCESS": 55,
        "EXECUTION": 60,
        "PRIVILEGE_ESCALATION": 70,
        "DISCOVERY": 65,
        "COMMAND_AND_CONTROL": 80,
        "DATA_EXFILTRATION": 90
    }

    DEFENSIVE_ACTIONS = {
        "INITIAL_ACCESS": {
            "action": "Block and investigate the suspected initial access vector.",
            "reduction": 20
        },

        "CREDENTIAL_ACCESS": {
            "action": "Protect affected credentials and review authentication activity.",
            "reduction": 20
        },

        "EXECUTION": {
            "action": "Isolate suspicious endpoint activity and preserve evidence.",
            "reduction": 20
        },

        "PRIVILEGE_ESCALATION": {
            "action": "Review privileged access and restrict unauthorized privilege changes.",
            "reduction": 25
        },

        "DISCOVERY": {
            "action": "Increase endpoint and network monitoring for abnormal discovery activity.",
            "reduction": 15
        },

        "COMMAND_AND_CONTROL": {
            "action": "Investigate suspicious communications and restrict confirmed malicious destinations.",
            "reduction": 25
        },

        "DATA_EXFILTRATION": {
            "action": "Review outbound transfers and apply data-loss prevention controls.",
            "reduction": 30
        }
    }

    def __init__(self):
        self.status = "READY"

    # =========================================================
    # TIMESTAMP
    # =========================================================

    def _timestamp(self):

        return datetime.now(
            timezone.utc
        ).isoformat()

    # =========================================================
    # RISK LEVEL
    # =========================================================

    def _risk_level(self, score):

        if score >= 70:
            return "CRITICAL"

        if score >= 45:
            return "HIGH"

        if score >= 20:
            return "MEDIUM"

        return "LOW"

    # =========================================================
    # SCENARIO CREATION
    # =========================================================

    def create_scenario(
        self,
        scenario_name="CYBERNEXUS DEMO INCIDENT"
    ):

        stages = []

        for stage in self.STAGES:

            stages.append(
                {
                    "stage": stage,
                    "status": "PENDING",
                    "risk_score": self.STAGE_RISK[
                        stage
                    ],
                    "evidence": [],
                    "defensive_action": (
                        self.DEFENSIVE_ACTIONS[
                            stage
                        ]["action"]
                    )
                }
            )

        return {
            "scenario_name": scenario_name,
            "created_at": self._timestamp(),
            "stages": stages
        }

    # =========================================================
    # SIMULATE STAGE
    # =========================================================

    def _simulate_stage(
        self,
        stage_data,
        stage_number
    ):

        stage = stage_data["stage"]

        stage_data["status"] = "SIMULATED"

        stage_data["evidence"] = [
            (
                f"Simulated {stage.lower().replace('_', ' ')} "
                f"activity observed."
            ),
            (
                f"Cyber Range event {stage_number} "
                f"recorded for defensive analysis."
            )
        ]

        return stage_data

    # =========================================================
    # CALCULATE INCIDENT RISK
    # =========================================================

    def _calculate_risk(
        self,
        stages
    ):

        if not stages:
            return 0

        scores = [
            stage["risk_score"]
            for stage in stages
            if stage["status"] == "SIMULATED"
        ]

        if not scores:
            return 0

        average = sum(scores) / len(scores)

        highest = max(scores)

        progression_bonus = 0

        if len(scores) >= 3:
            progression_bonus += 5

        if len(scores) >= 5:
            progression_bonus += 5

        if len(scores) >= 7:
            progression_bonus += 5

        score = round(
            (average * 0.5)
            + (highest * 0.5)
            + progression_bonus
        )

        return min(
            score,
            100
        )

    # =========================================================
    # DEFENSIVE RESPONSE
    # =========================================================

    def _apply_defensive_response(
        self,
        stages
    ):

        response_actions = []
        total_reduction = 0

        for stage in stages:

            if stage["status"] != "SIMULATED":
                continue

            stage_name = stage["stage"]

            control = self.DEFENSIVE_ACTIONS[
                stage_name
            ]

            old_score = stage[
                "risk_score"
            ]

            reduction = control[
                "reduction"
            ]

            new_score = max(
                old_score - reduction,
                0
            )

            stage[
                "post_response_score"
            ] = new_score

            response_actions.append(
                {
                    "stage": stage_name,
                    "action": control[
                        "action"
                    ],
                    "before": old_score,
                    "after": new_score,
                    "reduction": (
                        old_score - new_score
                    )
                }
            )

            total_reduction += (
                old_score - new_score
            )

        return {
            "actions": response_actions,
            "total_reduction": total_reduction
        }

    # =========================================================
    # POST RESPONSE RISK
    # =========================================================

    def _calculate_post_response_risk(
        self,
        stages
    ):

        scores = [
            stage.get(
                "post_response_score",
                stage["risk_score"]
            )
            for stage in stages
            if stage["status"] == "SIMULATED"
        ]

        if not scores:
            return 0

        average = sum(scores) / len(scores)

        highest = max(scores)

        score = round(
            (average * 0.5)
            + (highest * 0.5)
        )

        return min(
            score,
            100
        )

    # =========================================================
    # INCIDENT CLASSIFICATION
    # =========================================================

    def _classify_incident(
        self,
        stages
    ):

        active_stages = {
            stage["stage"]
            for stage in stages
            if stage["status"] == "SIMULATED"
        }

        if {
            "INITIAL_ACCESS",
            "CREDENTIAL_ACCESS",
            "EXECUTION"
        }.issubset(active_stages):

            if "DATA_EXFILTRATION" in active_stages:

                return "FULL_ATTACK_CHAIN_SIMULATION"

            return "MULTI_STAGE_INTRUSION"

        if (
            "INITIAL_ACCESS"
            in active_stages
        ):

            return "INITIAL_ACCESS_SIMULATION"

        return "LIMITED_INCIDENT_SIMULATION"

    # =========================================================
    # MAIN RANGE SIMULATION
    # =========================================================

    def run_range(
        self,
        scenario_name="CYBERNEXUS DEMO INCIDENT"
    ):

        scenario = self.create_scenario(
            scenario_name
        )

        stages = scenario[
            "stages"
        ]

        # -----------------------------------------------------
        # Simulate every stage
        # -----------------------------------------------------

        for index, stage in enumerate(
            stages,
            start=1
        ):

            self._simulate_stage(
                stage,
                index
            )

        # -----------------------------------------------------
        # Initial risk
        # -----------------------------------------------------

        initial_risk = (
            self._calculate_risk(
                stages
            )
        )

        initial_level = (
            self._risk_level(
                initial_risk
            )
        )

        # -----------------------------------------------------
        # Defensive response
        # -----------------------------------------------------

        response = (
            self._apply_defensive_response(
                stages
            )
        )

        # -----------------------------------------------------
        # Post-response risk
        # -----------------------------------------------------

        post_response_risk = (
            self._calculate_post_response_risk(
                stages
            )
        )

        post_response_level = (
            self._risk_level(
                post_response_risk
            )
        )

        risk_reduction = (
            initial_risk
            - post_response_risk
        )

        if initial_risk > 0:

            reduction_percentage = round(
                (
                    risk_reduction
                    / initial_risk
                ) * 100,
                2
            )

        else:

            reduction_percentage = 0

        classification = (
            self._classify_incident(
                stages
            )
        )

        if risk_reduction > 0:

            outcome = (
                "Defensive response reduced "
                "the simulated incident risk."
            )

        else:

            outcome = (
                "No simulated risk reduction "
                "was observed."
            )

        return {
            "success": True,
            "engine": self.ENGINE_NAME,
            "version": self.ENGINE_VERSION,
            "status": "RANGE_COMPLETED",

            "scenario": {
                "name": scenario[
                    "scenario_name"
                ],
                "created_at": scenario[
                    "created_at"
                ],
                "classification": classification
            },

            "initial_assessment": {
                "risk_score": initial_risk,
                "risk_level": initial_level,
                "active_stages": len(
                    stages
                )
            },

            "attack_progression": stages,

            "defensive_response": {
                "actions": response[
                    "actions"
                ],
                "total_reduction": response[
                    "total_reduction"
                ]
            },

            "final_assessment": {
                "risk_score": post_response_risk,
                "risk_level": post_response_level,
                "risk_reduction": risk_reduction,
                "reduction_percentage": (
                    reduction_percentage
                ),
                "outcome": outcome
            }
        }


def run_cyber_range(
    scenario_name="CYBERNEXUS DEMO INCIDENT"
):

    simulator = CyberRangeSimulator()

    return simulator.run_range(
        scenario_name
    )


# =============================================================
# DIRECT TEST
# =============================================================

if __name__ == "__main__":

    print("\n" + "=" * 70)
    print("CYBERNEXUS Ω - CYBER RANGE SIMULATOR TEST")
    print("=" * 70)

    simulator = CyberRangeSimulator()

    # ---------------------------------------------------------
    # RUN RANGE
    # ---------------------------------------------------------

    print("\n[1] CYBER RANGE SCENARIO")
    print("-" * 70)

    result = simulator.run_range(
        "CYBERNEXUS HACKATHON DEMO"
    )

    print(
        "Engine       :",
        result["engine"]
    )

    print(
        "Status       :",
        result["status"]
    )

    print(
        "Scenario     :",
        result["scenario"]["name"]
    )

    print(
        "Classification:",
        result["scenario"]["classification"]
    )

    # ---------------------------------------------------------
    # INITIAL ASSESSMENT
    # ---------------------------------------------------------

    print("\n[2] INITIAL ASSESSMENT")
    print("-" * 70)

    initial = result[
        "initial_assessment"
    ]

    print(
        "Risk Score   :",
        initial["risk_score"]
    )

    print(
        "Risk Level   :",
        initial["risk_level"]
    )

    print(
        "Active Stages:",
        initial["active_stages"]
    )

    # ---------------------------------------------------------
    # ATTACK PROGRESSION
    # ---------------------------------------------------------

    print("\n[3] ATTACK PROGRESSION")
    print("-" * 70)

    for index, stage in enumerate(
        result["attack_progression"],
        start=1
    ):

        print(
            f"{index}. "
            f"{stage['stage']:<25} "
            f"{stage['status']:<10} "
            f"Risk: {stage['risk_score']}"
        )

        for evidence in stage[
            "evidence"
        ]:

            print(
                "   -",
                evidence
            )

    # ---------------------------------------------------------
    # DEFENSIVE RESPONSE
    # ---------------------------------------------------------

    print("\n[4] DEFENSIVE RESPONSE")
    print("-" * 70)

    for action in result[
        "defensive_response"
    ]["actions"]:

        print(
            "Stage        :",
            action["stage"]
        )

        print(
            "Action       :",
            action["action"]
        )

        print(
            "Risk         :",
            action["before"],
            "->",
            action["after"]
        )

        print(
            "Reduction    :",
            action["reduction"]
        )

        print()

    print(
        "Total Reduction:",
        result[
            "defensive_response"
        ]["total_reduction"]
    )

    # ---------------------------------------------------------
    # FINAL ASSESSMENT
    # ---------------------------------------------------------

    print("\n[5] FINAL ASSESSMENT")
    print("-" * 70)

    final = result[
        "final_assessment"
    ]

    print(
        "Final Risk   :",
        final["risk_score"]
    )

    print(
        "Final Level  :",
        final["risk_level"]
    )

    print(
        "Risk Reduction:",
        final["risk_reduction"]
    )

    print(
        "Reduction %  :",
        final["reduction_percentage"],
        "%"
    )

    print(
        "Outcome      :",
        final["outcome"]
    )

    # ---------------------------------------------------------
    # FINAL
    # ---------------------------------------------------------

    print("\n" + "=" * 70)
    print("CYBER RANGE SIMULATOR TEST COMPLETED")
    print("=" * 70)