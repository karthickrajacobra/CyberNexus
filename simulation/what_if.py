class WhatIfSimulator:
    """
    CyberNexus Ω - What-If Security Simulation Engine

    Defensive simulation engine used to estimate how
    security controls could change an incident risk profile.

    This module does NOT execute attacks or security controls.
    It only performs defensive risk simulation.
    """

    ENGINE_NAME = "CyberNexus What-If Simulation Engine"
    ENGINE_VERSION = "1.0"

    CONTROL_EFFECTS = {
        "URL_BLOCKING": {
            "name": "URL Blocking",
            "affected_stages": [
                "INITIAL_ACCESS"
            ],
            "reduction": 25
        },

        "CREDENTIAL_PROTECTION": {
            "name": "Credential Protection",
            "affected_stages": [
                "CREDENTIAL_ACCESS"
            ],
            "reduction": 25
        },

        "ENDPOINT_PROTECTION": {
            "name": "Endpoint Protection",
            "affected_stages": [
                "EXECUTION"
            ],
            "reduction": 25
        },

        "PRIVILEGE_CONTROL": {
            "name": "Privilege Access Control",
            "affected_stages": [
                "PRIVILEGE_ESCALATION"
            ],
            "reduction": 30
        },

        "NETWORK_MONITORING": {
            "name": "Network Monitoring",
            "affected_stages": [
                "DISCOVERY",
                "COMMAND_AND_CONTROL"
            ],
            "reduction": 20
        },

        "DATA_LOSS_PREVENTION": {
            "name": "Data Loss Prevention",
            "affected_stages": [
                "DATA_EXFILTRATION"
            ],
            "reduction": 30
        }
    }

    def __init__(self):
        self.status = "READY"

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
    # COPY STAGE DATA
    # =========================================================

    def _copy_stages(self, stages):

        copied = {}

        for stage_name, stage_data in stages.items():

            copied[stage_name] = {
                "stage": stage_data.get(
                    "stage",
                    stage_name
                ),

                "active": stage_data.get(
                    "active",
                    False
                ),

                "risk_score": stage_data.get(
                    "risk_score",
                    0
                ),

                "evidence": list(
                    stage_data.get(
                        "evidence",
                        []
                    )
                )
            }

        return copied

    # =========================================================
    # BASELINE RISK
    # =========================================================

    def _calculate_baseline_risk(self, stages):

        active_stages = [
            data
            for data in stages.values()
            if data.get("active")
        ]

        if not active_stages:
            return 0

        scores = [
            data.get(
                "risk_score",
                0
            )
            for data in active_stages
        ]

        average_score = round(
            sum(scores) / len(scores)
        )

        highest_score = max(
            scores
        )

        stage_bonus = 0

        if len(active_stages) >= 3:
            stage_bonus += 5

        if len(active_stages) >= 5:
            stage_bonus += 5

        if len(active_stages) >= 7:
            stage_bonus += 5

        final_score = round(
            (average_score * 0.6)
            + (highest_score * 0.4)
            + stage_bonus
        )

        return min(
            final_score,
            100
        )

    # =========================================================
    # APPLY CONTROL
    # =========================================================

    def _apply_control(
        self,
        stages,
        control_id
    ):

        control = self.CONTROL_EFFECTS.get(
            control_id
        )

        if not control:
            return {
                "success": False,
                "message": (
                    "Unknown security control: "
                    + str(control_id)
                ),
                "affected_stages": [],
                "reduction": 0
            }

        affected_stages = []
        total_reduction = 0

        for stage_name in control[
            "affected_stages"
        ]:

            if stage_name not in stages:
                continue

            stage_data = stages[
                stage_name
            ]

            if not stage_data.get(
                "active"
            ):
                continue

            old_score = stage_data.get(
                "risk_score",
                0
            )

            reduction = control[
                "reduction"
            ]

            new_score = max(
                old_score - reduction,
                0
            )

            stage_data[
                "risk_score"
            ] = new_score

            affected_stages.append(
                {
                    "stage": stage_name,
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
            "success": True,
            "control_id": control_id,
            "control_name": control[
                "name"
            ],
            "affected_stages": affected_stages,
            "reduction": total_reduction
        }

    # =========================================================
    # SIMULATE
    # =========================================================

    def simulate(
        self,
        stages,
        controls=None
    ):

        if not stages:

            return {
                "success": False,
                "engine": self.ENGINE_NAME,
                "status": "NO_DATA",
                "message": (
                    "Attack graph stage data is required."
                )
            }

        if controls is None:

            controls = []

        if isinstance(
            controls,
            str
        ):

            controls = [
                controls
            ]

        baseline_stages = (
            self._copy_stages(
                stages
            )
        )

        baseline_score = (
            self._calculate_baseline_risk(
                baseline_stages
            )
        )

        baseline_level = (
            self._risk_level(
                baseline_score
            )
        )

        simulated_stages = (
            self._copy_stages(
                stages
            )
        )

        applied_controls = []
        invalid_controls = []

        for control_id in controls:

            result = self._apply_control(
                simulated_stages,
                control_id
            )

            if result["success"]:

                applied_controls.append(
                    result
                )

            else:

                invalid_controls.append(
                    {
                        "control_id": control_id,
                        "message": result[
                            "message"
                        ]
                    }
                )

        simulated_score = (
            self._calculate_baseline_risk(
                simulated_stages
            )
        )

        simulated_level = (
            self._risk_level(
                simulated_score
            )
        )

        risk_reduction = (
            baseline_score
            - simulated_score
        )

        if baseline_score > 0:

            reduction_percentage = round(
                (
                    risk_reduction
                    / baseline_score
                ) * 100,
                2
            )

        else:

            reduction_percentage = 0

        if risk_reduction > 0:

            outcome = (
                "Security controls reduced "
                "the simulated risk."
            )

        elif controls:

            outcome = (
                "The selected controls did not "
                "reduce the calculated simulated risk."
            )

        else:

            outcome = (
                "No security controls were applied."
            )

        return {
            "success": True,
            "engine": self.ENGINE_NAME,
            "version": self.ENGINE_VERSION,
            "status": "SIMULATED",

            "baseline": {
                "risk_score": baseline_score,
                "risk_level": baseline_level,
                "stages": baseline_stages
            },

            "simulation": {
                "risk_score": simulated_score,
                "risk_level": simulated_level,
                "stages": simulated_stages
            },

            "comparison": {
                "risk_reduction": risk_reduction,
                "reduction_percentage": (
                    reduction_percentage
                ),
                "baseline_level": baseline_level,
                "simulated_level": simulated_level,
                "outcome": outcome
            },

            "controls": {
                "requested": controls,
                "applied": applied_controls,
                "invalid": invalid_controls
            }
        }

    # =========================================================
    # AVAILABLE CONTROLS
    # =========================================================

    def get_available_controls(self):

        controls = []

        for control_id, data in (
            self.CONTROL_EFFECTS.items()
        ):

            controls.append(
                {
                    "control_id": control_id,
                    "name": data["name"],
                    "affected_stages": data[
                        "affected_stages"
                    ],
                    "reduction": data[
                        "reduction"
                    ]
                }
            )

        return controls


def simulate_what_if(
    stages,
    controls=None
):

    simulator = WhatIfSimulator()

    return simulator.simulate(
        stages,
        controls
    )


# =============================================================
# DIRECT TEST
# =============================================================

if __name__ == "__main__":

    print("\n" + "=" * 70)
    print("CYBERNEXUS Ω - WHAT-IF SIMULATION TEST")
    print("=" * 70)

    simulator = WhatIfSimulator()

    # ---------------------------------------------------------
    # SAMPLE ATTACK GRAPH
    # ---------------------------------------------------------

    sample_stages = {

        "INITIAL_ACCESS": {
            "stage": "INITIAL_ACCESS",
            "active": True,
            "risk_score": 86,
            "evidence": [
                "Suspicious URL activity"
            ]
        },

        "CREDENTIAL_ACCESS": {
            "stage": "CREDENTIAL_ACCESS",
            "active": True,
            "risk_score": 84,
            "evidence": [
                "Credential-related activity"
            ]
        },

        "EXECUTION": {
            "stage": "EXECUTION",
            "active": True,
            "risk_score": 86,
            "evidence": [
                "Suspicious file execution"
            ]
        },

        "PRIVILEGE_ESCALATION": {
            "stage": "PRIVILEGE_ESCALATION",
            "active": True,
            "risk_score": 100,
            "evidence": [
                "Privilege escalation"
            ]
        },

        "DISCOVERY": {
            "stage": "DISCOVERY",
            "active": True,
            "risk_score": 100,
            "evidence": [
                "High-volume discovery activity"
            ]
        },

        "COMMAND_AND_CONTROL": {
            "stage": "COMMAND_AND_CONTROL",
            "active": True,
            "risk_score": 100,
            "evidence": [
                "Suspicious network communication"
            ]
        },

        "DATA_EXFILTRATION": {
            "stage": "DATA_EXFILTRATION",
            "active": True,
            "risk_score": 100,
            "evidence": [
                "Potential unauthorized data transfer"
            ]
        }
    }

    # ---------------------------------------------------------
    # BASELINE
    # ---------------------------------------------------------

    print("\n[1] BASELINE INCIDENT")
    print("-" * 70)

    baseline_test = simulator.simulate(
        sample_stages,
        []
    )

    print(
        "Risk Score   :",
        baseline_test["baseline"][
            "risk_score"
        ]
    )

    print(
        "Risk Level   :",
        baseline_test["baseline"][
            "risk_level"
        ]
    )

    # ---------------------------------------------------------
    # WHAT-IF CONTROL SIMULATION
    # ---------------------------------------------------------

    print("\n[2] WHAT-IF CONTROL SIMULATION")
    print("-" * 70)

    controls = [
        "URL_BLOCKING",
        "CREDENTIAL_PROTECTION",
        "ENDPOINT_PROTECTION",
        "PRIVILEGE_CONTROL",
        "NETWORK_MONITORING",
        "DATA_LOSS_PREVENTION"
    ]

    result = simulator.simulate(
        sample_stages,
        controls
    )

    print(
        "Status       :",
        result["status"]
    )

    print(
        "Baseline Risk:",
        result["baseline"][
            "risk_score"
        ]
    )

    print(
        "Baseline Level:",
        result["baseline"][
            "risk_level"
        ]
    )

    print(
        "Simulated Risk:",
        result["simulation"][
            "risk_score"
        ]
    )

    print(
        "Simulated Level:",
        result["simulation"][
            "risk_level"
        ]
    )

    print(
        "Risk Reduction:",
        result["comparison"][
            "risk_reduction"
        ]
    )

    print(
        "Reduction %   :",
        result["comparison"][
            "reduction_percentage"
        ],
        "%"
    )

    print(
        "Outcome       :",
        result["comparison"][
            "outcome"
        ]
    )

    # ---------------------------------------------------------
    # CONTROL RESULTS
    # ---------------------------------------------------------

    print("\n[3] APPLIED CONTROLS")
    print("-" * 70)

    for control in result[
        "controls"
    ]["applied"]:

        print(
            "Control       :",
            control["control_name"]
        )

        print(
            "Reduction     :",
            control["reduction"]
        )

        for stage in control[
            "affected_stages"
        ]:

            print(
                "  -",
                stage["stage"],
                ":",
                stage["before"],
                "->",
                stage["after"]
            )

    # ---------------------------------------------------------
    # AVAILABLE CONTROLS
    # ---------------------------------------------------------

    print("\n[4] AVAILABLE SECURITY CONTROLS")
    print("-" * 70)

    for control in (
        simulator.get_available_controls()
    ):

        print(
            " -",
            control["control_id"],
            "=>",
            control["name"]
        )

    # ---------------------------------------------------------
    # INVALID CONTROL TEST
    # ---------------------------------------------------------

    print("\n[5] INVALID CONTROL TEST")
    print("-" * 70)

    invalid_result = simulator.simulate(
        sample_stages,
        [
            "UNKNOWN_CONTROL"
        ]
    )

    print(
        "Status       :",
        invalid_result["status"]
    )

    print(
        "Invalid Count:",
        len(
            invalid_result[
                "controls"
            ]["invalid"]
        )
    )

    print(
        "Message      :",
        invalid_result[
            "controls"
        ]["invalid"][0]["message"]
    )

    # ---------------------------------------------------------
    # EMPTY INPUT TEST
    # ---------------------------------------------------------

    print("\n[6] EMPTY INPUT TEST")
    print("-" * 70)

    empty_result = simulator.simulate(
        {},
        []
    )

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
    print("WHAT-IF SIMULATION TEST COMPLETED")
    print("=" * 70)