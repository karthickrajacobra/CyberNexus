"""
CYBERNEXUS Ω — Agent Orchestrator

Coordinates the existing CYBERNEXUS security agents.

Existing systems are preserved:
    Threat Agent
    Behaviour Agent
    Intelligence Agent
    Forensic Agent
    Graph Agent
    Response Agent
    Risk Engine
    Correlation Engine
    Incident Orchestrator

The orchestrator coordinates them without replacing
their existing logic.
"""

from datetime import datetime, timezone
from inspect import signature


# ============================================================
# EXISTING AGENTS
# ============================================================

from agents.threat_agent import ThreatAgent
from agents.behaviour_agent import BehaviourAgent
from agents.intelligence_agent import IntelligenceAgent
from agents.forensic_agent import ForensicAgent
from agents.graph_agent import GraphAgent
from agents.response_agent import ResponseAgent


# ============================================================
# EXISTING INCIDENT PIPELINE
# ============================================================

from core.incident_orchestrator import (
    run_incident_orchestration
)


class AgentOrchestrator:
    """
    Central coordinator for CYBERNEXUS Ω agents.
    """

    AGENT_NAME = "CyberNexus Agent Orchestrator"
    VERSION = "1.0.0"

    STATUS_READY = "READY"
    STATUS_RUNNING = "RUNNING"
    STATUS_COMPLETED = "COMPLETED"
    STATUS_COMPLETED_WITH_ERRORS = "COMPLETED_WITH_ERRORS"

    # ========================================================
    # INITIALIZATION
    # ========================================================

    def __init__(self):

        self.threat_agent = ThreatAgent()

        self.behaviour_agent = BehaviourAgent()

        self.intelligence_agent = IntelligenceAgent()

        self.forensic_agent = ForensicAgent()

        self.graph_agent = GraphAgent()

        self.response_agent = ResponseAgent()

    # ========================================================
    # TIMESTAMP
    # ========================================================

    @staticmethod
    def _timestamp():

        return datetime.now(
            timezone.utc
        ).isoformat()

    # ========================================================
    # SAFE METHOD INVOCATION
    # ========================================================

    @staticmethod
    def _invoke(method, values):
        """
        Call an existing agent method using only the
        parameters that method actually accepts.

        This keeps the orchestrator compatible with the
        existing agent implementations.
        """

        parameters = signature(
            method
        ).parameters

        # ----------------------------------------------------
        # If method accepts **kwargs
        # ----------------------------------------------------

        accepts_kwargs = any(
            parameter.kind.name == "VAR_KEYWORD"
            for parameter in parameters.values()
        )

        if accepts_kwargs:

            return method(
                **values
            )

        # ----------------------------------------------------
        # Build accepted arguments
        # ----------------------------------------------------

        kwargs = {}

        for name, parameter in parameters.items():

            if name not in values:
                continue

            if parameter.kind.name in (
                "POSITIONAL_ONLY",
                "VAR_POSITIONAL",
            ):
                continue

            kwargs[name] = values[name]

        return method(
            **kwargs
        )

    # ========================================================
    # BUILD BEHAVIOUR SIGNALS
    # ========================================================

    @staticmethod
    def _build_behaviour_signals(
        url_result=None,
        file_result=None,
        email_result=None,
        signals=None,
    ):
        """
        Build behaviour indicators from already observed
        detector results.

        No artificial threat indicators are created.
        """

        behaviour_signals = dict(
            signals or {}
        )

        # ----------------------------------------------------
        # URL
        # ----------------------------------------------------

        if url_result:

            url_level = str(
                url_result.get(
                    "risk_level",
                    ""
                )
            ).upper()

            behaviour_signals[
                "suspicious_url"
            ] = url_level in (
                "HIGH",
                "CRITICAL"
            )

        # ----------------------------------------------------
        # FILE
        # ----------------------------------------------------

        if file_result:

            file_level = str(
                file_result.get(
                    "risk_level",
                    ""
                )
            ).upper()

            behaviour_signals[
                "suspicious_file"
            ] = file_level in (
                "HIGH",
                "CRITICAL"
            )

        # ----------------------------------------------------
        # EMAIL
        # ----------------------------------------------------

        if email_result:

            email_level = str(
                email_result.get(
                    "risk_level",
                    ""
                )
            ).upper()

            behaviour_signals[
                "suspicious_email"
            ] = email_level in (
                "HIGH",
                "CRITICAL"
            )

        return behaviour_signals

    # ========================================================
    # MAIN ORCHESTRATION
    # ========================================================

    def run(
        self,
        url_result=None,
        file_result=None,
        email_result=None,
        signals=None,
        file_path=None,
        raw_url=None,
        raw_email=None,
        sender=None,
    ):
        """
        Execute the CYBERNEXUS Ω investigation workflow.

        Workflow:

        Input
          ↓
        Threat Agent
          ↓
        Behaviour Agent
          ↓
        Intelligence Agent
          ↓
        Existing Incident Pipeline
          ↓
        Graph Agent
          ↓
        Forensic Agent
          ↓
        Response Agent
          ↓
        Final Investigation Result
        """

        started_at = self._timestamp()

        agent_results = {}

        errors = []

        workflow = []

        # ====================================================
        # INTERNAL STAGE RECORDER
        # ====================================================

        def record_stage(
            name,
            status,
            details=None
        ):

            workflow.append({

                "stage": name,

                "status": status,

                "details": details or {},

                "timestamp": self._timestamp()
            })

        # ====================================================
        # STAGE 1 — THREAT AGENT
        # ====================================================

        try:

            threat_outputs = {}

            # ----------------------------------------------
            # Raw URL
            # ----------------------------------------------

            if raw_url:

                threat_outputs[
                    "url"
                ] = self.threat_agent.analyze(
                    "URL",
                    raw_url
                )

            # ----------------------------------------------
            # Raw Email
            # ----------------------------------------------

            if raw_email:

                threat_outputs[
                    "email"
                ] = self.threat_agent.analyze(
                    "EMAIL",
                    raw_email,
                    sender=sender
                )

            agent_results[
                "threat"
            ] = {

                "status": (
                    "COMPLETED"
                    if threat_outputs
                    else "SKIPPED"
                ),

                "results": threat_outputs,

                "message": (
                    "Raw security inputs analyzed."
                    if threat_outputs
                    else
                    "No raw URL or email supplied. "
                    "Existing detector results will be used."
                )
            }

            record_stage(
                "threat_analysis",
                agent_results[
                    "threat"
                ][
                    "status"
                ]
            )

        except Exception as exc:

            errors.append({

                "agent":
                    "ThreatAgent",

                "error":
                    str(exc)
            })

            agent_results[
                "threat"
            ] = {

                "status":
                    "FAILED",

                "error":
                    str(exc)
            }

            record_stage(
                "threat_analysis",
                "FAILED"
            )

        # ====================================================
        # STAGE 2 — BEHAVIOUR AGENT
        # ====================================================

        behaviour_result = None

        try:

            behaviour_signals = (
                self._build_behaviour_signals(

                    url_result=url_result,

                    file_result=file_result,

                    email_result=email_result,

                    signals=signals
                )
            )

            behaviour_result = (
                self.behaviour_agent.analyze(
                    behaviour_signals
                )
            )

            agent_results[
                "behaviour"
            ] = behaviour_result

            record_stage(
                "behaviour_analysis",
                "COMPLETED"
            )

        except Exception as exc:

            errors.append({

                "agent":
                    "BehaviourAgent",

                "error":
                    str(exc)
            })

            agent_results[
                "behaviour"
            ] = {

                "status":
                    "FAILED",

                "error":
                    str(exc)
            }

            record_stage(
                "behaviour_analysis",
                "FAILED"
            )

        # ====================================================
        # STAGE 3 — INTELLIGENCE AGENT
        # ====================================================

        intelligence_result = None

        try:

            intelligence_result = (
                self.intelligence_agent.analyze(

                    url_result=url_result,

                    file_result=file_result,

                    email_result=email_result,

                    behaviour_result=behaviour_result
                )
            )

            agent_results[
                "intelligence"
            ] = intelligence_result

            record_stage(
                "intelligence_analysis",
                "COMPLETED"
            )

        except Exception as exc:

            errors.append({

                "agent":
                    "IntelligenceAgent",

                "error":
                    str(exc)
            })

            agent_results[
                "intelligence"
            ] = {

                "status":
                    "FAILED",

                "error":
                    str(exc)
            }

            record_stage(
                "intelligence_analysis",
                "FAILED"
            )

        # ====================================================
        # STAGE 4 — EXISTING INCIDENT ORCHESTRATOR
        # ====================================================

        incident_result = None

        try:

            if (
                url_result
                or file_result
                or email_result
            ):

                incident_result = (
                    run_incident_orchestration(

                        url_result=url_result,

                        file_result=file_result,

                        email_result=email_result
                    )
                )

                agent_results[
                    "incident_pipeline"
                ] = incident_result

                record_stage(
                    "incident_pipeline",
                    "COMPLETED"
                )

            else:

                agent_results[
                    "incident_pipeline"
                ] = {

                    "status":
                        "SKIPPED",

                    "message":
                        "No detector results supplied."
                }

                record_stage(
                    "incident_pipeline",
                    "SKIPPED"
                )

        except Exception as exc:

            errors.append({

                "agent":
                    "IncidentOrchestrator",

                "error":
                    str(exc)
            })

            agent_results[
                "incident_pipeline"
            ] = {

                "status":
                    "FAILED",

                "error":
                    str(exc)
            }

            record_stage(
                "incident_pipeline",
                "FAILED"
            )

        # ====================================================
        # EXTRACT INCIDENT INFORMATION
        # ====================================================

        incident_id = None

        incident_data = {}

        if incident_result:

            incident_data = (
                incident_result.get(
                    "incident",
                    {}
                )
            )

            incident_id = (
                incident_data.get(
                    "incident_id"
                )
            )

        # ====================================================
        # STAGE 5 — GRAPH AGENT
        # ====================================================

        try:

            if incident_result:

                graph_result = self._invoke(

                    self.graph_agent.analyze,

                    {

                        "incident_id":
                            incident_id,

                        "url_result":
                            url_result,

                        "file_result":
                            file_result,

                        "email_result":
                            email_result
                    }
                )

                agent_results[
                    "graph"
                ] = graph_result

                record_stage(
                    "graph_analysis",
                    "COMPLETED"
                )

            else:

                agent_results[
                    "graph"
                ] = {

                    "status":
                        "SKIPPED",

                    "message":
                        "No incident graph available."
                }

                record_stage(
                    "graph_analysis",
                    "SKIPPED"
                )

        except Exception as exc:

            errors.append({

                "agent":
                    "GraphAgent",

                "error":
                    str(exc)
            })

            agent_results[
                "graph"
            ] = {

                "status":
                    "FAILED",

                "error":
                    str(exc)
            }

            record_stage(
                "graph_analysis",
                "FAILED"
            )

        # ====================================================
        # STAGE 6 — FORENSIC AGENT
        # ====================================================

        try:

            forensic_result = None

            # ----------------------------------------------
            # If actual file path exists
            # ----------------------------------------------

            if file_path:

                forensic_result = (
                    self.forensic_agent.hash_file(
                        file_path
                    )
                )

            # ----------------------------------------------
            # If incident exists
            # ----------------------------------------------

            elif incident_result:

                forensic_result = (
                    self.forensic_agent.verify_evidence()
                )

            if forensic_result is not None:

                agent_results[
                    "forensics"
                ] = forensic_result

                record_stage(
                    "forensic_analysis",
                    "COMPLETED"
                )

            else:

                agent_results[
                    "forensics"
                ] = {

                    "status":
                        "SKIPPED",

                    "message":
                        "No forensic file or evidence supplied."
                }

                record_stage(
                    "forensic_analysis",
                    "SKIPPED"
                )

        except Exception as exc:

            errors.append({

                "agent":
                    "ForensicAgent",

                "error":
                    str(exc)
            })

            agent_results[
                "forensics"
            ] = {

                "status":
                    "FAILED",

                "error":
                    str(exc)
            }

            record_stage(
                "forensic_analysis",
                "FAILED"
            )

        # ====================================================
        # STAGE 7 — RESPONSE AGENT
        # ====================================================

        try:

            # ----------------------------------------------
            # Unified risk
            # ----------------------------------------------

            unified_risk = {}

            if incident_result:

                unified_risk = (
                    incident_result.get(
                        "unified_risk",
                        {}
                    )
                )

            # ----------------------------------------------
            # Intelligence IOC data
            # ----------------------------------------------

            intelligence_iocs = {}

            if intelligence_result:

                intelligence_iocs = (
                    intelligence_result.get(
                        "iocs",
                        {}
                    )
                )

            # ----------------------------------------------
            # Behaviour information
            # ----------------------------------------------

            behaviour_data = {}

            if behaviour_result:

                behaviour_data = (
                    behaviour_result.get(
                        "behaviour",
                        {}
                    )
                )

            risk_level = (
                unified_risk.get(
                    "overall_level",
                    "LOW"
                )
            )

            risk_score = (
                unified_risk.get(
                    "overall_score",
                    0
                )
            )

            behaviour_profile = (
                behaviour_data.get(
                    "profile",
                    "NORMAL"
                )
            )

            # ----------------------------------------------
            # Response Agent
            # ----------------------------------------------

            response_result = self._invoke(

                self.response_agent.analyze,

                {

                    # Required incident identifier
                    "incident_id":
                        incident_id,

                    # Risk
                    "risk_level":
                        risk_level,

                    "overall_level":
                        risk_level,

                    "risk_score":
                        risk_score,

                    # Intelligence
                    "iocs":
                        intelligence_iocs,

                    "intelligence_result":
                        intelligence_result,

                    # Behaviour
                    "behaviour_profile":
                        behaviour_profile,

                    "behaviour_result":
                        behaviour_result,

                    # Incident
                    "incident_result":
                        incident_result
                }
            )

            agent_results[
                "response"
            ] = response_result

            record_stage(
                "response_recommendations",
                "COMPLETED"
            )

        except Exception as exc:

            errors.append({

                "agent":
                    "ResponseAgent",

                "error":
                    str(exc)
            })

            agent_results[
                "response"
            ] = {

                "status":
                    "FAILED",

                "error":
                    str(exc)
            }

            record_stage(
                "response_recommendations",
                "FAILED"
            )

        # ====================================================
        # FINAL WORKFLOW STATISTICS
        # ====================================================

        completed_count = sum(

            1

            for stage in workflow

            if stage[
                "status"
            ] == "COMPLETED"
        )

        failed_count = sum(

            1

            for stage in workflow

            if stage[
                "status"
            ] == "FAILED"
        )

        skipped_count = sum(

            1

            for stage in workflow

            if stage[
                "status"
            ] == "SKIPPED"
        )

        # ====================================================
        # FINAL STATUS
        # ====================================================

        if failed_count == 0:

            final_status = (
                self.STATUS_COMPLETED
            )

        else:

            final_status = (
                self.STATUS_COMPLETED_WITH_ERRORS
            )

        # ====================================================
        # FINAL RESULT
        # ====================================================

        return {

            "success":
                failed_count == 0,

            "orchestrator":
                self.AGENT_NAME,

            "version":
                self.VERSION,

            "status":
                final_status,

            "started_at":
                started_at,

            "completed_at":
                self._timestamp(),

            "summary": {

                "stages":
                    len(workflow),

                "completed":
                    completed_count,

                "failed":
                    failed_count,

                "skipped":
                    skipped_count,

                "errors":
                    len(errors)
            },

            "incident": (
                incident_data
                if incident_result
                else None
            ),

            "agent_results":
                agent_results,

            "workflow":
                workflow,

            "errors":
                errors
        }


# ============================================================
# CONVENIENCE FUNCTION
# ============================================================

def run_agent_orchestration(**kwargs):
    """
    Convenience function for Flask routes,
    tests and future automation services.
    """

    orchestrator = AgentOrchestrator()

    return orchestrator.run(
        **kwargs
    )


# ============================================================
# DIRECT TEST
# ============================================================

if __name__ == "__main__":

    print(
        "=" * 60
    )

    print(
        "CYBERNEXUS Ω — AGENT ORCHESTRATOR TEST"
    )

    print(
        "=" * 60
    )

    result = run_agent_orchestration()

    print(
        "\nSTATUS:",
        result["status"]
    )

    print(
        "\nSUMMARY:"
    )

    print(
        result["summary"]
    )

    print(
        "\nERRORS:"
    )

    print(
        result["errors"]
    )

    print(
        "\nWORKFLOW:"
    )

    for stage in result["workflow"]:

        print(
            f"  {stage['stage']}: "
            f"{stage['status']}"
        )

    print(
        "\n" + "=" * 60
    )