from core.risk_engine import calculate_unified_risk
from core.correlation_engine import correlate_security_signals
from graph.knowledge_graph import build_incident_graph
from forensics.evidence_ledger import add_evidence


def run_incident_orchestration(
    url_result=None,
    file_result=None,
    email_result=None
):
    """
    Complete CyberNexus incident pipeline.

    Flow:
    URL / FILE / EMAIL
            ↓
    Unified Risk Engine
            ↓
    Correlation Engine
            ↓
    Incident ID
            ↓
    Evidence Ledger
            ↓
    Knowledge Graph
    """

    # --------------------------------------------------
    # 1. UNIFIED RISK
    # --------------------------------------------------

    unified_risk = calculate_unified_risk(
        url_result=url_result,
        file_result=file_result,
        email_result=email_result
    )

    # --------------------------------------------------
    # 2. CORRELATION
    # --------------------------------------------------

    correlation = correlate_security_signals(
        url_result=url_result,
        file_result=file_result,
        email_result=email_result
    )

    incident_id = correlation.get("incident_id")

    # --------------------------------------------------
    # 3. EVIDENCE LEDGER
    # --------------------------------------------------

    evidence_records = []

    if url_result:
        evidence_records.append(
            add_evidence(
                evidence_type="URL",
                source="URL Detector",
                evidence=url_result,
                risk_score=url_result.get("risk_score", 0),
                risk_level=url_result.get("risk_level", "LOW")
            )
        )

    if file_result:
        evidence_records.append(
            add_evidence(
                evidence_type="FILE",
                source="File Detector",
                evidence=file_result,
                risk_score=file_result.get("risk_score", 0),
                risk_level=file_result.get("risk_level", "LOW")
            )
        )

    if email_result:
        evidence_records.append(
            add_evidence(
                evidence_type="EMAIL",
                source="Email Detector",
                evidence=email_result,
                risk_score=email_result.get("risk_score", 0),
                risk_level=email_result.get("risk_level", "LOW")
            )
        )

    # --------------------------------------------------
    # 4. ATTACK / KNOWLEDGE GRAPH
    # --------------------------------------------------

    graph = build_incident_graph(
        incident_id=incident_id or "CNX-UNKNOWN",
        url_result=url_result,
        file_result=file_result,
        email_result=email_result
    )

    # --------------------------------------------------
    # 5. FINAL INCIDENT OBJECT
    # --------------------------------------------------

    return {
        "success": True,

        "incident": {
            "incident_id": incident_id,
            "incident_level": correlation.get(
                "incident_level",
                "LOW"
            ),
            "correlation_score": correlation.get(
                "correlation_score",
                0
            ),
            "signal_count": correlation.get(
                "signal_count",
                0
            ),
            "high_risk_signal_count": correlation.get(
                "high_risk_signal_count",
                0
            )
        },

        "unified_risk": unified_risk,

        "correlation": correlation,

        "evidence": {
            "records_created": len(evidence_records),
            "records": evidence_records
        },

        "graph": graph
    }