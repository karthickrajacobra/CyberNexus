import os
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    KeepTogether
)


class CyberNexusReportGenerator:
    """
    CyberNexus Ω - Professional Security Report Generator

    Generates a defensive cybersecurity incident report in PDF format.

    This module only creates reports. It does not perform attacks,
    exploitation, network scanning, malware execution, or destructive
    operations.
    """

    ENGINE_NAME = "CyberNexus Security Report Generator"
    ENGINE_VERSION = "1.0"

    def __init__(self, output_directory=None):

        project_root = os.path.dirname(
            os.path.dirname(
                os.path.abspath(__file__)
            )
        )

        if output_directory is None:
            output_directory = os.path.join(
                project_root,
                "reports",
                "generated"
            )

        self.output_directory = output_directory

        os.makedirs(
            self.output_directory,
            exist_ok=True
        )

        self.styles = self._create_styles()

    # =========================================================
    # STYLES
    # =========================================================

    def _create_styles(self):

        styles = getSampleStyleSheet()

        styles.add(
            ParagraphStyle(
                name="CNXTitle",
                parent=styles["Title"],
                fontSize=24,
                leading=30,
                alignment=TA_CENTER,
                spaceAfter=12
            )
        )

        styles.add(
            ParagraphStyle(
                name="CNXSubtitle",
                parent=styles["Normal"],
                fontSize=11,
                leading=16,
                alignment=TA_CENTER,
                spaceAfter=18
            )
        )

        styles.add(
            ParagraphStyle(
                name="CNXHeading",
                parent=styles["Heading2"],
                fontSize=15,
                leading=20,
                spaceBefore=10,
                spaceAfter=8
            )
        )

        styles.add(
            ParagraphStyle(
                name="CNXSubHeading",
                parent=styles["Heading3"],
                fontSize=11,
                leading=15,
                spaceBefore=6,
                spaceAfter=5
            )
        )

        styles.add(
            ParagraphStyle(
                name="CNXBody",
                parent=styles["BodyText"],
                fontSize=9.5,
                leading=14,
                spaceAfter=6
            )
        )

        styles.add(
            ParagraphStyle(
                name="CNXSmall",
                parent=styles["BodyText"],
                fontSize=8,
                leading=11,
                spaceAfter=4
            )
        )

        styles.add(
            ParagraphStyle(
                name="CNXBullet",
                parent=styles["BodyText"],
                fontSize=9,
                leading=13,
                leftIndent=12,
                firstLineIndent=-6,
                spaceAfter=4
            )
        )

        return styles

    # =========================================================
    # HELPERS
    # =========================================================

    def _timestamp(self):

        return datetime.now(
            timezone.utc
        ).isoformat()

    def _safe_text(self, value):

        if value is None:
            return "N/A"

        return str(value)

    def _risk_level(self, score):

        try:
            score = float(score)
        except (TypeError, ValueError):
            score = 0

        if score >= 70:
            return "CRITICAL"

        if score >= 45:
            return "HIGH"

        if score >= 20:
            return "MEDIUM"

        return "LOW"

    def _get_overall_score(self, incident_data):

        if not isinstance(
            incident_data,
            dict
        ):
            return 0

        if "unified_risk" in incident_data:

            unified = incident_data[
                "unified_risk"
            ]

            if isinstance(
                unified,
                dict
            ):

                return unified.get(
                    "overall_score",
                    0
                )

        if "final_assessment" in incident_data:

            final = incident_data[
                "final_assessment"
            ]

            if isinstance(
                final,
                dict
            ):

                return final.get(
                    "risk_score",
                    0
                )

        if "risk_score" in incident_data:

            return incident_data.get(
                "risk_score",
                0
            )

        return 0

    def _get_overall_level(
        self,
        incident_data,
        score
    ):

        if isinstance(
            incident_data,
            dict
        ):

            if "unified_risk" in incident_data:

                unified = incident_data[
                    "unified_risk"
                ]

                if isinstance(
                    unified,
                    dict
                ):

                    level = unified.get(
                        "overall_level"
                    )

                    if level:
                        return level

            if "final_assessment" in incident_data:

                final = incident_data[
                    "final_assessment"
                ]

                if isinstance(
                    final,
                    dict
                ):

                    level = final.get(
                        "risk_level"
                    )

                    if level:
                        return level

            if incident_data.get(
                "risk_level"
            ):

                return incident_data[
                    "risk_level"
                ]

        return self._risk_level(
            score
        )

    def _paragraph(
        self,
        text,
        style="CNXBody"
    ):

        return Paragraph(
            self._safe_text(text),
            self.styles[style]
        )

    def _bullet_list(
        self,
        items
    ):

        elements = []

        if not items:

            elements.append(
                self._paragraph(
                    "No information available.",
                    "CNXSmall"
                )
            )

            return elements

        for item in items:

            elements.append(
                self._paragraph(
                    "• " + self._safe_text(item),
                    "CNXBullet"
                )
            )

        return elements

    # =========================================================
    # PAGE HEADER / FOOTER
    # =========================================================

    def _draw_header_footer(
        self,
        canvas,
        document
    ):

        canvas.saveState()

        width, height = A4

        canvas.setFont(
            "Helvetica",
            8
        )

        canvas.drawString(
            15 * mm,
            height - 10 * mm,
            "CYBERNEXUS Ω"
        )

        canvas.drawRightString(
            width - 15 * mm,
            height - 10 * mm,
            "CONFIDENTIAL SECURITY REPORT"
        )

        canvas.line(
            15 * mm,
            height - 12 * mm,
            width - 15 * mm,
            height - 12 * mm
        )

        canvas.line(
            15 * mm,
            12 * mm,
            width - 15 * mm,
            12 * mm
        )

        canvas.drawString(
            15 * mm,
            7 * mm,
            "CyberNexus Ω Security Intelligence Platform"
        )

        canvas.drawRightString(
            width - 15 * mm,
            7 * mm,
            f"Page {document.page}"
        )

        canvas.restoreState()

    # =========================================================
    # EXECUTIVE SUMMARY
    # =========================================================

    def _build_executive_summary(
        self,
        story,
        incident_data,
        score,
        level
    ):

        story.append(
            self._paragraph(
                "1. Executive Summary",
                "CNXHeading"
            )
        )

        incident = incident_data.get(
            "incident",
            {}
        )

        incident_id = incident.get(
            "incident_id",
            incident_data.get(
                "incident_id",
                "N/A"
            )
        )

        classification = (
            incident_data.get(
                "scenario",
                {}
            ).get(
                "classification",
                incident_data.get(
                    "classification",
                    "Security Incident"
                )
            )
        )

        summary = (
            f"CyberNexus Ω analyzed security telemetry "
            f"associated with incident "
            f"<b>{self._safe_text(incident_id)}</b>. "
            f"The consolidated assessment produced a "
            f"risk score of <b>{score}/100</b> with "
            f"a risk level of <b>{self._safe_text(level)}</b>. "
            f"The available evidence and analytical results "
            f"were correlated to support defensive investigation "
            f"and response planning."
        )

        story.append(
            self._paragraph(
                summary,
                "CNXBody"
            )
        )

        if classification:

            story.append(
                self._paragraph(
                    f"<b>Classification:</b> "
                    f"{self._safe_text(classification)}",
                    "CNXBody"
                )
            )

    # =========================================================
    # RISK ASSESSMENT
    # =========================================================

    def _build_risk_section(
        self,
        story,
        incident_data,
        score,
        level
    ):

        story.append(
            self._paragraph(
                "2. Risk Assessment",
                "CNXHeading"
            )
        )

        unified = incident_data.get(
            "unified_risk",
            {}
        )

        sources = unified.get(
            "sources",
            []
        )

        table_data = [
            [
                "Security Signal",
                "Risk Score",
                "Risk Level"
            ]
        ]

        if sources:

            for source in sources:

                table_data.append(
                    [
                        self._safe_text(
                            source.get(
                                "source",
                                "N/A"
                            )
                        ),
                        self._safe_text(
                            source.get(
                                "score",
                                0
                            )
                        ),
                        self._safe_text(
                            source.get(
                                "level",
                                "LOW"
                            )
                        )
                    ]
                )

        else:

            table_data.append(
                [
                    "Unified Assessment",
                    self._safe_text(
                        score
                    ),
                    self._safe_text(
                        level
                    )
                ]
            )

        table_data.append(
            [
                "OVERALL",
                self._safe_text(
                    score
                ),
                self._safe_text(
                    level
                )
            ]
        )

        table = Table(
            table_data,
            colWidths=[
                70 * mm,
                35 * mm,
                45 * mm
            ]
        )

        table.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, 0),
                        colors.HexColor(
                            "#1F2937"
                        )
                    ),
                    (
                        "TEXTCOLOR",
                        (0, 0),
                        (-1, 0),
                        colors.white
                    ),
                    (
                        "FONTNAME",
                        (0, 0),
                        (-1, 0),
                        "Helvetica-Bold"
                    ),
                    (
                        "FONTNAME",
                        (0, -1),
                        (-1, -1),
                        "Helvetica-Bold"
                    ),
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.5,
                        colors.grey
                    ),
                    (
                        "ALIGN",
                        (1, 1),
                        (-1, -1),
                        "CENTER"
                    ),
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "MIDDLE"
                    ),
                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        6
                    ),
                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        6
                    )
                ]
            )
        )

        story.append(
            table
        )

        story.append(
            Spacer(
                1,
                6
            )
        )

        explanation = unified.get(
            "explanation",
            []
        )

        if isinstance(
            explanation,
            list
        ):

            story.extend(
                self._bullet_list(
                    explanation
                )
            )

    # =========================================================
    # THREAT FINDINGS
    # =========================================================

    def _build_threat_section(
        self,
        story,
        incident_data
    ):

        story.append(
            self._paragraph(
                "3. Threat Findings",
                "CNXHeading"
            )
        )

        findings = []

        for key in [
            "url_result",
            "file_result",
            "email_result"
        ]:

            result = incident_data.get(
                key,
                {}
            )

            if not isinstance(
                result,
                dict
            ):
                continue

            result_findings = result.get(
                "findings",
                []
            )

            if isinstance(
                result_findings,
                list
            ):

                findings.extend(
                    result_findings
                )

        if not findings:

            findings = [
                "No direct threat findings were supplied."
            ]

        story.extend(
            self._bullet_list(
                findings
            )
        )

    # =========================================================
    # IOC SECTION
    # =========================================================

    def _build_ioc_section(
        self,
        story,
        incident_data
    ):

        story.append(
            self._paragraph(
                "4. Indicators of Compromise",
                "CNXHeading"
            )
        )

        intelligence = incident_data.get(
            "intelligence",
            incident_data.get(
                "intelligence_result",
                {}
            )
        )

        if not isinstance(
            intelligence,
            dict
        ):

            intelligence = {}

        indicators = intelligence.get(
            "indicators",
            {}
        )

        if not indicators:

            story.append(
                self._paragraph(
                    "No structured IOC information was supplied.",
                    "CNXBody"
                )
            )

            return

        for indicator_type, values in indicators.items():

            story.append(
                self._paragraph(
                    f"<b>{self._safe_text(indicator_type).upper()}</b>",
                    "CNXSubHeading"
                )
            )

            if isinstance(
                values,
                list
            ):

                story.extend(
                    self._bullet_list(
                        values
                    )
                )

            else:

                story.append(
                    self._paragraph(
                        self._safe_text(
                            values
                        ),
                        "CNXSmall"
                    )
                )

    # =========================================================
    # ATTACK DNA
    # =========================================================

    def _build_attack_dna_section(
        self,
        story,
        incident_data
    ):

        story.append(
            self._paragraph(
                "5. Attack DNA Analysis",
                "CNXHeading"
            )
        )

        dna = incident_data.get(
            "attack_dna",
            incident_data.get(
                "dna",
                {}
            )
        )

        if not isinstance(
            dna,
            dict
        ):

            dna = {}

        if not dna:

            story.append(
                self._paragraph(
                    "Attack DNA analysis data was not supplied.",
                    "CNXBody"
                )
            )

            return

        pattern = dna.get(
            "dna_pattern",
            dna.get(
                "pattern",
                "N/A"
            )
        )

        classification = dna.get(
            "classification",
            "N/A"
        )

        confidence = dna.get(
            "confidence",
            "N/A"
        )

        dna_score = dna.get(
            "risk_score",
            0
        )

        story.append(
            self._paragraph(
                f"<b>DNA Pattern:</b> "
                f"{self._safe_text(pattern)}",
                "CNXBody"
            )
        )

        story.append(
            self._paragraph(
                f"<b>Classification:</b> "
                f"{self._safe_text(classification)}",
                "CNXBody"
            )
        )

        story.append(
            self._paragraph(
                f"<b>Confidence:</b> "
                f"{self._safe_text(confidence)}",
                "CNXBody"
            )
        )

        story.append(
            self._paragraph(
                f"<b>Risk Score:</b> "
                f"{self._safe_text(dna_score)}",
                "CNXBody"
            )
        )

        attack_chain = dna.get(
            "attack_chain",
            []
        )

        if attack_chain:

            story.append(
                self._paragraph(
                    "<b>Attack Chain</b>",
                    "CNXSubHeading"
                )
            )

            story.extend(
                self._bullet_list(
                    attack_chain
                )
            )

    # =========================================================
    # ANOMALY SECTION
    # =========================================================

    def _build_anomaly_section(
        self,
        story,
        incident_data
    ):

        story.append(
            self._paragraph(
                "6. Anomaly Analysis",
                "CNXHeading"
            )
        )

        anomaly = incident_data.get(
            "anomaly",
            incident_data.get(
                "anomaly_result",
                {}
            )
        )

        if not isinstance(
            anomaly,
            dict
        ):

            anomaly = {}

        if not anomaly:

            story.append(
                self._paragraph(
                    "Anomaly analysis data was not supplied.",
                    "CNXBody"
                )
            )

            return

        anomaly_score = anomaly.get(
            "anomaly_score",
            anomaly.get(
                "score",
                0
            )
        )

        anomaly_level = anomaly.get(
            "risk_level",
            self._risk_level(
                anomaly_score
            )
        )

        summary = anomaly.get(
            "summary",
            "Anomaly assessment completed."
        )

        story.append(
            self._paragraph(
                f"<b>Anomaly Score:</b> "
                f"{self._safe_text(anomaly_score)}",
                "CNXBody"
            )
        )

        story.append(
            self._paragraph(
                f"<b>Risk Level:</b> "
                f"{self._safe_text(anomaly_level)}",
                "CNXBody"
            )
        )

        story.append(
            self._paragraph(
                f"<b>Summary:</b> "
                f"{self._safe_text(summary)}",
                "CNXBody"
            )
        )

        indicators = anomaly.get(
            "pattern_indicators",
            anomaly.get(
                "indicators",
                []
            )
        )

        if indicators:

            story.append(
                self._paragraph(
                    "<b>Detected Indicators</b>",
                    "CNXSubHeading"
                )
            )

            story.extend(
                self._bullet_list(
                    indicators
                )
            )

    # =========================================================
    # FORENSICS
    # =========================================================

    def _build_forensics_section(
        self,
        story,
        incident_data
    ):

        story.append(
            self._paragraph(
                "7. Digital Forensics & Evidence",
                "CNXHeading"
            )
        )

        forensic = incident_data.get(
            "forensics",
            incident_data.get(
                "forensic_result",
                {}
            )
        )

        if not isinstance(
            forensic,
            dict
        ):

            forensic = {}

        evidence = incident_data.get(
            "evidence",
            {}
        )

        records = evidence.get(
            "records",
            []
        ) if isinstance(
            evidence,
            dict
        ) else []

        if forensic:

            story.append(
                self._paragraph(
                    "<b>Forensic analysis information available.</b>",
                    "CNXBody"
                )
            )

            identity = forensic.get(
                "identity",
                {}
            )

            if isinstance(
                identity,
                dict
            ):

                sha256 = identity.get(
                    "sha256"
                )

                if sha256:

                    story.append(
                        self._paragraph(
                            f"<b>SHA-256:</b> "
                            f"{self._safe_text(sha256)}",
                            "CNXSmall"
                        )
                    )

            assessment = forensic.get(
                "assessment",
                {}
            )

            if isinstance(
                assessment,
                dict
            ):

                story.append(
                    self._paragraph(
                        f"<b>Forensic Risk:</b> "
                        f"{self._safe_text(assessment.get('risk_score', 0))} "
                        f"({self._safe_text(assessment.get('risk_level', 'LOW'))})",
                        "CNXBody"
                    )
                )

        if records:

            story.append(
                self._paragraph(
                    f"<b>Evidence Records:</b> "
                    f"{len(records)}",
                    "CNXBody"
                )
            )

            for record in records:

                if not isinstance(
                    record,
                    dict
                ):
                    continue

                event_id = record.get(
                    "event_id",
                    "N/A"
                )

                evidence_hash = record.get(
                    "evidence_hash",
                    "N/A"
                )

                ledger_hash = record.get(
                    "ledger_hash",
                    "N/A"
                )

                story.append(
                    self._paragraph(
                        f"• Event ID: {self._safe_text(event_id)}",
                        "CNXSmall"
                    )
                )

                story.append(
                    self._paragraph(
                        f"• Evidence Hash: {self._safe_text(evidence_hash)}",
                        "CNXSmall"
                    )
                )

                story.append(
                    self._paragraph(
                        f"• Ledger Hash: {self._safe_text(ledger_hash)}",
                        "CNXSmall"
                    )
                )

        else:

            story.append(
                self._paragraph(
                    "No evidence records were supplied.",
                    "CNXBody"
                )
            )

    # =========================================================
    # KNOWLEDGE GRAPH
    # =========================================================

    def _build_graph_section(
        self,
        story,
        incident_data
    ):

        story.append(
            self._paragraph(
                "8. Knowledge Graph",
                "CNXHeading"
            )
        )

        graph = incident_data.get(
            "graph",
            {}
        )

        if not isinstance(
            graph,
            dict
        ):

            graph = {}

        node_count = graph.get(
            "node_count",
            0
        )

        edge_count = graph.get(
            "edge_count",
            0
        )

        story.append(
            self._paragraph(
                f"<b>Nodes:</b> "
                f"{self._safe_text(node_count)}",
                "CNXBody"
            )
        )

        story.append(
            self._paragraph(
                f"<b>Relationships:</b> "
                f"{self._safe_text(edge_count)}",
                "CNXBody"
            )
        )

        edges = graph.get(
            "edges",
            []
        )

        if edges:

            story.append(
                self._paragraph(
                    "<b>Key Relationships</b>",
                    "CNXSubHeading"
                )
            )

            for edge in edges[:15]:

                if not isinstance(
                    edge,
                    dict
                ):
                    continue

                source = edge.get(
                    "source",
                    "N/A"
                )

                target = edge.get(
                    "target",
                    "N/A"
                )

                relationship = edge.get(
                    "relationship",
                    "RELATED_TO"
                )

                story.append(
                    self._paragraph(
                        f"• {self._safe_text(source)} "
                        f"→ [{self._safe_text(relationship)}] → "
                        f"{self._safe_text(target)}",
                        "CNXSmall"
                    )
                )

    # =========================================================
    # RESPONSE SECTION
    # =========================================================

    def _build_response_section(
        self,
        story,
        incident_data
    ):

        story.append(
            self._paragraph(
                "9. Defensive Response Plan",
                "CNXHeading"
            )
        )

        response = incident_data.get(
            "response",
            incident_data.get(
                "response_plan",
                {}
            )
        )

        if not isinstance(
            response,
            dict
        ):

            response = {}

        if not response:

            story.append(
                self._paragraph(
                    "No response plan data was supplied.",
                    "CNXBody"
                )
            )

            return

        for section_name, title in [
            (
                "containment_actions",
                "Containment"
            ),
            (
                "investigation_actions",
                "Investigation"
            ),
            (
                "recovery_actions",
                "Recovery"
            ),
            (
                "monitoring_actions",
                "Monitoring"
            )
        ]:

            actions = response.get(
                section_name,
                []
            )

            if actions:

                story.append(
                    self._paragraph(
                        title,
                        "CNXSubHeading"
                    )
                )

                story.extend(
                    self._bullet_list(
                        actions
                    )
                )

        priority = response.get(
            "priority"
        )

        if priority:

            story.append(
                self._paragraph(
                    f"<b>Response Priority:</b> "
                    f"{self._safe_text(priority)}",
                    "CNXBody"
                )
            )

    # =========================================================
    # SIMULATION SECTION
    # =========================================================

    def _build_simulation_section(
        self,
        story,
        incident_data
    ):

        story.append(
            self._paragraph(
                "10. Security Simulation",
                "CNXHeading"
            )
        )

        simulation = incident_data.get(
            "simulation",
            incident_data.get(
                "cyber_range",
                {}
            )
        )

        if not isinstance(
            simulation,
            dict
        ):

            simulation = {}

        if not simulation:

            story.append(
                self._paragraph(
                    "No simulation results were supplied.",
                    "CNXBody"
                )
            )

            return

        initial = simulation.get(
            "initial_assessment",
            {}
        )

        final = simulation.get(
            "final_assessment",
            {}
        )

        if isinstance(
            initial,
            dict
        ):

            story.append(
                self._paragraph(
                    f"<b>Initial Risk:</b> "
                    f"{self._safe_text(initial.get('risk_score', 0))} "
                    f"({self._safe_text(initial.get('risk_level', 'LOW'))})",
                    "CNXBody"
                )
            )

        if isinstance(
            final,
            dict
        ):

            story.append(
                self._paragraph(
                    f"<b>Final Risk:</b> "
                    f"{self._safe_text(final.get('risk_score', 0))} "
                    f"({self._safe_text(final.get('risk_level', 'LOW'))})",
                    "CNXBody"
                )
            )

            story.append(
                self._paragraph(
                    f"<b>Risk Reduction:</b> "
                    f"{self._safe_text(final.get('risk_reduction', 0))} "
                    f"points "
                    f"({self._safe_text(final.get('reduction_percentage', 0))}%)",
                    "CNXBody"
                )
            )

            story.append(
                self._paragraph(
                    f"<b>Outcome:</b> "
                    f"{self._safe_text(final.get('outcome', 'N/A'))}",
                    "CNXBody"
                )
            )

    # =========================================================
    # RECOMMENDATIONS
    # =========================================================

    def _build_recommendations(
        self,
        story,
        incident_data
    ):

        story.append(
            self._paragraph(
                "11. Security Recommendations",
                "CNXHeading"
            )
        )

        recommendations = []

        for source_key in [
            "recommendations",
            "response_recommendations"
        ]:

            values = incident_data.get(
                source_key,
                []
            )

            if isinstance(
                values,
                list
            ):

                recommendations.extend(
                    values
                )

        dna = incident_data.get(
            "attack_dna",
            {}
        )

        if isinstance(
            dna,
            dict
        ):

            dna_recommendations = dna.get(
                "recommendations",
                []
            )

            if isinstance(
                dna_recommendations,
                list
            ):

                recommendations.extend(
                    dna_recommendations
                )

        intelligence = incident_data.get(
            "intelligence",
            {}
        )

        if isinstance(
            intelligence,
            dict
        ):

            intelligence_recommendations = intelligence.get(
                "recommendations",
                []
            )

            if isinstance(
                intelligence_recommendations,
                list
            ):

                recommendations.extend(
                    intelligence_recommendations
                )

        # Remove duplicates while preserving order.

        unique_recommendations = []

        for recommendation in recommendations:

            if recommendation not in unique_recommendations:

                unique_recommendations.append(
                    recommendation
                )

        if not unique_recommendations:

            unique_recommendations = [
                "Investigate identified security indicators.",
                "Preserve relevant evidence for forensic analysis.",
                "Review authentication and endpoint telemetry.",
                "Monitor identified indicators for recurrence.",
                "Document incident findings and response actions."
            ]

        story.extend(
            self._bullet_list(
                unique_recommendations
            )
        )

    # =========================================================
    # CONCLUSION
    # =========================================================

    def _build_conclusion(
        self,
        story,
        score,
        level
    ):

        story.append(
            self._paragraph(
                "12. Conclusion",
                "CNXHeading"
            )
        )

        conclusion = (
            f"CyberNexus Ω completed a consolidated defensive "
            f"security assessment with an overall risk score of "
            f"<b>{self._safe_text(score)}/100</b> and risk level "
            f"<b>{self._safe_text(level)}</b>. The report combines "
            f"available detection, intelligence, forensic, correlation, "
            f"graph, simulation, and response information into a "
            f"single investigation artifact."
        )

        story.append(
            self._paragraph(
                conclusion,
                "CNXBody"
            )
        )

        story.append(
            Spacer(
                1,
                15
            )
        )

        story.append(
            self._paragraph(
                "Generated by CyberNexus Ω Security Intelligence Platform.",
                "CNXSmall"
            )
        )

    # =========================================================
    # GENERATE PDF
    # =========================================================

    def generate_report(
        self,
        incident_data,
        incident_id=None,
        filename=None
    ):

        if not isinstance(
            incident_data,
            dict
        ):

            return {
                "success": False,
                "status": "INVALID_DATA",
                "message": "Incident data must be a dictionary."
            }

        score = self._get_overall_score(
            incident_data
        )

        level = self._get_overall_level(
            incident_data,
            score
        )

        if incident_id is None:

            incident = incident_data.get(
                "incident",
                {}
            )

            if isinstance(
                incident,
                dict
            ):

                incident_id = incident.get(
                    "incident_id"
                )

        if not incident_id:

            incident_id = incident_data.get(
                "incident_id",
                "CNX-UNKNOWN"
            )

        if filename is None:

            safe_id = "".join(
                character
                if character.isalnum()
                or character in (
                    "-",
                    "_"
                )
                else "_"
                for character in str(
                    incident_id
                )
            )

            filename = (
                f"CyberNexus_Report_"
                f"{safe_id}.pdf"
            )

        if not filename.lower().endswith(
            ".pdf"
        ):

            filename += ".pdf"

        output_path = os.path.join(
            self.output_directory,
            filename
        )

        try:

            document = SimpleDocTemplate(
                output_path,
                pagesize=A4,
                rightMargin=15 * mm,
                leftMargin=15 * mm,
                topMargin=20 * mm,
                bottomMargin=18 * mm,
                title=(
                    "CyberNexus Ω Security Incident Report"
                ),
                author="CyberNexus Ω"
            )

            story = []

            # -------------------------------------------------
            # COVER
            # -------------------------------------------------

            story.append(
                Spacer(
                    1,
                    35
                )
            )

            story.append(
                self._paragraph(
                    "CYBERNEXUS Ω",
                    "CNXTitle"
                )
            )

            story.append(
                self._paragraph(
                    "SECURITY INCIDENT REPORT",
                    "CNXSubtitle"
                )
            )

            cover_data = [
                [
                    "Incident ID",
                    self._safe_text(
                        incident_id
                    )
                ],
                [
                    "Risk Score",
                    f"{self._safe_text(score)}/100"
                ],
                [
                    "Risk Level",
                    self._safe_text(level)
                ],
                [
                    "Generated UTC",
                    self._timestamp()
                ],
                [
                    "Engine",
                    self.ENGINE_NAME
                ]
            ]

            cover_table = Table(
                cover_data,
                colWidths=[
                    50 * mm,
                    110 * mm
                ]
            )

            cover_table.setStyle(
                TableStyle(
                    [
                        (
                            "GRID",
                            (0, 0),
                            (-1, -1),
                            0.5,
                            colors.grey
                        ),
                        (
                            "FONTNAME",
                            (0, 0),
                            (0, -1),
                            "Helvetica-Bold"
                        ),
                        (
                            "BACKGROUND",
                            (0, 0),
                            (0, -1),
                            colors.HexColor(
                                "#E5E7EB"
                            )
                        ),
                        (
                            "VALIGN",
                            (0, 0),
                            (-1, -1),
                            "MIDDLE"
                        ),
                        (
                            "TOPPADDING",
                            (0, 0),
                            (-1, -1),
                            8
                        ),
                        (
                            "BOTTOMPADDING",
                            (0, 0),
                            (-1, -1),
                            8
                        )
                    ]
                )
            )

            story.append(
                cover_table
            )

            story.append(
                Spacer(
                    1,
                    25
                )
            )

            story.append(
                self._paragraph(
                    "CONFIDENTIAL",
                    "CNXSubtitle"
                )
            )

            story.append(
                PageBreak()
            )

            # -------------------------------------------------
            # REPORT SECTIONS
            # -------------------------------------------------

            self._build_executive_summary(
                story,
                incident_data,
                score,
                level
            )

            self._build_risk_section(
                story,
                incident_data,
                score,
                level
            )

            self._build_threat_section(
                story,
                incident_data
            )

            self._build_ioc_section(
                story,
                incident_data
            )

            self._build_attack_dna_section(
                story,
                incident_data
            )

            self._build_anomaly_section(
                story,
                incident_data
            )

            self._build_forensics_section(
                story,
                incident_data
            )

            self._build_graph_section(
                story,
                incident_data
            )

            self._build_response_section(
                story,
                incident_data
            )

            self._build_simulation_section(
                story,
                incident_data
            )

            self._build_recommendations(
                story,
                incident_data
            )

            self._build_conclusion(
                story,
                score,
                level
            )

            # -------------------------------------------------
            # BUILD PDF
            # -------------------------------------------------

            document.build(
                story,
                onFirstPage=self._draw_header_footer,
                onLaterPages=self._draw_header_footer
            )

            return {
                "success": True,
                "status": "REPORT_GENERATED",
                "engine": self.ENGINE_NAME,
                "version": self.ENGINE_VERSION,
                "incident_id": incident_id,
                "risk_score": score,
                "risk_level": level,
                "file_path": output_path,
                "file_name": filename
            }

        except Exception as error:

            return {
                "success": False,
                "status": "REPORT_ERROR",
                "engine": self.ENGINE_NAME,
                "message": str(error),
                "file_path": output_path
            }


def generate_security_report(
    incident_data,
    incident_id=None,
    filename=None
):

    generator = CyberNexusReportGenerator()

    return generator.generate_report(
        incident_data=incident_data,
        incident_id=incident_id,
        filename=filename
    )


# =============================================================
# DIRECT TEST
# =============================================================

if __name__ == "__main__":

    print("\n" + "=" * 70)
    print(
        "CYBERNEXUS Ω - SECURITY REPORT GENERATOR TEST"
    )
    print("=" * 70)

    generator = CyberNexusReportGenerator()

    # ---------------------------------------------------------
    # TEST DATA
    # ---------------------------------------------------------

    test_data = {

        "incident": {
            "incident_id": "CNX-REPORT-TEST-001",
            "incident_level": "HIGH",
            "correlation_score": 59,
            "signal_count": 3,
            "high_risk_signal_count": 2
        },

        "unified_risk": {
            "overall_score": 57,
            "overall_level": "HIGH",

            "sources": [
                {
                    "source": "URL",
                    "score": 55,
                    "level": "HIGH"
                },
                {
                    "source": "FILE",
                    "score": 40,
                    "level": "MEDIUM"
                },
                {
                    "source": "EMAIL",
                    "score": 64,
                    "level": "HIGH"
                }
            ],

            "explanation": [
                "URL detector reported HIGH risk with score 55.",
                "File detector reported MEDIUM risk with score 40.",
                "Email detector reported HIGH risk with score 64."
            ]
        },

        "url_result": {
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
        },

        "file_result": {
            "file_name": "suspicious_test.txt",
            "risk_score": 40,
            "risk_level": "MEDIUM",
            "findings": [
                "Suspicious execution-related patterns detected"
            ]
        },

        "email_result": {
            "sender": "security@example.com",
            "risk_score": 64,
            "risk_level": "HIGH",
            "findings": [
                "Urgency indicators detected",
                "Sensitive-data indicators detected",
                "1 URL(s) detected",
                "URL shortener detected: bit.ly"
            ]
        },

        "intelligence": {

            "indicators": {

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
            },

            "recommendations": [
                "Investigate identified URLs.",
                "Review identified domains.",
                "Review IP-based indicators.",
                "Compare identified file hashes with trusted records."
            ]
        },

        "attack_dna": {

            "dna_pattern": (
                "PHISHING_CREDENTIAL_ATTACK"
            ),

            "classification": (
                "CREDENTIAL_ATTACK"
            ),

            "confidence": "92%",

            "risk_score": 100,

            "attack_chain": [
                "INITIAL_ACCESS",
                "CREDENTIAL_ACCESS",
                "EXECUTION",
                "PRIVILEGE_ESCALATION",
                "COMMAND_AND_CONTROL",
                "DISCOVERY",
                "DATA_EXFILTRATION"
            ],

            "recommendations": [
                "Investigate the suspected initial access vector.",
                "Review authentication activity.",
                "Investigate suspicious files.",
                "Review privileged account activity.",
                "Investigate outbound data transfers."
            ]
        },

        "anomaly": {

            "anomaly_score": 100,

            "risk_level": "CRITICAL",

            "summary": (
                "CyberNexus detected multiple abnormal "
                "behaviour metrics."
            ),

            "pattern_indicators": [
                "Excessive failed login activity.",
                "Privilege escalation behaviour detected.",
                "Unknown device activity detected.",
                "Suspicious URL activity detected.",
                "Large outbound data transfer detected."
            ]
        },

        "forensics": {

            "identity": {
                "sha256": (
                    "eaf3695cb93a4b4da830cbc0a1d52f118eee11d0c43a972a951489dc257b1646"
                )
            },

            "assessment": {
                "risk_score": 40,
                "risk_level": "MEDIUM"
            }
        },

        "evidence": {

            "records": [
                {
                    "event_id": "EVT-REPORT-001",
                    "evidence_hash": "abc123",
                    "ledger_hash": "def456"
                },
                {
                    "event_id": "EVT-REPORT-002",
                    "evidence_hash": "ghi789",
                    "ledger_hash": "jkl012"
                },
                {
                    "event_id": "EVT-REPORT-003",
                    "evidence_hash": "mno345",
                    "ledger_hash": "pqr678"
                }
            ]
        },

        "graph": {

            "node_count": 6,

            "edge_count": 6,

            "edges": [
                {
                    "source": "INCIDENT",
                    "target": "URL",
                    "relationship": "CONTAINS"
                },
                {
                    "source": "URL",
                    "target": "DOMAIN",
                    "relationship": "RESOLVES_TO"
                },
                {
                    "source": "EMAIL",
                    "target": "URL",
                    "relationship": "SUSPICIOUS_LINK"
                }
            ]
        },

        "response": {

            "priority": "IMMEDIATE",

            "containment_actions": [
                "Isolate affected systems.",
                "Block confirmed malicious indicators.",
                "Preserve relevant evidence."
            ],

            "investigation_actions": [
                "Review the complete incident timeline.",
                "Correlate endpoint and network telemetry.",
                "Investigate authentication activity."
            ],

            "recovery_actions": [
                "Restore systems only after security validation.",
                "Rotate potentially exposed credentials."
            ],

            "monitoring_actions": [
                "Increase monitoring for recurrence.",
                "Monitor identified indicators."
            ]
        },

        "simulation": {

            "initial_assessment": {
                "risk_score": 93,
                "risk_level": "CRITICAL"
            },

            "final_assessment": {
                "risk_score": 52,
                "risk_level": "HIGH",
                "risk_reduction": 41,
                "reduction_percentage": 44.09,
                "outcome": (
                    "Defensive response reduced "
                    "the simulated incident risk."
                )
            }
        }
    }

    # ---------------------------------------------------------
    # GENERATE REPORT
    # ---------------------------------------------------------

    print("\n[1] GENERATING SECURITY REPORT")
    print("-" * 70)

    result = generator.generate_report(
        incident_data=test_data,
        incident_id="CNX-REPORT-TEST-001"
    )

    print(
        "Engine       :",
        result.get("engine")
    )

    print(
        "Status       :",
        result.get("status")
    )

    print(
        "Incident ID  :",
        result.get("incident_id")
    )

    print(
        "Risk Score   :",
        result.get("risk_score")
    )

    print(
        "Risk Level   :",
        result.get("risk_level")
    )

    print(
        "File Name    :",
        result.get("file_name")
    )

    print(
        "File Path    :",
        result.get("file_path")
    )

    # ---------------------------------------------------------
    # VERIFY FILE
    # ---------------------------------------------------------

    print("\n[2] PDF FILE VERIFICATION")
    print("-" * 70)

    generated_file = result.get(
        "file_path"
    )

    if (
        result.get("success")
        and generated_file
        and os.path.exists(
            generated_file
        )
    ):

        file_size = os.path.getsize(
            generated_file
        )

        print(
            "Status       : PDF CREATED"
        )

        print(
            "File Size    :",
            file_size,
            "bytes"
        )

        print(
            "Exists       : True"
        )

    else:

        print(
            "Status       : PDF CREATION FAILED"
        )

        print(
            "Message      :",
            result.get(
                "message",
                "Unknown error"
            )
        )

    # ---------------------------------------------------------
    # EMPTY DATA TEST
    # ---------------------------------------------------------

    print("\n[3] INVALID DATA TEST")
    print("-" * 70)

    invalid_result = generator.generate_report(
        incident_data=None
    )

    print(
        "Status       :",
        invalid_result.get("status")
    )

    print(
        "Message      :",
        invalid_result.get("message")
    )

    # ---------------------------------------------------------
    # FINAL
    # ---------------------------------------------------------

    print("\n" + "=" * 70)
    print(
        "SECURITY REPORT GENERATOR TEST COMPLETED"
    )
    print("=" * 70)