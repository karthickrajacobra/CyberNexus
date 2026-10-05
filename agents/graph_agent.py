from datetime import datetime, timezone

from graph.knowledge_graph import build_incident_graph


class GraphAgent:
    """
    CyberNexus Ω - Graph Agent

    Responsibilities:
    - Build incident knowledge graphs
    - Analyze graph relationships
    - Count nodes and edges
    - Identify important relationships
    - Generate graph intelligence summary
    """

    AGENT_NAME = "CyberNexus Graph Agent"
    AGENT_VERSION = "1.0"

    def __init__(self):
        self.status = "READY"

    def _timestamp(self):
        return datetime.now(timezone.utc).isoformat()

    # ---------------------------------------------------------
    # NODE TYPE SUMMARY
    # ---------------------------------------------------------

    def _summarize_nodes(self, nodes):
        """
        Count graph nodes by node type.
        """

        summary = {}

        for node in nodes:

            node_type = node.get(
                "node_type",
                "UNKNOWN"
            )

            summary[node_type] = (
                summary.get(node_type, 0) + 1
            )

        return summary

    # ---------------------------------------------------------
    # RELATIONSHIP SUMMARY
    # ---------------------------------------------------------

    def _summarize_relationships(self, edges):
        """
        Count graph relationships.
        """

        summary = {}

        for edge in edges:

            relationship = edge.get(
                "relationship",
                "UNKNOWN"
            )

            summary[relationship] = (
                summary.get(relationship, 0) + 1
            )

        return summary

    # ---------------------------------------------------------
    # IMPORTANT RELATIONSHIPS
    # ---------------------------------------------------------

    def _identify_relationships(self, edges):
        """
        Extract security-relevant graph relationships.
        """

        relationships = []

        for edge in edges:

            source = edge.get(
                "source",
                "UNKNOWN"
            )

            target = edge.get(
                "target",
                "UNKNOWN"
            )

            relationship = edge.get(
                "relationship",
                "UNKNOWN"
            )

            relationships.append({
                "source": source,
                "target": target,
                "relationship": relationship
            })

        return relationships

    # ---------------------------------------------------------
    # GRAPH RISK
    # ---------------------------------------------------------

    def _calculate_graph_risk(
        self,
        nodes,
        edges,
        high_risk_signal_count=0
    ):
        """
        Calculate a graph-level risk indicator.

        This measures graph complexity and the presence
        of high-risk security signals. It is not a
        standalone malware verdict.
        """

        score = 0

        node_count = len(nodes)
        edge_count = len(edges)

        # -----------------------------------------------------
        # MULTIPLE NODES
        # -----------------------------------------------------

        if node_count >= 6:
            score += 20

        elif node_count >= 4:
            score += 10

        # -----------------------------------------------------
        # MULTIPLE RELATIONSHIPS
        # -----------------------------------------------------

        if edge_count >= 6:
            score += 20

        elif edge_count >= 4:
            score += 10

        # -----------------------------------------------------
        # HIGH-RISK SIGNALS
        # -----------------------------------------------------

        try:
            high_risk_signal_count = int(
                high_risk_signal_count
            )
        except (TypeError, ValueError):
            high_risk_signal_count = 0

        if high_risk_signal_count >= 3:
            score += 40

        elif high_risk_signal_count >= 2:
            score += 25

        elif high_risk_signal_count >= 1:
            score += 10

        return min(score, 100)

    # ---------------------------------------------------------
    # CLASSIFICATION
    # ---------------------------------------------------------

    def _classify(self, score):

        if score >= 70:

            return {
                "risk_level": "CRITICAL",
                "classification": "CRITICAL GRAPH ACTIVITY",
                "priority": "IMMEDIATE"
            }

        if score >= 45:

            return {
                "risk_level": "HIGH",
                "classification": "HIGH-RISK GRAPH ACTIVITY",
                "priority": "HIGH"
            }

        if score >= 20:

            return {
                "risk_level": "MEDIUM",
                "classification": "SUSPICIOUS GRAPH ACTIVITY",
                "priority": "MEDIUM"
            }

        return {
            "risk_level": "LOW",
            "classification": "LOW-RISK GRAPH ACTIVITY",
            "priority": "LOW"
        }

    # ---------------------------------------------------------
    # GRAPH SUMMARY
    # ---------------------------------------------------------

    def _generate_summary(
        self,
        incident_id,
        node_count,
        edge_count,
        node_types,
        relationships
    ):
        """
        Generate human-readable graph intelligence.
        """

        relationship_count = len(
            relationships
        )

        if relationship_count > 0:

            summary = (
                f"Incident {incident_id} produced a "
                f"knowledge graph containing "
                f"{node_count} node(s) and "
                f"{edge_count} relationship(s). "
                f"The graph contains "
                f"{len(node_types)} node type(s)."
            )

        else:

            summary = (
                f"Incident {incident_id} produced a "
                f"graph with {node_count} node(s) "
                f"and no relationships."
            )

        return summary

    # ---------------------------------------------------------
    # MAIN GRAPH ANALYSIS
    # ---------------------------------------------------------

    def analyze(
        self,
        incident_id,
        url_result=None,
        file_result=None,
        email_result=None,
        high_risk_signal_count=0
    ):
        """
        Build and analyze a CyberNexus incident graph.
        """

        if not incident_id:

            return {
                "success": False,
                "agent": self.AGENT_NAME,
                "status": "ERROR",
                "message": "Incident ID is required.",
                "timestamp": self._timestamp()
            }

        if not any([
            url_result,
            file_result,
            email_result
        ]):

            return {
                "success": False,
                "agent": self.AGENT_NAME,
                "status": "NO_DATA",
                "message": (
                    "At least one security result "
                    "is required to build the graph."
                ),
                "timestamp": self._timestamp()
            }

        try:

            # -------------------------------------------------
            # BUILD GRAPH
            # -------------------------------------------------

            graph = build_incident_graph(
                incident_id=incident_id,
                url_result=url_result,
                file_result=file_result,
                email_result=email_result
            )

            nodes = graph.get(
                "nodes",
                []
            )

            edges = graph.get(
                "edges",
                []
            )

            node_count = graph.get(
                "node_count",
                len(nodes)
            )

            edge_count = graph.get(
                "edge_count",
                len(edges)
            )

            # -------------------------------------------------
            # ANALYZE GRAPH
            # -------------------------------------------------

            node_types = self._summarize_nodes(
                nodes
            )

            relationship_types = (
                self._summarize_relationships(
                    edges
                )
            )

            relationships = (
                self._identify_relationships(
                    edges
                )
            )

            graph_score = self._calculate_graph_risk(
                nodes=nodes,
                edges=edges,
                high_risk_signal_count=(
                    high_risk_signal_count
                )
            )

            classification = self._classify(
                graph_score
            )

            summary = self._generate_summary(
                incident_id=incident_id,
                node_count=node_count,
                edge_count=edge_count,
                node_types=node_types,
                relationships=relationships
            )

            return {
                "success": True,
                "agent": self.AGENT_NAME,
                "version": self.AGENT_VERSION,
                "status": "ANALYZED",
                "type": "KNOWLEDGE_GRAPH",
                "graph": {
                    "incident_id": incident_id,
                    "node_count": node_count,
                    "edge_count": edge_count,
                    "risk_score": graph_score,
                    "risk_level": classification[
                        "risk_level"
                    ],
                    "classification": classification[
                        "classification"
                    ],
                    "priority": classification[
                        "priority"
                    ]
                },
                "node_types": node_types,
                "relationship_types": relationship_types,
                "relationships": relationships,
                "nodes": nodes,
                "edges": edges,
                "summary": summary,
                "timestamp": self._timestamp()
            }

        except Exception as error:

            return {
                "success": False,
                "agent": self.AGENT_NAME,
                "status": "ERROR",
                "message": str(error),
                "timestamp": self._timestamp()
            }


def run_graph_agent(
    incident_id,
    url_result=None,
    file_result=None,
    email_result=None,
    high_risk_signal_count=0
):
    """
    Convenience function for other CyberNexus modules.
    """

    agent = GraphAgent()

    return agent.analyze(
        incident_id=incident_id,
        url_result=url_result,
        file_result=file_result,
        email_result=email_result,
        high_risk_signal_count=high_risk_signal_count
    )


# =============================================================
# DIRECT TEST
# =============================================================

if __name__ == "__main__":

    print("\n" + "=" * 70)
    print("CYBERNEXUS Ω - GRAPH AGENT TEST")
    print("=" * 70)

    agent = GraphAgent()

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
    # INCIDENT TEST
    # ---------------------------------------------------------

    incident_id = "CNX-GRAPH-TEST-001"

    print("\n[1] KNOWLEDGE GRAPH ANALYSIS")
    print("-" * 70)

    result = agent.analyze(
        incident_id=incident_id,
        url_result=url_result,
        file_result=file_result,
        email_result=email_result,
        high_risk_signal_count=2
    )

    print("Agent        :", result.get("agent"))
    print("Status       :", result.get("status"))

    if result.get("success"):

        graph = result["graph"]

        print(
            "Incident ID  :",
            graph["incident_id"]
        )

        print(
            "Node Count   :",
            graph["node_count"]
        )

        print(
            "Edge Count   :",
            graph["edge_count"]
        )

        print(
            "Risk Score   :",
            graph["risk_score"]
        )

        print(
            "Risk Level   :",
            graph["risk_level"]
        )

        print(
            "Classification:",
            graph["classification"]
        )

        print(
            "Priority     :",
            graph["priority"]
        )

        # -----------------------------------------------------
        # NODE TYPES
        # -----------------------------------------------------

        print("\nNode Types:")

        for node_type, count in result.get(
            "node_types",
            {}
        ).items():

            print(
                f" - {node_type}: {count}"
            )

        # -----------------------------------------------------
        # RELATIONSHIPS
        # -----------------------------------------------------

        print("\nRelationship Types:")

        for relationship, count in result.get(
            "relationship_types",
            {}
        ).items():

            print(
                f" - {relationship}: {count}"
            )

        # -----------------------------------------------------
        # GRAPH EDGES
        # -----------------------------------------------------

        print("\nGraph Relationships:")

        for relationship in result.get(
            "relationships",
            []
        ):

            print(
                f" - {relationship['source']}"
                f" --[{relationship['relationship']}]--> "
                f"{relationship['target']}"
            )

        # -----------------------------------------------------
        # SUMMARY
        # -----------------------------------------------------

        print("\nSummary:")
        print(
            " ",
            result.get("summary")
        )

    else:

        print(
            "Error        :",
            result.get("message")
        )

    # ---------------------------------------------------------
    # EMPTY TEST
    # ---------------------------------------------------------

    print("\n[2] EMPTY INPUT TEST")
    print("-" * 70)

    empty_result = agent.analyze(
        incident_id="CNX-EMPTY-TEST"
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
    print("GRAPH AGENT TEST COMPLETED")
    print("=" * 70)