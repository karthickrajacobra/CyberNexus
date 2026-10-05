import networkx as nx


def build_incident_graph(
    incident_id,
    url_result=None,
    file_result=None,
    email_result=None
):
    """
    Build a cybersecurity knowledge graph
    from a correlated incident.
    """

    graph = nx.DiGraph()

    # ========================================================
    # INCIDENT NODE
    # ========================================================

    graph.add_node(
        incident_id,
        node_type="INCIDENT",
        label=incident_id
    )

    # ========================================================
    # URL NODE
    # ========================================================

    if url_result:

        url = url_result.get(
            "url",
            "Unknown URL"
        )

        url_node = f"URL:{url}"

        graph.add_node(
            url_node,
            node_type="URL",
            label=url
        )

        graph.add_edge(
            incident_id,
            url_node,
            relationship="CONTAINS"
        )

        # ----------------------------------------------------
        # DOMAIN
        # ----------------------------------------------------

        from urllib.parse import urlparse

        try:

            domain = (
                urlparse(url).hostname
                or "unknown"
            )

            domain_node = f"DOMAIN:{domain}"

            graph.add_node(
                domain_node,
                node_type="DOMAIN",
                label=domain
            )

            graph.add_edge(
                url_node,
                domain_node,
                relationship="RESOLVES_TO"
            )

        except Exception:
            pass

    # ========================================================
    # FILE NODE
    # ========================================================

    if file_result:

        file_hash = file_result.get(
            "sha256",
            "Unknown Hash"
        )

        file_node = f"FILE:{file_hash}"

        graph.add_node(
            file_node,
            node_type="FILE",
            label=file_hash
        )

        graph.add_edge(
            incident_id,
            file_node,
            relationship="CONTAINS"
        )

    # ========================================================
    # EMAIL NODE
    # ========================================================

    if email_result:

        sender = email_result.get(
            "sender",
            "Unknown Sender"
        )

        email_node = f"EMAIL:{sender}"

        graph.add_node(
            email_node,
            node_type="EMAIL",
            label=sender
        )

        graph.add_edge(
            incident_id,
            email_node,
            relationship="CONTAINS"
        )

        # ----------------------------------------------------
        # EMAIL URLs
        # ----------------------------------------------------

        email_urls = email_result.get(
            "urls",
            []
        )

        for email_url in email_urls:

            email_url_node = (
                f"URL:{email_url}"
            )

            graph.add_node(
                email_url_node,
                node_type="URL",
                label=email_url
            )

            graph.add_edge(
                email_node,
                email_url_node,
                relationship="CONTAINS_URL"
            )

    # ========================================================
    # CROSS-SIGNAL RELATIONSHIPS
    # ========================================================

    node_types = nx.get_node_attributes(
        graph,
        "node_type"
    )

    url_nodes = [
        node
        for node, node_type
        in node_types.items()
        if node_type == "URL"
    ]

    file_nodes = [
        node
        for node, node_type
        in node_types.items()
        if node_type == "FILE"
    ]

    email_nodes = [
        node
        for node, node_type
        in node_types.items()
        if node_type == "EMAIL"
    ]

    # Email -> URL relationship
    if email_nodes and url_nodes:

        for email_node in email_nodes:

            for url_node in url_nodes:

                if not graph.has_edge(
                    email_node,
                    url_node
                ):

                    graph.add_edge(
                        email_node,
                        url_node,
                        relationship="SUSPICIOUS_LINK"
                    )

    # Incident -> high-risk file
    if file_nodes:

        for file_node in file_nodes:

            graph.add_edge(
                incident_id,
                file_node,
                relationship="HIGH_RISK_ARTIFACT"
            )

    # ========================================================
    # GRAPH SUMMARY
    # ========================================================

    return {
        "nodes": [
            {
                "id": node,
                **graph.nodes[node]
            }
            for node in graph.nodes
        ],

        "edges": [
            {
                "source": source,
                "target": target,
                **graph.edges[source, target]
            }
            for source, target
            in graph.edges
        ],

        "node_count": graph.number_of_nodes(),

        "edge_count": graph.number_of_edges()
    }