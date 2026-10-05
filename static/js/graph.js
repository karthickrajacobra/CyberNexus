async function loadAttackGraph() {
    const graphContainer = document.getElementById("attackGraph");

    if (!graphContainer) {
        console.error("attackGraph container not found.");
        return;
    }

    graphContainer.innerHTML = `
        <div class="graph-loading">
            Loading CyberNexus attack graph...
        </div>
    `;

    try {
        const response = await fetch("/api/graph", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                incident_id: "CNX-4622F6EB6ECD",
                url_result: {
                    url: "https://example.com/login",
                    risk_score: 55,
                    risk_level: "HIGH"
                },
                file_result: {
                    sha256: "abc123",
                    risk_score: 70,
                    risk_level: "CRITICAL"
                },
                email_result: {
                    sender: "security@example.com",
                    urls: [
                        "https://example.com/login"
                    ],
                    risk_score: 54,
                    risk_level: "HIGH"
                }
            })
        });

        const data = await response.json();

        if (!data.success) {
            throw new Error("Graph API returned an error.");
        }

        renderAttackGraph(
            graphContainer,
            data.result
        );

    } catch (error) {
        console.error("Attack graph error:", error);

        graphContainer.innerHTML = `
            <div class="graph-error">
                <strong>GRAPH ERROR</strong>
                <br>
                Unable to load attack graph.
            </div>
        `;
    }
}


function renderAttackGraph(container, graphData) {

    container.innerHTML = "";

    const width = container.clientWidth || 900;
    const height = 430;

    const svgNS = "http://www.w3.org/2000/svg";

    const svg = document.createElementNS(
        svgNS,
        "svg"
    );

    svg.setAttribute("width", "100%");
    svg.setAttribute("height", height);
    svg.setAttribute("viewBox", `0 0 ${width} ${height}`);

    svg.style.background = "#07111f";
    svg.style.borderRadius = "12px";

    container.appendChild(svg);

    const nodes = graphData.nodes || [];
    const edges = graphData.edges || [];

    const positions = calculatePositions(
        nodes,
        width,
        height
    );

    // Draw edges first
    edges.forEach(edge => {

        const source = positions[edge.source];
        const target = positions[edge.target];

        if (!source || !target) {
            return;
        }

        const line = document.createElementNS(
            svgNS,
            "line"
        );

        line.setAttribute("x1", source.x);
        line.setAttribute("y1", source.y);
        line.setAttribute("x2", target.x);
        line.setAttribute("y2", target.y);

        line.setAttribute(
            "stroke",
            "#3b82f6"
        );

        line.setAttribute(
            "stroke-width",
            "2"
        );

        line.setAttribute(
            "stroke-opacity",
            "0.75"
        );

        svg.appendChild(line);

        // Relationship label
        const text = document.createElementNS(
            svgNS,
            "text"
        );

        text.setAttribute(
            "x",
            (source.x + target.x) / 2
        );

        text.setAttribute(
            "y",
            (source.y + target.y) / 2 - 6
        );

        text.setAttribute(
            "fill",
            "#94a3b8"
        );

        text.setAttribute(
            "font-size",
            "10"
        );

        text.setAttribute(
            "text-anchor",
            "middle"
        );

        text.textContent = edge.relationship;

        svg.appendChild(text);
    });


    // Draw nodes
    nodes.forEach(node => {

        const position = positions[node.id];

        if (!position) {
            return;
        }

        const group = document.createElementNS(
            svgNS,
            "g"
        );

        group.style.cursor = "pointer";


        const circle = document.createElementNS(
            svgNS,
            "circle"
        );

        circle.setAttribute(
            "cx",
            position.x
        );

        circle.setAttribute(
            "cy",
            position.y
        );

        circle.setAttribute(
            "r",
            "30"
        );

        circle.setAttribute(
            "fill",
            getNodeColor(node.node_type)
        );

        circle.setAttribute(
            "stroke",
            "#ffffff"
        );

        circle.setAttribute(
            "stroke-width",
            "2"
        );

        group.appendChild(circle);


        const typeText = document.createElementNS(
            svgNS,
            "text"
        );

        typeText.setAttribute(
            "x",
            position.x
        );

        typeText.setAttribute(
            "y",
            position.y + 4
        );

        typeText.setAttribute(
            "fill",
            "#ffffff"
        );

        typeText.setAttribute(
            "font-size",
            "9"
        );

        typeText.setAttribute(
            "font-weight",
            "bold"
        );

        typeText.setAttribute(
            "text-anchor",
            "middle"
        );

        typeText.textContent = node.node_type;

        group.appendChild(typeText);


        const label = document.createElementNS(
            svgNS,
            "text"
        );

        label.setAttribute(
            "x",
            position.x
        );

        label.setAttribute(
            "y",
            position.y + 52
        );

        label.setAttribute(
            "fill",
            "#e2e8f0"
        );

        label.setAttribute(
            "font-size",
            "11"
        );

        label.setAttribute(
            "text-anchor",
            "middle"
        );

        label.textContent =
            shortenLabel(node.label);

        group.appendChild(label);


        group.addEventListener(
            "click",
            () => {

                showNodeDetails(node);

            }
        );


        svg.appendChild(group);
    });


    // Graph title
    const title = document.createElementNS(
        svgNS,
        "text"
    );

    title.setAttribute(
        "x",
        "20"
    );

    title.setAttribute(
        "y",
        "28"
    );

    title.setAttribute(
        "fill",
        "#60a5fa"
    );

    title.setAttribute(
        "font-size",
        "14"
    );

    title.setAttribute(
        "font-weight",
        "bold"
    );

    title.textContent =
        "CYBERNEXUS Ω — LIVE ATTACK GRAPH";

    svg.appendChild(title);


    // Status
    const status = document.createElementNS(
        svgNS,
        "text"
    );

    status.setAttribute(
        "x",
        width - 20
    );

    status.setAttribute(
        "y",
        "28"
    );

    status.setAttribute(
        "fill",
        "#22c55e"
    );

    status.setAttribute(
        "font-size",
        "11"
    );

    status.setAttribute(
        "text-anchor",
        "end"
    );

    status.textContent =
        `${nodes.length} NODES • ${edges.length} LINKS`;

    svg.appendChild(status);
}


function calculatePositions(
    nodes,
    width,
    height
) {

    const positions = {};

    const centerX = width / 2;
    const centerY = height / 2;

    nodes.forEach(
        (node, index) => {

            const total = nodes.length;

            if (node.node_type === "INCIDENT") {

                positions[node.id] = {
                    x: centerX,
                    y: centerY
                };

            } else {

                const angle =
                    (index - 1) *
                    (Math.PI * 2 / Math.max(total - 1, 1));

                const radius =
                    Math.min(
                        width * 0.30,
                        145
                    );

                positions[node.id] = {

                    x:
                        centerX +
                        Math.cos(angle) * radius,

                    y:
                        centerY +
                        Math.sin(angle) * radius

                };
            }
        }
    );

    return positions;
}


function getNodeColor(nodeType) {

    switch (nodeType) {

        case "INCIDENT":
            return "#ef4444";

        case "URL":
            return "#f59e0b";

        case "DOMAIN":
            return "#22c55e";

        case "FILE":
            return "#a855f7";

        case "EMAIL":
            return "#06b6d4";

        default:
            return "#64748b";
    }
}


function shortenLabel(label) {

    if (!label) {
        return "Unknown";
    }

    if (label.length <= 28) {
        return label;
    }

    return label.substring(
        0,
        25
    ) + "...";
}


function showNodeDetails(node) {

    console.log(
        "CyberNexus Node:",
        node
    );

    const details = document.getElementById(
        "graphNodeDetails"
    );

    if (!details) {
        return;
    }

    details.innerHTML = `
        <strong>${node.node_type}</strong>
        <br>
        ${node.label}
    `;
}


// Start graph automatically
document.addEventListener(
    "DOMContentLoaded",
    () => {

        loadAttackGraph();

    }
);