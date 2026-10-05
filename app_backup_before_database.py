from flask import Flask, render_template, request, jsonify

from detection.url_detector import analyze_url
from detection.file_detector import analyze_file
from detection.email_detector import analyze_email

from core.risk_engine import calculate_unified_risk
from core.correlation_engine import correlate_security_signals
from core.incident_orchestrator import run_incident_orchestration

from graph.knowledge_graph import build_incident_graph

from forensics.evidence_ledger import (
    add_evidence,
    get_evidence,
    verify_ledger
)

import os
import tempfile


app = Flask(__name__)


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/")
def dashboard():
    return render_template("dashboard.html")


# ============================================================
# HEALTH
# ============================================================

@app.route("/health")
def health():
    return jsonify({
        "status": "operational",
        "system": "CYBERNEXUS Ω",
        "version": "1.0.0"
    })


# ============================================================
# API INFORMATION
# ============================================================

@app.route("/api")
def api_info():
    return jsonify({
        "system": "CYBERNEXUS Ω",
        "status": "operational",
        "endpoints": {
            "health": "/health",
            "url_analysis": "/api/analyze-url",
            "file_analysis": "/api/analyze-file",
            "email_analysis": "/api/analyze-email",
            "unified_risk": "/api/unified-risk",
            "correlation": "/api/correlate",
            "incident": "/api/incident",
            "graph": "/api/graph",
            "add_evidence": "/api/evidence",
            "get_evidence": "/api/evidence",
            "verify_evidence": "/api/evidence/verify"
        }
    })


# ============================================================
# URL ANALYSIS
# ============================================================

@app.route("/api/analyze-url", methods=["POST"])
def analyze_url_api():

    data = request.get_json(silent=True) or {}

    url = data.get("url", "").strip()

    if not url:
        return jsonify({
            "success": False,
            "error": "URL is required."
        }), 400

    try:

        result = analyze_url(url)

        return jsonify({
            "success": True,
            "result": result
        })

    except Exception as error:

        return jsonify({
            "success": False,
            "error": str(error)
        }), 500


# ============================================================
# FILE ANALYSIS
# ============================================================

@app.route("/api/analyze-file", methods=["POST"])
def analyze_file_api():

    if "file" not in request.files:
        return jsonify({
            "success": False,
            "error": "No file uploaded."
        }), 400

    uploaded_file = request.files["file"]

    if not uploaded_file.filename:
        return jsonify({
            "success": False,
            "error": "Filename is missing."
        }), 400

    temp_path = None

    try:

        suffix = os.path.splitext(
            uploaded_file.filename
        )[1]

        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=suffix
        ) as temp_file:

            uploaded_file.save(temp_file.name)
            temp_path = temp_file.name

        result = analyze_file(temp_path)

        return jsonify({
            "success": True,
            "result": result
        })

    except Exception as error:

        return jsonify({
            "success": False,
            "error": str(error)
        }), 500

    finally:

        if temp_path and os.path.exists(temp_path):

            try:
                os.remove(temp_path)

            except OSError:
                pass


# ============================================================
# EMAIL ANALYSIS
# ============================================================

@app.route("/api/analyze-email", methods=["POST"])
def analyze_email_api():

    data = request.get_json(silent=True) or {}

    email_text = data.get("email", "")
    sender = data.get("sender")

    if not email_text:

        return jsonify({
            "success": False,
            "error": "Email content is required."
        }), 400

    try:

        result = analyze_email(
            email_text,
            sender
        )

        return jsonify({
            "success": True,
            "result": result
        })

    except Exception as error:

        return jsonify({
            "success": False,
            "error": str(error)
        }), 500


# ============================================================
# UNIFIED RISK
# ============================================================

@app.route("/api/unified-risk", methods=["POST"])
def unified_risk_api():

    data = request.get_json(
        silent=True
    ) or {}

    url_result = data.get("url_result")
    file_result = data.get("file_result")
    email_result = data.get("email_result")

    try:

        result = calculate_unified_risk(
            url_result=url_result,
            file_result=file_result,
            email_result=email_result
        )

        return jsonify({
            "success": True,
            "result": result
        })

    except Exception as error:

        return jsonify({
            "success": False,
            "error": str(error)
        }), 500


# ============================================================
# CORRELATION ENGINE
# ============================================================

@app.route("/api/correlate", methods=["POST"])
def correlate_api():

    data = request.get_json(
        silent=True
    ) or {}

    url_result = data.get("url_result")
    file_result = data.get("file_result")
    email_result = data.get("email_result")

    try:

        result = correlate_security_signals(
            url_result=url_result,
            file_result=file_result,
            email_result=email_result
        )

        return jsonify({
            "success": True,
            "result": result
        })

    except Exception as error:

        return jsonify({
            "success": False,
            "error": str(error)
        }), 500


# ============================================================
# INCIDENT ORCHESTRATOR
# ============================================================

@app.route("/api/incident", methods=["POST"])
def incident_api():

    data = request.get_json(
        silent=True
    ) or {}

    url_result = data.get("url_result")
    file_result = data.get("file_result")
    email_result = data.get("email_result")

    if not any([
        url_result,
        file_result,
        email_result
    ]):
        return jsonify({
            "success": False,
            "error": "At least one security signal is required."
        }), 400

    try:

        result = run_incident_orchestration(
            url_result=url_result,
            file_result=file_result,
            email_result=email_result
        )

        return jsonify(result)

    except Exception as error:

        return jsonify({
            "success": False,
            "error": str(error)
        }), 500


# ============================================================
# KNOWLEDGE GRAPH
# ============================================================

@app.route("/api/graph", methods=["POST"])
def graph_api():

    data = request.get_json(
        silent=True
    ) or {}

    incident_id = data.get(
        "incident_id",
        "UNKNOWN-INCIDENT"
    )

    url_result = data.get(
        "url_result"
    )

    file_result = data.get(
        "file_result"
    )

    email_result = data.get(
        "email_result"
    )

    try:

        graph = build_incident_graph(
            incident_id=incident_id,
            url_result=url_result,
            file_result=file_result,
            email_result=email_result
        )

        return jsonify({
            "success": True,
            "result": graph
        })

    except Exception as error:

        return jsonify({
            "success": False,
            "error": str(error)
        }), 500


# ============================================================
# ADD EVIDENCE
# ============================================================

@app.route(
    "/api/evidence",
    methods=["POST"]
)
def add_evidence_api():

    data = request.get_json(
        silent=True
    ) or {}

    evidence_type = data.get(
        "evidence_type",
        "UNKNOWN"
    )

    source = data.get(
        "source",
        "Unknown"
    )

    evidence = data.get(
        "evidence",
        {}
    )

    risk_score = data.get(
        "risk_score",
        0
    )

    risk_level = data.get(
        "risk_level",
        "LOW"
    )

    try:

        record = add_evidence(
            evidence_type=evidence_type,
            source=source,
            evidence=evidence,
            risk_score=risk_score,
            risk_level=risk_level
        )

        return jsonify({
            "success": True,
            "record": record
        })

    except Exception as error:

        return jsonify({
            "success": False,
            "error": str(error)
        }), 500


# ============================================================
# GET EVIDENCE
# ============================================================

@app.route(
    "/api/evidence",
    methods=["GET"]
)
def get_evidence_api():

    try:

        records = get_evidence()

        return jsonify({
            "success": True,
            "records": records,
            "count": len(records)
        })

    except Exception as error:

        return jsonify({
            "success": False,
            "error": str(error)
        }), 500


# ============================================================
# VERIFY EVIDENCE
# ============================================================

@app.route(
    "/api/evidence/verify",
    methods=["GET"]
)
def verify_evidence_api():

    try:

        result = verify_ledger()

        return jsonify({
            "success": True,
            "verification": result
        })

    except Exception as error:

        return jsonify({
            "success": False,
            "error": str(error)
        }), 500


# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":

    print("=" * 60)
    print("        CYBERNEXUS Ω SECURITY PLATFORM")
    print("=" * 60)

    print(
        "Dashboard   : http://127.0.0.1:5000"
    )

    print(
        "Health      : http://127.0.0.1:5000/health"
    )

    print(
        "API         : http://127.0.0.1:5000/api"
    )

    print(
        "Correlation : http://127.0.0.1:5000/api/correlate"
    )

    print(
        "Incident    : http://127.0.0.1:5000/api/incident"
    )

    print(
        "Graph       : http://127.0.0.1:5000/api/graph"
    )

    print("=" * 60)

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
        use_reloader=False
    )