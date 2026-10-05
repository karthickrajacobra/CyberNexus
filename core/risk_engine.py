# core/risk_engine.py

def calculate_unified_risk(
    url_result=None,
    file_result=None,
    email_result=None
):
    """
    Combines URL, File and Email detector results
    into one unified cybersecurity risk assessment.
    """

    results = []

    if url_result:
        results.append({
            "source": "URL",
            "score": url_result.get("risk_score", 0),
            "level": url_result.get("risk_level", "LOW")
        })

    if file_result:
        results.append({
            "source": "FILE",
            "score": file_result.get("risk_score", 0),
            "level": file_result.get("risk_level", "LOW")
        })

    if email_result:
        results.append({
            "source": "EMAIL",
            "score": email_result.get("risk_score", 0),
            "level": email_result.get("risk_level", "LOW")
        })

    if not results:
        return {
            "overall_score": 0,
            "overall_level": "LOW",
            "sources": [],
            "explanation": "No security signals were provided."
        }

    # Average score
    total_score = sum(item["score"] for item in results)
    average_score = round(total_score / len(results))

    # Highest individual risk
    highest_score = max(item["score"] for item in results)

    # Final score gives extra weight to the strongest signal
    unified_score = round(
        (average_score * 0.6) +
        (highest_score * 0.4)
    )

    unified_score = min(unified_score, 100)

    # Determine overall risk level
    if unified_score >= 70:
        overall_level = "CRITICAL"
    elif unified_score >= 45:
        overall_level = "HIGH"
    elif unified_score >= 20:
        overall_level = "MEDIUM"
    else:
        overall_level = "LOW"

    # Generate explanation
    explanations = []

    for item in results:
        explanations.append(
            f"{item['source']} detector reported "
            f"{item['level']} risk with score {item['score']}."
        )

    return {
        "overall_score": unified_score,
        "overall_level": overall_level,
        "sources": results,
        "explanation": explanations
    }