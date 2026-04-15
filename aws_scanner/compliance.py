def calculate_compliance(results):
    total = len(results)

    if total == 0:
        return {
            "compliance_score": 100,
            "high_risk": 0,
            "medium_risk": 0,
            "low_risk": 0
        }

    high = sum(1 for r in results if r["severity"] == "High")
    medium = sum(1 for r in results if r["severity"] == "Medium")
    low = sum(1 for r in results if r["severity"] == "Low")

    passed = sum(1 for r in results if r["status"] == "PASS")

    compliance_score = round((passed / total) * 100)

    return {
        "compliance_score": compliance_score,
        "high_risk": high,
        "medium_risk": medium,
        "low_risk": low
    }