def calculate_compliance(results):
    total = len(results)

    if total == 0:
        return {
            "compliance_score": 100,
            "critical_risk": 0,
            "high_risk": 0,
            "medium_risk": 0,
            "low_risk": 0
        }

    critical = sum(1 for r in results if r.get("severity", "").lower() == "critical")
    high = sum(1 for r in results if r.get("severity", "").lower() == "high")
    medium = sum(1 for r in results if r.get("severity", "").lower() == "medium")
    low = sum(1 for r in results if r.get("severity", "").lower() == "low")

    passed = sum(1 for r in results if r.get("status", "").upper() == "PASS")

    compliance_score = round((passed / total) * 100)

    return {
        "compliance_score": compliance_score,
        "critical_risk": critical,
        "high_risk": high,
        "medium_risk": medium,
        "low_risk": low
    }