import boto3

def check_cloudtrail():
    cloudtrail = boto3.client("cloudtrail", region_name="eu-west-1")
    results = []

    try:
        trails = cloudtrail.describe_trails().get("trailList", [])

        if not trails:
            results.append({
                "service": "CloudTrail",
                "resource": "Account",
                "issue": "No CloudTrail trails configured",
                "severity": "High",
                "status": "FAIL"
            })
        else:
            for trail in trails:
                name = trail.get("Name", "Unknown")

                # Check if logging is enabled
                status = cloudtrail.get_trail_status(Name=name)

                if status.get("IsLogging"):
                    results.append({
                        "service": "CloudTrail",
                        "resource": name,
                        "issue": "Logging enabled",
                        "severity": "None",
                        "status": "PASS"
                    })
                else:
                    results.append({
                        "service": "CloudTrail",
                        "resource": name,
                        "issue": "Logging disabled",
                        "severity": "High",
                        "status": "FAIL"
                    })

    except Exception as e:
        results.append({
            "service": "CloudTrail",
            "resource": "N/A",
            "issue": str(e),
            "severity": "Unknown",
            "status": "ERROR"
        })

    return results