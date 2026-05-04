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
                "severity": "Critical",
                "status": "FAIL",
                "recommendation": "Enable CloudTrail to log account activity for security monitoring and auditing."
            })
        else:
            for trail in trails:
                name = trail.get("Name", "Unknown")

                status = cloudtrail.get_trail_status(Name=name)

                if status.get("IsLogging"):
                    results.append({
                        "service": "CloudTrail",
                        "resource": name,
                        "issue": "CloudTrail logging enabled",
                        "severity": "Low",
                        "status": "PASS",
                        "recommendation": "No action required."
                    })
                else:
                    results.append({
                        "service": "CloudTrail",
                        "resource": name,
                        "issue": "CloudTrail logging disabled",
                        "severity": "Critical",
                        "status": "FAIL",
                        "recommendation": "Enable logging for this trail to ensure activity is recorded."
                    })

    except Exception as e:
        results.append({
            "service": "CloudTrail",
            "resource": "N/A",
            "issue": f"Unable to verify CloudTrail configuration: {str(e)}",
            "severity": "High",
            "status": "ERROR",
            "recommendation": "Check AWS permissions and CloudTrail configuration."
        })

    return results