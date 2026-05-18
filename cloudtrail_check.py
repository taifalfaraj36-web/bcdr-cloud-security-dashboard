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
                "recommendation": "Go to AWS Console → CloudTrail → Create trail → Enable logging → choose an S3 bucket → Save.",
                "recommendation_link": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html"
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
                        "recommendation": "No action required.",
                        "recommendation_link": "#"
                    })
                else:
                    results.append({
                        "service": "CloudTrail",
                        "resource": name,
                        "issue": "CloudTrail logging disabled",
                        "severity": "Critical",
                        "status": "FAIL",
                        "recommendation": "Go to AWS Console → CloudTrail → Trails → select this trail → Start logging.",
                        "recommendation_link": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html"
                    })

    except Exception as e:
        results.append({
            "service": "CloudTrail",
            "resource": "N/A",
            "issue": f"Unable to verify CloudTrail configuration: {str(e)}",
            "severity": "High",
            "status": "ERROR",
            "recommendation": "Ensure the IAM role/user has permissions: cloudtrail:DescribeTrails and cloudtrail:GetTrailStatus.",
            "recommendation_link": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/security_iam_id-based-policy-examples.html"
        })

    return results