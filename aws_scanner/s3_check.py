import boto3

def check_s3_buckets():
    s3 = boto3.client("s3", region_name="eu-west-1")

    results = []

    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except Exception as e:
        return [{
            "service": "S3",
            "resource": "S3",
            "issue": f"Unable to list S3 buckets: {str(e)}",
            "severity": "High",
            "status": "ERROR",
            "recommendation": "Check that the required S3 read permissions are assigned."
        }]

    if not buckets:
        results.append({
            "service": "S3",
            "resource": "S3",
            "issue": "No S3 buckets found",
            "severity": "Low",
            "status": "PASS",
            "recommendation": "No action required."
        })
        return results

    for bucket in buckets:
        results.append({
            "service": "S3",
            "resource": bucket["Name"],
            "issue": "Bucket discovered. Detailed public access and encryption validation requires additional bucket-level checks.",
            "severity": "Low",
            "status": "PASS",
            "recommendation": "Review S3 Block Public Access and default encryption settings for this bucket."
        })

    return results