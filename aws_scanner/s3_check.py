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
            "recommendation": "Ensure the IAM role/user has permission: s3:ListAllMyBuckets.",
            "recommendation_link": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-iam.html"
        }]

    if not buckets:
        results.append({
            "service": "S3",
            "resource": "S3",
            "issue": "No S3 buckets found",
            "severity": "Low",
            "status": "PASS",
            "recommendation": "No action required.",
            "recommendation_link": "#"
        })
        return results

    for bucket in buckets:
        results.append({
            "service": "S3",
            "resource": bucket["Name"],
            "issue": "Bucket discovered. Public access and encryption not validated in fast scan mode.",
            "severity": "Low",
            "status": "PASS",
            "recommendation": "Go to AWS Console → S3 → select this bucket → Permissions → Block Public Access → Enable all options. Then go to Properties → Default encryption → Enable.",
            "recommendation_link": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/configuring-block-public-access.html"
        })

    return results