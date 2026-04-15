import boto3

def check_s3_buckets():
    s3 = boto3.client("s3", region_name="eu-west-1")

    buckets = s3.list_buckets().get("Buckets", [])

    results = []
    for bucket in buckets:
        results.append({
            "service": "S3",
            "resource": bucket["Name"],
            "issue": "Bucket discovered",
            "severity": "None",
            "status": "PASS"
        })

    return results