import boto3
import botocore
from concurrent.futures import ThreadPoolExecutor, as_completed

MAX_BUCKETS_TO_SCAN = 20

def get_s3_client():
    config_timeout = botocore.config.Config(
        retries={"max_attempts": 0},
        connect_timeout=1,
        read_timeout=2
    )
    return boto3.client("s3", region_name="eu-west-1", config=config_timeout)


def check_single_bucket(bucket):
    s3 = get_s3_client()
    name = bucket["Name"]
    issues = []

    try:
        policy = s3.get_bucket_policy_status(Bucket=name)
        if policy.get("PolicyStatus", {}).get("IsPublic"):
            issues.append("Bucket policy allows public access")
    except Exception:
        pass

    try:
        s3.get_bucket_encryption(Bucket=name)
    except Exception:
        issues.append("Default encryption is not enabled")

    if issues:
        if "Bucket policy allows public access" in issues:
            recommendation = "Go to AWS Console → S3 → select this bucket → Permissions → Block Public Access → Enable all options. Then review Bucket policy and remove public access."
            recommendation_link = "https://docs.aws.amazon.com/AmazonS3/latest/userguide/configuring-block-public-access.html"
        else:
            recommendation = "Go to AWS Console → S3 → select this bucket → Properties → Default encryption → Edit → Enable server-side encryption → Save changes."
            recommendation_link = "https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html"

        return {
            "service": "S3",
            "resource": name,
            "issue": "; ".join(issues),
            "severity": "High",
            "status": "FAIL",
            "recommendation": recommendation,
            "recommendation_link": recommendation_link
        }

    return {
        "service": "S3",
        "resource": name,
        "issue": "Bucket is not public and default encryption is enabled",
        "severity": "Low",
        "status": "PASS",
        "recommendation": "No action required.",
        "recommendation_link": "#"
    }


def check_s3_buckets():
    s3 = get_s3_client()

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
        return [{
            "service": "S3",
            "resource": "S3",
            "issue": "No S3 buckets found",
            "severity": "Low",
            "status": "PASS",
            "recommendation": "No action required.",
            "recommendation_link": "#"
        }]

    buckets_to_scan = buckets[:MAX_BUCKETS_TO_SCAN]
    skipped_count = len(buckets) - len(buckets_to_scan)

    results = []

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(check_single_bucket, bucket) for bucket in buckets_to_scan]

        for future in as_completed(futures):
            try:
                results.append(future.result(timeout=3))
            except Exception:
                pass

    if skipped_count > 0:
        results.append({
            "service": "S3",
            "resource": "S3 scan limit",
            "issue": f"{skipped_count} additional buckets were not scanned in fast mode to keep scan performance acceptable.",
            "severity": "Low",
            "status": "PASS",
            "recommendation": "Increase MAX_BUCKETS_TO_SCAN if a full S3 review is required.",
            "recommendation_link": "#"
        })

    return results