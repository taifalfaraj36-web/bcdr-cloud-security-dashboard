import boto3
import botocore

def check_iam_mfa():
    config_timeout = botocore.config.Config(
        retries={"max_attempts": 2},
        connect_timeout=3,
        read_timeout=5
    )

    iam = boto3.client("iam", region_name="eu-west-1", config=config_timeout)

    results = []

    try:
        users = iam.list_users().get("Users", [])
    except Exception as e:
        return [{
            "service": "IAM",
            "resource": "IAM",
            "issue": f"Unable to list IAM users: {str(e)}",
            "severity": "High",
            "status": "ERROR",
            "recommendation": "Ensure the IAM role or user has these read-only permissions: iam:ListUsers, iam:GetLoginProfile, and iam:ListMFADevices.",
            "recommendation_link": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html"
        }]

    for user in users:
        username = user["UserName"]

        has_console = False
        has_mfa = False

        try:
            iam.get_login_profile(UserName=username)
            has_console = True
        except iam.exceptions.NoSuchEntityException:
            has_console = False
        except Exception:
            has_console = False

        if has_console:
            try:
                mfa = iam.list_mfa_devices(UserName=username)
                has_mfa = len(mfa.get("MFADevices", [])) > 0
            except Exception:
                has_mfa = False

        if has_console and not has_mfa:
            results.append({
                "service": "IAM",
                "resource": username,
                "issue": "IAM user has console access without MFA enabled",
                "severity": "High",
                "status": "FAIL",
                "recommendation": "Go to AWS Console → IAM → Users → select this user → Security credentials → Assigned MFA device → Manage → Assign MFA device.",
                "recommendation_link": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable.html"
            })
        else:
            results.append({
                "service": "IAM",
                "resource": username,
                "issue": "MFA enabled or user does not have console access",
                "severity": "Low",
                "status": "PASS",
                "recommendation": "No action required.",
                "recommendation_link": "#"
            })

    return results