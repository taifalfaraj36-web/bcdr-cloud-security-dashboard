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
            "recommendation": "Ensure the IAM role/user has permissions: iam:ListUsers, iam:GetLoginProfile, iam:ListMFADevices.",
            "recommendation_link": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html"
        }]

    for user in users:
        username = user["UserName"]

        has_console = False
        has_mfa = False

        # Check console access
        try:
            iam.get_login_profile(UserName=username)
            has_console = True
        except iam.exceptions.NoSuchEntityException:
            has_console = False
        except Exception:
            has_console = False

        # Check MFA only if console access exists
        if has_console:
            try:
                mfa = iam.list_mfa_devices(UserName=username)
                has_mfa = len(mfa.get("MFADevices", [])) > 0
            except Exception:
                has_mfa = False

        # 🔴 Case 1: Console user WITHOUT MFA (real risk)
        if has_console and not has_mfa:
            results.append({
                "service": "IAM",
                "resource": username,
                "issue": "IAM user has console access but MFA is not enabled",
                "severity": "High",
                "status": "FAIL",
                "recommendation": "Go to AWS Console → IAM → Users → select this user → Security credentials → Assigned MFA device → Manage → Assign MFA device → Use an authenticator app.",
                "recommendation_link": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable.html"
            })

        # 🟡 Case 2: Console user WITH MFA
        elif has_console and has_mfa:
            results.append({
                "service": "IAM",
                "resource": username,
                "issue": "MFA is enabled for this IAM console user",
                "severity": "Low",
                "status": "PASS",
                "recommendation": "No action required.",
                "recommendation_link": "#"
            })

        # 🟢 Case 3: API-only user (IMPORTANT FIX)
        else:
            results.append({
                "service": "IAM",
                "resource": username,
                "issue": "IAM user does not have console access (API-only user)",
                "severity": "Low",
                "status": "PASS",
                "recommendation": "No MFA required for API-only users. Ensure access keys are rotated regularly and follow least privilege.",
                "recommendation_link": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"
            })

    return results