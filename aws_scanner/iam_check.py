import boto3

def check_iam_mfa():
    iam = boto3.client('iam', region_name='eu-west-1')
    
    users = iam.list_users()['Users']
    results = []
    
    for user in users:
        username = user['UserName']
        mfa = iam.list_mfa_devices(UserName=username)
        
        if not mfa['MFADevices']:
            status = "FAIL"
            issue = "MFA not enabled"
            severity = "High"
        else:
            status = "PASS"
            issue = "MFA enabled"
            severity = "Low"
        
        results.append({
            "service": "IAM",
            "resource": username,
            "issue": issue,
            "severity": severity,
            "status": status
        })
    
    return results