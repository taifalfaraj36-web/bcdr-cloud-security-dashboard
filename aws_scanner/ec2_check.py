import boto3

# Ports commonly considered more sensitive if exposed publicly
HIGH_RISK_PORTS = {22, 3389, 3306, 5432, 6379, 27017}
MEDIUM_RISK_PORTS = {80, 443, 8080, 8443}

def classify_severity(from_port, to_port):
    # Handle "all ports" or unknown ports
    if from_port == "All" or to_port == "All":
        return "High"

    # Check every port in the range
    try:
        port_range = range(int(from_port), int(to_port) + 1)
    except Exception:
        return "Unknown"

    if any(port in HIGH_RISK_PORTS for port in port_range):
        return "High"
    if any(port in MEDIUM_RISK_PORTS for port in port_range):
        return "Medium"
    return "Low"

def check_ec2_security_groups():
    ec2 = boto3.client("ec2", region_name="eu-west-1")
    results = []

    response = ec2.describe_security_groups()
    security_groups = response.get("SecurityGroups", [])

    for sg in security_groups:
        sg_name = sg.get("GroupName", "Unknown")
        sg_id = sg.get("GroupId", "Unknown")

        for permission in sg.get("IpPermissions", []):
            from_port = permission.get("FromPort", "All")
            to_port = permission.get("ToPort", "All")

            # IPv4 ranges
            for ip_range in permission.get("IpRanges", []):
                cidr = ip_range.get("CidrIp", "")
                if cidr == "0.0.0.0/0":
                    severity = classify_severity(from_port, to_port)
                    results.append({
                        "service": "EC2",
                        "resource": f"{sg_name} ({sg_id})",
                        "issue": f"Port {from_port}-{to_port} open to the internet via IPv4",
                        "severity": severity,
                        "status": "FAIL"
                    })

            # IPv6 ranges
            for ipv6_range in permission.get("Ipv6Ranges", []):
                cidr_ipv6 = ipv6_range.get("CidrIpv6", "")
                if cidr_ipv6 == "::/0":
                    severity = classify_severity(from_port, to_port)
                    results.append({
                        "service": "EC2",
                        "resource": f"{sg_name} ({sg_id})",
                        "issue": f"Port {from_port}-{to_port} open to the internet via IPv6",
                        "severity": severity,
                        "status": "FAIL"
                    })

    if not results:
        results.append({
            "service": "EC2",
            "resource": "Security Groups",
            "issue": "No public inbound rules detected",
            "severity": "None",
            "status": "PASS"
        })

    return results