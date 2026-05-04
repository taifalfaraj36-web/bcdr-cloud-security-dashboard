import boto3

CRITICAL_RISK_PORTS = {22, 3389, 3306, 5432, 6379, 27017}
HIGH_RISK_PORTS = {21, 23, 25, 53, 110, 143}
MEDIUM_RISK_PORTS = {80, 443, 8080, 8443}


def classify_severity(from_port, to_port):
    if from_port == "All" or to_port == "All":
        return "Critical"

    try:
        start_port = int(from_port)
        end_port = int(to_port)
        port_range = range(start_port, end_port + 1)
    except Exception:
        return "High"

    if any(port in CRITICAL_RISK_PORTS for port in port_range):
        return "Critical"

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
            protocol = permission.get("IpProtocol", "")
            from_port = permission.get("FromPort", "All")
            to_port = permission.get("ToPort", "All")

            if protocol == "-1":
                port_display = "All traffic"
            elif protocol == "icmp":
                prot_display = "ICMP"    
            else:
                port_display = f"{from_port}-{to_port}"

            for ip_range in permission.get("IpRanges", []):
                cidr = ip_range.get("CidrIp", "")
                if cidr == "0.0.0.0/0":
                    severity = classify_severity(from_port, to_port)

                    results.append({
                        "service": "EC2",
                        "resource": f"{sg_name} ({sg_id})",
                        "issue": f"Port {port_display} open to the internet via IPv4",
                        "severity": severity,
                        "status": "FAIL",
                        "recommendation": "Go to AWS Console → EC2 → Security Groups → select this security group → Edit inbound rules → remove 0.0.0.0/0 or restrict it to a trusted IP address only.",
                        "recommendation_link": "https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html"
                    })

            for ipv6_range in permission.get("Ipv6Ranges", []):
                cidr_ipv6 = ipv6_range.get("CidrIpv6", "")
                if cidr_ipv6 == "::/0":
                    severity = classify_severity(from_port, to_port)

                    results.append({
                        "service": "EC2",
                        "resource": f"{sg_name} ({sg_id})",
                        "issue": f"Port {port_display} open to the internet via IPv6",
                        "severity": severity,
                        "status": "FAIL",
                        "recommendation": "Go to AWS Console → EC2 → Security Groups → select this security group → Edit inbound rules → remove ::/0 or restrict IPv6 access to trusted addresses only.",
                        "recommendation_link": "https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html"
                    })

    if not results:
        results.append({
            "service": "EC2",
            "resource": "Security Groups",
            "issue": "No public inbound rules detected",
            "severity": "Low",
            "status": "PASS",
            "recommendation": "No action required.",
            "recommendation_link": "#"
        })

    return results