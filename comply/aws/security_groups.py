"""AWS Security Group compliance checks."""

from .base import BaseAWSScanner, Finding

# Ports that should NEVER be open to the world
SENSITIVE_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MSSQL",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
    5900: "VNC",
    23: "Telnet",
    21: "FTP",
    445: "SMB",
    135: "RPC",
}


class SecurityGroupScanner(BaseAWSScanner):
    """Scans AWS Security Groups for overly permissive rules."""

    def scan(self) -> list:
        ec2 = self.get_client("ec2")
        self.findings = []

        try:
            paginator = ec2.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page["SecurityGroups"]:
                    self._check_ingress_rules(sg)
                    self._check_unrestricted_egress(sg)
        except Exception as e:
            self.add_finding(
                Finding(
                    check_id="SG-ERR-001",
                    title="Security Group Scan Error",
                    resource="N/A",
                    status=Finding.STATUS_WARN,
                    severity=Finding.SEVERITY_INFO,
                    description=f"Could not scan security groups: {str(e)}",
                    remediation="Verify AWS credentials and permissions.",
                )
            )

        return self.get_findings()

    def _check_ingress_rules(self, sg: dict):
        sg_id = sg["GroupId"]
        sg_name = sg.get("GroupName", "Unknown")

        for rule in sg.get("IpPermissions", []):
            from_port = rule.get("FromPort", 0)
            to_port = rule.get("ToPort", 65535)

            # Check IPv4 ranges
            for ip_range in rule.get("IpRanges", []):
                cidr = ip_range.get("CidrIp", "")
                if cidr == "0.0.0.0/0":
                    self._evaluate_open_rule(sg_id, sg_name, from_port, to_port, cidr)

            # Check IPv6 ranges
            for ip_range in rule.get("Ipv6Ranges", []):
                cidr = ip_range.get("CidrIpv6", "")
                if cidr == "::/0":
                    self._evaluate_open_rule(sg_id, sg_name, from_port, to_port, cidr)

    def _evaluate_open_rule(self, sg_id, sg_name, from_port, to_port, cidr):
        # Check if any sensitive port falls in the range
        for port, service in SENSITIVE_PORTS.items():
            if from_port <= port <= to_port:
                self.add_finding(
                    Finding(
                        check_id=f"SG-001-{port}",
                        title=f"{service} (port {port}) open to the internet",
                        resource=f"{sg_id} ({sg_name})",
                        status=Finding.STATUS_FAIL,
                        severity=Finding.SEVERITY_CRITICAL if port in [22, 3389, 3306, 5432] else Finding.SEVERITY_HIGH,
                        description=(
                            f"Security group {sg_id} allows inbound traffic on port {port} "
                            f"({service}) from {cidr}. This exposes the service to the entire internet."
                        ),
                        remediation=(
                            f"Restrict inbound access on port {port} to specific trusted IP ranges. "
                            f"Use VPN or bastion hosts for remote access."
                        ),
                        frameworks={
                            "CIS_AWS": ["4.1", "4.2"],
                            "SOC2": ["CC6.1", "CC6.6"],
                            "ISO27001": ["A.13.1.1", "A.13.1.3"],
                        },
                    )
                )

        # Check for fully open range (all ports)
        if from_port == 0 and to_port == 65535:
            self.add_finding(
                Finding(
                    check_id="SG-002",
                    title="All ports open to the internet",
                    resource=f"{sg_id} ({sg_name})",
                    status=Finding.STATUS_FAIL,
                    severity=Finding.SEVERITY_CRITICAL,
                    description=(
                        f"Security group {sg_id} allows ALL inbound traffic (ports 0-65535) "
                        f"from {cidr}. This is a critical misconfiguration."
                    ),
                    remediation="Immediately restrict to only required ports and trusted IP ranges.",
                    frameworks={
                        "CIS_AWS": ["4.1", "4.2", "4.3"],
                        "SOC2": ["CC6.1", "CC6.6", "CC7.1"],
                        "ISO27001": ["A.13.1.1", "A.13.1.3", "A.9.1.2"],
                    },
                )
            )

    def _check_unrestricted_egress(self, sg: dict):
        sg_id = sg["GroupId"]
        sg_name = sg.get("GroupName", "Unknown")

        for rule in sg.get("IpPermissionsEgress", []):
            for ip_range in rule.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":
                    from_port = rule.get("FromPort")
                    to_port = rule.get("ToPort")
                    if from_port is None and to_port is None:
                        self.add_finding(
                            Finding(
                                check_id="SG-003",
                                title="Unrestricted egress to the internet",
                                resource=f"{sg_id} ({sg_name})",
                                status=Finding.STATUS_WARN,
                                severity=Finding.SEVERITY_MEDIUM,
                                description=(
                                    f"Security group {sg_id} allows all outbound traffic to 0.0.0.0/0. "
                                    f"While common, this can enable data exfiltration."
                                ),
                                remediation=(
                                    "Consider restricting outbound traffic to only required "
                                    "destinations and ports."
                                ),
                                frameworks={
                                    "CIS_AWS": ["4.4"],
                                    "SOC2": ["CC6.6"],
                                    "ISO27001": ["A.13.1.1"],
                                },
                            )
                        )
