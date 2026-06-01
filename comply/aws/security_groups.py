"""AWS Security Group compliance checks with audit reasoning."""

from .base import BaseAWSScanner, Finding

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

DOMAIN = "Network Security"


class SecurityGroupScanner(BaseAWSScanner):
    """Scans AWS Security Groups for overly permissive rules."""

    def scan(self) -> list:
        ec2 = self.get_client("ec2")
        self.findings = []

        try:
            paginator = ec2.get_paginator("describe_security_groups")
            all_sgs = []
            for page in paginator.paginate():
                for sg in page["SecurityGroups"]:
                    all_sgs.append(sg)
                    self._check_ingress_rules(sg)
                    self._check_unrestricted_egress(sg)
                    self._check_default_sg(sg)

            # If we scanned SGs and none had open sensitive ports, add a PASS
            if all_sgs:
                self._check_sg_inventory(all_sgs)

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
                    reasoning="The scanner was unable to connect to the EC2 API to retrieve security group configurations. This may indicate insufficient IAM permissions or a network connectivity issue.",
                    control_domain=DOMAIN,
                )
            )

        return self.get_findings()

    def _check_sg_inventory(self, all_sgs):
        """Report on total SG count for visibility."""
        self.add_finding(
            Finding(
                check_id="SG-INV-001",
                title=f"Security group inventory: {len(all_sgs)} groups scanned",
                resource="All Security Groups",
                status=Finding.STATUS_PASS,
                severity=Finding.SEVERITY_INFO,
                description=f"Scanned {len(all_sgs)} security groups across the account.",
                remediation="No action required. Review periodically to remove unused security groups.",
                reasoning=f"A total of {len(all_sgs)} security groups were enumerated and inspected. Maintaining an accurate inventory of network access controls is required under SOC 2 CC6.1 (Logical Access) and ISO 27001 A.13.1.1 (Network Controls). Each group was evaluated for overly permissive inbound and outbound rules.",
                control_domain=DOMAIN,
                frameworks={
                    "SOC2": ["CC6.1"],
                    "ISO27001": ["A.13.1.1"],
                },
            )
        )

    def _check_ingress_rules(self, sg: dict):
        sg_id = sg["GroupId"]
        sg_name = sg.get("GroupName", "Unknown")
        has_open_sensitive = False

        for rule in sg.get("IpPermissions", []):
            from_port = rule.get("FromPort", 0)
            to_port = rule.get("ToPort", 65535)

            for ip_range in rule.get("IpRanges", []):
                cidr = ip_range.get("CidrIp", "")
                if cidr == "0.0.0.0/0":
                    has_open_sensitive = True
                    self._evaluate_open_rule(sg_id, sg_name, from_port, to_port, cidr)

            for ip_range in rule.get("Ipv6Ranges", []):
                cidr = ip_range.get("CidrIpv6", "")
                if cidr == "::/0":
                    has_open_sensitive = True
                    self._evaluate_open_rule(sg_id, sg_name, from_port, to_port, cidr)

        # If no open-to-world rules found, report a PASS
        if not has_open_sensitive:
            self.add_finding(
                Finding(
                    check_id="SG-001-PASS",
                    title="Security group has no unrestricted inbound rules",
                    resource=f"{sg_id} ({sg_name})",
                    status=Finding.STATUS_PASS,
                    severity=Finding.SEVERITY_INFO,
                    description=f"Security group {sg_id} ({sg_name}) does not allow inbound traffic from 0.0.0.0/0 or ::/0 on any sensitive ports.",
                    remediation="No action required.",
                    reasoning=f"Inspected all inbound rules for security group {sg_id} ({sg_name}). No rules were found that permit unrestricted access (0.0.0.0/0 or ::/0) to sensitive services such as SSH (22), RDP (3389), or database ports. This is compliant with CIS AWS 4.1–4.2, SOC 2 CC6.1/CC6.6, and ISO 27001 A.13.1.1.",
                    control_domain=DOMAIN,
                    frameworks={
                        "CIS_AWS": ["4.1", "4.2"],
                        "SOC2": ["CC6.1", "CC6.6"],
                        "ISO27001": ["A.13.1.1"],
                    },
                )
            )

    def _evaluate_open_rule(self, sg_id, sg_name, from_port, to_port, cidr):
        for port, service in SENSITIVE_PORTS.items():
            if from_port <= port <= to_port:
                is_critical = port in [22, 3389, 3306, 5432]
                self.add_finding(
                    Finding(
                        check_id=f"SG-001-{port}",
                        title=f"{service} (port {port}) open to the internet",
                        resource=f"{sg_id} ({sg_name})",
                        status=Finding.STATUS_FAIL,
                        severity=Finding.SEVERITY_CRITICAL if is_critical else Finding.SEVERITY_HIGH,
                        description=(
                            f"Security group {sg_id} allows inbound traffic on port {port} "
                            f"({service}) from {cidr}. This exposes the service to the entire internet."
                        ),
                        remediation=(
                            f"Restrict inbound access on port {port} to specific trusted IP ranges. "
                            f"Use VPN or bastion hosts for remote access."
                        ),
                        reasoning=(
                            f"FAIL: Security group {sg_id} ({sg_name}) contains an inbound rule allowing traffic on port {port} ({service}) "
                            f"from source {cidr}, which represents the entire {'IPv4' if cidr == '0.0.0.0/0' else 'IPv6'} internet. "
                            f"This violates the principle of least privilege for network access. "
                            f"{'SSH and RDP ports are primary attack vectors for brute-force and credential-stuffing attacks. ' if port in [22, 3389] else ''}"
                            f"{'Database ports exposed to the internet risk unauthorized data access and SQL injection attacks. ' if port in [3306, 5432, 1433, 27017] else ''}"
                            f"CIS AWS Benchmark 4.1 requires no security groups allow ingress from 0.0.0.0/0 to port 22; "
                            f"4.2 requires the same for port 3389. SOC 2 CC6.1 requires logical access controls restrict "
                            f"unauthorized access, and CC6.6 requires secure boundaries for data transmission."
                        ),
                        control_domain=DOMAIN,
                        frameworks={
                            "CIS_AWS": ["4.1", "4.2"],
                            "SOC2": ["CC6.1", "CC6.6"],
                            "ISO27001": ["A.13.1.1", "A.13.1.3"],
                        },
                    )
                )

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
                    reasoning=(
                        f"FAIL: Security group {sg_id} ({sg_name}) permits inbound traffic on ALL ports (0-65535) from {cidr}. "
                        f"This is equivalent to having no firewall — every service running on any associated instance is fully exposed "
                        f"to the internet. This is a critical violation of CIS AWS 4.1, 4.2, and 4.3 (restrict default SG traffic), "
                        f"SOC 2 CC6.1 (logical access controls), CC6.6 (transmission security), and CC7.1 (vulnerability management). "
                        f"An attacker can scan all ports, discover running services, and exploit any unpatched vulnerabilities."
                    ),
                    control_domain=DOMAIN,
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

        has_unrestricted_egress = False
        for rule in sg.get("IpPermissionsEgress", []):
            for ip_range in rule.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":
                    from_port = rule.get("FromPort")
                    to_port = rule.get("ToPort")
                    if from_port is None and to_port is None:
                        has_unrestricted_egress = True
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
                                reasoning=(
                                    f"WARNING: Security group {sg_id} ({sg_name}) has an outbound rule allowing all traffic to 0.0.0.0/0 "
                                    f"on all ports. While AWS creates this as a default egress rule, unrestricted outbound access "
                                    f"means a compromised instance could exfiltrate data to any external destination, establish "
                                    f"reverse shells, or communicate with command-and-control servers. CIS AWS 4.4 recommends "
                                    f"restricting egress to only necessary traffic. SOC 2 CC6.6 requires controls over data "
                                    f"transmission boundaries."
                                ),
                                control_domain=DOMAIN,
                                frameworks={
                                    "CIS_AWS": ["4.4"],
                                    "SOC2": ["CC6.6"],
                                    "ISO27001": ["A.13.1.1"],
                                },
                            )
                        )

    def _check_default_sg(self, sg: dict):
        """Check if the default security group has any rules (it shouldn't)."""
        if sg.get("GroupName") != "default":
            return

        sg_id = sg["GroupId"]
        has_ingress = len(sg.get("IpPermissions", [])) > 0

        if has_ingress:
            self.add_finding(
                Finding(
                    check_id="SG-004",
                    title="Default security group has inbound rules",
                    resource=f"{sg_id} (default)",
                    status=Finding.STATUS_FAIL,
                    severity=Finding.SEVERITY_MEDIUM,
                    description=(
                        f"The default security group {sg_id} has active inbound rules. "
                        f"The default SG should restrict all traffic per CIS benchmarks."
                    ),
                    remediation=(
                        "Remove all inbound and outbound rules from the default security group. "
                        "Create purpose-specific security groups instead."
                    ),
                    reasoning=(
                        f"FAIL: The default security group ({sg_id}) in this VPC contains active inbound rules. "
                        f"CIS AWS Benchmark 4.3 requires that the default security group restricts all inbound and outbound traffic. "
                        f"The default SG is automatically assigned to instances that are not explicitly associated with another SG, "
                        f"meaning any rules here could inadvertently grant network access to resources. Best practice is to keep the "
                        f"default SG empty and use purpose-built security groups with explicit allow rules."
                    ),
                    control_domain=DOMAIN,
                    frameworks={
                        "CIS_AWS": ["4.3"],
                        "SOC2": ["CC6.1"],
                        "ISO27001": ["A.13.1.1"],
                    },
                )
            )
        else:
            self.add_finding(
                Finding(
                    check_id="SG-004-PASS",
                    title="Default security group restricts all traffic",
                    resource=f"{sg_id} (default)",
                    status=Finding.STATUS_PASS,
                    severity=Finding.SEVERITY_INFO,
                    description=f"The default security group {sg_id} has no inbound rules configured.",
                    remediation="No action required.",
                    reasoning=(
                        f"PASS: The default security group ({sg_id}) has no active inbound rules, which complies with "
                        f"CIS AWS Benchmark 4.3. Resources not explicitly assigned to a security group will inherit the "
                        f"default SG, so keeping it locked down prevents unintended network exposure."
                    ),
                    control_domain=DOMAIN,
                    frameworks={
                        "CIS_AWS": ["4.3"],
                        "SOC2": ["CC6.1"],
                        "ISO27001": ["A.13.1.1"],
                    },
                )
            )
