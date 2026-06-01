"""Compliance framework control mappings — SOC 2, ISO 27001, CIS AWS."""

FRAMEWORK_MAPPINGS = {
    "SOC2": {
        "name": "SOC 2 Type II — Trust Service Criteria",
        "controls": {
            "CC6.1": "Logical and Physical Access Controls",
            "CC6.2": "Authentication and Authorization",
            "CC6.6": "Security of Transmission and Communication",
            "CC6.7": "Encryption of Data at Rest",
            "CC7.1": "Vulnerability Management",
            "CC7.4": "Incident Response",
            "CC7.5": "Recovery Operations",
            "CC8.1": "Change Management",
            "A1.1": "Availability — Processing Capacity",
            "A1.2": "Availability — Recovery and Continuity",
            "CC1.1": "Control Environment — Governance",
        },
    },
    "ISO27001": {
        "name": "ISO 27001:2022 — Annex A Controls",
        "controls": {
            "A.9.1.2": "Access to Networks and Network Services",
            "A.9.2.1": "User Registration and De-registration",
            "A.9.2.5": "Review of User Access Rights",
            "A.9.4.1": "Information Access Restriction",
            "A.9.4.2": "Secure Log-on Procedures",
            "A.9.4.3": "Password Management System",
            "A.10.1.1": "Policy on the Use of Cryptographic Controls",
            "A.12.1.2": "Change Management",
            "A.12.3.1": "Information Backup",
            "A.12.6.1": "Management of Technical Vulnerabilities",
            "A.13.1.1": "Network Controls",
            "A.13.1.3": "Segregation in Networks",
            "A.14.2.2": "System Change Control Procedures",
            "A.16.1.2": "Reporting Information Security Events",
            "A.17.1.1": "Planning Information Security Continuity",
            "A.17.1.2": "Implementing Information Security Continuity",
            "A.18.1.3": "Protection of Records",
        },
    },
    "CIS_AWS": {
        "name": "CIS AWS Foundations Benchmark v3.0",
        "controls": {
            "1.5": "Ensure MFA is enabled for the root user account",
            "1.8": "Ensure IAM password policy is configured",
            "1.10": "Ensure MFA is enabled for all IAM users with console access",
            "1.14": "Ensure access keys are rotated every 90 days or less",
            "2.1.1": "Ensure S3 Bucket Policy is set to deny HTTP requests",
            "2.2.1": "Ensure EBS Volume Encryption is Enabled",
            "2.3.1": "Ensure RDS Instances Have Encryption Enabled",
            "2.3.2": "Ensure RDS Instances Have Automated Backups Enabled",
            "4.1": "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22",
            "4.2": "Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389",
            "4.3": "Ensure the default security group restricts all traffic",
            "4.4": "Ensure egress is restricted to necessary traffic only",
        },
    },
}


def get_framework_summary(findings: list) -> dict:
    """Analyze findings and return compliance summary per framework."""
    summary = {}

    for fw_key, fw_data in FRAMEWORK_MAPPINGS.items():
        controls_tested = set()
        controls_passed = set()
        controls_failed = set()

        for finding in findings:
            fw_controls = finding.get("frameworks", {}).get(fw_key, [])
            for control in fw_controls:
                controls_tested.add(control)
                if finding["status"] == "PASS":
                    controls_passed.add(control)
                elif finding["status"] in ("FAIL", "WARNING"):
                    controls_failed.add(control)

        total = len(controls_tested)
        passed = len(controls_passed - controls_failed)  # Only count if ALL checks pass
        score = round((passed / total) * 100, 1) if total > 0 else 0

        summary[fw_key] = {
            "name": fw_data["name"],
            "controls_tested": total,
            "controls_passed": passed,
            "controls_failed": len(controls_failed),
            "compliance_score": score,
        }

    return summary
