"""AWS Encryption compliance checks — S3, EBS, RDS."""

from .base import BaseAWSScanner, Finding


class EncryptionScanner(BaseAWSScanner):
    """Scans AWS resources for encryption-at-rest compliance."""

    def scan(self) -> list:
        self.findings = []
        self._check_s3_encryption()
        self._check_ebs_encryption()
        self._check_rds_encryption()
        return self.get_findings()

    # ── S3 Bucket Encryption ──────────────────────────────────
    def _check_s3_encryption(self):
        s3 = self.get_client("s3")

        try:
            buckets = s3.list_buckets().get("Buckets", [])
        except Exception as e:
            self.add_finding(Finding(
                check_id="ENC-ERR-S3",
                title="S3 Encryption Scan Error",
                resource="N/A",
                status=Finding.STATUS_WARN,
                severity=Finding.SEVERITY_INFO,
                description=f"Could not list S3 buckets: {str(e)}",
                remediation="Verify AWS credentials have s3:ListAllMyBuckets permission.",
            ))
            return

        for bucket in buckets:
            name = bucket["Name"]
            try:
                s3.get_bucket_encryption(Bucket=name)
                self.add_finding(Finding(
                    check_id="ENC-S3-PASS",
                    title="S3 bucket encryption enabled",
                    resource=name,
                    status=Finding.STATUS_PASS,
                    severity=Finding.SEVERITY_INFO,
                    description=f"S3 bucket '{name}' has server-side encryption enabled.",
                    remediation="No action required.",
                    frameworks={
                        "CIS_AWS": ["2.1.1"],
                        "SOC2": ["CC6.1", "CC6.7"],
                        "ISO27001": ["A.10.1.1"],
                    },
                ))
            except s3.exceptions.ClientError as e:
                error_code = e.response["Error"]["Code"]
                if error_code == "ServerSideEncryptionConfigurationNotFoundError":
                    self.add_finding(Finding(
                        check_id="ENC-S3-001",
                        title="S3 bucket missing encryption",
                        resource=name,
                        status=Finding.STATUS_FAIL,
                        severity=Finding.SEVERITY_HIGH,
                        description=(
                            f"S3 bucket '{name}' does not have default server-side encryption "
                            f"enabled. Data stored in this bucket is unencrypted at rest."
                        ),
                        remediation=(
                            "Enable default encryption on the bucket using SSE-S3 (AES-256) "
                            "or SSE-KMS. Go to S3 > Bucket > Properties > Default Encryption."
                        ),
                        frameworks={
                            "CIS_AWS": ["2.1.1"],
                            "SOC2": ["CC6.1", "CC6.7"],
                            "ISO27001": ["A.10.1.1", "A.18.1.3"],
                        },
                    ))
                else:
                    self.add_finding(Finding(
                        check_id="ENC-ERR-S3-BUCKET",
                        title=f"Could not check encryption for bucket",
                        resource=name,
                        status=Finding.STATUS_WARN,
                        severity=Finding.SEVERITY_LOW,
                        description=f"Error checking bucket '{name}': {error_code}",
                        remediation="Verify bucket permissions and try again.",
                    ))

    # ── EBS Volume Encryption ─────────────────────────────────
    def _check_ebs_encryption(self):
        ec2 = self.get_client("ec2")

        try:
            paginator = ec2.get_paginator("describe_volumes")
            for page in paginator.paginate():
                for vol in page["Volumes"]:
                    vol_id = vol["VolumeId"]
                    encrypted = vol.get("Encrypted", False)

                    if not encrypted:
                        self.add_finding(Finding(
                            check_id="ENC-EBS-001",
                            title="EBS volume not encrypted",
                            resource=vol_id,
                            status=Finding.STATUS_FAIL,
                            severity=Finding.SEVERITY_HIGH,
                            description=(
                                f"EBS volume {vol_id} is not encrypted at rest. "
                                f"State: {vol.get('State', 'unknown')}, "
                                f"Size: {vol.get('Size', '?')} GiB."
                            ),
                            remediation=(
                                "Create an encrypted snapshot of this volume and replace it. "
                                "Enable default EBS encryption in EC2 settings for the region."
                            ),
                            frameworks={
                                "CIS_AWS": ["2.2.1"],
                                "SOC2": ["CC6.1", "CC6.7"],
                                "ISO27001": ["A.10.1.1"],
                            },
                        ))
                    else:
                        self.add_finding(Finding(
                            check_id="ENC-EBS-PASS",
                            title="EBS volume encrypted",
                            resource=vol_id,
                            status=Finding.STATUS_PASS,
                            severity=Finding.SEVERITY_INFO,
                            description=f"EBS volume {vol_id} is encrypted at rest.",
                            remediation="No action required.",
                            frameworks={
                                "CIS_AWS": ["2.2.1"],
                                "SOC2": ["CC6.1", "CC6.7"],
                                "ISO27001": ["A.10.1.1"],
                            },
                        ))
        except Exception as e:
            self.add_finding(Finding(
                check_id="ENC-ERR-EBS",
                title="EBS Encryption Scan Error",
                resource="N/A",
                status=Finding.STATUS_WARN,
                severity=Finding.SEVERITY_INFO,
                description=f"Could not scan EBS volumes: {str(e)}",
                remediation="Verify AWS credentials and EC2 permissions.",
            ))

    # ── RDS Encryption ────────────────────────────────────────
    def _check_rds_encryption(self):
        rds = self.get_client("rds")

        try:
            paginator = rds.get_paginator("describe_db_instances")
            for page in paginator.paginate():
                for db in page["DBInstances"]:
                    db_id = db["DBInstanceIdentifier"]
                    encrypted = db.get("StorageEncrypted", False)

                    if not encrypted:
                        self.add_finding(Finding(
                            check_id="ENC-RDS-001",
                            title="RDS instance not encrypted at rest",
                            resource=db_id,
                            status=Finding.STATUS_FAIL,
                            severity=Finding.SEVERITY_CRITICAL,
                            description=(
                                f"RDS instance '{db_id}' ({db.get('Engine', 'unknown')}) "
                                f"does not have storage encryption enabled."
                            ),
                            remediation=(
                                "RDS encryption cannot be enabled after creation. "
                                "Create an encrypted snapshot, restore from it, and "
                                "migrate traffic to the new encrypted instance."
                            ),
                            frameworks={
                                "CIS_AWS": ["2.3.1"],
                                "SOC2": ["CC6.1", "CC6.7"],
                                "ISO27001": ["A.10.1.1", "A.18.1.3"],
                            },
                        ))
                    else:
                        self.add_finding(Finding(
                            check_id="ENC-RDS-PASS",
                            title="RDS instance encrypted",
                            resource=db_id,
                            status=Finding.STATUS_PASS,
                            severity=Finding.SEVERITY_INFO,
                            description=f"RDS instance '{db_id}' has storage encryption enabled.",
                            remediation="No action required.",
                            frameworks={
                                "CIS_AWS": ["2.3.1"],
                                "SOC2": ["CC6.1", "CC6.7"],
                                "ISO27001": ["A.10.1.1"],
                            },
                        ))
        except Exception as e:
            self.add_finding(Finding(
                check_id="ENC-ERR-RDS",
                title="RDS Encryption Scan Error",
                resource="N/A",
                status=Finding.STATUS_WARN,
                severity=Finding.SEVERITY_INFO,
                description=f"Could not scan RDS instances: {str(e)}",
                remediation="Verify AWS credentials and RDS permissions.",
            ))
