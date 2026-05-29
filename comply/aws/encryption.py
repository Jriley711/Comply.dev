"""AWS Encryption compliance checks with audit reasoning."""

from .base import BaseAWSScanner, Finding

DOMAIN = "Data Protection"


class EncryptionScanner(BaseAWSScanner):
    """Scans AWS resources for encryption-at-rest compliance."""

    def scan(self) -> list:
        self.findings = []
        self._check_s3_encryption()
        self._check_ebs_encryption()
        self._check_rds_encryption()
        return self.get_findings()

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
                reasoning=f"The scanner could not call s3:ListAllMyBuckets. Error: {str(e)}. Without this permission, encryption status of S3 buckets cannot be verified.",
                control_domain=DOMAIN,
            ))
            return

        for bucket in buckets:
            name = bucket["Name"]
            try:
                enc_config = s3.get_bucket_encryption(Bucket=name)
                rules = enc_config.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                algo = "Unknown"
                if rules:
                    algo = rules[0].get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm", "Unknown")

                self.add_finding(Finding(
                    check_id="ENC-S3-PASS",
                    title="S3 bucket encryption enabled",
                    resource=name,
                    status=Finding.STATUS_PASS,
                    severity=Finding.SEVERITY_INFO,
                    description=f"S3 bucket \'{name}\' has server-side encryption enabled using {algo}.",
                    remediation="No action required.",
                    reasoning=(
                        f"PASS: S3 bucket \'{name}\' has default server-side encryption enabled (algorithm: {algo}). "
                        f"All objects stored in this bucket are automatically encrypted at rest. This satisfies "
                        f"CIS AWS 2.1.1 (S3 encryption), SOC 2 CC6.7 (encryption of data at rest), and "
                        f"ISO 27001 A.10.1.1 (cryptographic controls). No manual encryption is needed per-object."
                    ),
                    control_domain=DOMAIN,
                    frameworks={
                        "CIS_AWS": ["2.1.1"],
                        "SOC2": ["CC6.1", "CC6.7"],
                        "ISO27001": ["A.10.1.1"],
                    },
                ))
            except Exception as e:
                error_str = str(e)
                if "ServerSideEncryptionConfigurationNotFoundError" in error_str:
                    self.add_finding(Finding(
                        check_id="ENC-S3-001",
                        title="S3 bucket missing encryption",
                        resource=name,
                        status=Finding.STATUS_FAIL,
                        severity=Finding.SEVERITY_HIGH,
                        description=(
                            f"S3 bucket \'{name}\' does not have default server-side encryption "
                            f"enabled. Data stored in this bucket is unencrypted at rest."
                        ),
                        remediation=(
                            "Enable default encryption on the bucket using SSE-S3 (AES-256) "
                            "or SSE-KMS. Go to S3 > Bucket > Properties > Default Encryption."
                        ),
                        reasoning=(
                            f"FAIL: S3 bucket \'{name}\' returned ServerSideEncryptionConfigurationNotFoundError, "
                            f"confirming no default encryption is configured. Any object uploaded without explicit "
                            f"encryption headers will be stored in plaintext. This violates CIS AWS 2.1.1, "
                            f"SOC 2 CC6.7 (data-at-rest encryption), and ISO 27001 A.10.1.1 (cryptographic controls) "
                            f"and A.18.1.3 (protection of records). If this bucket contains PII, financial data, or "
                            f"health records, this is also a potential regulatory compliance issue."
                        ),
                        control_domain=DOMAIN,
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
                        description=f"Error checking bucket \'{name}\': {error_str}",
                        remediation="Verify bucket permissions and try again.",
                        reasoning=f"The scanner encountered an unexpected error when checking encryption for bucket \'{name}\': {error_str}. This may be a permissions issue or a bucket in a different region.",
                        control_domain=DOMAIN,
                    ))

    def _check_ebs_encryption(self):
        ec2 = self.get_client("ec2")

        try:
            paginator = ec2.get_paginator("describe_volumes")
            for page in paginator.paginate():
                for vol in page["Volumes"]:
                    vol_id = vol["VolumeId"]
                    encrypted = vol.get("Encrypted", False)
                    state = vol.get("State", "unknown")
                    size = vol.get("Size", "?")

                    if not encrypted:
                        self.add_finding(Finding(
                            check_id="ENC-EBS-001",
                            title="EBS volume not encrypted",
                            resource=vol_id,
                            status=Finding.STATUS_FAIL,
                            severity=Finding.SEVERITY_HIGH,
                            description=f"EBS volume {vol_id} is not encrypted at rest. State: {state}, Size: {size} GiB.",
                            remediation="Create an encrypted snapshot of this volume and replace it. Enable default EBS encryption in EC2 settings for the region.",
                            reasoning=(
                                f"FAIL: EBS volume {vol_id} (State: {state}, Size: {size} GiB) does not have encryption "
                                f"enabled. Data on this volume is stored in plaintext on the underlying physical storage. "
                                f"If the physical disk is decommissioned or the snapshot is shared, data could be exposed. "
                                f"CIS AWS 2.2.1 requires EBS volume encryption. SOC 2 CC6.7 mandates encryption of data at rest. "
                                f"Note: EBS encryption cannot be toggled after creation — the volume must be replaced with an encrypted copy."
                            ),
                            control_domain=DOMAIN,
                            frameworks={
                                "CIS_AWS": ["2.2.1"],
                                "SOC2": ["CC6.1", "CC6.7"],
                                "ISO27001": ["A.10.1.1"],
                            },
                        ))
                    else:
                        kms_key = vol.get("KmsKeyId", "default")
                        self.add_finding(Finding(
                            check_id="ENC-EBS-PASS",
                            title="EBS volume encrypted",
                            resource=vol_id,
                            status=Finding.STATUS_PASS,
                            severity=Finding.SEVERITY_INFO,
                            description=f"EBS volume {vol_id} is encrypted at rest.",
                            remediation="No action required.",
                            reasoning=(
                                f"PASS: EBS volume {vol_id} (State: {state}, Size: {size} GiB) is encrypted at rest "
                                f"using KMS key: {kms_key}. All data written to this volume, all snapshots created from it, "
                                f"and all volumes restored from those snapshots will also be encrypted. This satisfies "
                                f"CIS AWS 2.2.1, SOC 2 CC6.7, and ISO 27001 A.10.1.1."
                            ),
                            control_domain=DOMAIN,
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
                reasoning=f"Scanner could not call ec2:DescribeVolumes. Error: {str(e)}.",
                control_domain=DOMAIN,
            ))

    def _check_rds_encryption(self):
        rds = self.get_client("rds")

        try:
            paginator = rds.get_paginator("describe_db_instances")
            for page in paginator.paginate():
                for db in page["DBInstances"]:
                    db_id = db["DBInstanceIdentifier"]
                    encrypted = db.get("StorageEncrypted", False)
                    engine = db.get("Engine", "unknown")
                    db_class = db.get("DBInstanceClass", "unknown")

                    if not encrypted:
                        self.add_finding(Finding(
                            check_id="ENC-RDS-001",
                            title="RDS instance not encrypted at rest",
                            resource=db_id,
                            status=Finding.STATUS_FAIL,
                            severity=Finding.SEVERITY_CRITICAL,
                            description=f"RDS instance \'{db_id}\' ({engine}) does not have storage encryption enabled.",
                            remediation="RDS encryption cannot be enabled after creation. Create an encrypted snapshot, restore from it, and migrate traffic to the new encrypted instance.",
                            reasoning=(
                                f"FAIL: RDS instance \'{db_id}\' (Engine: {engine}, Class: {db_class}) does not have "
                                f"storage encryption enabled. All data in this database — including automated backups, "
                                f"read replicas, and snapshots — is stored unencrypted. This is a CRITICAL finding because "
                                f"databases typically contain the most sensitive organizational data (PII, financial records, "
                                f"credentials). CIS AWS 2.3.1 requires RDS encryption. SOC 2 CC6.7 mandates data-at-rest "
                                f"encryption. ISO 27001 A.10.1.1 and A.18.1.3 require cryptographic protection of records. "
                                f"IMPORTANT: RDS encryption cannot be enabled retroactively — the instance must be recreated."
                            ),
                            control_domain=DOMAIN,
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
                            description=f"RDS instance \'{db_id}\' has storage encryption enabled.",
                            remediation="No action required.",
                            reasoning=(
                                f"PASS: RDS instance \'{db_id}\' (Engine: {engine}, Class: {db_class}) has storage encryption "
                                f"enabled. All data at rest, automated backups, snapshots, and read replicas inherit encryption. "
                                f"This satisfies CIS AWS 2.3.1, SOC 2 CC6.7, and ISO 27001 A.10.1.1."
                            ),
                            control_domain=DOMAIN,
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
                reasoning=f"Scanner could not call rds:DescribeDBInstances. Error: {str(e)}.",
                control_domain=DOMAIN,
            ))
