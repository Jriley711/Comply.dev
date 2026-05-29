"""AWS Backup compliance checks — RDS backup retention, Multi-AZ."""

from .base import BaseAWSScanner, Finding

MINIMUM_BACKUP_RETENTION_DAYS = 7


class BackupScanner(BaseAWSScanner):
    """Scans AWS resources for backup and availability compliance."""

    def scan(self) -> list:
        self.findings = []
        self._check_rds_backups()
        self._check_rds_multi_az()
        return self.get_findings()

    def _check_rds_backups(self):
        rds = self.get_client("rds")

        try:
            paginator = rds.get_paginator("describe_db_instances")
            for page in paginator.paginate():
                for db in page["DBInstances"]:
                    db_id = db["DBInstanceIdentifier"]
                    retention = db.get("BackupRetentionPeriod", 0)

                    if retention == 0:
                        self.add_finding(Finding(
                            check_id="BKP-RDS-001",
                            title="RDS automated backups disabled",
                            resource=db_id,
                            status=Finding.STATUS_FAIL,
                            severity=Finding.SEVERITY_CRITICAL,
                            description=(
                                f"RDS instance '{db_id}' has automated backups disabled "
                                f"(retention period = 0 days). No point-in-time recovery is possible."
                            ),
                            remediation=(
                                f"Enable automated backups with a minimum retention period of "
                                f"{MINIMUM_BACKUP_RETENTION_DAYS} days. Go to RDS > Instance > "
                                f"Modify > Backup Retention Period."
                            ),
                            frameworks={
                                "CIS_AWS": ["2.3.2"],
                                "SOC2": ["A1.2", "CC7.5"],
                                "ISO27001": ["A.12.3.1", "A.17.1.1"],
                            },
                        ))
                    elif retention < MINIMUM_BACKUP_RETENTION_DAYS:
                        self.add_finding(Finding(
                            check_id="BKP-RDS-002",
                            title="RDS backup retention below minimum",
                            resource=db_id,
                            status=Finding.STATUS_WARN,
                            severity=Finding.SEVERITY_MEDIUM,
                            description=(
                                f"RDS instance '{db_id}' has a backup retention period of "
                                f"{retention} days, below the recommended minimum of "
                                f"{MINIMUM_BACKUP_RETENTION_DAYS} days."
                            ),
                            remediation=(
                                f"Increase backup retention to at least "
                                f"{MINIMUM_BACKUP_RETENTION_DAYS} days."
                            ),
                            frameworks={
                                "CIS_AWS": ["2.3.2"],
                                "SOC2": ["A1.2"],
                                "ISO27001": ["A.12.3.1"],
                            },
                        ))
                    else:
                        self.add_finding(Finding(
                            check_id="BKP-RDS-PASS",
                            title="RDS backup retention adequate",
                            resource=db_id,
                            status=Finding.STATUS_PASS,
                            severity=Finding.SEVERITY_INFO,
                            description=(
                                f"RDS instance '{db_id}' has automated backups enabled "
                                f"with {retention}-day retention."
                            ),
                            remediation="No action required.",
                            frameworks={
                                "CIS_AWS": ["2.3.2"],
                                "SOC2": ["A1.2"],
                                "ISO27001": ["A.12.3.1"],
                            },
                        ))
        except Exception as e:
            self.add_finding(Finding(
                check_id="BKP-ERR-RDS",
                title="RDS Backup Scan Error",
                resource="N/A",
                status=Finding.STATUS_WARN,
                severity=Finding.SEVERITY_INFO,
                description=f"Could not scan RDS backups: {str(e)}",
                remediation="Verify AWS credentials and RDS permissions.",
            ))

    def _check_rds_multi_az(self):
        rds = self.get_client("rds")

        try:
            paginator = rds.get_paginator("describe_db_instances")
            for page in paginator.paginate():
                for db in page["DBInstances"]:
                    db_id = db["DBInstanceIdentifier"]
                    multi_az = db.get("MultiAZ", False)

                    if not multi_az:
                        self.add_finding(Finding(
                            check_id="BKP-RDS-003",
                            title="RDS instance not Multi-AZ",
                            resource=db_id,
                            status=Finding.STATUS_WARN,
                            severity=Finding.SEVERITY_MEDIUM,
                            description=(
                                f"RDS instance '{db_id}' is not configured for Multi-AZ "
                                f"deployment. This means no automatic failover in case of "
                                f"an availability zone outage."
                            ),
                            remediation=(
                                "Enable Multi-AZ for production databases to ensure "
                                "high availability and automatic failover."
                            ),
                            frameworks={
                                "SOC2": ["A1.1", "A1.2"],
                                "ISO27001": ["A.17.1.1", "A.17.1.2"],
                            },
                        ))
                    else:
                        self.add_finding(Finding(
                            check_id="BKP-RDS-PASS-AZ",
                            title="RDS Multi-AZ enabled",
                            resource=db_id,
                            status=Finding.STATUS_PASS,
                            severity=Finding.SEVERITY_INFO,
                            description=f"RDS instance '{db_id}' has Multi-AZ enabled.",
                            remediation="No action required.",
                            frameworks={
                                "SOC2": ["A1.1", "A1.2"],
                                "ISO27001": ["A.17.1.1"],
                            },
                        ))
        except Exception as e:
            pass  # Already handled in _check_rds_backups
