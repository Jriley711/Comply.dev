"""AWS Backup compliance checks with audit reasoning."""

from .base import BaseAWSScanner, Finding

MINIMUM_BACKUP_RETENTION_DAYS = 7
DOMAIN = "Backup & Availability"


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
                    engine = db.get("Engine", "unknown")

                    if retention == 0:
                        self.add_finding(Finding(
                            check_id="BKP-RDS-001",
                            title="RDS automated backups disabled",
                            resource=db_id,
                            status=Finding.STATUS_FAIL,
                            severity=Finding.SEVERITY_CRITICAL,
                            description=f"RDS instance \'{db_id}\' has automated backups disabled (retention = 0 days).",
                            remediation=f"Enable automated backups with minimum {MINIMUM_BACKUP_RETENTION_DAYS}-day retention.",
                            reasoning=(
                                f"FAIL: RDS instance \'{db_id}\' (Engine: {engine}) has a backup retention period of 0 days, "
                                f"meaning automated backups are completely disabled. No point-in-time recovery (PITR) is possible. "
                                f"If data is lost due to accidental deletion, corruption, or a security incident, there is NO recovery "
                                f"path. This is a CRITICAL violation of CIS AWS 2.3.2 (automated backups), SOC 2 A1.2 (recovery and "
                                f"continuity), CC7.5 (recovery operations), and ISO 27001 A.12.3.1 (information backup) and A.17.1.1 "
                                f"(business continuity planning)."
                            ),
                            control_domain=DOMAIN,
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
                            description=f"RDS instance \'{db_id}\' has {retention}-day retention (minimum: {MINIMUM_BACKUP_RETENTION_DAYS}).",
                            remediation=f"Increase backup retention to at least {MINIMUM_BACKUP_RETENTION_DAYS} days.",
                            reasoning=(
                                f"WARNING: RDS instance \'{db_id}\' (Engine: {engine}) has automated backups enabled but with only "
                                f"{retention}-day retention, below the recommended minimum of {MINIMUM_BACKUP_RETENTION_DAYS} days. "
                                f"A short retention window limits the ability to recover from incidents that are not discovered immediately "
                                f"(e.g., data corruption that goes unnoticed for several days). SOC 2 A1.2 requires adequate recovery "
                                f"capabilities. Industry best practice recommends 7-35 days depending on criticality."
                            ),
                            control_domain=DOMAIN,
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
                            description=f"RDS instance \'{db_id}\' has {retention}-day backup retention.",
                            remediation="No action required.",
                            reasoning=(
                                f"PASS: RDS instance \'{db_id}\' (Engine: {engine}) has automated backups enabled with "
                                f"{retention}-day retention, meeting or exceeding the {MINIMUM_BACKUP_RETENTION_DAYS}-day minimum. "
                                f"Point-in-time recovery (PITR) is available within the retention window. This satisfies CIS AWS 2.3.2, "
                                f"SOC 2 A1.2 (recovery and continuity), and ISO 27001 A.12.3.1 (information backup)."
                            ),
                            control_domain=DOMAIN,
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
                reasoning=f"Scanner could not call rds:DescribeDBInstances for backup checks. Error: {str(e)}.",
                control_domain=DOMAIN,
            ))

    def _check_rds_multi_az(self):
        rds = self.get_client("rds")

        try:
            paginator = rds.get_paginator("describe_db_instances")
            for page in paginator.paginate():
                for db in page["DBInstances"]:
                    db_id = db["DBInstanceIdentifier"]
                    multi_az = db.get("MultiAZ", False)
                    engine = db.get("Engine", "unknown")
                    az = db.get("AvailabilityZone", "unknown")

                    if not multi_az:
                        self.add_finding(Finding(
                            check_id="BKP-RDS-003",
                            title="RDS instance not Multi-AZ",
                            resource=db_id,
                            status=Finding.STATUS_WARN,
                            severity=Finding.SEVERITY_MEDIUM,
                            description=f"RDS instance \'{db_id}\' is single-AZ (no automatic failover).",
                            remediation="Enable Multi-AZ for production databases.",
                            reasoning=(
                                f"WARNING: RDS instance \'{db_id}\' (Engine: {engine}) is deployed in a single Availability Zone "
                                f"({az}). If this AZ experiences an outage (hardware failure, network issue, natural disaster), the "
                                f"database will be unavailable with no automatic failover. Multi-AZ deployments maintain a synchronous "
                                f"standby replica in a different AZ and automatically failover in ~60 seconds. SOC 2 A1.1 (processing "
                                f"capacity) and A1.2 (recovery) require adequate availability controls. ISO 27001 A.17.1.1 and A.17.1.2 "
                                f"address business continuity planning and implementation."
                            ),
                            control_domain=DOMAIN,
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
                            description=f"RDS instance \'{db_id}\' has Multi-AZ enabled.",
                            remediation="No action required.",
                            reasoning=(
                                f"PASS: RDS instance \'{db_id}\' (Engine: {engine}) is configured for Multi-AZ deployment. "
                                f"A synchronous standby replica is maintained in a separate Availability Zone, providing automatic "
                                f"failover (~60 seconds) in case of infrastructure failure. This satisfies SOC 2 A1.1 (processing "
                                f"capacity), A1.2 (recovery), and ISO 27001 A.17.1.1 (continuity planning)."
                            ),
                            control_domain=DOMAIN,
                            frameworks={
                                "SOC2": ["A1.1", "A1.2"],
                                "ISO27001": ["A.17.1.1"],
                            },
                        ))
        except Exception as e:
            pass  # Already handled in _check_rds_backups
