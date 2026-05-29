"""Expanded test suite for Comply.dev scanners."""

import pytest
import os
import json
import tempfile
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch, PropertyMock

from comply.aws.base import Finding, BaseAWSScanner
from comply.frameworks.mappings import get_framework_summary


# ── Finding Tests ────────────────────────────────────────────

class TestFinding:

    def test_finding_creation(self):
        f = Finding(
            check_id="TEST-001", title="Test Finding", resource="test-resource",
            status=Finding.STATUS_FAIL, severity=Finding.SEVERITY_HIGH,
            description="Test.", remediation="Fix it.",
            frameworks={"SOC2": ["CC6.1"]},
        )
        assert f.check_id == "TEST-001"
        assert f.status == "FAIL"
        assert f.severity == "HIGH"

    def test_finding_to_dict(self):
        f = Finding(
            check_id="TEST-002", title="Test", resource="res",
            status="PASS", severity="INFO", description="desc", remediation="none",
        )
        d = f.to_dict()
        assert isinstance(d, dict)
        assert d["check_id"] == "TEST-002"
        assert "timestamp" in d

    def test_finding_defaults(self):
        f = Finding("T", "T", "R", "PASS", "INFO", "D", "R")
        assert f.control_domain == "General"
        assert f.frameworks == {}
        assert f.reasoning == ""


# ── Framework Summary Tests ──────────────────────────────────

class TestFrameworkSummary:

    def test_empty_findings(self):
        summary = get_framework_summary([])
        assert "SOC2" in summary
        assert summary["SOC2"]["compliance_score"] == 0

    def test_all_pass(self):
        findings = [{"status": "PASS", "severity": "INFO", "frameworks": {"SOC2": ["CC6.1"]}}]
        summary = get_framework_summary(findings)
        assert summary["SOC2"]["compliance_score"] == 100.0

    def test_mixed_results(self):
        findings = [
            {"status": "PASS", "severity": "INFO", "frameworks": {"SOC2": ["CC6.1"]}},
            {"status": "FAIL", "severity": "HIGH", "frameworks": {"SOC2": ["CC6.7"]}},
        ]
        summary = get_framework_summary(findings)
        assert summary["SOC2"]["controls_tested"] == 2
        assert summary["SOC2"]["controls_failed"] == 1


# ── Base Scanner Tests ───────────────────────────────────────

class TestBaseScanner:

    def test_add_finding(self):
        scanner = BaseAWSScanner.__new__(BaseAWSScanner)
        scanner.findings = []
        finding = Finding("T", "T", "R", "PASS", "INFO", "D", "R")
        scanner.add_finding(finding)
        assert len(scanner.findings) == 1

    def test_get_findings_returns_dicts(self):
        scanner = BaseAWSScanner.__new__(BaseAWSScanner)
        scanner.findings = [Finding("T", "T", "R", "PASS", "INFO", "D", "R")]
        results = scanner.get_findings()
        assert isinstance(results[0], dict)


# ── Security Group Scanner Tests ─────────────────────────────

class TestSecurityGroupScanner:

    @patch("boto3.Session")
    def test_open_ssh_detected(self, mock_session):
        from comply.aws.security_groups import SecurityGroupScanner
        mock_ec2 = MagicMock()
        mock_session_instance = MagicMock()
        mock_session_instance.client.return_value = mock_ec2

        mock_paginator = MagicMock()
        mock_ec2.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [{
            "SecurityGroups": [{
                "GroupId": "sg-test123",
                "GroupName": "test-sg",
                "IpPermissions": [{
                    "FromPort": 22, "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [],
                }],
                "IpPermissionsEgress": [],
            }]
        }]

        scanner = SecurityGroupScanner(session=mock_session_instance)
        results = scanner.scan()
        fail_findings = [f for f in results if f["status"] == "FAIL"]
        assert len(fail_findings) > 0
        assert any("22" in f.get("title", "") or "SSH" in f.get("title", "") for f in fail_findings)

    @patch("boto3.Session")
    def test_clean_sg_passes(self, mock_session):
        from comply.aws.security_groups import SecurityGroupScanner
        mock_ec2 = MagicMock()
        mock_session_instance = MagicMock()
        mock_session_instance.client.return_value = mock_ec2

        mock_paginator = MagicMock()
        mock_ec2.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [{
            "SecurityGroups": [{
                "GroupId": "sg-clean",
                "GroupName": "clean-sg",
                "IpPermissions": [{
                    "FromPort": 443, "ToPort": 443,
                    "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                    "Ipv6Ranges": [],
                }],
                "IpPermissionsEgress": [],
            }]
        }]

        scanner = SecurityGroupScanner(session=mock_session_instance)
        results = scanner.scan()
        pass_findings = [f for f in results if f["status"] == "PASS"]
        assert len(pass_findings) > 0


# ── IAM Scanner Tests ────────────────────────────────────────

class TestIAMScanner:

    @patch("boto3.Session")
    def test_root_no_mfa(self, mock_session):
        from comply.aws.iam import IAMScanner
        mock_iam = MagicMock()
        mock_session_instance = MagicMock()
        mock_session_instance.client.return_value = mock_iam

        mock_iam.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 0}}

        mock_paginator = MagicMock()
        mock_iam.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [{"Users": []}]
        mock_iam.list_access_keys.return_value = {"AccessKeyMetadata": []}

        # Mock password policy
        mock_iam.get_account_password_policy.return_value = {"PasswordPolicy": {
            "MinimumPasswordLength": 14, "RequireUppercaseCharacters": True,
            "RequireLowercaseCharacters": True, "RequireNumbers": True,
            "RequireSymbols": True, "MaxPasswordAge": 90, "PasswordReusePrevention": 24,
        }}

        scanner = IAMScanner(session=mock_session_instance)
        results = scanner.scan()
        root_findings = [f for f in results if f.get("resource") == "root"]
        assert any(f["status"] == "FAIL" and f["severity"] == "CRITICAL" for f in root_findings)

    @patch("boto3.Session")
    def test_old_access_key(self, mock_session):
        from comply.aws.iam import IAMScanner
        mock_iam = MagicMock()
        mock_session_instance = MagicMock()
        mock_session_instance.client.return_value = mock_iam

        mock_iam.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 1}}

        old_date = datetime.now(timezone.utc) - timedelta(days=100)
        mock_paginator = MagicMock()
        mock_iam.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [{"Users": [{"UserName": "testuser"}]}]
        mock_iam.get_login_profile.side_effect = mock_iam.exceptions.NoSuchEntityException
        # Create the exception class
        mock_iam.exceptions = MagicMock()
        mock_iam.exceptions.NoSuchEntityException = type("NoSuchEntityException", (Exception,), {})
        mock_iam.get_login_profile.side_effect = mock_iam.exceptions.NoSuchEntityException()
        mock_iam.list_access_keys.return_value = {"AccessKeyMetadata": [
            {"AccessKeyId": "AKIA_OLD", "Status": "Active", "CreateDate": old_date}
        ]}
        mock_iam.get_account_password_policy.return_value = {"PasswordPolicy": {
            "MinimumPasswordLength": 14, "RequireUppercaseCharacters": True,
            "RequireLowercaseCharacters": True, "RequireNumbers": True,
            "RequireSymbols": True, "MaxPasswordAge": 90, "PasswordReusePrevention": 24,
        }}

        scanner = IAMScanner(session=mock_session_instance)
        results = scanner.scan()
        key_findings = [f for f in results if "AKIA_OLD" in f.get("resource", "")]
        assert any(f["status"] == "FAIL" for f in key_findings)


# ── Backup Scanner Tests ─────────────────────────────────────

class TestBackupScanner:

    @patch("boto3.Session")
    def test_no_backups(self, mock_session):
        from comply.aws.backups import BackupScanner
        mock_rds = MagicMock()
        mock_session_instance = MagicMock()
        mock_session_instance.client.return_value = mock_rds

        mock_paginator = MagicMock()
        mock_rds.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [{"DBInstances": [{
            "DBInstanceIdentifier": "test-db",
            "BackupRetentionPeriod": 0,
            "Engine": "mysql",
            "MultiAZ": False,
            "AvailabilityZone": "us-east-1a",
        }]}]

        scanner = BackupScanner(session=mock_session_instance)
        results = scanner.scan()
        fail_findings = [f for f in results if f["status"] == "FAIL"]
        assert any(f["severity"] == "CRITICAL" for f in fail_findings)

    @patch("boto3.Session")
    def test_adequate_backups(self, mock_session):
        from comply.aws.backups import BackupScanner
        mock_rds = MagicMock()
        mock_session_instance = MagicMock()
        mock_session_instance.client.return_value = mock_rds

        mock_paginator = MagicMock()
        mock_rds.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [{"DBInstances": [{
            "DBInstanceIdentifier": "prod-db",
            "BackupRetentionPeriod": 14,
            "Engine": "postgres",
            "MultiAZ": True,
            "AvailabilityZone": "us-east-1a",
        }]}]

        scanner = BackupScanner(session=mock_session_instance)
        results = scanner.scan()
        pass_findings = [f for f in results if f["status"] == "PASS"]
        assert len(pass_findings) >= 2  # backup retention + multi-az


# ── Encryption Scanner Tests ─────────────────────────────────

class TestEncryptionScanner:

    @patch("boto3.Session")
    def test_encrypted_ebs(self, mock_session):
        from comply.aws.encryption import EncryptionScanner
        mock_ec2 = MagicMock()
        mock_s3 = MagicMock()
        mock_rds = MagicMock()
        mock_session_instance = MagicMock()

        def client_factory(service):
            if service == "ec2":
                return mock_ec2
            elif service == "s3":
                return mock_s3
            elif service == "rds":
                return mock_rds

        mock_session_instance.client.side_effect = client_factory

        # S3 - no buckets
        mock_s3.list_buckets.return_value = {"Buckets": []}

        # EBS - encrypted volume
        mock_ec2_paginator = MagicMock()
        mock_ec2.get_paginator.return_value = mock_ec2_paginator
        mock_ec2_paginator.paginate.return_value = [{"Volumes": [{
            "VolumeId": "vol-enc123", "Encrypted": True, "State": "in-use",
            "Size": 100, "KmsKeyId": "arn:aws:kms:us-east-1:123:key/abc",
        }]}]

        # RDS - no instances
        mock_rds_paginator = MagicMock()
        mock_rds.get_paginator.return_value = mock_rds_paginator
        mock_rds_paginator.paginate.return_value = [{"DBInstances": []}]

        scanner = EncryptionScanner(session=mock_session_instance)
        results = scanner.scan()
        ebs_pass = [f for f in results if "vol-enc123" in f.get("resource", "")]
        assert any(f["status"] == "PASS" for f in ebs_pass)


# ── Report Generator Tests ───────────────────────────────────

class TestReportGenerator:

    def test_json_generation(self):
        from comply.reports.generator import ReportGenerator
        findings = [
            {"check_id": "T-1", "title": "Test", "resource": "r", "status": "PASS",
             "severity": "INFO", "description": "d", "remediation": "r",
             "reasoning": "", "control_domain": "Test", "frameworks": {}, "timestamp": ""},
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ReportGenerator(findings, output_dir=tmpdir)
            path = gen.generate_json()
            assert os.path.exists(path)
            assert path.endswith(".json")
            with open(path) as f:
                data = json.load(f)
            assert "findings" in data
            assert len(data["findings"]) == 1

    def test_html_generation(self):
        from comply.reports.generator import ReportGenerator
        findings = [
            {"check_id": "T-1", "title": "Test", "resource": "r", "status": "FAIL",
             "severity": "HIGH", "description": "d", "remediation": "r",
             "reasoning": "reason", "control_domain": "Test", "frameworks": {"SOC2": ["CC6.1"]},
             "timestamp": ""},
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ReportGenerator(findings, output_dir=tmpdir)
            path = gen.generate_html()
            assert os.path.exists(path)
            assert path.endswith(".html")
            with open(path) as f:
                content = f.read()
            assert "Comply.dev" in content
            assert "FAIL" in content
