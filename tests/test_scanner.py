"""Basic tests for Comply.dev scanners."""

import pytest
from unittest.mock import MagicMock, patch
from comply.aws.base import Finding, BaseAWSScanner
from comply.frameworks.mappings import get_framework_summary


class TestFinding:
    """Tests for the Finding class."""

    def test_finding_creation(self):
        finding = Finding(
            check_id="TEST-001",
            title="Test Finding",
            resource="test-resource",
            status=Finding.STATUS_FAIL,
            severity=Finding.SEVERITY_HIGH,
            description="This is a test finding.",
            remediation="Fix it.",
            frameworks={"SOC2": ["CC6.1"]},
        )
        assert finding.check_id == "TEST-001"
        assert finding.status == "FAIL"
        assert finding.severity == "HIGH"

    def test_finding_to_dict(self):
        finding = Finding(
            check_id="TEST-002",
            title="Test",
            resource="res",
            status="PASS",
            severity="INFO",
            description="desc",
            remediation="none",
        )
        d = finding.to_dict()
        assert isinstance(d, dict)
        assert d["check_id"] == "TEST-002"
        assert "timestamp" in d


class TestFrameworkSummary:
    """Tests for framework compliance summary."""

    def test_empty_findings(self):
        summary = get_framework_summary([])
        assert "SOC2" in summary
        assert summary["SOC2"]["compliance_score"] == 0

    def test_all_pass(self):
        findings = [
            {
                "status": "PASS",
                "severity": "INFO",
                "frameworks": {"SOC2": ["CC6.1"]},
            }
        ]
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


class TestBaseScanner:
    """Tests for BaseAWSScanner."""

    def test_add_finding(self):
        scanner = BaseAWSScanner.__new__(BaseAWSScanner)
        scanner.findings = []
        finding = Finding("T", "T", "R", "PASS", "INFO", "D", "R")
        scanner.add_finding(finding)
        assert len(scanner.findings) == 1

    def test_get_findings_returns_dicts(self):
        scanner = BaseAWSScanner.__new__(BaseAWSScanner)
        scanner.findings = [
            Finding("T", "T", "R", "PASS", "INFO", "D", "R")
        ]
        results = scanner.get_findings()
        assert isinstance(results[0], dict)
