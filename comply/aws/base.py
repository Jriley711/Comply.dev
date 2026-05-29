"""Base AWS scanner class with shared utilities."""

import boto3
from datetime import datetime, timezone


class Finding:
    """Represents a single compliance finding."""

    SEVERITY_CRITICAL = "CRITICAL"
    SEVERITY_HIGH = "HIGH"
    SEVERITY_MEDIUM = "MEDIUM"
    SEVERITY_LOW = "LOW"
    SEVERITY_INFO = "INFO"

    STATUS_FAIL = "FAIL"
    STATUS_PASS = "PASS"
    STATUS_WARN = "WARNING"

    def __init__(
        self,
        check_id: str,
        title: str,
        resource: str,
        status: str,
        severity: str,
        description: str,
        remediation: str,
        frameworks: dict = None,
    ):
        self.check_id = check_id
        self.title = title
        self.resource = resource
        self.status = status
        self.severity = severity
        self.description = description
        self.remediation = remediation
        self.frameworks = frameworks or {}
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self):
        return {
            "check_id": self.check_id,
            "title": self.title,
            "resource": self.resource,
            "status": self.status,
            "severity": self.severity,
            "description": self.description,
            "remediation": self.remediation,
            "frameworks": self.frameworks,
            "timestamp": self.timestamp,
        }


class BaseAWSScanner:
    """Base class for AWS scanners."""

    def __init__(self, session: boto3.Session = None):
        self.session = session or boto3.Session()
        self.findings = []

    def get_client(self, service: str):
        return self.session.client(service)

    def add_finding(self, finding: Finding):
        self.findings.append(finding)

    def get_findings(self) -> list:
        return [f.to_dict() for f in self.findings]

    def scan(self) -> list:
        raise NotImplementedError("Subclasses must implement scan()")
