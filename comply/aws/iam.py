"""AWS IAM compliance checks — MFA, access keys, password policy."""

from datetime import datetime, timezone
from .base import BaseAWSScanner, Finding

MAX_ACCESS_KEY_AGE_DAYS = 90


class IAMScanner(BaseAWSScanner):
    """Scans AWS IAM for security compliance."""

    def scan(self) -> list:
        self.findings = []
        self._check_root_mfa()
        self._check_user_mfa()
        self._check_access_key_rotation()
        self._check_password_policy()
        return self.get_findings()

    # ── Root Account MFA ──────────────────────────────────────
    def _check_root_mfa(self):
        iam = self.get_client("iam")

        try:
            summary = iam.get_account_summary()["SummaryMap"]
            root_mfa = summary.get("AccountMFAEnabled", 0)

            if root_mfa == 0:
                self.add_finding(Finding(
                    check_id="IAM-001",
                    title="Root account MFA not enabled",
                    resource="root",
                    status=Finding.STATUS_FAIL,
                    severity=Finding.SEVERITY_CRITICAL,
                    description=(
                        "The AWS root account does not have MFA enabled. "
                        "The root account has unrestricted access to all resources."
                    ),
                    remediation=(
                        "Enable MFA on the root account immediately. Use a hardware "
                        "MFA device for maximum security. Go to IAM > Security credentials."
                    ),
                    frameworks={
                        "CIS_AWS": ["1.5"],
                        "SOC2": ["CC6.1", "CC6.2"],
                        "ISO27001": ["A.9.2.1", "A.9.4.2"],
                    },
                ))
            else:
                self.add_finding(Finding(
                    check_id="IAM-001-PASS",
                    title="Root account MFA enabled",
                    resource="root",
                    status=Finding.STATUS_PASS,
                    severity=Finding.SEVERITY_INFO,
                    description="The AWS root account has MFA enabled.",
                    remediation="No action required.",
                    frameworks={
                        "CIS_AWS": ["1.5"],
                        "SOC2": ["CC6.1", "CC6.2"],
                        "ISO27001": ["A.9.2.1", "A.9.4.2"],
                    },
                ))
        except Exception as e:
            self.add_finding(Finding(
                check_id="IAM-ERR-ROOT",
                title="Root MFA Check Error",
                resource="root",
                status=Finding.STATUS_WARN,
                severity=Finding.SEVERITY_INFO,
                description=f"Could not check root MFA: {str(e)}",
                remediation="Verify IAM permissions.",
            ))

    # ── User MFA ──────────────────────────────────────────────
    def _check_user_mfa(self):
        iam = self.get_client("iam")

        try:
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page["Users"]:
                    username = user["UserName"]

                    # Check if user has console access
                    try:
                        iam.get_login_profile(UserName=username)
                        has_console = True
                    except iam.exceptions.NoSuchEntityException:
                        has_console = False
                    except Exception:
                        has_console = None

                    if has_console:
                        mfa_devices = iam.list_mfa_devices(UserName=username)
                        if not mfa_devices.get("MFADevices"):
                            self.add_finding(Finding(
                                check_id="IAM-002",
                                title="Console user without MFA",
                                resource=username,
                                status=Finding.STATUS_FAIL,
                                severity=Finding.SEVERITY_HIGH,
                                description=(
                                    f"IAM user '{username}' has console access but no MFA "
                                    f"device configured."
                                ),
                                remediation=(
                                    f"Enable MFA for user '{username}'. Consider enforcing "
                                    f"MFA via IAM policy for all console users."
                                ),
                                frameworks={
                                    "CIS_AWS": ["1.10"],
                                    "SOC2": ["CC6.1", "CC6.2"],
                                    "ISO27001": ["A.9.4.2"],
                                },
                            ))
                        else:
                            self.add_finding(Finding(
                                check_id="IAM-002-PASS",
                                title="Console user has MFA",
                                resource=username,
                                status=Finding.STATUS_PASS,
                                severity=Finding.SEVERITY_INFO,
                                description=f"IAM user '{username}' has MFA enabled.",
                                remediation="No action required.",
                                frameworks={
                                    "CIS_AWS": ["1.10"],
                                    "SOC2": ["CC6.1"],
                                    "ISO27001": ["A.9.4.2"],
                                },
                            ))
        except Exception as e:
            self.add_finding(Finding(
                check_id="IAM-ERR-MFA",
                title="User MFA Check Error",
                resource="N/A",
                status=Finding.STATUS_WARN,
                severity=Finding.SEVERITY_INFO,
                description=f"Could not check user MFA: {str(e)}",
                remediation="Verify IAM permissions.",
            ))

    # ── Access Key Rotation ───────────────────────────────────
    def _check_access_key_rotation(self):
        iam = self.get_client("iam")

        try:
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page["Users"]:
                    username = user["UserName"]
                    keys = iam.list_access_keys(UserName=username)

                    for key in keys.get("AccessKeyMetadata", []):
                        if key["Status"] == "Active":
                            created = key["CreateDate"]
                            if created.tzinfo is None:
                                created = created.replace(tzinfo=timezone.utc)
                            age_days = (datetime.now(timezone.utc) - created).days

                            if age_days > MAX_ACCESS_KEY_AGE_DAYS:
                                self.add_finding(Finding(
                                    check_id="IAM-003",
                                    title="Access key not rotated",
                                    resource=f"{username} / {key['AccessKeyId']}",
                                    status=Finding.STATUS_FAIL,
                                    severity=Finding.SEVERITY_HIGH,
                                    description=(
                                        f"Access key {key['AccessKeyId']} for user '{username}' "
                                        f"is {age_days} days old (max: {MAX_ACCESS_KEY_AGE_DAYS})."
                                    ),
                                    remediation=(
                                        "Rotate the access key: create a new key, update "
                                        "applications, then deactivate and delete the old key."
                                    ),
                                    frameworks={
                                        "CIS_AWS": ["1.14"],
                                        "SOC2": ["CC6.1"],
                                        "ISO27001": ["A.9.2.5"],
                                    },
                                ))
                            else:
                                self.add_finding(Finding(
                                    check_id="IAM-003-PASS",
                                    title="Access key within rotation policy",
                                    resource=f"{username} / {key['AccessKeyId']}",
                                    status=Finding.STATUS_PASS,
                                    severity=Finding.SEVERITY_INFO,
                                    description=(
                                        f"Access key {key['AccessKeyId']} for user '{username}' "
                                        f"is {age_days} days old (within {MAX_ACCESS_KEY_AGE_DAYS}-day limit)."
                                    ),
                                    remediation="No action required.",
                                    frameworks={
                                        "CIS_AWS": ["1.14"],
                                        "SOC2": ["CC6.1"],
                                        "ISO27001": ["A.9.2.5"],
                                    },
                                ))
        except Exception as e:
            self.add_finding(Finding(
                check_id="IAM-ERR-KEYS",
                title="Access Key Rotation Check Error",
                resource="N/A",
                status=Finding.STATUS_WARN,
                severity=Finding.SEVERITY_INFO,
                description=f"Could not check access keys: {str(e)}",
                remediation="Verify IAM permissions.",
            ))

    # ── Password Policy ───────────────────────────────────────
    def _check_password_policy(self):
        iam = self.get_client("iam")

        try:
            policy = iam.get_account_password_policy()["PasswordPolicy"]

            checks = [
                ("MinimumPasswordLength", 14, ">=", "IAM-004a", "Minimum password length too short"),
                ("RequireUppercaseCharacters", True, "==", "IAM-004b", "Uppercase characters not required"),
                ("RequireLowercaseCharacters", True, "==", "IAM-004c", "Lowercase characters not required"),
                ("RequireNumbers", True, "==", "IAM-004d", "Numbers not required in password"),
                ("RequireSymbols", True, "==", "IAM-004e", "Symbols not required in password"),
                ("MaxPasswordAge", 90, "<=", "IAM-004f", "Password max age too long"),
                ("PasswordReusePrevention", 24, ">=", "IAM-004g", "Password reuse prevention too low"),
            ]

            for key, threshold, operator, check_id, title in checks:
                value = policy.get(key)
                if value is None:
                    continue

                if operator == ">=" and value < threshold:
                    failed = True
                elif operator == "==" and value != threshold:
                    failed = True
                elif operator == "<=" and value > threshold:
                    failed = True
                else:
                    failed = False

                if failed:
                    self.add_finding(Finding(
                        check_id=check_id,
                        title=title,
                        resource="Account Password Policy",
                        status=Finding.STATUS_FAIL,
                        severity=Finding.SEVERITY_MEDIUM,
                        description=f"{key} is {value} (expected {operator} {threshold}).",
                        remediation=f"Update password policy: set {key} {operator} {threshold}.",
                        frameworks={
                            "CIS_AWS": ["1.8"],
                            "SOC2": ["CC6.1"],
                            "ISO27001": ["A.9.4.3"],
                        },
                    ))

        except iam.exceptions.NoSuchEntityException:
            self.add_finding(Finding(
                check_id="IAM-004",
                title="No password policy configured",
                resource="Account Password Policy",
                status=Finding.STATUS_FAIL,
                severity=Finding.SEVERITY_HIGH,
                description="No custom password policy is configured for this AWS account.",
                remediation="Configure a strong password policy in IAM settings.",
                frameworks={
                    "CIS_AWS": ["1.8"],
                    "SOC2": ["CC6.1"],
                    "ISO27001": ["A.9.4.3"],
                },
            ))
        except Exception as e:
            self.add_finding(Finding(
                check_id="IAM-ERR-PWD",
                title="Password Policy Check Error",
                resource="N/A",
                status=Finding.STATUS_WARN,
                severity=Finding.SEVERITY_INFO,
                description=f"Could not check password policy: {str(e)}",
                remediation="Verify IAM permissions.",
            ))
