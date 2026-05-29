"""AWS IAM compliance checks with audit reasoning."""

from datetime import datetime, timezone
from .base import BaseAWSScanner, Finding

MAX_ACCESS_KEY_AGE_DAYS = 90
DOMAIN = "Identity & Access Management"


class IAMScanner(BaseAWSScanner):
    """Scans AWS IAM for security compliance."""

    def scan(self) -> list:
        self.findings = []
        self._check_root_mfa()
        self._check_user_mfa()
        self._check_access_key_rotation()
        self._check_password_policy()
        return self.get_findings()

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
                    description="The AWS root account does not have MFA enabled.",
                    remediation="Enable MFA on the root account immediately using a hardware MFA device.",
                    reasoning=(
                        "FAIL: The AWS root account (the account created during AWS signup) does not have multi-factor "
                        "authentication (MFA) enabled. The root account has UNRESTRICTED access to every resource and service "
                        "in the AWS account — it cannot be limited by IAM policies. If compromised via password breach, phishing, "
                        "or credential stuffing, an attacker gains total control: they can delete all resources, exfiltrate all data, "
                        "create new admin users, and run up unlimited charges. CIS AWS 1.5 requires root MFA. SOC 2 CC6.1 and CC6.2 "
                        "require strong authentication controls. ISO 27001 A.9.4.2 requires secure log-on procedures. "
                        "This is the single highest-impact finding possible in an AWS environment."
                    ),
                    control_domain=DOMAIN,
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
                    reasoning=(
                        "PASS: The AWS root account has MFA enabled. Even if the root password is compromised, an attacker "
                        "would also need the physical MFA device or TOTP code to gain access. This satisfies CIS AWS 1.5, "
                        "SOC 2 CC6.1/CC6.2, and ISO 27001 A.9.4.2. Best practice: use a hardware MFA device (YubiKey) for "
                        "root and avoid using the root account for day-to-day operations."
                    ),
                    control_domain=DOMAIN,
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
                reasoning=f"Scanner could not call iam:GetAccountSummary. Error: {str(e)}.",
                control_domain=DOMAIN,
            ))

    def _check_user_mfa(self):
        iam = self.get_client("iam")

        try:
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page["Users"]:
                    username = user["UserName"]

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
                                description=f"IAM user \'{username}\' has console access but no MFA configured.",
                                remediation=f"Enable MFA for user \'{username}\'. Consider enforcing MFA via IAM policy.",
                                reasoning=(
                                    f"FAIL: IAM user \'{username}\' has AWS Management Console access (login profile exists) but "
                                    f"no MFA device is registered. This means the account is protected only by a password, which can "
                                    f"be compromised through phishing, credential stuffing, password reuse, or brute force. "
                                    f"CIS AWS 1.10 requires MFA for all IAM users with console access. SOC 2 CC6.1 and CC6.2 require "
                                    f"multi-factor authentication as part of logical access controls. ISO 27001 A.9.4.2 requires secure "
                                    f"log-on procedures including strong authentication."
                                ),
                                control_domain=DOMAIN,
                                frameworks={
                                    "CIS_AWS": ["1.10"],
                                    "SOC2": ["CC6.1", "CC6.2"],
                                    "ISO27001": ["A.9.4.2"],
                                },
                            ))
                        else:
                            mfa_type = mfa_devices["MFADevices"][0].get("SerialNumber", "")
                            is_virtual = "mfa" in mfa_type.lower() and "arn:aws:iam" in mfa_type
                            self.add_finding(Finding(
                                check_id="IAM-002-PASS",
                                title="Console user has MFA",
                                resource=username,
                                status=Finding.STATUS_PASS,
                                severity=Finding.SEVERITY_INFO,
                                description=f"IAM user \'{username}\' has MFA enabled.",
                                remediation="No action required.",
                                reasoning=(
                                    f"PASS: IAM user \'{username}\' has console access AND an MFA device registered "
                                    f"({'virtual MFA' if is_virtual else 'hardware MFA'}). Authentication requires both a password "
                                    f"and the MFA code, significantly reducing the risk of account compromise. This satisfies "
                                    f"CIS AWS 1.10, SOC 2 CC6.1/CC6.2, and ISO 27001 A.9.4.2."
                                ),
                                control_domain=DOMAIN,
                                frameworks={
                                    "CIS_AWS": ["1.10"],
                                    "SOC2": ["CC6.1"],
                                    "ISO27001": ["A.9.4.2"],
                                },
                            ))
                    elif has_console is False:
                        # Programmatic-only user, no console — still note it
                        self.add_finding(Finding(
                            check_id="IAM-002-NA",
                            title="Programmatic-only user (no console access)",
                            resource=username,
                            status=Finding.STATUS_PASS,
                            severity=Finding.SEVERITY_INFO,
                            description=f"IAM user \'{username}\' has no console access. MFA check not applicable.",
                            remediation="No action required for MFA. Ensure access keys are rotated regularly.",
                            reasoning=(
                                f"PASS (N/A): IAM user \'{username}\' does not have a console login profile, meaning this is a "
                                f"programmatic-only account (API/CLI access via access keys). Console MFA is not applicable. "
                                f"However, access key security should be monitored — see access key rotation checks."
                            ),
                            control_domain=DOMAIN,
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
                reasoning=f"Scanner could not enumerate IAM users or MFA devices. Error: {str(e)}.",
                control_domain=DOMAIN,
            ))

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
                            key_id = key["AccessKeyId"]

                            if age_days > MAX_ACCESS_KEY_AGE_DAYS:
                                self.add_finding(Finding(
                                    check_id="IAM-003",
                                    title="Access key not rotated",
                                    resource=f"{username} / {key_id}",
                                    status=Finding.STATUS_FAIL,
                                    severity=Finding.SEVERITY_HIGH,
                                    description=f"Access key {key_id} is {age_days} days old (max: {MAX_ACCESS_KEY_AGE_DAYS}).",
                                    remediation="Rotate the access key: create new key, update apps, deactivate old key.",
                                    reasoning=(
                                        f"FAIL: Access key {key_id} for user \'{username}\' was created {age_days} days ago, "
                                        f"exceeding the {MAX_ACCESS_KEY_AGE_DAYS}-day rotation policy. Long-lived access keys increase "
                                        f"the window of exposure if compromised — an attacker who obtains an old key has had more time "
                                        f"to use it before detection. CIS AWS 1.14 requires keys rotated every 90 days. SOC 2 CC6.1 "
                                        f"requires periodic credential rotation. ISO 27001 A.9.2.5 requires regular review of access rights."
                                    ),
                                    control_domain=DOMAIN,
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
                                    resource=f"{username} / {key_id}",
                                    status=Finding.STATUS_PASS,
                                    severity=Finding.SEVERITY_INFO,
                                    description=f"Access key {key_id} is {age_days} days old (within {MAX_ACCESS_KEY_AGE_DAYS}-day limit).",
                                    remediation="No action required.",
                                    reasoning=(
                                        f"PASS: Access key {key_id} for user \'{username}\' is {age_days} days old, within the "
                                        f"{MAX_ACCESS_KEY_AGE_DAYS}-day rotation window. This satisfies CIS AWS 1.14, SOC 2 CC6.1, "
                                        f"and ISO 27001 A.9.2.5. Key should be rotated before day {MAX_ACCESS_KEY_AGE_DAYS}."
                                    ),
                                    control_domain=DOMAIN,
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
                reasoning=f"Scanner could not enumerate access keys. Error: {str(e)}.",
                control_domain=DOMAIN,
            ))

    def _check_password_policy(self):
        iam = self.get_client("iam")

        try:
            policy = iam.get_account_password_policy()["PasswordPolicy"]

            checks = [
                ("MinimumPasswordLength", 14, ">=", "IAM-004a", "Minimum password length too short",
                 "Short passwords are vulnerable to brute-force attacks. NIST 800-63B and CIS recommend >= 14 characters."),
                ("RequireUppercaseCharacters", True, "==", "IAM-004b", "Uppercase characters not required",
                 "Complexity requirements increase the keyspace attackers must search."),
                ("RequireLowercaseCharacters", True, "==", "IAM-004c", "Lowercase characters not required",
                 "Complexity requirements increase the keyspace attackers must search."),
                ("RequireNumbers", True, "==", "IAM-004d", "Numbers not required in password",
                 "Numeric characters add entropy and are a standard complexity requirement."),
                ("RequireSymbols", True, "==", "IAM-004e", "Symbols not required in password",
                 "Symbol requirements are a common compliance expectation, though length is more impactful."),
                ("MaxPasswordAge", 90, "<=", "IAM-004f", "Password max age too long",
                 "Passwords older than 90 days have a higher chance of being compromised through various attack vectors."),
                ("PasswordReusePrevention", 24, ">=", "IAM-004g", "Password reuse prevention too low",
                 "Low reuse prevention allows users to cycle back to previously compromised passwords."),
            ]

            all_passed = True
            for key, threshold, operator, check_id, title, reason_detail in checks:
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
                    all_passed = False
                    self.add_finding(Finding(
                        check_id=check_id,
                        title=title,
                        resource="Account Password Policy",
                        status=Finding.STATUS_FAIL,
                        severity=Finding.SEVERITY_MEDIUM,
                        description=f"{key} is {value} (expected {operator} {threshold}).",
                        remediation=f"Update password policy: set {key} {operator} {threshold}.",
                        reasoning=(
                            f"FAIL: Password policy setting \'{key}\' has value {value}, which does not meet the threshold "
                            f"of {operator} {threshold}. {reason_detail} CIS AWS 1.8 requires a comprehensive password policy. "
                            f"SOC 2 CC6.1 requires logical access controls including credential management. "
                            f"ISO 27001 A.9.4.3 requires a password management system."
                        ),
                        control_domain=DOMAIN,
                        frameworks={
                            "CIS_AWS": ["1.8"],
                            "SOC2": ["CC6.1"],
                            "ISO27001": ["A.9.4.3"],
                        },
                    ))

            if all_passed:
                self.add_finding(Finding(
                    check_id="IAM-004-PASS",
                    title="Password policy meets all requirements",
                    resource="Account Password Policy",
                    status=Finding.STATUS_PASS,
                    severity=Finding.SEVERITY_INFO,
                    description="Account password policy meets or exceeds all CIS benchmark requirements.",
                    remediation="No action required.",
                    reasoning=(
                        "PASS: The AWS account password policy meets all checked thresholds: minimum length >= 14, "
                        "uppercase/lowercase/numbers/symbols required, max age <= 90 days, and reuse prevention >= 24. "
                        "This satisfies CIS AWS 1.8, SOC 2 CC6.1, and ISO 27001 A.9.4.3."
                    ),
                    control_domain=DOMAIN,
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
                reasoning=(
                    "FAIL: No custom password policy exists. AWS will use the default policy which has weaker requirements "
                    "(minimum 8 characters, no complexity, no rotation, no reuse prevention). This means users can set weak "
                    "passwords like \'password\' or \'12345678\'. CIS AWS 1.8 requires a configured policy. SOC 2 CC6.1 and "
                    "ISO 27001 A.9.4.3 require password management controls."
                ),
                control_domain=DOMAIN,
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
                reasoning=f"Scanner could not call iam:GetAccountPasswordPolicy. Error: {str(e)}.",
                control_domain=DOMAIN,
            ))
