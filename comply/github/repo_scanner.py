"""GitHub repository compliance scanner with audit reasoning."""

import os
from datetime import datetime, timezone
from github import Github, GithubException

DOMAIN_SCM = "Source Code Management"
DOMAIN_VULN = "Vulnerability Management"
DOMAIN_ACCESS = "Access Control"


class GitHubFinding:
    """Represents a GitHub compliance finding."""

    def __init__(self, check_id, title, repo, status, severity, description, remediation,
                 reasoning="", control_domain="Source Code Management", frameworks=None):
        self.check_id = check_id
        self.title = title
        self.repo = repo
        self.status = status
        self.severity = severity
        self.description = description
        self.remediation = remediation
        self.reasoning = reasoning
        self.control_domain = control_domain
        self.frameworks = frameworks or {}
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self):
        return {
            "check_id": self.check_id,
            "title": self.title,
            "resource": self.repo,
            "status": self.status,
            "severity": self.severity,
            "description": self.description,
            "remediation": self.remediation,
            "reasoning": self.reasoning,
            "control_domain": self.control_domain,
            "frameworks": self.frameworks,
            "timestamp": self.timestamp,
        }


class GitHubRepoScanner:
    """Scans GitHub repositories for security and compliance best practices."""

    def __init__(self, token: str = None, repos: list = None):
        self.token = token or os.getenv("GITHUB_TOKEN")
        self.github = Github(self.token)
        self.repos = repos or []
        self.findings = []

    def scan(self, repo_name: str = None) -> list:
        self.findings = []
        targets = [repo_name] if repo_name else self.repos

        for name in targets:
            try:
                repo = self.github.get_repo(name)
                self._check_branch_protection(repo)
                self._check_security_policy(repo)
                self._check_gitignore(repo)
                self._check_secrets_in_env(repo)
                self._check_dependabot(repo)
                self._check_default_branch_name(repo)
                self._check_license(repo)
            except GithubException as e:
                self.findings.append(GitHubFinding(
                    check_id="GH-ERR-001",
                    title="Repository Access Error",
                    repo=name,
                    status="ERROR",
                    severity="INFO",
                    description=f"Could not access repo '{name}': {str(e)}",
                    remediation="Verify GitHub token permissions and repo name.",
                    reasoning=f"The scanner could not access repository '{name}'. This may indicate an invalid token, insufficient permissions, or the repository does not exist. Error: {str(e)}",
                    control_domain=DOMAIN_SCM,
                ).to_dict())

        return self.findings

    def _check_branch_protection(self, repo):
        name = repo.full_name
        default_branch = repo.default_branch

        try:
            branch = repo.get_branch(default_branch)
            protection = branch.get_protection()

            checks_missing = []
            checks_present = []

            # Check required reviews
            try:
                reviews = protection.required_pull_request_reviews
                if reviews is None:
                    checks_missing.append("PR reviews not required")
                else:
                    checks_present.append("PR reviews required")
            except Exception:
                checks_missing.append("PR reviews not configured")

            # Check status checks
            try:
                status_checks = protection.required_status_checks
                if status_checks is None:
                    checks_missing.append("Status checks not required")
                else:
                    checks_present.append("Status checks required")
            except Exception:
                checks_missing.append("Status checks not configured")

            # Check force push restriction
            try:
                allow_force = protection.allow_force_pushes
                if allow_force and allow_force.enabled:
                    checks_missing.append("Force pushes allowed")
                else:
                    checks_present.append("Force pushes blocked")
            except Exception:
                checks_present.append("Force push status unknown (likely restricted)")

            # Check deletion protection
            try:
                allow_delete = protection.allow_deletions
                if allow_delete and allow_delete.enabled:
                    checks_missing.append("Branch deletion allowed")
                else:
                    checks_present.append("Branch deletion blocked")
            except Exception:
                pass

            if checks_missing:
                self.findings.append(GitHubFinding(
                    check_id="GH-BP-002",
                    title="Branch protection incomplete",
                    repo=name,
                    status="WARNING",
                    severity="MEDIUM",
                    description=f"Branch '{default_branch}' has protection but is missing: {', '.join(checks_missing)}.",
                    remediation="Enable required PR reviews, status checks, and restrict force pushes.",
                    reasoning=(
                        f"WARNING: Branch protection is enabled on '{default_branch}' but has gaps. "
                        f"Present controls: {', '.join(checks_present) if checks_present else 'None'}. "
                        f"Missing controls: {', '.join(checks_missing)}. "
                        f"Without required PR reviews, code changes bypass peer review — a key control for catching "
                        f"bugs, security vulnerabilities, and unauthorized changes. Without status checks, broken code "
                        f"can be merged to the main branch. SOC 2 CC8.1 requires change management controls including "
                        f"authorization and testing before deployment. ISO 27001 A.12.1.2 and A.14.2.2 require change "
                        f"management procedures."
                    ),
                    control_domain=DOMAIN_SCM,
                    frameworks={
                        "SOC2": ["CC8.1"],
                        "ISO27001": ["A.12.1.2", "A.14.2.2"],
                    },
                ).to_dict())
            else:
                self.findings.append(GitHubFinding(
                    check_id="GH-BP-PASS",
                    title="Branch protection properly configured",
                    repo=name,
                    status="PASS",
                    severity="INFO",
                    description=f"Branch '{default_branch}' has full protection: {', '.join(checks_present)}.",
                    remediation="No action required.",
                    reasoning=(
                        f"PASS: Branch '{default_branch}' on {name} has comprehensive protection enabled. "
                        f"Active controls: {', '.join(checks_present)}. "
                        f"All code changes must go through pull requests with peer review, pass automated checks, "
                        f"and cannot be force-pushed or deleted. This enforces a proper change management workflow "
                        f"that satisfies SOC 2 CC8.1 (change management) and ISO 27001 A.12.1.2 (change management) "
                        f"and A.14.2.2 (system change control)."
                    ),
                    control_domain=DOMAIN_SCM,
                    frameworks={
                        "SOC2": ["CC8.1"],
                        "ISO27001": ["A.12.1.2"],
                    },
                ).to_dict())

        except GithubException:
            self.findings.append(GitHubFinding(
                check_id="GH-BP-001",
                title="No branch protection on default branch",
                repo=name,
                status="FAIL",
                severity="HIGH",
                description=f"The default branch '{default_branch}' has no branch protection rules.",
                remediation="Enable branch protection rules: require PR reviews, status checks, restrict force pushes.",
                reasoning=(
                    f"FAIL: The default branch '{default_branch}' on {name} has NO branch protection rules configured. "
                    f"This means: (1) Anyone with write access can push directly to the main branch without review. "
                    f"(2) Code changes bypass all quality gates and peer review. (3) Force pushes can rewrite history "
                    f"and destroy audit trails. (4) The branch can be deleted. This is a fundamental change management "
                    f"failure. SOC 2 CC8.1 requires that changes are authorized, tested, and approved before implementation. "
                    f"ISO 27001 A.12.1.2 requires documented change management procedures. Without branch protection, "
                    f"there is no enforced separation of duties between code author and code reviewer."
                ),
                control_domain=DOMAIN_SCM,
                frameworks={
                    "SOC2": ["CC8.1", "CC6.1"],
                    "ISO27001": ["A.12.1.2", "A.14.2.2"],
                },
            ).to_dict())

    def _check_security_policy(self, repo):
        name = repo.full_name
        try:
            repo.get_contents("SECURITY.md")
            self.findings.append(GitHubFinding(
                check_id="GH-SEC-PASS",
                title="Security policy present",
                repo=name,
                status="PASS",
                severity="INFO",
                description="SECURITY.md file found in repository.",
                remediation="No action required.",
                reasoning=(
                    f"PASS: Repository {name} contains a SECURITY.md file, providing a documented process for "
                    f"reporting security vulnerabilities. This satisfies SOC 2 CC1.1 (governance) and CC7.4 "
                    f"(incident response) by establishing a communication channel for security issues. "
                    f"ISO 27001 A.16.1.2 requires reporting of information security events."
                ),
                control_domain=DOMAIN_SCM,
                frameworks={"SOC2": ["CC1.1", "CC7.4"], "ISO27001": ["A.16.1.2"]},
            ).to_dict())
        except GithubException:
            self.findings.append(GitHubFinding(
                check_id="GH-SEC-001",
                title="Missing security policy",
                repo=name,
                status="FAIL",
                severity="MEDIUM",
                description="No SECURITY.md file found.",
                remediation="Add a SECURITY.md file with vulnerability reporting instructions.",
                reasoning=(
                    f"FAIL: Repository {name} has no SECURITY.md file. Without a security policy, external "
                    f"researchers or users who discover vulnerabilities have no documented way to report them "
                    f"responsibly. This increases the risk of public disclosure without a fix (zero-day). "
                    f"SOC 2 CC1.1 requires governance documentation. CC7.4 requires incident response processes. "
                    f"ISO 27001 A.16.1.2 requires mechanisms for reporting security events."
                ),
                control_domain=DOMAIN_SCM,
                frameworks={
                    "SOC2": ["CC1.1", "CC7.4"],
                    "ISO27001": ["A.16.1.2"],
                },
            ).to_dict())

    def _check_gitignore(self, repo):
        name = repo.full_name
        try:
            repo.get_contents(".gitignore")
            self.findings.append(GitHubFinding(
                check_id="GH-GI-PASS",
                title=".gitignore present",
                repo=name,
                status="PASS",
                severity="INFO",
                description=".gitignore file found.",
                remediation="No action required.",
                reasoning=(
                    f"PASS: Repository {name} has a .gitignore file configured, reducing the risk of accidentally "
                    f"committing sensitive files (credentials, environment files, private keys) to version control."
                ),
                control_domain=DOMAIN_ACCESS,
            ).to_dict())
        except GithubException:
            self.findings.append(GitHubFinding(
                check_id="GH-GI-001",
                title="Missing .gitignore",
                repo=name,
                status="WARNING",
                severity="LOW",
                description="No .gitignore file. Sensitive files may be accidentally committed.",
                remediation="Add a .gitignore file appropriate for your tech stack.",
                reasoning=(
                    f"WARNING: Repository {name} has no .gitignore file. Without it, developers may accidentally "
                    f"commit sensitive files such as .env (credentials), private keys, or build artifacts. "
                    f"SOC 2 CC6.1 requires access controls over sensitive information. "
                    f"ISO 27001 A.9.4.1 requires information access restriction."
                ),
                control_domain=DOMAIN_ACCESS,
                frameworks={
                    "SOC2": ["CC6.1"],
                    "ISO27001": ["A.9.4.1"],
                },
            ).to_dict())

    def _check_secrets_in_env(self, repo):
        name = repo.full_name
        env_files = [".env", ".env.local", ".env.production"]
        found_any = False

        for env_file in env_files:
            try:
                repo.get_contents(env_file)
                found_any = True
                self.findings.append(GitHubFinding(
                    check_id="GH-ENV-001",
                    title=f"Sensitive file committed: {env_file}",
                    repo=name,
                    status="FAIL",
                    severity="CRITICAL",
                    description=f"File '{env_file}' is committed to the repository.",
                    remediation=f"Remove '{env_file}', rotate exposed secrets, add to .gitignore.",
                    reasoning=(
                        f"FAIL: File '{env_file}' is committed to repository {name}. Environment files typically "
                        f"contain secrets such as API keys, database passwords, encryption keys, and third-party "
                        f"credentials. Once committed, these secrets exist in the git history PERMANENTLY (even if "
                        f"the file is later deleted) and may be accessible to anyone with read access to the repo. "
                        f"If the repo is public, these secrets are exposed to the entire internet. "
                        f"SOC 2 CC6.1 requires protection of credentials. CC6.7 requires encryption of sensitive data. "
                        f"ISO 27001 A.9.4.1 and A.10.1.1 require access restriction and cryptographic controls. "
                        f"IMMEDIATE ACTION: Rotate ALL secrets that were in this file."
                    ),
                    control_domain=DOMAIN_ACCESS,
                    frameworks={
                        "SOC2": ["CC6.1", "CC6.7"],
                        "ISO27001": ["A.9.4.1", "A.10.1.1"],
                    },
                ).to_dict())
            except GithubException:
                pass

        if not found_any:
            self.findings.append(GitHubFinding(
                check_id="GH-ENV-PASS",
                title="No sensitive environment files committed",
                repo=name,
                status="PASS",
                severity="INFO",
                description="No .env, .env.local, or .env.production files found in repository.",
                remediation="No action required.",
                reasoning=(
                    f"PASS: Repository {name} does not have any common environment files (.env, .env.local, "
                    f".env.production) committed. Secrets appear to be managed outside of version control, "
                    f"which is the expected practice per SOC 2 CC6.1 and ISO 27001 A.9.4.1."
                ),
                control_domain=DOMAIN_ACCESS,
                frameworks={"SOC2": ["CC6.1"], "ISO27001": ["A.9.4.1"]},
            ).to_dict())

    def _check_dependabot(self, repo):
        name = repo.full_name
        try:
            repo.get_contents(".github/dependabot.yml")
            self.findings.append(GitHubFinding(
                check_id="GH-DEP-PASS",
                title="Dependabot configured",
                repo=name,
                status="PASS",
                severity="INFO",
                description="Dependabot is configured for automated dependency updates.",
                remediation="No action required.",
                reasoning=(
                    f"PASS: Repository {name} has Dependabot configured (.github/dependabot.yml). "
                    f"Dependabot automatically scans dependencies for known vulnerabilities (CVEs) and creates "
                    f"pull requests to update vulnerable packages. This provides continuous vulnerability management "
                    f"without manual effort. SOC 2 CC7.1 requires vulnerability management. "
                    f"ISO 27001 A.12.6.1 requires management of technical vulnerabilities."
                ),
                control_domain=DOMAIN_VULN,
                frameworks={
                    "SOC2": ["CC7.1"],
                    "ISO27001": ["A.12.6.1"],
                },
            ).to_dict())
        except GithubException:
            self.findings.append(GitHubFinding(
                check_id="GH-DEP-001",
                title="Dependabot not configured",
                repo=name,
                status="WARNING",
                severity="MEDIUM",
                description="No Dependabot configuration found.",
                remediation="Add .github/dependabot.yml to enable automated security updates.",
                reasoning=(
                    f"WARNING: Repository {name} does not have Dependabot configured. Without automated dependency "
                    f"scanning, the project may unknowingly use libraries with known critical vulnerabilities (CVEs). "
                    f"For example, a vulnerable version of a logging library (like Log4Shell) could remain in the "
                    f"codebase indefinitely. SOC 2 CC7.1 requires ongoing vulnerability identification and remediation. "
                    f"ISO 27001 A.12.6.1 requires timely management of technical vulnerabilities."
                ),
                control_domain=DOMAIN_VULN,
                frameworks={
                    "SOC2": ["CC7.1"],
                    "ISO27001": ["A.12.6.1"],
                },
            ).to_dict())

    def _check_default_branch_name(self, repo):
        name = repo.full_name
        if repo.default_branch == "master":
            self.findings.append(GitHubFinding(
                check_id="GH-BR-001",
                title="Default branch is 'master'",
                repo=name,
                status="WARNING",
                severity="LOW",
                description="Default branch is 'master'. Industry best practice recommends 'main'.",
                remediation="Rename default branch to 'main' via repository settings.",
                reasoning=(
                    f"WARNING: Repository {name} uses 'master' as the default branch name. While not a security "
                    f"vulnerability, industry best practice (GitHub, GitLab, Bitbucket defaults) has moved to 'main'. "
                    f"Some CI/CD tools and integrations now default to 'main', which could cause configuration drift."
                ),
                control_domain=DOMAIN_SCM,
            ).to_dict())

    def _check_license(self, repo):
        name = repo.full_name
        try:
            repo.get_contents("LICENSE")
            self.findings.append(GitHubFinding(
                check_id="GH-LIC-PASS",
                title="LICENSE file present",
                repo=name,
                status="PASS",
                severity="INFO",
                description="LICENSE file found in repository.",
                remediation="No action required.",
                reasoning=(
                    f"PASS: Repository {name} has a LICENSE file, clearly defining the terms under which the code "
                    f"can be used, modified, and distributed. This is a governance best practice."
                ),
                control_domain=DOMAIN_SCM,
                frameworks={"SOC2": ["CC1.1"]},
            ).to_dict())
        except GithubException:
            self.findings.append(GitHubFinding(
                check_id="GH-LIC-001",
                title="Missing LICENSE file",
                repo=name,
                status="WARNING",
                severity="LOW",
                description="No LICENSE file found.",
                remediation="Add a LICENSE file (MIT, Apache 2.0, etc.) to define usage terms.",
                reasoning=(
                    f"WARNING: Repository {name} has no LICENSE file. Without a license, the code is technically "
                    f"under exclusive copyright by default — others cannot legally use, modify, or distribute it. "
                    f"For open-source projects, this creates legal ambiguity."
                ),
                control_domain=DOMAIN_SCM,
                frameworks={"SOC2": ["CC1.1"]},
            ).to_dict())
