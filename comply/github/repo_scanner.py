"""GitHub repository compliance scanner."""

import os
from datetime import datetime, timezone
from github import Github, GithubException


class GitHubFinding:
    """Represents a GitHub compliance finding."""

    def __init__(self, check_id, title, repo, status, severity, description, remediation, frameworks=None):
        self.check_id = check_id
        self.title = title
        self.repo = repo
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
            "resource": self.repo,
            "status": self.status,
            "severity": self.severity,
            "description": self.description,
            "remediation": self.remediation,
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
        """Scan a specific repo or all configured repos."""
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
            except GithubException as e:
                self.findings.append(GitHubFinding(
                    check_id="GH-ERR-001",
                    title="Repository Access Error",
                    repo=name,
                    status="ERROR",
                    severity="INFO",
                    description=f"Could not access repo '{name}': {str(e)}",
                    remediation="Verify GitHub token permissions and repo name.",
                ).to_dict())

        return self.findings

    def _check_branch_protection(self, repo):
        """Check if the default branch has protection rules."""
        name = repo.full_name
        default_branch = repo.default_branch

        try:
            branch = repo.get_branch(default_branch)
            protection = branch.get_protection()

            checks = []
            # Check required reviews
            try:
                reviews = protection.required_pull_request_reviews
                if reviews is None:
                    checks.append("PR reviews not required")
            except Exception:
                checks.append("PR reviews not configured")

            # Check status checks
            try:
                status_checks = protection.required_status_checks
                if status_checks is None:
                    checks.append("Status checks not required")
            except Exception:
                checks.append("Status checks not configured")

            if checks:
                self.findings.append(GitHubFinding(
                    check_id="GH-BP-002",
                    title="Branch protection incomplete",
                    repo=name,
                    status="WARNING",
                    severity="MEDIUM",
                    description=(
                        f"Branch '{default_branch}' has protection enabled but is missing: "
                        f"{', '.join(checks)}."
                    ),
                    remediation="Enable required PR reviews and status checks.",
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
                    description=f"Branch '{default_branch}' has full protection enabled.",
                    remediation="No action required.",
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
                description=(
                    f"The default branch '{default_branch}' has no branch protection rules. "
                    f"Anyone with write access can push directly."
                ),
                remediation=(
                    "Enable branch protection rules: require PR reviews, "
                    "status checks, and restrict force pushes."
                ),
                frameworks={
                    "SOC2": ["CC8.1", "CC6.1"],
                    "ISO27001": ["A.12.1.2", "A.14.2.2"],
                },
            ).to_dict())

    def _check_security_policy(self, repo):
        """Check if SECURITY.md exists."""
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
                frameworks={"SOC2": ["CC1.1"]},
            ).to_dict())
        except GithubException:
            self.findings.append(GitHubFinding(
                check_id="GH-SEC-001",
                title="Missing security policy",
                repo=name,
                status="FAIL",
                severity="MEDIUM",
                description="No SECURITY.md file found. Users have no way to report vulnerabilities.",
                remediation="Add a SECURITY.md file with vulnerability reporting instructions.",
                frameworks={
                    "SOC2": ["CC1.1", "CC7.4"],
                    "ISO27001": ["A.16.1.2"],
                },
            ).to_dict())

    def _check_gitignore(self, repo):
        """Check if .gitignore exists."""
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
                frameworks={
                    "SOC2": ["CC6.1"],
                    "ISO27001": ["A.9.4.1"],
                },
            ).to_dict())

    def _check_secrets_in_env(self, repo):
        """Check if .env files are committed (they shouldn't be)."""
        name = repo.full_name
        env_files = [".env", ".env.local", ".env.production"]

        for env_file in env_files:
            try:
                repo.get_contents(env_file)
                self.findings.append(GitHubFinding(
                    check_id="GH-ENV-001",
                    title=f"Sensitive file committed: {env_file}",
                    repo=name,
                    status="FAIL",
                    severity="CRITICAL",
                    description=(
                        f"File '{env_file}' is committed to the repository. "
                        f"This may contain secrets, API keys, or credentials."
                    ),
                    remediation=(
                        f"Remove '{env_file}' from the repository, rotate any exposed "
                        f"secrets, and add it to .gitignore."
                    ),
                    frameworks={
                        "SOC2": ["CC6.1", "CC6.7"],
                        "ISO27001": ["A.9.4.1", "A.10.1.1"],
                    },
                ).to_dict())
            except GithubException:
                pass  # Good — file not found

    def _check_dependabot(self, repo):
        """Check if Dependabot config exists."""
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
                description="No Dependabot configuration found. Dependencies may have known vulnerabilities.",
                remediation="Add .github/dependabot.yml to enable automated security updates.",
                frameworks={
                    "SOC2": ["CC7.1"],
                    "ISO27001": ["A.12.6.1"],
                },
            ).to_dict())

    def _check_default_branch_name(self, repo):
        """Flag if default branch is still 'master' (best practice is 'main')."""
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
            ).to_dict())

