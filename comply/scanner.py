"""Main scanner orchestrator — runs all compliance checks."""

from datetime import datetime, timezone

import boto3
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from comply.aws import SecurityGroupScanner, EncryptionScanner, BackupScanner, IAMScanner
from comply.github import GitHubRepoScanner
from comply.reports import ReportGenerator
from comply.frameworks.mappings import get_framework_summary


console = Console()


class ComplyScanner:
    """Orchestrates all compliance scans and generates reports."""

    def __init__(self, aws_session=None, github_token=None, github_repos=None):
        self.aws_session = aws_session or boto3.Session()
        self.github_token = github_token
        self.github_repos = github_repos or []
        self.all_findings = []

    def run_aws_scan(self) -> list:
        """Run all AWS compliance scans."""
        console.print(Panel("☁️  Running AWS Compliance Scans", style="bold cyan"))
        findings = []

        scanners = [
            ("🔒 Security Groups", SecurityGroupScanner(self.aws_session)),
            ("🔐 Encryption (S3/EBS/RDS)", EncryptionScanner(self.aws_session)),
            ("💾 Backups & Availability", BackupScanner(self.aws_session)),
            ("👤 IAM Security", IAMScanner(self.aws_session)),
        ]

        for name, scanner in scanners:
            console.print(f"  {name}...", end=" ")
            try:
                results = scanner.scan()
                findings.extend(results)
                fail_count = sum(1 for r in results if r["status"] == "FAIL")
                pass_count = sum(1 for r in results if r["status"] == "PASS")
                console.print(f"[green]{pass_count} passed[/green], [red]{fail_count} failed[/red]")
            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")

        return findings

    def run_github_scan(self) -> list:
        """Run GitHub repository compliance scans."""
        if not self.github_token or not self.github_repos:
            console.print("[yellow]⚠️  Skipping GitHub scan (no token or repos configured)[/yellow]")
            return []

        console.print(Panel("🐙 Running GitHub Compliance Scans", style="bold cyan"))
        scanner = GitHubRepoScanner(token=self.github_token, repos=self.github_repos)
        findings = scanner.scan()

        for repo in self.github_repos:
            repo_findings = [f for f in findings if f["resource"] == repo]
            fail_count = sum(1 for f in repo_findings if f["status"] == "FAIL")
            pass_count = sum(1 for f in repo_findings if f["status"] == "PASS")
            console.print(f"  📦 {repo}: [green]{pass_count} passed[/green], [red]{fail_count} failed[/red]")

        return findings

    def run_full_scan(self) -> dict:
        """Run all scans, generate reports, and display summary.

        Returns a dict compatible with the Streamlit dashboard:
          {
            "scan_time": "<ISO timestamp>",
            "findings":  [ ... ],
            "summary":   { ... },
            "json_report": "<path>",
            "html_report": "<path>",
          }
        """
        scan_time = datetime.now(timezone.utc).isoformat()

        console.print()
        console.print(Panel.fit(
            "[bold cyan]🛡️  Comply.dev — Cloud Compliance Scanner[/bold cyan]\n"
            "[dim]Automated compliance checks for AWS & GitHub[/dim]",
            border_style="cyan",
        ))
        console.print()

        # Run scans
        aws_findings = self.run_aws_scan()
        github_findings = self.run_github_scan()
        self.all_findings = aws_findings + github_findings

        # Generate reports
        console.print()
        console.print(Panel("📄 Generating Reports", style="bold cyan"))
        reporter = ReportGenerator(self.all_findings)
        json_path = reporter.generate_json()
        html_path = reporter.generate_html()
        console.print(f"  📋 JSON report: [blue]{json_path}[/blue]")
        console.print(f"  🌐 HTML report: [blue]{html_path}[/blue]")

        # Display summary
        self._display_summary()

        # FIX: include scan_time so the dashboard can display it
        return {
            "scan_time": scan_time,
            "findings": self.all_findings,
            "summary": reporter.get_summary(),
            "json_report": json_path,
            "html_report": html_path,
        }

    def _display_summary(self):
        """Display a rich summary table in the terminal."""
        console.print()
        summary = get_framework_summary(self.all_findings)

        table = Table(title="📊 Framework Compliance Summary", show_lines=True)
        table.add_column("Framework", style="cyan", no_wrap=True)
        table.add_column("Score", justify="center")
        table.add_column("Passed", justify="center", style="green")
        table.add_column("Failed", justify="center", style="red")
        table.add_column("Total", justify="center")

        for key, data in summary.items():
            score = data["compliance_score"]
            score_color = "green" if score >= 80 else "yellow" if score >= 50 else "red"
            table.add_row(
                data["name"],
                f"[{score_color}]{score}%[/{score_color}]",
                str(data["controls_passed"]),
                str(data["controls_failed"]),
                str(data["controls_tested"]),
            )

        console.print(table)

        console.print()
        severity_table = Table(title="🚨 Findings by Severity")
        severity_table.add_column("Severity", style="bold")
        severity_table.add_column("Count", justify="center")

        severity_counts = {}
        for f in self.all_findings:
            sev = f.get("severity", "UNKNOWN")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        severity_colors = {
            "CRITICAL": "red", "HIGH": "orange3",
            "MEDIUM": "yellow", "LOW": "green", "INFO": "dim",
        }

        for sev in severity_order:
            count = severity_counts.get(sev, 0)
            if count > 0:
                color = severity_colors.get(sev, "white")
                severity_table.add_row(f"[{color}]{sev}[/{color}]", str(count))

        console.print(severity_table)
        console.print()
