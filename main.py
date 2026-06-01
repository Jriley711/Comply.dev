#!/usr/bin/env python3
"""Comply.dev — CLI entry point."""

import os
import sys
import click
import boto3
from dotenv import load_dotenv
from comply.scanner import ComplyScanner

load_dotenv()


@click.group()
@click.version_option(version="0.1.0", prog_name="comply-dev")
def cli():
    """🛡️ Comply.dev — Cloud Compliance Scanner

    Automated compliance checks for AWS and GitHub repositories,
    mapped to SOC 2, ISO 27001, and CIS AWS Benchmarks.
    """
    pass


@cli.command()
@click.option("--aws-profile", default=None, help="AWS profile name from ~/.aws/credentials")
@click.option("--region", default=None, help="AWS region (default: from env/config)")
@click.option("--github-token", default=None, help="GitHub personal access token")
@click.option("--github-repos", default=None, help="Comma-separated list of repos (owner/repo)")
@click.option("--output-dir", default="reports", help="Directory for report output")
@click.option("--skip-aws", is_flag=True, help="Skip AWS scans")
@click.option("--skip-github", is_flag=True, help="Skip GitHub scans")
def scan(aws_profile, region, github_token, github_repos, output_dir, skip_aws, skip_github):
    """Run a full compliance scan."""
    if skip_aws and skip_github:
        click.echo("❌ Both AWS and GitHub scans skipped. Nothing to do.")
        sys.exit(1)

    # AWS session setup
    session_kwargs = {}
    if aws_profile:
        session_kwargs["profile_name"] = aws_profile
    if region:
        session_kwargs["region_name"] = region
    aws_session = boto3.Session(**session_kwargs) if not skip_aws else None

    # GitHub setup
    gh_token = github_token or os.getenv("GITHUB_TOKEN")
    gh_repos = []
    if github_repos:
        gh_repos = [r.strip() for r in github_repos.split(",")]
    elif os.getenv("GITHUB_REPOS"):
        gh_repos = [r.strip() for r in os.getenv("GITHUB_REPOS").split(",")]

    if skip_github:
        gh_token = None
        gh_repos = []

    # Run scanner
    scanner = ComplyScanner(
        aws_session=aws_session,
        github_token=gh_token,
        github_repos=gh_repos,
    )

    results = scanner.run_full_scan()

    # Exit code based on findings
    critical_count = sum(
        1 for f in results["findings"]
        if f.get("severity") == "CRITICAL" and f.get("status") == "FAIL"
    )

     if critical_count > 0:
        click.echo(f"\n⚠️  {critical_count} CRITICAL findings detected.")


@cli.command()
@click.argument("repo")
@click.option("--github-token", default=None, help="GitHub personal access token")
def scan_repo(repo, github_token):
    """Scan a single GitHub repository.

    REPO should be in the format: owner/repo
    """
    gh_token = github_token or os.getenv("GITHUB_TOKEN")
    if not gh_token:
        click.echo("❌ GitHub token required. Set GITHUB_TOKEN env var or use --github-token.")
        sys.exit(1)

    # FIX: corrected import paths to match actual module structure
    from comply.github.repo_scanner import GitHubRepoScanner
    from comply.reports.generator import ReportGenerator
    from rich.console import Console

    console = Console()

    gh_scanner = GitHubRepoScanner(token=gh_token, repos=[repo])
    findings = gh_scanner.scan()

    reporter = ReportGenerator(findings)
    json_path = reporter.generate_json()
    html_path = reporter.generate_html()

    console.print(f"\n📋 JSON report: [blue]{json_path}[/blue]")
    console.print(f"🌐 HTML report: [blue]{html_path}[/blue]")

    fail_count = sum(1 for f in findings if f["status"] == "FAIL")
    pass_count = sum(1 for f in findings if f["status"] == "PASS")
    console.print(f"\n✅ {pass_count} passed | ❌ {fail_count} failed")


if __name__ == "__main__":
    cli()
