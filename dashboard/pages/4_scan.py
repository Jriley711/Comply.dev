"""Run Scan page — trigger live scans or upload reports."""

import streamlit as st
import os

from dashboard.config import get_secret, mask
from dashboard.data import load_from_upload, parse_report

st.markdown("## ⚡ Run Scan")

tab1, tab2 = st.tabs(["Live scan", "Upload report"])

# ─────────────────────────────────────────────────────────────
# Tab 1: Live scan
# ─────────────────────────────────────────────────────────────
with tab1:
    st.markdown(
        "Trigger a live scan of your AWS environment and GitHub repositories. "
        "Credentials are read from Streamlit secrets or environment variables — "
        "they are never displayed or logged."
    )

    # Credential status
    aws_key    = get_secret("AWS_ACCESS_KEY_ID")
    aws_secret = get_secret("AWS_SECRET_ACCESS_KEY")
    aws_region = get_secret("AWS_DEFAULT_REGION", "us-east-1")
    gh_token   = get_secret("GITHUB_TOKEN") or get_secret("GH_TOKEN")
    gh_repos   = get_secret("GITHUB_REPOS") or get_secret("GH_REPOS")

    with st.expander("Credential status", expanded=True):
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("**AWS**")
            aws_ok = bool(aws_key and aws_secret)
            st.markdown(f"Access key ID: `{mask(aws_key)}`")
            st.markdown(f"Region: `{aws_region}`")
            if aws_ok:
                st.success("AWS credentials configured", icon="✅")
            else:
                st.error("AWS credentials missing", icon="❌")

        with c2:
            st.markdown("**GitHub**")
            gh_ok = bool(gh_token)
            st.markdown(f"Token: `{mask(gh_token)}`")
            st.markdown(f"Repos: `{gh_repos or 'not set'}`")
            if gh_ok:
                st.success("GitHub token configured", icon="✅")
            else:
                st.warning("GitHub token not set — GitHub scan will be skipped", icon="⚠️")

    if not aws_ok:
        st.error(
            "AWS credentials are required to run a scan. "
            "Set `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` in your "
            "Streamlit secrets or as environment variables."
        )
        st.markdown("""
**To configure credentials:**

1. Create a `.streamlit/secrets.toml` file in the project root:
```toml
AWS_ACCESS_KEY_ID     = "AKIA..."
AWS_SECRET_ACCESS_KEY = "..."
AWS_DEFAULT_REGION    = "us-east-1"
GITHUB_TOKEN          = "ghp_..."
GITHUB_REPOS          = "owner/repo1,owner/repo2"
```
2. Or set environment variables before starting the app.
""")
    else:
        st.markdown("---")
        st.markdown("**Scan scope**")
        run_aws    = st.checkbox("AWS (IAM, Security Groups, Encryption, Backups)", value=True)
        run_github = st.checkbox("GitHub repositories", value=gh_ok)

        st.markdown("")
        if st.button("▶ Run scan now", type="primary", use_container_width=False):
            with st.spinner("Running compliance scan… this typically takes 30–90 seconds."):
                try:
                    import boto3
                    from comply.scanner import ComplyScanner

                    session = boto3.Session(
                        aws_access_key_id=aws_key,
                        aws_secret_access_key=aws_secret,
                        region_name=aws_region,
                    )
                    repos = [r.strip() for r in gh_repos.split(",")] if gh_repos and run_github else []
                    scanner = ComplyScanner(
                        aws_session=session,
                        github_token=gh_token if run_github else None,
                        github_repos=repos,
                    )
                    result = scanner.run_full_scan()

                    if result:
                        parsed = parse_report(result)
                        st.success(
                            f"Scan complete — {parsed['total']} checks, "
                            f"{parsed['passed']} passed, {parsed['failed']} failed.",
                            icon="✅",
                        )
                        st.markdown(
                            "Report saved. Return to **Overview** to see results, "
                            "or refresh the Findings page."
                        )
                    else:
                        st.error("Scan completed but returned no results.")

                except Exception as e:
                    # Surface a clean message without leaking credential details
                    err_msg = str(e)
                    if any(s in err_msg for s in ["key", "secret", "token", "credential", "auth"]):
                        st.error("Scan failed: authentication error. Check your credentials and permissions.")
                    else:
                        st.error(f"Scan failed: {err_msg}")

# ─────────────────────────────────────────────────────────────
# Tab 2: Upload report
# ─────────────────────────────────────────────────────────────
with tab2:
    st.markdown(
        "Upload a previously generated JSON report to view it in the dashboard "
        "without running a new scan."
    )

    uploaded = st.file_uploader("Upload JSON report", type=["json"])
    if uploaded:
        report = load_from_upload(uploaded.read())
        if report:
            data = parse_report(report)
            st.success(
                f"Report loaded — {data['total']} checks, score {data['score']}%.",
                icon="✅",
            )
            st.info("Note: uploaded reports are not persisted. Use the Findings page while this file is loaded.")

            from dashboard.components import metric_card
            m1, m2, m3, m4 = st.columns(4)
            with m1:
                metric_card("Score", f"{data['score']}%")
            with m2:
                metric_card("Passed", str(data["passed"]), color="#1D9E75")
            with m3:
                metric_card("Failed", str(data["failed"]), color="#E24B4A")
            with m4:
                metric_card("Warnings", str(data["warnings"]), color="#EF9F27")
        else:
            st.error("Could not parse the uploaded file. Make sure it is a valid Comply.dev JSON report.")
