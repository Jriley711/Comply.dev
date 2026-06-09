<div align="center">

# 🛡️ Comply.dev

### Open-source cloud compliance automation for AWS & GitHub

[![Live Demo](https://img.shields.io/badge/Live%20Demo-Streamlit-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)](https://complydev-ctc89uxiuaaokjw4mt2lnv.streamlit.app/)
[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](LICENSE)

**Built by an auditor, for auditors.**

Comply.dev scans your AWS environment and GitHub repositories for compliance gaps mapped to **SOC 2**, **ISO 27001**, and the **CIS AWS Foundations Benchmark**. It replaces manual control checklists with automated checks, audit-quality reasoning, and a real-time dashboard — so you can spend less time gathering evidence and more time fixing what matters.

[🚀 Live Demo](https://complydev-ctc89uxiuaaokjw4mt2lnv.streamlit.app/) · [📖 Secrets Setup](SECRETS_SETUP.md) · [🐛 Issues](https://github.com/Jriley711/Comply.dev/issues)

</div>

---

## What it does

Comply.dev runs automated compliance checks against your cloud environment and surfaces the results in a structured dashboard. Every finding includes:

- The **control it maps to** across SOC 2, ISO 27001, and CIS AWS
- The **audit reasoning** behind the pass or fail determination
- A **remediation step** when action is required
- A **severity rating** (Critical / High / Medium / Low / Info)

Scans run automatically on a weekly schedule via GitHub Actions and store results so the dashboard can show compliance drift between scans — what's new, what's been fixed, and what's still open.

---

## Dashboard

```bash
streamlit run dashboard/app.py
```

The dashboard is organized into five pages:

| Page | Description |
|------|-------------|
| **Overview** | Compliance score, severity breakdown, framework scores, critical finding preview |
| **Findings** | Filterable findings table with drill-down — filter by status, severity, domain, or keyword |
| **Frameworks** | Per-control breakdown for SOC 2, ISO 27001, and CIS AWS |
| **Drift** | New issues, resolved findings, and persistent gaps between scans with score trend |
| **Run Scan** | Trigger a live scan or upload a report — credentials are masked and never logged |

---

## What it checks

### AWS

| Domain | Checks |
|--------|--------|
| **IAM** | Root MFA, user MFA for console accounts, access key rotation (90-day), password policy (length, complexity, reuse, expiry) |
| **Security Groups** | Unrestricted inbound on SSH (22), RDP (3389), MySQL (3306), PostgreSQL (5432), MSSQL (1433), MongoDB (27017), Redis (6379); all-port exposure; default SG rules; unrestricted egress |
| **Encryption** | S3 server-side encryption, EBS volume encryption at rest, RDS storage encryption |
| **Backups** | RDS automated backup retention (7-day minimum), Multi-AZ deployment |

### GitHub

| Check | What it looks for |
|-------|-------------------|
| Branch protection | PR reviews required, status checks enforced, force push restricted |
| Security policy | `SECURITY.md` present in repo |
| Secrets in repo | `.env` files committed to version control |
| Dependabot | Automated dependency vulnerability scanning enabled |
| `.gitignore` | Prevents accidental secret commits |
| Default branch naming | Follows `main` convention |
| License | `LICENSE` file present |

### Framework coverage

Every finding is tagged to specific controls:

- **SOC 2 Type II** — CC6.1, CC6.2, CC6.6, CC6.7, CC7.1, CC7.4, CC7.5, CC8.1, A1.1, A1.2
- **ISO 27001:2022** — A.9, A.10, A.12, A.13, A.14, A.16, A.17, A.18
- **CIS AWS Foundations Benchmark v3.0** — Sections 1 (IAM), 2 (Storage), 4 (Networking)

---

## Quick start

### 1. Clone and install

```bash
git clone https://github.com/Jriley711/Comply.dev.git
cd Comply.dev
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure credentials

Create `.streamlit/secrets.toml`:

```toml
AWS_ACCESS_KEY_ID     = "AKIA..."
AWS_SECRET_ACCESS_KEY = "..."
AWS_DEFAULT_REGION    = "us-east-1"
GITHUB_TOKEN          = "ghp_..."
GITHUB_REPOS          = "owner/repo1,owner/repo2"
```

See [SECRETS_SETUP.md](SECRETS_SETUP.md) for a full walkthrough including IAM policy setup.

### 3. Run a scan

```bash
# Full scan (AWS + GitHub)
python main.py scan

# AWS only
python main.py scan --skip-github

# GitHub only
python main.py scan --skip-aws
```

### 4. View the dashboard

```bash
streamlit run dashboard/app.py
```

---

## AWS IAM permissions

The scanner requires read-only access. Attach this policy to your IAM user:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeVolumes",
                "s3:ListAllMyBuckets",
                "s3:GetBucketEncryption",
                "rds:DescribeDBInstances",
                "iam:GetAccountSummary",
                "iam:ListUsers",
                "iam:GetLoginProfile",
                "iam:ListMFADevices",
                "iam:ListAccessKeys",
                "iam:GetAccountPasswordPolicy"
            ],
            "Resource": "*"
        }
    ]
}

```bash
Comply.dev/
├── comply/
│   ├── scanner.py               # Scan orchestrator
│   ├── aws/
│   │   ├── base.py              # Base scanner class + Finding model
│   │   ├── iam.py               # IAM checks
│   │   ├── security_groups.py   # Security group checks
│   │   ├── encryption.py        # S3 / EBS / RDS encryption
│   │   └── backups.py           # Backup retention + Multi-AZ
│   ├── github/
│   │   └── repo_scanner.py      # GitHub repository checks
│   ├── frameworks/
│   │   └── mappings.py          # SOC 2 / ISO 27001 / CIS control mappings
│   └── reports/
│       └── generator.py         # JSON + HTML report generation
├── dashboard/
│   ├── app.py                   # Overview page (entry point)
│   ├── config.py                # Shared config and helpers
│   ├── data.py                  # Data loading and parsing
│   ├── components.py            # Reusable chart and UI components
│   └── pages/
│       ├── 1_findings.py        # Filterable findings explorer
│       ├── 2_frameworks.py      # Per-framework control breakdown
│       ├── 3_drift.py           # Scan-to-scan comparison
│       └── 4_scan.py            # Live scan + report upload
├── main.py                      # CLI entry point + check registry
├── requirements.txt
└── SECRETS_SETUP.md

---

## Automated scans

Comply.dev includes a GitHub Actions workflow that runs a full scan weekly and commits the report to the `reports-data` branch, which the dashboard reads automatically. To enable it, add your AWS and GitHub credentials as repository secrets.

See `.github/workflows/scan.yml` for configuration.

---

## Roadmap

- [ ] Azure scanner module
- [ ] GCP scanner module
- [ ] Slack / Teams alerting for critical findings
- [ ] PDF report export
- [ ] CI/CD integration — fail pipeline on critical findings
- [ ] Custom policy engine — define your own checks
- [ ] Historical trend analysis across multiple scans

---

## Testing

```bash
pytest tests/ -v
```

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

<div align="center">

Built by [Jonathan Riley](https://linkedin.com/in/JonathanMichaelRiley) · Senior Associate, Strategic Assurance & SOC Services

*If this saved you time in an audit, consider leaving a ⭐*

</div>

---
