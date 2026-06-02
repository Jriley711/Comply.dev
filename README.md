<div align="center">

# 🛡️ Comply.dev

### Lightweight GRC Automation & Cloud Risk Insights Platform

[![Live Demo](https://img.shields.io/badge/Live%20Demo-Streamlit-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)](https://complydev-ctc89uxiuaaokjw4mt2lnv.streamlit.app/)
[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](LICENSE)

**Built by an auditor, for auditors.**

Comply.dev scans your AWS environment and GitHub repositories for compliance gaps across **SOC 2**, **ISO 27001**, and **CIS AWS Foundations Benchmark**. It automates control checks that auditors typically perform manually, then surfaces real-time compliance dashboards with remediation guidance and drift detection.

[🚀 Live Demo](https://complydev-ctc89uxiuaaokjw4mt2lnv.streamlit.app/) · [📖 Secrets Setup](SECRETS_SETUP.md) · [🐛 Report a Bug](https://github.com/Jriley711/Comply.dev/issues)

</div>

---

## ✨ Features

- **Automated compliance scanning** across AWS and GitHub — no manual checklists
- **Framework-mapped findings** tagged to SOC 2, ISO 27001, and CIS controls
- **Drift detection** — instantly see what's new, resolved, or still open since the last scan
- **Compliance score trending** — track your posture over time with scan-to-scan comparison
- **Critical issue alerting** — critical failures surface immediately at the top of the dashboard
- **Interactive dashboard** — filterable findings table with severity breakdown and score gauges
- **Automated weekly scans** via GitHub Actions with zero manual effort

---

## 🔍 What It Checks

### AWS Scans

| Category | Checks |
|----------|--------|
| **Security Groups** | Open ports (SSH, RDP, MySQL, PostgreSQL, MSSQL, MongoDB, Redis), unrestricted ingress/egress, all-port exposure, default SG rules |
| **Encryption** | S3 bucket encryption, EBS volume encryption, RDS encryption at rest |
| **Backups** | RDS automated backup retention (7-day minimum), Multi-AZ deployment |
| **IAM** | Root MFA, user MFA, access key rotation (90-day), password policy (length, complexity, reuse, expiry) |

### GitHub Scans

| Check | Description |
|-------|-------------|
| Branch Protection | PR reviews required, status checks, force push restrictions |
| Security Policy | `SECURITY.md` presence |
| Secrets Detection | `.env` files committed to repo |
| Dependabot | Automated dependency vulnerability scanning enabled |
| `.gitignore` | Prevents accidental secret commits |

### Framework Mapping

Every finding is tagged to specific controls across:

- **SOC 2 Type II** — Trust Service Criteria (CC6, CC7, CC8, A1)
- **ISO 27001:2022** — Annex A Controls
- **CIS AWS Foundations Benchmark v3.0**

---

## 🚀 Quick Start

### 1. Clone & Install

```bash
git clone https://github.com/Jriley711/Comply.dev.git
cd Comply.dev
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure Credentials

```bash
cp .env.example .env
# Edit .env with your AWS credentials and GitHub token
```

See [SECRETS_SETUP.md](SECRETS_SETUP.md) for a full walkthrough.

### 3. Run a Scan

```bash
# Full scan (AWS + GitHub)
python main.py scan

# AWS only
python main.py scan --skip-github

# GitHub only
python main.py scan --skip-aws

# Scan a single GitHub repo
python main.py scan-repo owner/repo-name

# Specify AWS profile and region
python main.py scan --aws-profile my-profile --region us-west-2
```

### 4. View Results

```bash
# Reports saved to ./reports/
open reports/comply_report_*.html

# Or launch the interactive dashboard
streamlit run dashboard/app.py
```

---

## 🖥️ Dashboard

Launch the interactive Streamlit dashboard:

```bash
streamlit run dashboard/app.py
```

The dashboard provides:

- **Compliance score** with delta vs previous scan
- **Drift detection** — new issues, resolved, and still-present findings side by side
- **Critical issue banner** — CRITICAL failures highlighted with resource and remediation steps
- **Score trend chart** — previous vs current scan comparison
- **Filterable findings table** — browse all findings by status, severity, category, and framework

---

## 📁 Project Structure

```
Comply.dev/
├── main.py                      # Streamlit app + full check registry
├── requirements.txt             # Python dependencies
├── SECRETS_SETUP.md             # Credential configuration guide
├── comply/
│   ├── scanner.py               # Main scan orchestrator
│   ├── aws/
│   │   ├── base.py              # Base scanner + Finding class
│   │   ├── security_groups.py   # Security group checks
│   │   ├── encryption.py        # S3 / EBS / RDS encryption checks
│   │   ├── backups.py           # Backup retention + Multi-AZ
│   │   └── iam.py               # IAM MFA, keys, password policy
│   ├── github/
│   │   └── repo_scanner.py      # GitHub repo compliance checks
│   ├── frameworks/
│   │   └── mappings.py          # SOC 2 / ISO 27001 / CIS mappings
│   └── reports/
│       └── generator.py         # JSON + HTML report generator
├── dashboard/
│   └── app.py                   # Streamlit compliance dashboard
├── tests/
│   └── test_scanner.py          # Unit tests
└── .github/workflows/
    └── scan.yml                 # Automated weekly scans
```

---

## ☁️ AWS Setup

1. Create an AWS account at [aws.amazon.com/free](https://aws.amazon.com/free)
2. Create an IAM user with **ReadOnlyAccess** policy
3. Generate access keys and add to `.env`

**Required IAM Permissions:**

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
```

---

## 🧪 Testing

```bash
pytest tests/ -v
```

---

## 🗺️ Roadmap

- [ ] Azure & GCP scanner modules
- [ ] Slack / Teams notifications for critical findings
- [ ] PDF report export
- [ ] Custom policy engine (define your own checks)
- [ ] CI/CD integration (fail pipeline on critical findings)
- [ ] Historical trend analysis across multiple scans

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

**Built by [Jonathan Riley](https://linkedin.com/in/JonathanMichaelRiley)**

*If this saved you time in an audit, consider leaving a ⭐*

</div>
