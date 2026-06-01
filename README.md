**Lightweight GRC Automation & Cloud Risk Insights Platform**

Comply.dev scans your AWS environment and GitHub repositories for compliance gaps across common frameworks — **SOC 2**, **ISO 27001**, and **CIS AWS Foundations Benchmark**. It automates control checks that auditors typically perform manually, then generates real-time compliance dashboards with remediation guidance.

**https://complydev-ctc89uxiuaaokjw4mt2lnv.streamlit.app/**

**Built by an auditor, for auditors.**
---
## What It Checks

### AWS Scans
| Category | Checks |
|----------|--------|
| **Security Groups** | Open ports (SSH, RDP, DB), unrestricted ingress/egress, all-port exposure |
| **Encryption** | S3 bucket encryption, EBS volume encryption, RDS encryption at rest |
| **Backups** | RDS automated backup retention, Multi-AZ deployment |
| **IAM** | Root MFA, user MFA, access key rotation (90-day), password policy |

### GitHub Scans
| Check | Description |
|-------|-------------|
| Branch Protection | PR reviews, status checks, force push restrictions |
| Security Policy | SECURITY.md presence |
| Secrets Detection | .env files committed to repo |
| Dependabot | Automated dependency vulnerability scanning |
| .gitignore | Prevent accidental secret commits |

### Framework Mapping
Every finding is mapped to specific controls across:
- **SOC 2 Type II** — Trust Service Criteria (CC6, CC7, CC8, A1)
- **ISO 27001:2022** — Annex A Controls
- **CIS AWS Foundations Benchmark v3.0**

---

## Quick Start

### 1. Clone & Install
```bash
git clone https://github.com/YOUR_USERNAME/comply-dev.git
cd comply-dev
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure Credentials
```bash
cp .env.example .env
# Edit .env with your AWS credentials and GitHub token
```

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

# Specify AWS profile
python main.py scan --aws-profile my-profile --region us-west-2
```

### 4. View Results
```bash
# Reports are saved to ./reports/
# Open the HTML report in your browser
open reports/comply_report_*.html

# Or launch the interactive dashboard
streamlit run dashboard/app.py
```

---

## 📁 Project Structure
```
comply-dev/
├── main.py                      # CLI entry point
├── requirements.txt             # Python dependencies
├── .env.example                 # Environment variable template
├── comply/
│   ├── scanner.py               # Main scan orchestrator
│   ├── aws/
│   │   ├── base.py              # Base scanner + Finding class
│   │   ├── security_groups.py   # Security group checks
│   │   ├── encryption.py        # S3/EBS/RDS encryption checks
│   │   ├── backups.py           # Backup retention + Multi-AZ
│   │   └── iam.py               # IAM MFA, keys, password policy
│   ├── github/
│   │   └── repo_scanner.py      # GitHub repo compliance checks
│   ├── frameworks/
│   │   └── mappings.py          # SOC2/ISO/CIS control mappings
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

## 🖥️ Dashboard

Launch the interactive Streamlit dashboard:
```bash
streamlit run dashboard/app.py
```

Features:
- 📊 Framework compliance gauges (SOC 2, ISO 27001, CIS)
- 🚨 Severity breakdown charts
- 🔍 Filterable findings table with search
- 📤 Upload historical JSON reports for comparison

---

## 🔧 AWS Setup (Free Tier)

1. Create an AWS Free Tier account at [aws.amazon.com/free](https://aws.amazon.com/free)
2. Create an IAM user with **ReadOnlyAccess** policy
3. Generate access keys and add to `.env`
4. Deploy some test resources (S3 bucket, security group, etc.)

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
- [ ] Slack/Teams notifications for critical findings
- [ ] Trend analysis (compare scans over time)
- [ ] Custom policy engine (define your own checks)
- [ ] PDF report export
- [ ] CI/CD integration (fail pipeline on critical findings)

---

## 📄 License
MIT License — see [LICENSE](LICENSE) for details.

---

**Built by [Jonathan Riley](https://linkedin.com/in/JonathanMichaelRiley)
