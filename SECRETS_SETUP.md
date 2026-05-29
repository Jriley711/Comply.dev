# Secrets & Credentials Setup Guide

This guide tells you **exactly where to put each secret** for every environment
where Comply.dev runs.

---

## 1 — Local development (your machine)

**File:** `.streamlit/secrets.toml` ← already in `.gitignore`, never committed

Copy `.streamlit/secrets.toml` from the template in this repo and fill in your real values:

```toml
AWS_ACCESS_KEY_ID     = "AKIA..."
AWS_SECRET_ACCESS_KEY = "..."
AWS_DEFAULT_REGION    = "us-east-1"
GITHUB_TOKEN          = "ghp_..."
GITHUB_REPOS          = "Jriley711/your-repo"
GITHUB_USERNAME       = "Jriley711"
GITHUB_REPO           = "Comply.dev"
```

Then run the dashboard locally with:
```bash
streamlit run dashboard/app.py
```

For CLI usage, use a `.env` file (copied from `.env.example`) instead:
```bash
cp .env.example .env
# edit .env with real values
python main.py scan
```

---

## 2 — Streamlit Cloud (your live app)

Go to: **share.streamlit.io → your app → ⚙ Settings → Secrets**

Paste this block (replace the placeholder values):

```toml
AWS_ACCESS_KEY_ID     = "AKIA..."
AWS_SECRET_ACCESS_KEY = "..."
AWS_DEFAULT_REGION    = "us-east-1"
GITHUB_TOKEN          = "ghp_..."
GITHUB_REPOS          = "Jriley711/your-repo"
GITHUB_USERNAME       = "Jriley711"
GITHUB_REPO           = "Comply.dev"
```

Click **Save**. The app reboots automatically with the new secrets.

---

## 3 — GitHub Actions (automated weekly scan)

Go to: **GitHub repo → Settings → Secrets and variables → Actions → New repository secret**

Add each secret individually:

| Secret name              | Value                                      |
|--------------------------|--------------------------------------------|
| `AWS_ACCESS_KEY_ID`      | Your IAM access key ID                     |
| `AWS_SECRET_ACCESS_KEY`  | Your IAM secret access key                 |
| `AWS_DEFAULT_REGION`     | e.g. `us-east-1`                           |
| `COMPLY_GITHUB_TOKEN`    | Your GitHub PAT (repo or public_repo scope)|
| `GITHUB_REPOS`           | e.g. `Jriley711/your-repo`                 |

> **Why `COMPLY_GITHUB_TOKEN` and not `GITHUB_TOKEN`?**
> GitHub Actions automatically creates its own `GITHUB_TOKEN` secret for
> workflow permissions. Using a different name for your PAT avoids a conflict.
> The workflow file already references `secrets.COMPLY_GITHUB_TOKEN`.

---

## 4 — How to create the credentials

### AWS IAM access key
1. AWS Console → **IAM → Users → your user → Security credentials**
2. Click **Create access key** → choose "Application running outside AWS"
3. Copy the key ID and secret — you only see the secret once

**Minimum IAM permissions needed** (attach as an inline policy):
```json
{
  "Version": "2012-10-17",
  "Statement": [{
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
  }]
}
```

### GitHub Personal Access Token
1. GitHub → **Settings → Developer settings → Personal access tokens → Tokens (classic)**
2. Click **Generate new token (classic)**
3. Set an expiry (90 days recommended)
4. Check **`repo`** scope (or just `public_repo` if you only scan public repos)
5. Click Generate and copy immediately

---

## 5 — First-time GitHub Actions run

The workflow publishes scan results to a branch called `reports-data`.
This branch doesn't exist until the first workflow run.

To trigger the first run manually:
1. Go to **Actions tab** in your GitHub repo
2. Click **Compliance Scan** in the left sidebar
3. Click **Run workflow → Run workflow**

After it completes, the `reports-data` branch will exist and the Streamlit
dashboard will load data automatically.
