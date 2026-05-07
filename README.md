# 🔍 AWS Security Auditor

A command-line tool that scans your AWS account for common security misconfigurations and generates a prioritized remediation report — inspired by the CIS AWS Foundations Benchmark.

---

## What It Checks

| Service | Checks |
|---|---|
| **S3** | Public access blocks, default encryption, versioning |
| **IAM** | Root MFA, password policy strength, access key rotation (>90 days) |
| **EC2** | Security groups exposing SSH/RDP/databases to 0.0.0.0/0, EBS encryption |
| **CloudTrail** | Audit logging enabled, multi-region coverage |

---

## Severity Levels

| Level | Meaning |
|---|---|
| 🔴 **CRITICAL** | Immediate risk — public exposure, no MFA on root, SSH open to internet |
| 🔴 **HIGH** | Serious gap — unencrypted storage, logging disabled, stale credentials |
| 🟡 **MEDIUM** | Best-practice violations — weak password policy, single-region logging |
| 🔵 **LOW** | Minor improvements — versioning off, minor config gaps |
| ✅ **PASS** | Check passed |

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/Randalls59/aws-security-auditor.git
cd aws-security-auditor

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure AWS credentials
aws configure

# 4. Run the audit
python auditor.py
```

**Sample output:**

```
════════════════════════════════════════════════════════════════
  AWS SECURITY AUDIT REPORT
  Account : 123456789012
  Region  : us-east-1
  Time    : 2026-05-07 14:32:10 UTC
════════════════════════════════════════════════════════════════

  ■ CRITICAL (2)

  [CRITICAL] Root account MFA is NOT enabled
  Resource : arn:aws:iam::root
  Detail   : The root account has no MFA device...
  Fix      : Log into AWS Console → Security Credentials → Assign MFA

  [CRITICAL] Security group exposes SSH (:22) to the internet
  Resource : sg/sg-0abc1234 (launch-wizard-1)
  Fix      : aws ec2 revoke-security-group-ingress --group-id sg-0abc1234 ...

  ■ HIGH (1)

  [HIGH] Access key older than 90 days
  Resource : iam:user/admin key/AKIA...
  Fix      : aws iam create-access-key --user-name admin

════════════════════════════════════════════════════════════════
  SUMMARY
  Total checks  : 12
  Issues found  : 3
  Passed        : 9
  Security score: 75/100
════════════════════════════════════════════════════════════════
```

---

## Output

The tool prints a colour-coded report to your terminal and saves a machine-readable JSON report:

```
audit-123456789012-20260507-143210.json
```

---

## Required AWS Permissions

The tool only needs **read** permissions — it never modifies your infrastructure.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketEncryption",
        "s3:GetBucketVersioning",
        "iam:GetAccountSummary",
        "iam:GetAccountPasswordPolicy",
        "iam:ListUsers",
        "iam:ListAccessKeys",
        "ec2:DescribeSecurityGroups",
        "ec2:GetEbsEncryptionByDefault",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## Roadmap

- [ ] Add RDS public accessibility check
- [ ] Add GuardDuty enabled check
- [ ] Add unused IAM roles / policies check
- [ ] HTML report export
- [ ] Slack / email notifications
- [ ] GitHub Actions integration for continuous auditing

---

## License

MIT — free to use, modify, and distribute.
