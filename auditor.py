#!/usr/bin/env python3
"""
AWS Security Auditor
====================
Scans your AWS account for common security misconfigurations and
generates a prioritized report with remediation steps.

Author : Randalls59
License: MIT
"""

import boto3
import json
import sys
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import List, Optional


# ── ANSI colours ──────────────────────────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
BLUE   = "\033[94m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

SEVERITY_COLOUR = {"CRITICAL": RED, "HIGH": RED, "MEDIUM": YELLOW, "LOW": BLUE, "PASS": GREEN}


# ── Data model ────────────────────────────────────────────────────────────────
@dataclass
class Finding:
    severity: str          # CRITICAL | HIGH | MEDIUM | LOW | PASS
    service:  str          # e.g. "S3", "IAM", "EC2"
    title:    str
    resource: str
    detail:   str
    fix:      str


@dataclass
class AuditReport:
    account_id: str
    region:     str
    timestamp:  str
    findings:   List[Finding] = field(default_factory=list)

    def add(self, finding: Finding):
        self.findings.append(finding)

    @property
    def critical(self): return [f for f in self.findings if f.severity == "CRITICAL"]
    @property
    def high(self):     return [f for f in self.findings if f.severity == "HIGH"]
    @property
    def medium(self):   return [f for f in self.findings if f.severity == "MEDIUM"]
    @property
    def passed(self):   return [f for f in self.findings if f.severity == "PASS"]


# ── Checks ────────────────────────────────────────────────────────────────────

def check_s3(report: AuditReport):
    """S3 — public access, encryption, versioning, logging."""
    print(f"  {BLUE}Scanning S3 buckets...{RESET}")
    s3 = boto3.client("s3")

    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except Exception as e:
        print(f"  {YELLOW}⚠ S3 scan skipped: {e}{RESET}")
        return

    for bucket in buckets:
        name = bucket["Name"]

        # 1. Block public access
        try:
            bpa = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            all_blocked = all([
                bpa.get("BlockPublicAcls", False),
                bpa.get("IgnorePublicAcls", False),
                bpa.get("BlockPublicPolicy", False),
                bpa.get("RestrictPublicBuckets", False),
            ])
            if not all_blocked:
                report.add(Finding(
                    severity="CRITICAL", service="S3",
                    title="S3 bucket does not fully block public access",
                    resource=f"s3://{name}",
                    detail="One or more Block Public Access settings are disabled.",
                    fix=f"aws s3api put-public-access-block --bucket {name} "
                        f"--public-access-block-configuration BlockPublicAcls=true,"
                        f"IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
                ))
            else:
                report.add(Finding(severity="PASS", service="S3",
                    title="S3 public access blocked", resource=f"s3://{name}",
                    detail="All Block Public Access settings enabled.", fix=""))
        except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
            report.add(Finding(
                severity="CRITICAL", service="S3",
                title="S3 bucket has no public access block configuration",
                resource=f"s3://{name}",
                detail="No Block Public Access configuration found — bucket may be fully public.",
                fix=f"aws s3api put-public-access-block --bucket {name} "
                    f"--public-access-block-configuration BlockPublicAcls=true,"
                    f"IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
            ))
        except Exception:
            pass

        # 2. Server-side encryption
        try:
            s3.get_bucket_encryption(Bucket=name)
            report.add(Finding(severity="PASS", service="S3",
                title="S3 encryption enabled", resource=f"s3://{name}",
                detail="Default encryption is configured.", fix=""))
        except s3.exceptions.ClientError as e:
            if "ServerSideEncryptionConfigurationNotFoundError" in str(e):
                report.add(Finding(
                    severity="HIGH", service="S3",
                    title="S3 bucket missing default encryption",
                    resource=f"s3://{name}",
                    detail="Objects stored without encryption unless explicitly encrypted at upload.",
                    fix=f"aws s3api put-bucket-encryption --bucket {name} "
                        f"--server-side-encryption-configuration "
                        f"'{{\"Rules\":[{{\"ApplyServerSideEncryptionByDefault\":{{\"SSEAlgorithm\":\"AES256\"}}}}]}}'",
                ))

        # 3. Versioning
        try:
            ver = s3.get_bucket_versioning(Bucket=name)
            if ver.get("Status") != "Enabled":
                report.add(Finding(
                    severity="LOW", service="S3",
                    title="S3 bucket versioning not enabled",
                    resource=f"s3://{name}",
                    detail="Without versioning, deleted or overwritten objects cannot be recovered.",
                    fix=f"aws s3api put-bucket-versioning --bucket {name} "
                        f"--versioning-configuration Status=Enabled",
                ))
        except Exception:
            pass


def check_iam(report: AuditReport):
    """IAM — root MFA, access key age, password policy, unused credentials."""
    print(f"  {BLUE}Scanning IAM...{RESET}")
    iam = boto3.client("iam")

    # 1. Root account MFA
    try:
        summary = iam.get_account_summary()["SummaryMap"]
        if summary.get("AccountMFAEnabled", 0) == 0:
            report.add(Finding(
                severity="CRITICAL", service="IAM",
                title="Root account MFA is NOT enabled",
                resource="arn:aws:iam::root",
                detail="The root account has no MFA device. Anyone with the root password has full account access.",
                fix="Log into AWS Console → Security Credentials → Assign MFA device to root.",
            ))
        else:
            report.add(Finding(severity="PASS", service="IAM",
                title="Root MFA enabled", resource="arn:aws:iam::root",
                detail="Root account MFA is active.", fix=""))
    except Exception as e:
        print(f"  {YELLOW}⚠ Root MFA check skipped: {e}{RESET}")

    # 2. Password policy
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
        issues = []
        if policy.get("MinimumPasswordLength", 0) < 14:
            issues.append("Minimum password length < 14")
        if not policy.get("RequireSymbols"):
            issues.append("Symbols not required")
        if not policy.get("RequireNumbers"):
            issues.append("Numbers not required")
        if not policy.get("RequireUppercaseCharacters"):
            issues.append("Uppercase not required")
        if not policy.get("RequireLowercaseCharacters"):
            issues.append("Lowercase not required")
        if not policy.get("ExpirePasswords"):
            issues.append("Password expiry not enabled")

        if issues:
            report.add(Finding(
                severity="MEDIUM", service="IAM",
                title="IAM password policy does not meet best practices",
                resource="arn:aws:iam::password-policy",
                detail="Issues: " + "; ".join(issues),
                fix="aws iam update-account-password-policy --minimum-password-length 14 "
                    "--require-symbols --require-numbers --require-uppercase-characters "
                    "--require-lowercase-characters --max-password-age 90 --password-reuse-prevention 12",
            ))
        else:
            report.add(Finding(severity="PASS", service="IAM",
                title="Password policy meets best practices", resource="arn:aws:iam::password-policy",
                detail="All password policy checks passed.", fix=""))
    except iam.exceptions.NoSuchEntityException:
        report.add(Finding(
            severity="HIGH", service="IAM",
            title="No IAM account password policy set",
            resource="arn:aws:iam::password-policy",
            detail="Without a password policy any password complexity is allowed.",
            fix="aws iam update-account-password-policy --minimum-password-length 14 "
                "--require-symbols --require-numbers --require-uppercase-characters "
                "--require-lowercase-characters",
        ))

    # 3. Access key age
    try:
        users = iam.list_users()["Users"]
        now = datetime.now(timezone.utc)
        for user in users:
            uname = user["UserName"]
            keys  = iam.list_access_keys(UserName=uname)["AccessKeyMetadata"]
            for key in keys:
                if key["Status"] != "Active":
                    continue
                age_days = (now - key["CreateDate"]).days
                if age_days > 90:
                    report.add(Finding(
                        severity="HIGH", service="IAM",
                        title=f"Access key older than 90 days",
                        resource=f"iam:user/{uname} key/{key['AccessKeyId']}",
                        detail=f"Key is {age_days} days old. Rotate regularly to limit exposure window.",
                        fix=f"aws iam create-access-key --user-name {uname}  # then delete old key",
                    ))
    except Exception as e:
        print(f"  {YELLOW}⚠ Access key age check skipped: {e}{RESET}")


def check_ec2(report: AuditReport):
    """EC2 — security groups with 0.0.0.0/0, IMDSv2, EBS encryption."""
    print(f"  {BLUE}Scanning EC2 / Security Groups...{RESET}")
    ec2 = boto3.client("ec2")

    # 1. Security groups with dangerous open rules
    try:
        sgs = ec2.describe_security_groups()["SecurityGroups"]
        dangerous_ports = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB"}

        for sg in sgs:
            for rule in sg.get("IpPermissions", []):
                from_port = rule.get("FromPort", 0)
                to_port   = rule.get("ToPort", 65535)
                open_ipv4 = any(r["CidrIp"] == "0.0.0.0/0" for r in rule.get("IpRanges", []))
                open_ipv6 = any(r["CidrIpv6"] == "::/0" for r in rule.get("Ipv6Ranges", []))

                if open_ipv4 or open_ipv6:
                    for port, service in dangerous_ports.items():
                        if from_port <= port <= to_port:
                            report.add(Finding(
                                severity="CRITICAL", service="EC2",
                                title=f"Security group exposes {service} (:{port}) to the internet",
                                resource=f"sg/{sg['GroupId']} ({sg['GroupName']})",
                                detail=f"Rule allows 0.0.0.0/0 → port {port} ({service}). "
                                       f"Anyone on the internet can attempt to connect.",
                                fix=f"aws ec2 revoke-security-group-ingress "
                                    f"--group-id {sg['GroupId']} --protocol tcp "
                                    f"--port {port} --cidr 0.0.0.0/0",
                            ))
    except Exception as e:
        print(f"  {YELLOW}⚠ Security group check skipped: {e}{RESET}")

    # 2. Default EBS encryption
    try:
        enc = ec2.get_ebs_encryption_by_default()
        if not enc["EbsEncryptionByDefault"]:
            report.add(Finding(
                severity="MEDIUM", service="EC2",
                title="EBS default encryption is disabled",
                resource="aws::ec2::ebs-encryption",
                detail="New EBS volumes will not be encrypted by default. "
                       "Sensitive data on volumes may be exposed if snapshots are shared.",
                fix="aws ec2 enable-ebs-encryption-by-default",
            ))
        else:
            report.add(Finding(severity="PASS", service="EC2",
                title="EBS default encryption enabled", resource="aws::ec2::ebs-encryption",
                detail="All new EBS volumes will be encrypted.", fix=""))
    except Exception as e:
        print(f"  {YELLOW}⚠ EBS encryption check skipped: {e}{RESET}")


def check_cloudtrail(report: AuditReport):
    """CloudTrail — ensure audit logging is enabled in all regions."""
    print(f"  {BLUE}Scanning CloudTrail...{RESET}")
    ct = boto3.client("cloudtrail")

    try:
        trails = ct.describe_trails(includeShadowTrails=False)["trailList"]
        if not trails:
            report.add(Finding(
                severity="CRITICAL", service="CloudTrail",
                title="No CloudTrail trails found",
                resource="aws::cloudtrail",
                detail="Without CloudTrail, there is no audit log of API calls. "
                       "Security incidents cannot be investigated.",
                fix="aws cloudtrail create-trail --name management-events "
                    "--s3-bucket-name <your-log-bucket> --is-multi-region-trail\n"
                    "aws cloudtrail start-logging --name management-events",
            ))
            return

        for trail in trails:
            name = trail["Name"]
            status = ct.get_trail_status(Name=trail["TrailARN"])

            if not status.get("IsLogging"):
                report.add(Finding(
                    severity="HIGH", service="CloudTrail",
                    title=f"CloudTrail trail '{name}' exists but is NOT logging",
                    resource=trail["TrailARN"],
                    detail="The trail is configured but logging is paused — no audit records being written.",
                    fix=f"aws cloudtrail start-logging --name {name}",
                ))
            else:
                multi = trail.get("IsMultiRegionTrail", False)
                report.add(Finding(
                    severity="PASS" if multi else "MEDIUM",
                    service="CloudTrail",
                    title=f"CloudTrail '{name}' logging" + (" (single-region)" if not multi else ""),
                    resource=trail["TrailARN"],
                    detail="Logging active." if multi else
                           "Trail only covers one region. Activity in other regions is not logged.",
                    fix="" if multi else
                        f"aws cloudtrail update-trail --name {name} --is-multi-region-trail",
                ))
    except Exception as e:
        print(f"  {YELLOW}⚠ CloudTrail check skipped: {e}{RESET}")


# ── Report printer ─────────────────────────────────────────────────────────────

def print_report(report: AuditReport):
    print(f"\n{'═'*64}")
    print(f"{BOLD}  AWS SECURITY AUDIT REPORT{RESET}")
    print(f"  Account : {report.account_id}")
    print(f"  Region  : {report.region}")
    print(f"  Time    : {report.timestamp}")
    print(f"{'═'*64}")

    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    for sev in severity_order:
        group = [f for f in report.findings if f.severity == sev]
        if not group:
            continue
        colour = SEVERITY_COLOUR[sev]
        print(f"\n{colour}{BOLD}  ■ {sev} ({len(group)}){RESET}")
        for f in group:
            print(f"\n  {colour}[{f.severity}]{RESET} {BOLD}{f.title}{RESET}")
            print(f"  Resource : {f.resource}")
            print(f"  Detail   : {f.detail}")
            print(f"  Fix      : {f.fix}")
            print(f"  {'─'*58}")

    passed = len(report.passed)
    total  = len(report.findings)
    issues = total - passed

    print(f"\n{'═'*64}")
    print(f"{BOLD}  SUMMARY{RESET}")
    print(f"  Total checks : {total}")
    print(f"  {RED}Issues found : {issues}{RESET}")
    print(f"  {GREEN}Passed       : {passed}{RESET}")
    score = int((passed / total) * 100) if total else 0
    colour = GREEN if score >= 80 else YELLOW if score >= 60 else RED
    print(f"  {colour}Security score : {score}/100{RESET}")
    print(f"{'═'*64}\n")


def save_json(report: AuditReport, path: str):
    data = {
        "account_id": report.account_id,
        "region":     report.region,
        "timestamp":  report.timestamp,
        "findings": [
            {
                "severity": f.severity,
                "service":  f.service,
                "title":    f.title,
                "resource": f.resource,
                "detail":   f.detail,
                "fix":      f.fix,
            }
            for f in report.findings
        ],
    }
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    print(f"  {GREEN}JSON report saved → {path}{RESET}")


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    print(f"\n{BOLD}{'═'*64}")
    print(f"  🔍  AWS Security Auditor  —  github.com/Randalls59")
    print(f"{'═'*64}{RESET}\n")

    # Resolve account / region
    sts    = boto3.client("sts")
    ec2_r  = boto3.client("ec2")
    try:
        identity   = sts.get_caller_identity()
        account_id = identity["Account"]
        region     = boto3.session.Session().region_name or "us-east-1"
    except Exception as e:
        print(f"{RED}Cannot connect to AWS: {e}{RESET}")
        sys.exit(1)

    report = AuditReport(
        account_id=account_id,
        region=region,
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    )

    print(f"  Account : {account_id}   Region : {region}\n")
    print(f"  Running checks...\n")

    check_s3(report)
    check_iam(report)
    check_ec2(report)
    check_cloudtrail(report)

    print_report(report)

    # Optional: save JSON
    out = f"audit-{account_id}-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    save_json(report, out)


if __name__ == "__main__":
    main()
