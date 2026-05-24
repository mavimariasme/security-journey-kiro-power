# Multi-Account Assessment Guide

## Overview

Many AWS environments use multiple accounts (via AWS Organizations) to separate workloads, environments, and teams. This guide helps you assess security across multiple accounts systematically.

## When This Applies

- You have an AWS Organization with multiple member accounts
- You manage separate AWS accounts for dev/staging/production
- You want a consolidated security view across accounts

## Account Discovery

### Step 1: Identify Your Account Structure

Use `aws___run_script` to discover your organization structure:

```python
import boto3

sts = boto3.client('sts')
identity = sts.get_caller_identity()
print(f"Current Account: {identity['Account']}")

try:
    org = boto3.client('organizations')
    org_info = org.describe_organization()['Organization']
    print(f"Organization ID: {org_info['Id']}")
    print(f"Management Account: {org_info['MasterAccountId']}")

    # List all accounts
    accounts = org.list_accounts()['Accounts']
    print(f"\nAccounts ({len(accounts)}):")
    for acct in accounts:
        print(f"  {acct['Id']} - {acct['Name']} ({acct['Status']})")

    # List OUs
    roots = org.list_roots()['Roots']
    for root in roots:
        print(f"\nRoot: {root['Name']} ({root['Id']})")
        ous = org.list_organizational_units_for_parent(ParentId=root['Id'])['OrganizationalUnits']
        for ou in ous:
            print(f"  OU: {ou['Name']} ({ou['Id']})")
except Exception as e:
    print(f"Not in an Organization or no access: {e}")
```

### Step 2: Determine Assessment Scope

Ask the user:
1. Which accounts should be assessed? (all, specific OUs, specific accounts)
2. Is there a delegated administrator account for security services?
3. Which account has centralized logging (CloudTrail, Config)?
4. Is there a dedicated security tooling account?

### Step 3: Identify the Assessment Approach

There are two approaches depending on access:

**Approach A: Cross-Account Role Assumption (Recommended)**
- A single IAM role exists in each member account that the assessor can assume
- Common with AWS Control Tower (AWSControlTowerExecution role) or custom OrganizationAccountAccessRole

**Approach B: Per-Account Credentials**
- Separate AWS profiles configured for each account
- The user switches profiles between account assessments

## Assessment Strategy

### Organization-Level Controls (Assess Once)

These controls are assessed from the management account or delegated admin and apply to the entire organization:

| Control | Where to Assess |
|---------|----------------|
| Service Control Policies (SCPs) | Management account |
| Resource Control Policies (RCPs) | Management account |
| AWS Organizations configuration | Management account |
| Centralized CloudTrail (org trail) | Management/logging account |
| Centralized Config | Management/delegated admin |
| Security Hub (aggregated) | Delegated admin account |
| GuardDuty (aggregated) | Delegated admin account |
| IAM Access Analyzer (organization) | Delegated admin account |

### Per-Account Controls (Assess Each Account)

These controls must be checked in each individual account:

| Control | Notes |
|---------|-------|
| MFA for IAM users | Each account has its own IAM users |
| S3 Block Public Access | Account-level setting per account |
| Security groups | VPC-specific, per account |
| Encryption at rest | Per-account resources |
| IMDSv2 enforcement | Per-account EC2 instances |
| Backup configuration | Per-account backup vaults |
| WAF deployment | Per-account/per-resource |

### Delegated Services (Assess from Admin Account)

If delegated administration is configured, these can be assessed centrally. Use `aws___call_aws` or `aws___run_script`:

```python
import boto3

org = boto3.client('organizations')

try:
    admins = org.list_delegated_administrators()['DelegatedAdministrators']
    print("Delegated Administrators:")
    for admin in admins:
        print(f"  {admin['Id']} - {admin['Name']}")
        services = org.list_delegated_services_for_account(AccountId=admin['Id'])['DelegatedServices']
        for svc in services:
            print(f"    Service: {svc['ServicePrincipal']}")
except Exception as e:
    print(f"Not running from management account or no delegated admins: {e}")
```

## Execution Workflow

### Step 1: Assess Organization-Level Controls First

Start from the management account (or delegated admin). Use `aws___run_script`:

```python
import boto3

sts = boto3.client('sts')
org = boto3.client('organizations')

identity = sts.get_caller_identity()
org_info = org.describe_organization()['Organization']

print(f"Current Account: {identity['Account']}")
print(f"Management Account: {org_info['MasterAccountId']}")
print(f"Is Management: {identity['Account'] == org_info['MasterAccountId']}")
```

Run organization-level checks: SCPs, org trail, delegated admins, Security Hub aggregation.

Save findings to `assessment-findings-org-{ORG_ID}.md`.

### Step 2: Assess Each Member Account

For each account in scope, use `aws___run_script` to assume the cross-account role and run checks:

**Using cross-account role assumption:**
```python
import boto3

TARGET_ACCOUNT_ID = "123456789012"  # Replace with target account
ROLE_NAME = "OrganizationAccountAccessRole"  # Or your custom role

sts = boto3.client('sts')
creds = sts.assume_role(
    RoleArn=f"arn:aws:iam::{TARGET_ACCOUNT_ID}:role/{ROLE_NAME}",
    RoleSessionName="security-assessment"
)['Credentials']

# Create session with assumed role credentials
session = boto3.Session(
    aws_access_key_id=creds['AccessKeyId'],
    aws_secret_access_key=creds['SecretAccessKey'],
    aws_session_token=creds['SessionToken']
)

# Verify identity in target account
target_sts = session.client('sts')
identity = target_sts.get_caller_identity()
print(f"Now operating as: {identity['Arn']} in account {identity['Account']}")
```

Run the standard per-account assessment phases. Save findings to `assessment-findings-{ACCOUNT_ID}.md`.

### Step 3: Generate Consolidated Report

After all accounts are assessed, the agent should:

1. Read all `assessment-findings-*.md` files
2. Create a consolidated summary in `assessment-findings-consolidated.md`
3. Highlight controls that are failing across multiple accounts (systemic issues)
4. Identify accounts with the weakest security posture
5. Prioritize organization-level remediations that fix issues across all accounts at once

## Consolidated Report Structure

```markdown
# Consolidated Security Assessment

- **Organization ID**: o-xxxxxxxxxx
- **Assessment Date**: 2025-03-13
- **Accounts Assessed**: 5 of 8 total

## Organization-Level Findings
- SCPs: 3 active policies
- Org CloudTrail: Enabled, multi-region
- Security Hub aggregation: Enabled in delegated admin

## Per-Account Summary

| Account | Alias | Phase 2 | Phase 3 | Phase 4 | Phase 5 | Critical Gaps |
|---------|-------|---------|---------|---------|---------|---------------|
| 111111111111 | prod | 15/17 | 12/19 | — | — | IMDSv2, encryption |
| 222222222222 | staging | 13/17 | — | — | — | MFA, GuardDuty |
| 333333333333 | dev | 10/17 | — | — | — | MFA, CloudTrail, S3 BPA |

## Systemic Issues (Failing in 2+ Accounts)
1. **IMDSv2 not enforced** — Accounts: prod, staging (recommend org-wide SCP)
2. **MFA gaps** — Accounts: staging, dev (recommend Identity Center migration)

## Recommended Organization-Level Remediations
1. Deploy SCP to enforce IMDSv2 on all new instances (fixes all accounts)
2. Enable Security Hub auto-enable for new accounts
3. ...
```

## Multi-Account CSV Tracking

For multi-account assessments, use one of these approaches:

**Option A: Separate CSV per account**
- `aws-security-maturity-tracking-{account-alias}.csv`
- Simpler, each account tracked independently

**Option B: Single CSV with account column**
- Add an `Account` column to the CSV
- Allows cross-account reporting in one file
- Better for consolidated dashboards

The agent should ask the user which approach they prefer on first multi-account assessment.

## Tips

- Start with the management account and security tooling account — these are the most critical
- Use Security Hub cross-account aggregation to get a quick overview before deep-diving per account
- Organization-level remediations (SCPs, org-wide services) give the best ROI — fix once, apply everywhere
- For large organizations (50+ accounts), focus on production and security-critical accounts first
- Temporary credentials from `sts assume-role` expire after 1 hour by default — plan phases accordingly
