# Multi-Account Assessment Guide

## Overview

Many AWS environments use multiple accounts (via AWS Organizations) to separate workloads, environments, and teams. This guide helps you assess security across multiple accounts systematically.

## When This Applies

- You have an AWS Organization with multiple member accounts
- You manage separate AWS accounts for dev/staging/production
- You want a consolidated security view across accounts

## Account Discovery

### Step 1: Identify Your Account Structure

```bash
# Check if Organizations is enabled and get org details
aws organizations describe-organization --query 'Organization.{Id:Id,MasterAccountId:MasterAccountId,MasterAccountEmail:MasterAccountEmail}' --output table

# List all accounts in the organization
aws organizations list-accounts --query 'Accounts[].{Id:Id,Name:Name,Email:Email,Status:Status}' --output table

# List organizational units (OUs)
aws organizations list-roots --query 'Roots[].{Id:Id,Name:Name}' --output text | while read root_id root_name; do
  echo "Root: $root_name ($root_id)"
  aws organizations list-organizational-units-for-parent --parent-id $root_id --query 'OrganizationalUnits[].{Id:Id,Name:Name}' --output table
done
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

If delegated administration is configured, these can be assessed centrally:

```bash
# Check delegated administrators
aws organizations list-delegated-administrators --query 'DelegatedAdministrators[].{Id:Id,Name:Name,Email:Email,Services:DelegatedServices}' --output table 2>/dev/null || echo "Not running from management account or no delegated admins"

# Common delegated services
aws organizations list-delegated-services-for-account --account-id <admin-account-id> --query 'DelegatedServices[].ServicePrincipal' --output table 2>/dev/null
```

## Execution Workflow

### Step 1: Assess Organization-Level Controls First

Start from the management account (or delegated admin):

```bash
# Verify you're in the management account
aws organizations describe-organization --query 'Organization.MasterAccountId' --output text
aws sts get-caller-identity --query 'Account' --output text
```

Run organization-level checks: SCPs, org trail, delegated admins, Security Hub aggregation.

Save findings to `assessment-findings-org-{ORG_ID}.md`.

### Step 2: Assess Each Member Account

For each account in scope:

**Using cross-account role assumption:**
```bash
# Assume role in target account
CREDS=$(aws sts assume-role \
  --role-arn arn:aws:iam::{TARGET_ACCOUNT_ID}:role/{ROLE_NAME} \
  --role-session-name security-assessment \
  --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' \
  --output text)

# Export temporary credentials
export AWS_ACCESS_KEY_ID=$(echo $CREDS | awk '{print $1}')
export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | awk '{print $2}')
export AWS_SESSION_TOKEN=$(echo $CREDS | awk '{print $3}')

# Verify identity
aws sts get-caller-identity
```

**Using named profiles:**
```bash
# Switch to target account profile
export AWS_PROFILE=account-name-profile
aws sts get-caller-identity
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
