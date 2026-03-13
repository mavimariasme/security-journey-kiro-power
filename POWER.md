---
name: "security-journey-power"
displayName: "Security Journey Power"
description: "Assess and improve your AWS security posture using the AWS Security Maturity Model framework - automated assessment, remediation planning, and implementation guidance with progress tracking"
keywords: ["aws", "security", "maturity", "assessment", "remediation", "compliance", "guardrails", "cloudtrail", "guardduty"]
author: "mariasme@amazon.com"
---

# Security Journey Power

## Overview

This power helps you systematically assess and improve your AWS security posture using the official AWS Security Maturity Model framework. It provides:

- Automated Assessment: Uses AWS CLI and APIs to retrieve current security configurations
- Progress Tracking: Maintains a CSV file tracking your security maturity across all domains
- Remediation Planning: Analyzes gaps and creates prioritized remediation plans
- Implementation Guidance: Provides step-by-step AWS CLI commands and console instructions
- Continuous Improvement: Updates tracking as you implement remediations

The AWS Security Maturity Model organizes security controls into 4 phases (Quick Wins, Foundational, Efficient, Optimized) across 10 security domains, helping you prioritize improvements based on ease of implementation and security impact.

## Prerequisites

### 1. Install uvx (Python package runner)

All MCP servers in this power are distributed via [uvx](https://docs.astral.sh/uv/). Install it before using the power:

```bash
# macOS/Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# Or via pip
pip install uv

# Verify installation
uvx --version
```

### 2. AWS CLI Installed and Configured

```bash
aws --version
aws configure list
```

### 3. AWS IAM Permissions (Least Privilege)

The power requires read-only access to assess your security posture. Below is the minimum IAM policy needed for running assessments. Remediation steps require additional write permissions that are documented per-control in the remediation workflow.

**Assessment-only IAM Policy (least privilege):**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SecurityJourneyAssessmentReadOnly",
      "Effect": "Allow",
      "Action": [
        "iam:GetAccountSummary",
        "iam:GetAccountPasswordPolicy",
        "iam:ListUsers",
        "iam:ListMFADevices",
        "iam:ListVirtualMFADevices",
        "iam:ListAccessKeys",
        "iam:GetAccessKeyLastUsed",
        "iam:ListAttachedUserPolicies",
        "iam:ListUserPolicies",
        "iam:GetLoginProfile",
        "iam:ListAccountAliases",
        "sts:GetCallerIdentity",
        "guardduty:ListDetectors",
        "guardduty:GetDetector",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "s3control:GetPublicAccessBlock",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketEncryption",
        "s3:GetBucketVersioning",
        "s3:GetBucketLogging",
        "s3:ListAllMyBuckets",
        "securityhub:DescribeHub",
        "securityhub:GetFindings",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeInstances",
        "ec2:DescribeVpcs",
        "ec2:DescribeFlowLogs",
        "ec2:DescribeRegions",
        "ec2:DescribeImages",
        "config:DescribeConfigurationRecorders",
        "config:DescribeConfigurationRecorderStatus",
        "organizations:DescribeOrganization",
        "organizations:ListPolicies",
        "access-analyzer:ListAnalyzers",
        "wafv2:ListWebACLs",
        "elasticloadbalancing:DescribeLoadBalancers",
        "rds:DescribeDBInstances",
        "rds:DescribeDBClusters",
        "kms:ListKeys",
        "kms:DescribeKey",
        "kms:GetKeyRotationStatus",
        "logs:DescribeLogGroups",
        "cloudwatch:DescribeAlarms",
        "sns:ListTopics",
        "sns:ListSubscriptions",
        "lambda:ListFunctions",
        "lambda:GetFunctionConfiguration",
        "backup:ListBackupPlans",
        "macie2:GetMacieSession",
        "inspector2:BatchGetAccountStatus",
        "detective:ListGraphs",
        "account:GetAlternateContact"
      ],
      "Resource": "*"
    }
  ]
}
```

**To create this policy and attach it to your user/role:**

```bash
# Save the policy above to a file called security-journey-policy.json
aws iam create-policy \
  --policy-name SecurityJourneyAssessmentReadOnly \
  --policy-document file://security-journey-policy.json

# Attach to your IAM user (replace YOUR_USERNAME)
aws iam attach-user-policy \
  --user-name YOUR_USERNAME \
  --policy-arn arn:aws:iam::YOUR_ACCOUNT_ID:policy/SecurityJourneyAssessmentReadOnly
```

> **Note**: For remediation (implementing fixes), you will need additional write permissions specific to each service. The remediation workflow guides document the exact permissions needed for each control.

### 4. AWS Profile Configuration (Optional)

If using multiple AWS accounts:

```bash
export AWS_PROFILE=your-profile-name
export AWS_REGION=us-east-1
```

### 5. Security Maturity Tracking CSV

The power includes a CSV template (`aws-security-maturity-tracking-template.csv`) with all 73 controls.

**On first use:**
1. Copy the template to your workspace root
2. Rename it to `aws-security-maturity-tracking.csv`
3. The agent will use this file to track your progress

## Available Steering Files

- **assessment-workflow.md** - Complete workflow for assessing your AWS account
- **remediation-workflow.md** - Step-by-step remediation implementation guide
- **csv-management.md** - Managing and updating the security maturity CSV
- **implementation-guide.md** - Detailed implementation guide for all controls

## Available MCP Servers

This power uses multiple MCP servers to provide comprehensive AWS security assessment capabilities:

### aws-core
Core AWS operations and utilities for account information retrieval.

### aws-api
Direct AWS API access for retrieving security configurations and settings.

### aws-knowledge
AWS security best practices and knowledge base for remediation guidance.

### aws-documentation
Access to official AWS documentation for detailed implementation instructions.

### document-loader
Loads and processes the security maturity CSV and markdown files.

## Assessment Execution Rules

**CRITICAL: The assessment workflow MUST be executed one phase at a time, never all at once.**

The `assessment-workflow.md` file contains CLI checks for all 73 controls across 5 phases. Attempting to run the entire assessment in a single pass will exceed context limits and produce unreliable results.

### Required Execution Pattern

1. Always start by asking the user which phase to assess — do not assume all phases should run
2. Execute one phase per conversation turn:
   - Phase 1: Account Information
   - Phase 2: Quick Wins Assessment (17 controls)
   - Phase 3: Foundational Controls Assessment (19 controls)
   - Phase 4: Efficient Controls Assessment (20 controls)
   - Phase 5: Optimized Controls Assessment (19 controls)
3. After completing each phase, summarize findings, update the CSV, and ask the user if they want to proceed to the next phase
4. Never read the entire assessment-workflow.md at once — only read the section for the current phase being assessed

### Phase Boundaries

When the user asks for a "full assessment" or "complete assessment":
- Explain that the assessment covers 73 controls across 5 phases
- Recommend starting with Phase 2 (Quick Wins) as it provides the highest security impact with lowest effort
- Execute each phase sequentially, pausing between phases for user review
- Track completed phases in the CSV so the assessment can be resumed later

### Per-Phase Workflow

For each phase:
1. Read only the relevant phase section from `assessment-workflow.md`
2. Execute CLI checks for each control in that phase
3. Record results (pass/fail/not-applicable) for each control
4. Update the CSV tracking file with findings
5. Present a phase summary with counts and critical findings
6. Ask the user: "Phase X complete. Would you like to proceed to Phase Y?"


## Common Workflows

### Workflow 1: Initial Security Assessment

**Goal**: Assess your current AWS security posture across all domains

1. Ask the agent: "Retrieve my AWS account information including account ID, regions in use, and basic configuration"
2. Ask the agent: "Assess my AWS security controls for Phase 1 Quick Wins"
3. The agent will check MFA status, GuardDuty, CloudTrail, S3 Block Public Access, Security Hub, security groups, WAF, and more
4. Ask the agent: "Update the security maturity CSV with assessment findings"

### Workflow 2: Create Remediation Plan

**Goal**: Generate a prioritized plan to address security gaps

1. Ask the agent: "Read my security maturity CSV and identify gaps"
2. Ask the agent: "Create a remediation plan for the next 30 days"
3. The agent presents prioritized controls with estimated effort, dependencies, and expected impact

### Workflow 3: Implement Remediation

**Goal**: Implement a specific security control with guidance

1. Ask the agent: "I want to implement GuardDuty. Guide me through it."
2. Follow the step-by-step CLI commands or console instructions
3. Ask the agent: "Verify that GuardDuty is properly configured"
4. Ask the agent: "Update the CSV to mark GuardDuty as completed"

### Workflow 4: Continuous Monitoring

**Goal**: Regularly assess and track security improvements

1. Ask the agent: "Assess my security posture and compare to last month"
2. Ask the agent: "Generate a security maturity progress report"

## Troubleshooting

### MCP Server Connection Issues

1. Verify uvx is installed: `uvx --version`
2. Check MCP server status in Kiro Powers panel
3. Restart Kiro and reconnect MCP servers
4. Check environment variables are set correctly

### AWS CLI Authentication Issues

1. Verify AWS CLI configuration: `aws configure list` and `aws sts get-caller-identity`
2. Check AWS profile: `export AWS_PROFILE=your-profile-name`
3. Verify IAM permissions match the least-privilege policy above

### CSV File Issues

1. Verify CSV file path is correct
2. Check file permissions (read/write access)
3. Ensure CSV follows the expected structure
4. Ask agent to create a new CSV template if needed

## Best Practices

- Start with Quick Wins: Focus on Phase 1 controls first for immediate security improvements
- Regular Assessments: Run assessments monthly to track progress and catch regressions
- Document Everything: Use the CSV notes field to document implementation details
- Test in Non-Production: Test remediations in dev/test accounts before production
- Incremental Implementation: Follow the phased approach, don't try everything at once
- Verify After Implementation: Always verify controls are working as expected
- Consider Compliance: Map controls to your compliance requirements (SOC 2, ISO 27001, etc.)

## MCP Config Placeholders

The mcp.json is pre-configured and ready to use. No placeholders to replace.

If you want to use a different AWS profile or region, edit `mcp.json` and modify the `aws-api` server's `env` section:

```json
"aws-api": {
  "command": "uvx",
  "args": ["awslabs.aws-api-mcp-server@latest"],
  "env": {
    "AWS_PROFILE": "your-profile-name",
    "AWS_REGION": "your-region",
    "FASTMCP_LOG_LEVEL": "ERROR"
  }
}
```

After any changes, reconnect MCP servers in Kiro Powers panel.

---

**Framework**: [AWS Security Maturity Model](https://maturitymodel.security.aws.dev)

This power integrates with the following MCP servers, all licensed under the Apache-2.0 license:
- [awslabs.core-mcp-server](https://github.com/awslabs/mcp) (Apache-2.0)
- [awslabs.aws-api-mcp-server](https://github.com/awslabs/mcp) (Apache-2.0)
- [awslabs.aws-documentation-mcp-server](https://github.com/awslabs/mcp) (Apache-2.0)
- [awslabs.document-loader-mcp-server](https://github.com/awslabs/mcp) (Apache-2.0)
- [AWS Knowledge MCP Server](https://knowledge.mcp.aws.dev) (AWS-managed remote service)

This power does not collect any client-side telemetry.
