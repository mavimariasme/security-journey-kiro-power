---
name: "security-journey-power"
displayName: "Security Journey Power"
description: "Assess and improve your AWS security posture using the AWS Security Maturity Model framework - automated assessment, remediation planning, and implementation guidance with progress tracking"
keywords: ["aws", "security", "maturity", "assessment", "remediation", "compliance", "guardrails", "cloudtrail", "guardduty", "well-architected"]
author: "mariasme@amazon.com"
---

# Security Journey Power

## Safety Rules — Read-Only by Default

**CRITICAL: This power operates in READ-ONLY mode by default. The agent MUST follow these rules at all times:**

1. The agent MAY autonomously execute AWS CLI commands that only READ data (describe, list, get, lookup, generate-credential-report).
2. The agent MUST NEVER autonomously execute any AWS CLI command that creates, modifies, deletes, enables, disables, attaches, detaches, revokes, or authorizes AWS resources or configurations.
3. When a remediation step requires a write/modify/delete action, the agent MUST:
   - Clearly present the exact command(s) to the user
   - Explain what the command will do and what resources it will affect
   - Explicitly ask the user for approval before executing
   - Only execute the command after receiving explicit user confirmation
4. This applies to ALL write operations including but not limited to: `create-*`, `delete-*`, `put-*`, `modify-*`, `update-*`, `enable-*`, `disable-*`, `attach-*`, `detach-*`, `revoke-*`, `authorize-*`, `start-logging`, `stop-logging`.
5. The agent MUST NOT batch multiple write commands together. Each write action requires separate user approval.
6. If the user asks the agent to "fix everything" or "remediate all", the agent MUST still present each write action individually for approval.

## Overview

This power turns Kiro into a security assessment companion for your AWS accounts. You talk to the agent in natural language, and it checks your security configuration against 73 controls from the official [AWS Security Maturity Model](https://maturitymodel.security.aws.dev) framework.

**What happens when you start an assessment:**

1. The agent validates your AWS credentials and asks scoping questions
2. It runs read-only checks against your AWS account, one phase at a time
3. Findings are saved incrementally to a markdown file (nothing is lost if the conversation is interrupted)
4. A CSV tracking file is updated with pass/fail status for each control
5. After each phase, you get a summary and decide whether to continue
6. When gaps are found, the agent creates a prioritized remediation plan
7. For each fix, the agent presents the exact command and waits for your approval before executing

**Key capabilities:**

- Automated Assessment: Uses AWS CLI and APIs to retrieve current security configurations (read-only, runs automatically)
- Progress Tracking: Maintains a CSV file tracking your security maturity across all domains
- Remediation Planning: Analyzes gaps and creates prioritized remediation plans
- Implementation Guidance: Provides step-by-step AWS CLI commands and console instructions (requires user approval before execution)
- Multi-Account Support: Assess multiple AWS accounts in an organization with consolidated reporting
- Continuous Improvement: Updates tracking as you implement remediations

The AWS Security Maturity Model organizes security controls into 4 phases (Quick Wins, Foundational, Efficient, Optimized) across 10 security domains, helping you prioritize improvements based on ease of implementation and security impact.

| Phase | Controls | What It Covers |
|-------|----------|----------------|
| Quick Wins | 17 | MFA, GuardDuty, CloudTrail, S3 Block Public Access, Security Hub, WAF, billing alarms |
| Foundational | 19 | SCPs, temporary credentials, IMDSv2, encryption at rest, backups, network segmentation |
| Efficient | 20 | DevSecOps pipelines, security champions, least privilege reviews, threat modeling, Macie |
| Optimized | 19 | IAM data perimeters, red/blue teams, chaos engineering, temporary elevated access |

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

- **pre-assessment-checklist.md** - Mandatory pre-flight checks and scoping questions before any assessment
- **assessment-workflow.md** - Complete workflow for assessing your AWS account
- **remediation-workflow.md** - Step-by-step remediation implementation guide
- **csv-management.md** - Managing and updating the security maturity CSV
- **implementation-guide.md** - Detailed implementation guide for all controls
- **findings-persistence.md** - How the agent saves findings incrementally to avoid context loss
- **multi-account-assessment.md** - Guide for assessing multiple AWS accounts in an organization

## Available MCP Servers

This power uses multiple MCP servers to provide comprehensive AWS security assessment capabilities:

### aws-core
Core AWS operations and utilities for account information retrieval.

### aws-api
Direct AWS API access for retrieving security configurations and settings. Configured with `READ_OPERATIONS_ONLY=true` by default for safety — remediation commands that require write access will be presented to the user for manual execution or the user can reconfigure this setting.

### aws-knowledge
Fully managed remote MCP server providing up-to-date AWS documentation, code samples, regional availability information, and best practices. No authentication required. Accessed via `https://knowledge-mcp.global.api.aws`.

### aws-documentation
Access to official AWS documentation for detailed implementation instructions.

### well-architected-security
AWS Well-Architected Security Assessment Tool MCP server. Provides operational tools for monitoring and assessing AWS environments against the AWS Well-Architected Framework Security Pillar, including:
- `CheckSecurityServices` — Monitor operational status of GuardDuty, Security Hub, Inspector, and IAM Access Analyzer
- `GetSecurityFindings` — Retrieve and analyze security findings from AWS services
- `AnalyzeSecurityPosture` — Comprehensive security posture analysis against the Well-Architected Framework
- `GetResourceComplianceStatus` — Monitor resource compliance against security standards
- `ExploreAwsResources` — Discover and inventory AWS resources across services and regions
- `GetStoredSecurityContext` — Access historical security context data for trend analysis

### document-loader
Loads and processes the security maturity CSV and markdown files.

## Assessment Execution Rules

**CRITICAL: The assessment workflow MUST be executed one phase at a time, never all at once.**

The `assessment-workflow.md` file contains CLI checks for all 73 controls across 5 phases. Attempting to run the entire assessment in a single pass will exceed context limits and produce unreliable results.

### Pre-Assessment Checklist (Mandatory)

**Before running ANY assessment commands, the agent MUST complete the `pre-assessment-checklist.md` workflow:**

1. Validate AWS credentials automatically (do not proceed if auth fails)
2. Ask the user scoping questions (assessment scope, account scope, region scope) in a single grouped message
3. Confirm the plan and get explicit user approval
4. Initialize the findings file and CSV

This checklist applies to every assessment session, including resumed assessments (credential validation is always required; scoping questions can be skipped if resuming).

### Findings Persistence (Mandatory)

**The agent MUST save findings incrementally to a markdown file as it works through each phase.** This prevents data loss from context overflow or conversation interruptions. See `findings-persistence.md` for the full protocol.

Key rules:
1. Create `assessment-findings-{ACCOUNT_ID}.md` at assessment start
2. After checking each control (or small group of 2-3 controls), immediately append results to the file using `fsAppend`
3. Never accumulate all findings in context and write at the end — write as you go
4. Write a phase summary block after completing each phase
5. When resuming an assessment, read the existing findings file to determine progress

### Multi-Account Assessments

When the user has multiple AWS accounts (AWS Organizations), follow the `multi-account-assessment.md` guide:
1. Assess organization-level controls first (SCPs, org trail, delegated admins) from the management account
2. Then assess per-account controls for each member account in scope
3. Create separate findings files per account: `assessment-findings-{ACCOUNT_ID}.md`
4. Generate a consolidated report after all accounts are assessed

### Required Execution Pattern

1. Always start by asking the user which phase to assess — do not assume all phases should run
2. For multi-account environments, ask which accounts are in scope before starting
3. Execute one phase per conversation turn:
   - Phase 1: Account Information
   - Phase 2: Quick Wins Assessment (17 controls)
   - Phase 3: Foundational Controls Assessment (19 controls)
   - Phase 4: Efficient Controls Assessment (20 controls)
   - Phase 5: Optimized Controls Assessment (19 controls)
4. After completing each phase, write the phase summary to the findings file, update the CSV, and ask the user if they want to proceed to the next phase
5. Never read the entire assessment-workflow.md at once — only read the section for the current phase being assessed

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
3. After each control (or group of 2-3 controls), append results to the findings markdown file immediately
4. After all controls in the phase are checked, write a phase summary to the findings file
5. Update the CSV tracking file with findings
6. Present the phase summary to the user
7. Ask the user: "Phase X complete. Would you like to proceed to Phase Y?"


## Common Workflows

### Workflow 1: Initial Security Assessment

**Goal**: Assess your current AWS security posture across all domains

1. Ask the agent: "Retrieve my AWS account information including account ID, regions in use, and basic configuration"
2. Ask the agent: "Assess my AWS security controls for Phase 2 Quick Wins"
3. The agent will check MFA status, GuardDuty, CloudTrail, S3 Block Public Access, Security Hub, security groups, WAF, and more — saving findings incrementally to `assessment-findings-{ACCOUNT_ID}.md`
4. Review the findings file and ask the agent to continue with the next phase

### Workflow 2: Multi-Account Assessment

**Goal**: Assess security across multiple AWS accounts in an organization

1. Ask the agent: "I have multiple AWS accounts. Help me assess my organization's security posture"
2. The agent will discover your organization structure and ask which accounts to assess
3. Organization-level controls (SCPs, org trail) are assessed first from the management account
4. Per-account controls are assessed for each account in scope, with separate findings files
5. Ask the agent: "Generate a consolidated security report across all assessed accounts"

### Workflow 3: Create Remediation Plan

**Goal**: Generate a prioritized plan to address security gaps

1. Ask the agent: "Read my security maturity CSV and identify gaps"
2. Ask the agent: "Create a remediation plan for the next 30 days"
3. The agent presents prioritized controls with estimated effort, dependencies, and expected impact

### Workflow 4: Implement Remediation

**Goal**: Implement a specific security control with guidance

1. Ask the agent: "I want to implement GuardDuty. Guide me through it."
2. The agent will present each AWS CLI command and ask for your approval before executing
3. Follow the step-by-step guidance, approving each action
4. Ask the agent: "Verify that GuardDuty is properly configured"
5. Ask the agent: "Update the CSV to mark GuardDuty as completed"

> Note: The agent will never execute write/modify/delete AWS commands without your explicit approval. Each action is presented individually for review.

### Workflow 5: Continuous Monitoring

**Goal**: Regularly assess and track security improvements

1. Ask the agent: "Assess my security posture and compare to last month"
2. Ask the agent: "Generate a security maturity progress report"

## Example Prompts

The power responds to natural language in any language. Here are example prompts in English, Portuguese, and Spanish.

### 🇺🇸 English

**Start an assessment:**
- "Assess my AWS security posture using the Security Maturity Model"
- "Run a Quick Wins security assessment on my AWS account"
- "Check if GuardDuty, CloudTrail, and Security Hub are enabled in all regions"
- "Assess the security of my AWS Organization across all member accounts"

**Resume or continue:**
- "Resume my security assessment from where I left off"
- "Continue with Phase 3 Foundational controls"
- "What phases have I already completed?"

**Remediation:**
- "Create a 30-day remediation plan based on my security gaps"
- "Help me enable GuardDuty in all regions"
- "What are the most critical security issues I should fix first?"
- "Guide me through implementing S3 Block Public Access"

**Tracking and reporting:**
- "Show my security maturity progress"
- "Compare my current security posture with last month's assessment"
- "Generate a security maturity report for my management team"
- "Which security domains have the most gaps?"

### 🇧🇷 Português

**Iniciar uma avaliação:**
- "Avalie a postura de segurança da minha conta AWS usando o Security Maturity Model"
- "Execute uma avaliação de segurança Quick Wins na minha conta AWS"
- "Verifique se o GuardDuty, CloudTrail e Security Hub estão habilitados em todas as regiões"
- "Avalie a segurança da minha AWS Organization em todas as contas membro"

**Retomar ou continuar:**
- "Continue minha avaliação de segurança de onde parei"
- "Continue com a Fase 3 controles Foundational"
- "Quais fases eu já completei?"

**Remediação:**
- "Crie um plano de remediação de 30 dias baseado nas minhas lacunas de segurança"
- "Me ajude a habilitar o GuardDuty em todas as regiões"
- "Quais são os problemas de segurança mais críticos que devo corrigir primeiro?"
- "Me guie na implementação do S3 Block Public Access"

**Acompanhamento e relatórios:**
- "Mostre meu progresso de maturidade de segurança"
- "Compare minha postura de segurança atual com a avaliação do mês passado"
- "Gere um relatório de maturidade de segurança para minha equipe de gestão"
- "Quais domínios de segurança têm mais lacunas?"

### 🇪🇸 Español

**Iniciar una evaluación:**
- "Evalúa la postura de seguridad de mi cuenta AWS usando el Security Maturity Model"
- "Ejecuta una evaluación de seguridad Quick Wins en mi cuenta AWS"
- "Verifica si GuardDuty, CloudTrail y Security Hub están habilitados en todas las regiones"
- "Evalúa la seguridad de mi AWS Organization en todas las cuentas miembro"

**Reanudar o continuar:**
- "Continúa mi evaluación de seguridad desde donde la dejé"
- "Continúa con la Fase 3 controles Foundational"
- "¿Qué fases ya he completado?"

**Remediación:**
- "Crea un plan de remediación de 30 días basado en mis brechas de seguridad"
- "Ayúdame a habilitar GuardDuty en todas las regiones"
- "¿Cuáles son los problemas de seguridad más críticos que debo corregir primero?"
- "Guíame en la implementación de S3 Block Public Access"

**Seguimiento y reportes:**
- "Muestra mi progreso de madurez de seguridad"
- "Compara mi postura de seguridad actual con la evaluación del mes pasado"
- "Genera un reporte de madurez de seguridad para mi equipo directivo"
- "¿Qué dominios de seguridad tienen más brechas?"

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

The mcp.json is pre-configured and ready to use. The `aws-api` server is set to `READ_OPERATIONS_ONLY=true` by default for safety during assessments.

If you want to use a different AWS profile or region, edit `mcp.json` and modify the `aws-api` and `well-architected-security` servers' `env` sections:

```json
"aws-api": {
  "command": "uvx",
  "args": ["awslabs.aws-api-mcp-server@latest"],
  "env": {
    "AWS_PROFILE": "your-profile-name",
    "AWS_REGION": "your-region",
    "READ_OPERATIONS_ONLY": "true",
    "FASTMCP_LOG_LEVEL": "ERROR"
  }
},
"well-architected-security": {
  "command": "uvx",
  "args": ["--from", "awslabs.well-architected-security-mcp-server", "well-architected-security-mcp-server"],
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
- [awslabs.well-architected-security-mcp-server](https://github.com/awslabs/mcp) (Apache-2.0)
- [awslabs.document-loader-mcp-server](https://github.com/awslabs/mcp) (Apache-2.0)
- [AWS Knowledge MCP Server](https://knowledge-mcp.global.api.aws) (AWS-managed remote service)

This power does not collect any client-side telemetry.
