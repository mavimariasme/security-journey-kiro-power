---
name: "security-journey-power"
displayName: "Security Journey Power"
description: "Assess and improve your AWS security posture using the AWS Security Maturity Model framework - automated assessment, remediation planning, and implementation guidance with multi-account support and progress tracking via CSV"
keywords: ["aws", "security", "maturity", "assessment", "remediation", "compliance", "guardrails", "cloudtrail", "guardduty", "well-architected"]
author: "AWS"
---

# Security Journey Power

## Safety Rules — Read-Only by Default

**CRITICAL: This power operates in READ-ONLY mode by default. The agent MUST follow these rules at all times:**

1. The agent MAY autonomously execute read-only AWS operations (describe, list, get, lookup, generate-credential-report) via the AWS MCP Server tools.
2. The agent MUST NEVER autonomously execute any AWS operation that creates, modifies, deletes, enables, disables, attaches, detaches, revokes, or authorizes AWS resources or configurations.
3. When a remediation step requires a write/modify/delete action, the agent MUST:
   - Clearly present the exact command(s) or API call(s) to the user
   - Explain what the operation will do and what resources it will affect
   - Explicitly ask the user for approval before executing
   - Only execute the operation after receiving explicit user confirmation
4. This applies to ALL write operations including but not limited to: `Create*`, `Delete*`, `Put*`, `Modify*`, `Update*`, `Enable*`, `Disable*`, `Attach*`, `Detach*`, `Revoke*`, `Authorize*`, `StartLogging`, `StopLogging`.
5. The agent MUST NOT batch multiple write operations together. Each write action requires separate user approval.
6. If the user asks the agent to "fix everything" or "remediate all", the agent MUST still present each write action individually for approval.

## Overview

This power turns Kiro into a security assessment companion for your AWS accounts. You talk to the agent in natural language, and it checks your security configuration against 73 controls from the official [AWS Security Maturity Model](https://maturitymodel.security.aws.dev) framework.

**What happens when you start an assessment:**

1. The agent validates your AWS credentials and asks scoping questions
2. It runs read-only checks against your AWS account using the AWS MCP Server, one phase at a time
3. Findings are saved incrementally to a markdown file (nothing is lost if the conversation is interrupted)
4. A CSV tracking file is updated with pass/fail status for each control
5. After each phase, you get a summary and decide whether to continue
6. When gaps are found, the agent creates a prioritized remediation plan
7. For each fix, the agent presents the exact operation and waits for your approval before executing

**Key capabilities:**

- Automated Assessment: Uses the AWS MCP Server to retrieve current security configurations (read-only, runs automatically)
- Skills-Driven Guidance: Leverages curated AWS Agent Toolkit skills for IAM, secrets management, CloudTrail, and operations
- Progress Tracking: Maintains a CSV file tracking your security maturity across all domains
- Remediation Planning: Analyzes gaps and creates prioritized remediation plans
- Implementation Guidance: Provides step-by-step instructions using AWS MCP Server tools (requires user approval before execution)
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

### 1. Install uv (Python package runner)

The AWS MCP Server proxy is distributed via [uvx](https://docs.astral.sh/uv/). Install it before using the power:

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
aws --version          # Requires version 2.32.0 or later
aws sts get-caller-identity
```

**Recommended authentication method:**

```bash
aws login
```

This automatically rotates your credentials every 15 minutes, keeping your session valid for up to 12 hours. For other credential methods (SSO, IAM access keys, cross-account roles), see [Sign in with the AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sign-in.html).

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

If using multiple AWS accounts or a non-default region:

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

## AWS MCP Server

This power uses the official [AWS MCP Server](https://docs.aws.amazon.com/agent-toolkit/latest/userguide/understanding-mcp-server-tools.html) — a managed remote server that provides full AWS API coverage, documentation search, skills retrieval, and sandboxed script execution through a single authenticated endpoint.

The AWS MCP Server is the successor to the individual AWS Labs MCP servers (aws-api, aws-knowledge, aws-documentation, core). It offers:

- **Full AWS API coverage** — Interact with any of the 300+ AWS services through a single authenticated endpoint
- **Sandboxed script execution** — Run Python scripts in an isolated environment for complex multi-step operations
- **Real-time documentation access** — Search and retrieve current AWS documentation, API references, and service capabilities
- **Skills retrieval** — Load curated AWS Agent Toolkit skills on demand for domain-specific guidance
- **Enterprise controls** — CloudWatch metrics, IAM condition keys for agent-specific policies, and CloudTrail audit logging

### Available Tools

| Tool | Purpose | Use In This Power |
|------|---------|-------------------|
| `aws___call_aws` | Execute authenticated AWS API calls | Primary tool for all security checks (read-only) and remediations (with user approval) |
| `aws___run_script` | Execute Python scripts in sandboxed environment | Multi-step checks, parallel API calls, cross-service assessments, retry logic |
| `aws___search_documentation` | Search AWS docs, API references, and skills | Find best practices, discover available skills, get implementation guidance |
| `aws___retrieve_skill` | Load domain-specific AWS skills | Load IAM, secrets, CloudTrail, and operations skills for guided workflows |
| `aws___suggest_aws_commands` | Get API syntax help | Discover correct API parameters for unfamiliar services |
| `aws___list_regions` | List all AWS regions | Determine which regions to assess |
| `aws___get_regional_availability` | Check service availability by region | Verify services are available before checking them |
| `aws___read_documentation` | Retrieve specific AWS doc pages | Get detailed implementation instructions |
| `aws___recommend` | Get content recommendations | Find related documentation and best practices |
| `aws___get_presigned_url` | Generate S3 pre-signed URLs | Upload/download files for remediation workflows |
| `aws___get_tasks` | Poll long-running task status | Monitor async operations started by call_aws or run_script |

### Relevant Agent Toolkit Skills

The AWS MCP Server provides access to curated skills from the [Agent Toolkit for AWS](https://github.com/aws/agent-toolkit-for-aws). The agent should retrieve these skills when working on related controls:

| Skill | When to Use |
|-------|-------------|
| `aws-iam` | When assessing or remediating IAM controls — contains verified edge cases for policy evaluation, trust policies, STS session limits, Organizations quirks, and MFA specifics |
| `creating-secrets-using-best-practices` | When remediating secrets management controls — provides production-grade procedures for KMS encryption, rotation, least-privilege policies, and CloudTrail auditing |
| `setting-up-cloudtrail-multi-region` | When remediating CloudTrail controls — provides step-by-step procedure for multi-region trail with S3 storage, CloudWatch Logs integration, and log analysis |
| `setting-up-cloudwatch-alarm-notifications` | When remediating billing alarms or monitoring controls — provides CloudWatch alarm setup with SNS notifications |
| `troubleshooting-application-failures` | When investigating security incidents or operational issues — provides systematic troubleshooting procedures |

**How to use skills:** Call `aws___retrieve_skill` with the skill name to load the full skill content before performing related assessment or remediation tasks. Skills provide workflows, best practices, and step-by-step procedures that the agent should follow exactly.

**How to discover skills:** Call `aws___search_documentation` with `topic: "skills"` to search for available skills related to a specific domain.

## Assessment Execution Rules

**CRITICAL: The assessment workflow MUST be executed one phase at a time, never all at once.**

The `assessment-workflow.md` file contains checks for all 73 controls across 5 phases. Attempting to run the entire assessment in a single pass will exceed context limits and produce unreliable results.

### Pre-Assessment Checklist (Mandatory)

**Before running ANY assessment operations, the agent MUST complete the `pre-assessment-checklist.md` workflow:**

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
   - Phase 0: Account Information
   - Phase 1: Quick Wins Assessment (17 controls)
   - Phase 2: Foundational Controls Assessment (19 controls)
   - Phase 3: Efficient Controls Assessment (20 controls)
   - Phase 4: Optimized Controls Assessment (19 controls)
4. After completing each phase, write the phase summary to the findings file, update the CSV, and ask the user if they want to proceed to the next phase
5. Never read the entire assessment-workflow.md at once — only read the section for the current phase being assessed

### Using the AWS MCP Server for Assessments

**Preferred approach for each phase:**

1. **Start with `aws___retrieve_skill`** — Load relevant skills (e.g., `aws-iam` for IAM controls, `setting-up-cloudtrail-multi-region` for CloudTrail checks)
2. **Use `aws___call_aws` for individual API checks** — Execute read-only AWS API calls to check each control
3. **Use `aws___run_script` for multi-step checks** — When a control requires multiple API calls, parallel execution, or complex logic (e.g., checking all regions, iterating over resources)
4. **Use `aws___search_documentation` for context** — When you need current best practices or implementation details for a specific control

**Example — checking GuardDuty across all regions:**
```
Tool: aws___run_script
Script: Check GuardDuty detector status in all active regions, return a summary of which regions have it enabled vs disabled
```

**Example — checking IAM credential report:**
```
Tool: aws___call_aws
Service: iam
Action: GetCredentialReport
```

### Phase Boundaries

When the user asks for a "full assessment" or "complete assessment":
- Explain that the assessment covers 73 controls across 5 phases
- Recommend starting with Phase 1 (Quick Wins) as it provides the highest security impact with lowest effort
- Execute each phase sequentially, pausing between phases for user review
- Track completed phases in the CSV so the assessment can be resumed later

### Per-Phase Workflow

For each phase:
1. Read only the relevant phase section from `assessment-workflow.md`
2. Load relevant skills using `aws___retrieve_skill` for the controls in that phase
3. Execute checks for each control using `aws___call_aws` or `aws___run_script`
4. After each control (or group of 2-3 controls), append results to the findings markdown file immediately
5. After all controls in the phase are checked, write a phase summary to the findings file
6. Update the CSV tracking file with findings
7. Present the phase summary to the user
8. Ask the user: "Phase X complete. Would you like to proceed to Phase Y?"


## Common Workflows

### Workflow 1: Initial Security Assessment

**Goal**: Assess your current AWS security posture across all domains

1. Ask the agent: "Assess my AWS security posture using the Security Maturity Model"
2. The agent validates credentials, asks scoping questions, and begins Phase 1
3. The agent uses `aws___call_aws` and `aws___run_script` to check each control, saving findings incrementally to `assessment-findings-{ACCOUNT_ID}.md`
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
2. The agent retrieves the relevant skill using `aws___retrieve_skill` and presents each step
3. For each write operation, the agent presents the exact API call and waits for your approval
4. Ask the agent: "Verify that GuardDuty is properly configured"
5. Ask the agent: "Update the CSV to mark GuardDuty as completed"

> Note: The agent will never execute write/modify/delete AWS operations without your explicit approval. Each action is presented individually for review.

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
- "Continue with Phase 2 Foundational controls"
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
- "Continue com a Fase 2 controles Foundational"
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
- "Continúa con la Fase 2 controles Foundational"
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

1. Verify uv/uvx is installed: `uvx --version`
2. Verify AWS credentials: `aws sts get-caller-identity`
3. Check MCP server status in Kiro Powers panel
4. Restart Kiro and reconnect MCP servers
5. If using a non-default region, set `AWS_REGION` environment variable

### Common Authentication Errors

| Error | Cause | Fix |
|-------|-------|-----|
| `ExpiredTokenException` | Session token expired | Run `aws login` again or refresh SSO with `aws sso login` |
| `UnrecognizedClientException` | Invalid credentials | Run `aws sts get-caller-identity` to verify, reconfigure if needed |
| `InvalidSignatureException` | Clock skew or wrong region | Check system clock, verify region configuration |
| No credentials found | AWS not configured | Run `aws login` or `aws configure sso` |

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
- Use Skills: When remediating, ask the agent to retrieve the relevant AWS skill for step-by-step guidance

## MCP Config

The `mcp.json` configures the official AWS MCP Server via the [MCP Proxy for AWS](https://github.com/aws/mcp-proxy-for-aws). The proxy translates MCP requests into AWS requests authenticated with SigV4.

**Configuration:**

```json
{
  "mcpServers": {
    "aws": {
      "command": "uvx",
      "args": [
        "mcp-proxy-for-aws@latest",
        "https://aws-mcp.us-east-1.api.aws/mcp",
        "--metadata", "AWS_REGION=${AWS_REGION:-us-east-1}"
      ]
    }
  }
}
```

**Region behavior:**
- The endpoint URL (`us-east-1`) determines which MCP server you connect to
- The `AWS_REGION` metadata parameter sets the default region for AWS operations
- These can be different — connect to `us-east-1` endpoint while operating on resources in another region
- You can override the region in queries (e.g., "list my EC2 instances in eu-west-1")

**Available endpoints:**
- US East (N. Virginia): `https://aws-mcp.us-east-1.api.aws/mcp`
- Europe (Frankfurt): `https://aws-mcp.eu-central-1.api.aws/mcp`

**To change your default region:**

```bash
export AWS_REGION="your-region"
```

After any changes, reconnect MCP servers in Kiro Powers panel.

---

**Framework**: [AWS Security Maturity Model](https://maturitymodel.security.aws.dev)

This power uses the official [AWS MCP Server](https://docs.aws.amazon.com/agent-toolkit/latest/userguide/understanding-mcp-server-tools.html) (AWS-managed service, governed by the [AWS Service Terms](https://aws.amazon.com/service-terms/)) via the [MCP Proxy for AWS](https://github.com/aws/mcp-proxy-for-aws) (Apache-2.0). Skills are sourced from the [Agent Toolkit for AWS](https://github.com/aws/agent-toolkit-for-aws) (Apache-2.0).

This power does not collect any client-side telemetry.
