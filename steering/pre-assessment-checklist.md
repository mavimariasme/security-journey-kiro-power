# Pre-Assessment Checklist

## Purpose

Before running any AWS CLI commands or MCP tool calls, the agent MUST complete this pre-assessment checklist. This ensures credentials work, scope is clear, and the user understands what will happen.

## Rules

1. **Do NOT skip this checklist.** Every assessment session must start here, even if the user says "just run it".
2. **Do NOT run AWS CLI commands until Step 1 (credential validation) passes.**
3. **Ask clarifying questions in a single grouped message** — do not ask one question at a time across multiple turns. Present all questions together and let the user answer.
4. **If resuming a previous assessment**, still validate credentials (Step 1) but skip the scoping questions if answers are already in the existing findings file.

## Step 1: Validate AWS Credentials (Automated)

Run these checks silently before asking the user anything. If they fail, stop and help the user fix credentials before proceeding.

```bash
# Check 1: Can we call AWS at all?
aws sts get-caller-identity

# Check 2: What account are we in?
aws sts get-caller-identity --query 'Account' --output text

# Check 3: What region is configured?
aws configure get region || echo "No default region set"

# Check 4: Is this an Organizations management account?
aws organizations describe-organization --query 'Organization.MasterAccountId' --output text 2>/dev/null || echo "NOT_ORG_OR_NO_ACCESS"
```

**If credential check fails:**
- Tell the user: "I couldn't authenticate with AWS. Let's fix that first."
- Ask if they have AWS CLI installed (`aws --version`)
- Ask if they have a profile configured (`aws configure list`)
- Suggest: `export AWS_PROFILE=your-profile-name` if they have multiple profiles
- Do NOT proceed until `sts get-caller-identity` succeeds

**If credential check succeeds:**
- Note the account ID, IAM principal, and region
- Note whether this is an Organizations management account
- Proceed to Step 2

## Step 2: Ask Scoping Questions

Present these questions to the user in a single message. Adapt based on what you learned in Step 1.

### Core Questions (Always Ask)

**1. Assessment scope:**
> "What would you like to assess?
> - **Full assessment** (all 73 controls across 4 phases — recommended for first-time)
> - **Specific phase** (Quick Wins, Foundational, Efficient, or Optimized)
> - **Specific domain** (e.g., Identity and Access Management, Threat Detection)
> - **Resume previous assessment** (I'll check for existing findings)"

**2. Account scope** (only if Organizations detected in Step 1):
> "I see this account is part of an AWS Organization. Would you like to:
> - **Assess this account only**
> - **Assess multiple accounts** (I'll help you set up cross-account access)
> - **Assess the entire organization** (org-level controls + member accounts)"

**3. Region scope:**
> "Which AWS regions should I check?
> - **All active regions** (thorough but slower)
> - **Primary region only** ({detected_region})
> - **Specific regions** (list them)"

### Situational Questions (Ask When Relevant)

**4. If existing findings file detected:**
> "I found an existing assessment from {date} in `assessment-findings-{account}.md`. Would you like to:
> - **Resume** from where it left off (Phase {N})
> - **Start fresh** (I'll archive the old file first)"

**5. If existing CSV detected:**
> "I found an existing tracking CSV with {N} controls already marked. I'll use this as the baseline and update it with new findings."

**6. If multi-account selected:**
> "Which accounts should I assess? I can:
> - List all accounts in your organization so you can pick
> - Assess all accounts
> - Assess specific account IDs you provide
>
> How will I access other accounts?
> - **Cross-account role** (e.g., OrganizationAccountAccessRole)
> - **Separate AWS profiles** (you'll tell me which profile for each account)"

## Step 3: Confirm and Summarize

Before starting, present a summary of what will happen and get explicit confirmation:

> **Assessment Plan:**
> - **Account**: {account_id} ({account_alias if available})
> - **Scope**: {Full / Phase X / Domain Y}
> - **Regions**: {All active / us-east-1 only / specific list}
> - **Mode**: Read-only (I will not modify any AWS resources)
> - **Findings file**: `assessment-findings-{account_id}.md`
> - **CSV tracking**: `aws-security-maturity-tracking.csv`
>
> I'll save findings incrementally as I go, so nothing is lost if we need to pause.
>
> **Ready to start?**

Wait for user confirmation before running any assessment commands.

## Step 4: Initialize Files

After user confirms:

1. **Create or verify the findings file** — If new assessment, create `assessment-findings-{ACCOUNT_ID}.md` with the header (see `findings-persistence.md` for format). If resuming, read the existing file to determine progress.

2. **Create or verify the CSV** — If no CSV exists, copy the template:
   ```
   cp aws-security-maturity-tracking-template.csv aws-security-maturity-tracking.csv
   ```
   If CSV exists, read it to understand current state.

3. **Log the assessment start** in the findings file:
   ```markdown
   # Security Assessment Findings

   - **Account ID**: {account_id}
   - **Account Alias**: {alias or "not set"}
   - **IAM Principal**: {arn from sts get-caller-identity}
   - **Assessment Date**: {today}
   - **Regions in Scope**: {region list}
   - **Assessment Scope**: {full / phase / domain}
   - **Organization**: {Yes (management) / Yes (member) / No}

   ---
   ```

4. **Begin the first phase** per the assessment workflow.

## Edge Cases

### User says "just assess everything, don't ask questions"
- Still run Step 1 (credential validation) — this is non-negotiable
- Default to: full assessment, all active regions, single account, new findings file
- Briefly confirm: "I'll run a full assessment of account {ID} across all active regions in read-only mode. Findings will be saved to `assessment-findings-{ID}.md`. Starting with Phase 1."

### User provides an account ID that doesn't match current credentials
- Warn the user: "Your current credentials are for account {X} but you asked to assess account {Y}. Should I switch profiles or assume a role into account {Y}?"

### User wants to assess an account they don't have credentials for
- Guide them through setting up cross-account access (see `multi-account-assessment.md`)
- Do not attempt to run commands against accounts where authentication will fail

### Credentials expire mid-assessment
- If a CLI command fails with an auth error, tell the user immediately
- Save any unsaved findings to the file first
- Help them refresh credentials
- Resume from where the assessment stopped
