# Findings Persistence Guide

## Purpose

Assessment phases generate large volumes of CLI output and findings. To prevent context overflow and data loss between conversation turns, the agent MUST incrementally persist findings to a markdown file as it works through each phase.

## Rules for the Agent

### 1. Create the Findings File at Assessment Start

At the beginning of any assessment (or when resuming), create or append to a findings file:

- **Single account**: `assessment-findings-{ACCOUNT_ID}.md`
- **Multi-account**: `assessment-findings-{ACCOUNT_ALIAS_OR_ID}.md` (one file per account)

If the file already exists, read the existing content first to understand what phases have already been completed, then append new findings. Never overwrite previous phase results.

### 2. Write Findings Incrementally — Not at the End

**CRITICAL: Do NOT accumulate all findings in context and write them at the end of a phase.** Instead:

- After checking each control (or small group of 2-3 related controls), immediately append the results to the findings file
- This ensures that if the conversation is interrupted or context is lost, all findings up to that point are preserved
- Use `fsAppend` to add to the file after each control check — do not rewrite the entire file

### 3. Findings File Structure

Use this structure for the findings markdown file:

```markdown
# Security Assessment Findings

- **Account ID**: 123456789012
- **Account Alias**: my-account
- **Assessment Date**: 2025-03-13
- **AWS Region**: us-east-1
- **Assessed By**: [agent/user]

---

## Phase 1: Account Information

- **Account ID**: 123456789012
- **Regions in use**: us-east-1, us-west-2, eu-west-1
- **Account alias**: my-account
- **Organizations**: Yes (management account)

---

## Phase 2: Quick Wins Assessment

### 1. Multi-Factor Authentication (MFA)
- **Status**: FAIL
- **Finding**: Root MFA enabled. 3 of 12 IAM users missing MFA: user-a, user-b, user-c
- **Priority**: Critical
- **Recommendation**: Enable MFA for all IAM users

### 2. GuardDuty
- **Status**: PASS
- **Finding**: Enabled in all 3 active regions (us-east-1, us-west-2, eu-west-1)
- **Priority**: Critical

### 3. CloudTrail
- **Status**: PARTIAL
- **Finding**: Multi-region trail exists but log file validation is disabled
- **Priority**: Critical
- **Recommendation**: Enable log file validation on trail "my-trail"

<!-- ... more controls ... -->

### Phase 2 Summary
- **Total controls**: 17
- **Passed**: 10
- **Failed**: 5
- **Partial**: 2
- **Not Applicable**: 0

---

## Phase 3: Foundational Controls Assessment
<!-- appended when Phase 3 is assessed -->
```

### 4. Control Result Format

For each control, write exactly these fields:

```markdown
### {N}. {Control Name}
- **Status**: PASS | FAIL | PARTIAL | NOT_APPLICABLE | ERROR
- **Finding**: One-line summary of what was found
- **Priority**: Critical | High | Medium | Low
- **Recommendation**: What to do (only if Status is FAIL or PARTIAL)
- **Details**: (optional) Multi-line details for complex findings
```

Status definitions:
- **PASS** — Control is fully implemented and working as expected
- **FAIL** — Control is not implemented or misconfigured
- **PARTIAL** — Control is partially implemented (some resources compliant, others not)
- **NOT_APPLICABLE** — Control does not apply to this account (e.g., no EKS clusters for EKS-related controls)
- **ERROR** — Could not assess the control (permission denied, API error, etc.)

### 5. Write a Phase Summary After Each Phase

After all controls in a phase are checked and written, append a phase summary block:

```markdown
### Phase {N} Summary
- **Total controls**: {count}
- **Passed**: {count}
- **Failed**: {count}
- **Partial**: {count}
- **Not Applicable**: {count}
- **Errors**: {count}
- **Critical findings**: {brief list of most important failures}
```

### 6. Sync with CSV After Each Phase

After writing the phase summary to the findings file, also update the CSV tracking file. The findings file is the detailed record; the CSV is the structured tracking record. Both should stay in sync.

### 7. Resuming an Assessment

When the user asks to continue an assessment:

1. Read the existing findings file to determine which phases are complete
2. Read the CSV to confirm status alignment
3. Tell the user which phases are done and which remain
4. Continue from the next incomplete phase, appending to the same findings file

### 8. Context Management

The findings file serves as persistent memory. The agent should:

- **Never hold more than one phase of raw CLI output in context at a time**
- **Write findings to disk before moving to the next control group**
- **When starting a new phase, briefly re-read the findings file header and previous phase summaries** (not full details) to maintain awareness of overall progress
- **If context feels large, write immediately and summarize** rather than accumulating more output
