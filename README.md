# Security Journey Power

A Kiro Power for assessing and improving your AWS security posture using the [AWS Security Maturity Model](https://maturitymodel.security.aws.dev) framework.

## What It Does

- Runs automated security assessments against 73 controls across 10 security domains
- Tracks your security maturity progress in a CSV file
- Creates prioritized remediation plans based on risk and effort
- Provides step-by-step implementation guidance with AWS CLI commands
- Organizes controls into 4 phases: Quick Wins, Foundational, Efficient, Optimized

## Prerequisites

### 1. uvx (Python package runner)

All MCP servers are distributed via [uvx](https://docs.astral.sh/uv/):

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
# or: pip install uv
```

### 2. AWS CLI

```bash
aws --version
aws configure list
```

### 3. AWS IAM Permissions (Least Privilege)

For assessment (read-only), create a policy with the permissions listed in `POWER.md` under "Prerequisites > AWS IAM Permissions". The policy includes read-only access to IAM, GuardDuty, CloudTrail, S3, SecurityHub, EC2, Config, Organizations, WAF, RDS, KMS, CloudWatch, Lambda, Backup, Macie, Inspector, and Detective.

For remediation, additional write permissions are documented per-control in the steering files.

## Installation

1. Open Kiro Powers Panel (command palette: "Open Kiro Powers")
2. Click "Add Custom Power" > "Local Directory"
3. Enter the full path to this directory
4. MCP servers will connect automatically using your default AWS credentials

### Optional: Custom AWS Profile/Region

Edit `mcp.json` and add `AWS_PROFILE` / change `AWS_REGION` in the `aws-api` server's `env` section.

## Quick Start

1. Copy the CSV template to your workspace:
   ```bash
   cp path/to/this/power/aws-security-maturity-tracking-template.csv ./aws-security-maturity-tracking.csv
   ```

2. Start an assessment:
   ```
   "Assess my AWS security posture using the Security Maturity Model"
   ```

3. Create a remediation plan:
   ```
   "Create a 30-day remediation plan based on my security gaps"
   ```

4. Implement a control:
   ```
   "Help me enable GuardDuty in all regions"
   ```

5. Track progress:
   ```
   "Show my security maturity progress"
   ```

## Files

| File | Description |
|------|-------------|
| `POWER.md` | Main power documentation |
| `mcp.json` | MCP server configuration |
| `aws-security-maturity-tracking-template.csv` | CSV template with all 73 controls |
| `steering/assessment-workflow.md` | Step-by-step assessment process |
| `steering/remediation-workflow.md` | Remediation implementation guide |
| `steering/implementation-guide.md` | Detailed implementation guide |
| `steering/csv-management.md` | CSV tracking file management |

## MCP Servers

| Server | Purpose | License |
|--------|---------|---------|
| [awslabs.core-mcp-server](https://github.com/awslabs/mcp) | Core AWS operations | Apache-2.0 |
| [awslabs.aws-api-mcp-server](https://github.com/awslabs/mcp) | AWS API access for security configs | Apache-2.0 |
| [AWS Knowledge MCP](https://knowledge.mcp.aws.dev) | AWS security best practices | AWS-managed |
| [awslabs.aws-documentation-mcp-server](https://github.com/awslabs/mcp) | Official AWS documentation | Apache-2.0 |
| [awslabs.document-loader-mcp-server](https://github.com/awslabs/mcp) | CSV and markdown processing | Apache-2.0 |

## Troubleshooting

- **MCP servers won't connect**: Verify `uvx --version`, check Powers panel, restart Kiro
- **AWS CLI errors**: Run `aws sts get-caller-identity` to verify credentials
- **CSV issues**: Verify file exists and has read/write permissions

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

This power is based on the [AWS Security Maturity Model](https://maturitymodel.security.aws.dev) framework.

This power integrates with MCP servers from [awslabs/mcp](https://github.com/awslabs/mcp), licensed under Apache-2.0.

This power does not collect any client-side telemetry.
