# Security Journey Power

A Kiro Power for assessing and improving your AWS security posture using the [AWS Security Maturity Model](https://maturitymodel.security.aws.dev) framework.

## How It Works

This power turns Kiro into a security assessment companion for your AWS accounts. You talk to the agent in natural language, and it uses the official [AWS MCP Server](https://docs.aws.amazon.com/agent-toolkit/latest/userguide/understanding-mcp-server-tools.html) to check your security configuration against 73 controls organized into 4 maturity phases.

```
You: "Assess my AWS security posture"
Agent: validates credentials → asks scoping questions → runs checks → saves findings → updates CSV
```

The agent will:
1. Verify your AWS credentials before doing anything
2. Ask what you want to assess (which phases, which accounts, which regions)
3. Run read-only checks against your AWS account via the AWS MCP Server
4. Save findings incrementally to a markdown file (nothing is lost if the conversation is interrupted)
5. Update a CSV tracking file with pass/fail status for each control
6. Recommend remediations prioritized by impact and effort

The agent never modifies your AWS environment without asking first. Every write operation is presented for your explicit approval.

## What It Covers

73 security controls across 10 domains, organized into 4 phases:

| Phase | Controls | Description |
|-------|----------|-------------|
| Quick Wins | 17 | High impact, low effort — MFA, GuardDuty, CloudTrail, S3 Block Public Access, Security Hub, WAF, billing alarms |
| Foundational | 19 | Essential controls — SCPs, temporary credentials, IMDSv2, encryption at rest, backups, network segmentation |
| Efficient | 20 | Advanced — DevSecOps pipelines, security champions, least privilege reviews, threat modeling, Macie |
| Optimized | 19 | Mature — IAM data perimeters, red/blue teams, chaos engineering, temporary elevated access |

## Prerequisites

### 1. uv (Python package runner)

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
# or: pip install uv
uvx --version
```

### 2. AWS CLI configured (v2.32.0+)

```bash
aws --version
aws login                      # recommended — auto-rotates credentials
aws sts get-caller-identity    # must succeed before using the power
```

### 3. IAM permissions

The power needs read-only access. See `POWER.md` for the full least-privilege IAM policy. The simplest option for a first assessment is the AWS-managed `SecurityAudit` policy.

## Installation

1. Open Kiro Powers Panel (command palette → "Open Kiro Powers")
2. Click "Add Custom Power" → "Local Directory"
3. Enter the full path to this directory
4. The AWS MCP Server connects automatically

### Changing the AWS Region

The default region is `us-east-1`. If you need to operate in a different region, you have two options:

**Option 1 — Set the `AWS_REGION` environment variable** (recommended):

```bash
export AWS_REGION=us-west-2
```

The `mcp.json` reads `AWS_REGION` from your environment via `${AWS_REGION:-us-east-1}`, so the proxy will pick it up automatically.

**Option 2 — Edit `mcp.json` directly:**

```json
{
  "mcpServers": {
    "aws": {
      "command": "uvx",
      "args": [
        "mcp-proxy-for-aws@latest",
        "https://aws-mcp.us-east-1.api.aws/mcp",
        "--metadata", "AWS_REGION=us-west-2"
      ]
    }
  }
}
```

Note: The endpoint URL determines which AWS MCP Server you connect to (currently available in `us-east-1` and `eu-central-1`). The `AWS_REGION` metadata sets the default region for AWS operations the server performs on your behalf — these can be different. You can also override the region per query (e.g., "list my EC2 instances in eu-west-1").

Reconnect MCP servers in the Kiro Powers panel after any config change.

## Quick Start

Copy the CSV template to your workspace:

```bash
cp path/to/this/power/aws-security-maturity-tracking-template.csv ./aws-security-maturity-tracking.csv
```

Then start talking to the agent. Here are example prompts to get you going:

---

## Example Prompts

### 🇺🇸 English

**Assessment:**
- `Assess my AWS security posture using the Security Maturity Model`
- `Run a Quick Wins security assessment on my AWS account`
- `Check if GuardDuty, CloudTrail, and Security Hub are enabled in all regions`
- `Resume my security assessment from where I left off`
- `Assess the security of my AWS Organization across all member accounts`

**Remediation:**
- `Create a 30-day remediation plan based on my security gaps`
- `Help me enable GuardDuty in all regions`
- `What are the most critical security issues I should fix first?`
- `Guide me through implementing S3 Block Public Access`
- `Help me enforce IMDSv2 on all my EC2 instances`

**Tracking and reporting:**
- `Show my security maturity progress`
- `Compare my current security posture with last month's assessment`
- `What percentage of Quick Wins controls have I completed?`
- `Generate a security maturity report for my management team`
- `Which security domains have the most gaps?`

### 🇧🇷 Português

**Avaliação:**
- `Avalie a postura de segurança da minha conta AWS usando o Security Maturity Model`
- `Execute uma avaliação de segurança Quick Wins na minha conta AWS`
- `Verifique se o GuardDuty, CloudTrail e Security Hub estão habilitados em todas as regiões`
- `Continue minha avaliação de segurança de onde parei`
- `Avalie a segurança da minha AWS Organization em todas as contas membro`

**Remediação:**
- `Crie um plano de remediação de 30 dias baseado nas minhas lacunas de segurança`
- `Me ajude a habilitar o GuardDuty em todas as regiões`
- `Quais são os problemas de segurança mais críticos que devo corrigir primeiro?`
- `Me guie na implementação do S3 Block Public Access`
- `Me ajude a aplicar IMDSv2 em todas as minhas instâncias EC2`

**Acompanhamento e relatórios:**
- `Mostre meu progresso de maturidade de segurança`
- `Compare minha postura de segurança atual com a avaliação do mês passado`
- `Qual porcentagem dos controles Quick Wins eu já completei?`
- `Gere um relatório de maturidade de segurança para minha equipe de gestão`
- `Quais domínios de segurança têm mais lacunas?`

### 🇪🇸 Español

**Evaluación:**
- `Evalúa la postura de seguridad de mi cuenta AWS usando el Security Maturity Model`
- `Ejecuta una evaluación de seguridad Quick Wins en mi cuenta AWS`
- `Verifica si GuardDuty, CloudTrail y Security Hub están habilitados en todas las regiones`
- `Continúa mi evaluación de seguridad desde donde la dejé`
- `Evalúa la seguridad de mi AWS Organization en todas las cuentas miembro`

**Remediación:**
- `Crea un plan de remediación de 30 días basado en mis brechas de seguridad`
- `Ayúdame a habilitar GuardDuty en todas las regiones`
- `¿Cuáles son los problemas de seguridad más críticos que debo corregir primero?`
- `Guíame en la implementación de S3 Block Public Access`
- `Ayúdame a aplicar IMDSv2 en todas mis instancias EC2`

**Seguimiento y reportes:**
- `Muestra mi progreso de madurez de seguridad`
- `Compara mi postura de seguridad actual con la evaluación del mes pasado`
- `¿Qué porcentaje de los controles Quick Wins he completado?`
- `Genera un reporte de madurez de seguridad para mi equipo directivo`
- `¿Qué dominios de seguridad tienen más brechas?`

---

## How the Assessment Works (Step by Step)

1. **Pre-flight checks** — The agent validates your AWS credentials and asks scoping questions (what to assess, which accounts, which regions)
2. **Phase-by-phase execution** — Controls are checked one phase at a time, never all at once
3. **Incremental persistence** — Findings are saved to `assessment-findings-{ACCOUNT_ID}.md` after every few controls, so nothing is lost
4. **CSV tracking** — Each control is marked as PASS/FAIL/PARTIAL in the tracking CSV
5. **Phase summary** — After each phase, you get a summary and can decide whether to continue
6. **Remediation planning** — Once gaps are identified, the agent creates a prioritized plan
7. **Guided implementation** — Each fix is presented step-by-step with your approval required for every write operation

## Files

| File | Description |
|------|-------------|
| `POWER.md` | Full power documentation and agent instructions |
| `mcp.json` | MCP server configuration (AWS MCP Server via mcp-proxy-for-aws) |
| `aws-security-maturity-tracking-template.csv` | CSV template with all 73 controls |
| `steering/pre-assessment-checklist.md` | Pre-flight credential checks and scoping questions |
| `steering/assessment-workflow.md` | Step-by-step assessment checks |
| `steering/remediation-workflow.md` | Remediation implementation guide |
| `steering/implementation-guide.md` | Detailed implementation guide for all controls |
| `steering/csv-management.md` | CSV tracking file management |
| `steering/findings-persistence.md` | Incremental findings persistence protocol |
| `steering/multi-account-assessment.md` | Multi-account organization assessment guide |

## AWS MCP Server

This power uses the official [AWS MCP Server](https://docs.aws.amazon.com/agent-toolkit/latest/userguide/understanding-mcp-server-tools.html) — a single managed endpoint that replaces the previous individual AWS Labs MCP servers.

| Tool | Purpose |
|------|---------|
| `aws___call_aws` | Execute authenticated AWS API calls (300+ services) |
| `aws___run_script` | Run Python scripts in sandboxed environment |
| `aws___search_documentation` | Search AWS docs, API references, and skills |
| `aws___retrieve_skill` | Load domain-specific skills for guided workflows |
| `aws___suggest_aws_commands` | Get API syntax help |
| `aws___list_regions` | List all AWS regions |
| `aws___get_regional_availability` | Check service availability by region |
| `aws___read_documentation` | Retrieve specific AWS doc pages |
| `aws___get_presigned_url` | Generate S3 pre-signed URLs |
| `aws___get_tasks` | Poll long-running task status |

The server provides enterprise controls including CloudWatch metrics, IAM condition keys for agent-specific policies, and CloudTrail audit logging.

## Troubleshooting

- **MCP server won't connect**: Run `uvx --version` to verify installation, check the Powers panel, restart Kiro
- **AWS authentication errors**: Run `aws login` to refresh credentials, or `aws sts get-caller-identity` to verify
- **Permission denied on specific checks**: Your IAM policy may be missing permissions — see the full policy in `POWER.md`
- **CSV issues**: Verify the file exists and has read/write permissions
- **Assessment interrupted**: Just ask the agent to resume — it reads the existing findings file and picks up where it left off

## License

This power is licensed under the Apache License 2.0 — see [LICENSE](LICENSE).

Components used by this power:

- **[MCP Proxy for AWS](https://github.com/aws/mcp-proxy-for-aws)** (`mcp-proxy-for-aws`) — Apache License 2.0. Client-side proxy that handles SigV4 authentication between Kiro and the AWS MCP Server.
- **[AWS MCP Server](https://docs.aws.amazon.com/agent-toolkit/latest/userguide/mcp-server.html)** — AWS-managed service. Use is governed by the [AWS Service Terms](https://aws.amazon.com/service-terms/) and standard AWS pricing applies for the underlying API calls executed on your behalf.
- **[Agent Toolkit for AWS](https://github.com/aws/agent-toolkit-for-aws)** — Apache License 2.0. Source of the skills (`aws-iam`, `creating-secrets-using-best-practices`, `setting-up-cloudtrail-multi-region`, etc.) loaded on demand via `aws___retrieve_skill`.

Based on the [AWS Security Maturity Model](https://maturitymodel.security.aws.dev). Does not collect client-side telemetry.
