# Security Journey Power

A Kiro Power for assessing and improving your AWS security posture using the [AWS Security Maturity Model](https://maturitymodel.security.aws.dev) framework.

## How It Works

This power turns Kiro into a security assessment companion for your AWS accounts. You talk to the agent in natural language, and it runs read-only AWS CLI commands to check your security configuration against 73 controls organized into 4 maturity phases.

```
You: "Assess my AWS security posture"
Agent: validates credentials → asks scoping questions → runs checks → saves findings → updates CSV
```

The agent will:
1. Verify your AWS credentials before doing anything
2. Ask what you want to assess (which phases, which accounts, which regions)
3. Run read-only checks against your AWS account
4. Save findings incrementally to a markdown file (nothing is lost if the conversation is interrupted)
5. Update a CSV tracking file with pass/fail status for each control
6. Recommend remediations prioritized by impact and effort

The agent never modifies your AWS environment without asking first. Every write command is presented for your explicit approval.

## What It Covers

73 security controls across 10 domains, organized into 4 phases:

| Phase | Controls | Description |
|-------|----------|-------------|
| Quick Wins | 17 | High impact, low effort — MFA, GuardDuty, CloudTrail, S3 Block Public Access, Security Hub, WAF, billing alarms |
| Foundational | 19 | Essential controls — SCPs, temporary credentials, IMDSv2, encryption at rest, backups, network segmentation |
| Efficient | 20 | Advanced — DevSecOps pipelines, security champions, least privilege reviews, threat modeling, Macie |
| Optimized | 19 | Mature — IAM data perimeters, red/blue teams, chaos engineering, temporary elevated access |

## Prerequisites

### 1. uvx (Python package runner)

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
# or: pip install uv
uvx --version
```

### 2. AWS CLI configured

```bash
aws --version
aws sts get-caller-identity   # must succeed before using the power
```

### 3. IAM permissions

The power needs read-only access. See `POWER.md` for the full least-privilege IAM policy. The simplest option for a first assessment is the AWS-managed `SecurityAudit` policy.

## Installation

1. Open Kiro Powers Panel (command palette → "Open Kiro Powers")
2. Click "Add Custom Power" → "Local Directory"
3. Enter the full path to this directory
4. MCP servers connect automatically

### Optional: Custom AWS Profile/Region

Edit `mcp.json` and add `AWS_PROFILE` / change `AWS_REGION` in the `aws-api` server.

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
7. **Guided implementation** — Each fix is presented step-by-step with your approval required for every write command

## Files

| File | Description |
|------|-------------|
| `POWER.md` | Full power documentation and agent instructions |
| `mcp.json` | MCP server configuration (pre-configured) |
| `aws-security-maturity-tracking-template.csv` | CSV template with all 73 controls |
| `steering/pre-assessment-checklist.md` | Pre-flight credential checks and scoping questions |
| `steering/assessment-workflow.md` | Step-by-step assessment CLI checks |
| `steering/remediation-workflow.md` | Remediation implementation guide |
| `steering/implementation-guide.md` | Detailed implementation guide for all controls |
| `steering/csv-management.md` | CSV tracking file management |
| `steering/findings-persistence.md` | Incremental findings persistence protocol |
| `steering/multi-account-assessment.md` | Multi-account organization assessment guide |

## MCP Servers

| Server | Purpose | License |
|--------|---------|---------|
| [awslabs.core-mcp-server](https://github.com/awslabs/mcp) | Core AWS operations | Apache-2.0 |
| [awslabs.aws-api-mcp-server](https://github.com/awslabs/mcp) | AWS API access (read-only by default) | Apache-2.0 |
| [AWS Knowledge MCP](https://knowledge-mcp.global.api.aws) | AWS best practices and documentation | AWS-managed |
| [awslabs.aws-documentation-mcp-server](https://github.com/awslabs/mcp) | Official AWS documentation | Apache-2.0 |

## Troubleshooting

- **MCP servers won't connect**: Run `uvx --version` to verify installation, check the Powers panel, restart Kiro
- **AWS CLI errors**: Run `aws sts get-caller-identity` — if this fails, the power can't work
- **Permission denied on specific checks**: Your IAM policy may be missing permissions — see the full policy in `POWER.md`
- **CSV issues**: Verify the file exists and has read/write permissions
- **Assessment interrupted**: Just ask the agent to resume — it reads the existing findings file and picks up where it left off

## License

Apache License 2.0 — see [LICENSE](LICENSE).

Based on the [AWS Security Maturity Model](https://maturitymodel.security.aws.dev). Integrates with MCP servers from [awslabs/mcp](https://github.com/awslabs/mcp) (Apache-2.0) and the [AWS Knowledge MCP Server](https://knowledge-mcp.global.api.aws). Does not collect client-side telemetry.
