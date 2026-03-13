# AWS Security Maturity Model - Implementation Guide

## ⚠️ User Approval Required

This guide contains AWS CLI commands and procedures that modify your AWS environment. The agent MUST present each write/modify/delete command to the user and obtain explicit approval before execution. No AWS resource changes should be made automatically.

## Overview

The AWS Security Maturity Model is a prescriptive framework that helps organizations prioritize security improvements based on ease of implementation, cost efficiency, and security impact. Unlike traditional maturity models, it focuses on practical, field-tested approaches to strengthen your AWS security posture.

**Source**: [AWS Security Maturity Model](https://maturitymodel.security.aws.dev)

## Four Maturity Phases

The model organizes security controls into four progressive phases:

### Phase 1: Quick Wins
Simple configurations that can be implemented in 1-2 weeks with high security value. These are the "low-hanging fruits" that provide immediate security improvements.

### Phase 2: Foundational
Essential controls that require more effort but are critical for a solid security foundation. These may take several weeks to implement.

### Phase 3: Efficient
Advanced controls that optimize security operations and automate security processes. These require mature processes and teams.

### Phase 4: Optimized
Sophisticated security capabilities for organizations with advanced security maturity, including red teams, blue teams, and chaos engineering.

---

## Security Domains

The model covers 10 key security domains:

1. **Security Governance**
2. **Security Assurance**
3. **Identity and Access Management (IAM)**
4. **Threat Detection**
5. **Vulnerability Management**
6. **Infrastructure Protection**
7. **Data Protection**
8. **Application Security**
9. **Incident Response**
10. **Resiliency**

---

## Phase 1: Quick Wins - Implementation Guide

### 1. Multi-Factor Authentication (MFA)

**Implementation Steps:**
- Enable MFA for root account (highest priority)
- Enable MFA for all IAM users, especially privileged users
- Configure MFA in AWS IAM Identity Center for federated access
- Enable MFA in Amazon Cognito for application users

**Tools:**
- Free virtual tokens: Authy, Duo Mobile, Google Authenticator, Microsoft Authenticator
- Hardware tokens: Yubikey, Gemalto (purchase required)

**Best Practices:**
- Implement MFA for everyone, not just admins
- Use context-aware/adaptive authentication to balance security and UX
- Consider requiring MFA on every authentication for high-security environments

**Cost:** Free (no additional AWS charges)

---

### 2. Detect Common Threats with Amazon GuardDuty

**Implementation Steps:**
1. Enable GuardDuty in your AWS account (one-click activation)
2. For multi-account: Enable at organization level
3. Configure SNS alerts for critical findings
4. Review findings regularly and investigate anomalies

**What GuardDuty Detects:**
- Command & Control activity
- Reconnaissance attempts
- Privilege escalation
- Anomalous behavior
- Cryptocurrency mining
- Compromised credentials

**Why GuardDuty First:**
- Simpler than deploying SIEM, UEBA, or NBAD solutions
- Lower cost than generating VPC Flow Logs everywhere
- Immediate threat detection without infrastructure setup
- 30-day free trial

**Resources:**
- [GuardDuty Mindmap](https://www.xmind.net/m/K3fmSB)
- [Pricing](https://aws.amazon.com/guardduty/pricing)

---

### 3. Audit API Calls with AWS CloudTrail

**Implementation Steps:**
1. Review free 90-day event history in CloudTrail console
2. Create a Trail to retain logs beyond 90 days
3. Configure Trail to send logs to S3 bucket
4. Centralize logs in a dedicated Logging account
5. Protect logs with IAM policies
6. Train security team on CloudTrail log investigation

**For Multi-Account Organizations:**
- Use AWS Control Tower to automatically create Logging account
- Logs are centralized and protected automatically

**Best Practices:**
- Retain logs according to your security policy requirements
- Encrypt logs with AWS KMS for enhanced security
- Implement log file validation
- Set up S3 bucket policies to prevent deletion

**Resources:**
- [CloudTrail Mindmap](https://www.xmind.net/m/sY4HG3)
- Free: 90-day event history viewing
- Paid: Trail storage in S3

---

### 4. Block Public Access for S3 Buckets

**Implementation Steps:**
1. Enable S3 Block Public Access (BPA) at account level for all accounts
2. Verify BPA is enabled at bucket level for sensitive buckets
3. Use Service Control Policies (SCPs) to prevent BPA removal
4. Block public access for AMIs
5. Block public access for EBS Snapshots

**Monitoring:**
- Use AWS Security Hub control S3.1 to check account-level BPA
- Use Security Hub control S3.8 to validate bucket-level BPA

**Visual Indicators:**
- Yellow "Public" label appears on buckets with public access

**When Public Access is Needed:**
- Only remove BPA for specific use cases (e.g., static websites)
- Document the business justification
- Implement additional controls (CloudFront, WAF)

**Cost:** Free

---

### 5. Assign Security Contacts

**Implementation Steps:**
1. Navigate to AWS Account settings
2. Add security contact email addresses
3. Ensure contacts are monitored 24/7
4. Configure alternate contacts for billing and operations

**Purpose:**
- Receive critical security notifications from AWS
- Get alerts about potential security issues
- Ensure rapid response to AWS security communications

---

### 6. Select Regions and Block Unused Ones

**Implementation Steps:**
1. Identify regions where you operate
2. Use Service Control Policies to deny access to unused regions
3. Document approved regions in your security policy
4. Review region usage quarterly

**Benefits:**
- Reduce attack surface
- Simplify compliance (data residency)
- Prevent shadow IT in unapproved regions
- Lower costs

---

### 7. Cleanup Risky Open Ports

**Implementation Steps:**
1. Audit Security Groups for overly permissive rules
2. Identify rules with 0.0.0.0/0 (any IP) access
3. Remove or restrict access to risky ports:
   - RDP (3389)
   - SSH (22)
   - Database ports (3306, 5432, 1433, etc.)
   - Management ports
4. Implement least privilege network access
5. Use AWS Systems Manager Session Manager instead of direct SSH/RDP

**Tools:**
- AWS Security Hub
- AWS Config rules
- Third-party CSPM tools

---

### 8. WAF with Managed Rules

**Implementation Steps:**
1. Deploy AWS WAF on CloudFront, ALB, or API Gateway
2. Enable AWS Managed Rules for common threats:
   - Core Rule Set (CRS)
   - Known Bad Inputs
   - SQL Injection
   - Linux/Windows OS rules
3. Configure logging to S3 or CloudWatch
4. Set up alerts for blocked requests
5. Review and tune rules based on false positives

**Managed Rule Groups:**
- AWS Managed Rules (free)
- AWS Marketplace rules (paid)
- Custom rules (Phase 3)

---

### 9. Billing Alarms

**Implementation Steps:**
1. Enable billing alerts in account preferences
2. Create CloudWatch billing alarm
3. Set threshold based on expected usage
4. Configure SNS notification
5. Review billing regularly for anomalies

**Purpose:**
- Detect compromised resources (crypto mining)
- Prevent unexpected costs
- Early warning of security incidents

---

### 10. Act on Critical Security Findings

**Implementation Steps:**
1. Aggregate findings in AWS Security Hub
2. Set up automated notifications for CRITICAL and HIGH findings
3. Define SLAs for remediation:
   - Critical: 24 hours
   - High: 7 days
   - Medium: 30 days
4. Track remediation progress
5. Implement automated remediation where possible

---

## Phase 2: Foundational - Implementation Guide

### 1. GuardRails: Service Control Policies (SCPs) and Resource Control Policies (RCPs)

**Service Control Policies (SCPs):**

**Implementation Steps:**
1. Identify security invariants (things you never want to allow)
2. Create SCPs to enforce these invariants
3. Apply SCPs at organization, OU, or account level
4. Test SCPs in non-production first
5. Document all SCPs and their purpose

**Common SCP Use Cases:**
- Prevent disabling of security services (GuardDuty, CloudTrail)
- Enforce encryption requirements
- Restrict regions
- Prevent root user actions
- Require MFA for sensitive operations
- Block public S3 buckets

**SCP Characteristics:**
- Apply to all users including root (except management account)
- Do not grant permissions, only limit maximum permissions
- Work with IAM policies (intersection of both)

**Resource Control Policies (RCPs):**

**Implementation Steps:**
1. Identify resources that need centralized protection
2. Create RCPs to control resource access
3. Apply RCPs across organization
4. Monitor RCP effectiveness

**RCP Use Cases:**
- Prevent deletion of critical resources
- Enforce encryption on resources
- Control cross-account access
- Protect backup vaults

**Cost:** Free

---

### 2. Use Temporary Credentials

**Implementation Steps:**
1. Eliminate long-term IAM access keys
2. Use IAM roles for EC2 instances
3. Use IAM roles for Lambda functions
4. Use IAM roles for ECS tasks
5. Implement AWS IAM Identity Center for human access
6. Use STS AssumeRole for cross-account access
7. Set maximum session duration appropriately

**Benefits:**
- Automatic credential rotation
- Reduced risk of credential exposure
- Better audit trail
- Simplified credential management

---

### 3. Instance Metadata Service (IMDS) v2

**Implementation Steps:**
1. Audit instances using IMDSv1
2. Update applications to use IMDSv2
3. Configure instances to require IMDSv2
4. Use SCPs to enforce IMDSv2 for new instances
5. Set hop limit to 1 for containers

**Why IMDSv2:**
- Protects against SSRF attacks
- Session-oriented (token-based)
- More secure than IMDSv1

**Migration:**
```bash
# Configure instance to require IMDSv2
aws ec2 modify-instance-metadata-options \
    --instance-id i-1234567890abcdef0 \
    --http-tokens required \
    --http-put-response-hop-limit 1
```

---

### 4. Involve Security Teams in Development

**Implementation Steps:**
1. Include security in project kickoffs
2. Conduct security design reviews early
3. Establish security champions in dev teams
4. Create secure development guidelines
5. Make security team accessible to developers
6. Implement shift-left security practices

**Assessment Questions:**
- How is your security team working with dev teams? Proactive or reactive?
- Are architectural decisions made with security input?
- Is security providing early guidance on best practices?
- How close to launch is security involved?
- Is security easily reachable for developers?

**Risk Mitigation:**
- Prevents last-minute security issues
- Reduces time to remediate vulnerabilities
- Builds constructive security culture
- Reduces production vulnerabilities

---

### 5. Manage Infrastructure Vulnerabilities

**Implementation Steps:**
1. Enable Amazon Inspector for EC2, ECR, Lambda
2. Configure automated scanning
3. Integrate findings into Security Hub
4. Define remediation SLAs by severity
5. Track vulnerability trends
6. Implement patch management process

**What Inspector Scans:**
- EC2 instances (OS vulnerabilities)
- Container images in ECR
- Lambda functions (code and dependencies)
- Network reachability issues

---

### 6. Manage Application Vulnerabilities

**Implementation Steps:**
1. Implement SAST (Static Application Security Testing)
2. Implement DAST (Dynamic Application Security Testing)
3. Scan open-source dependencies (SCA)
4. Integrate security testing in CI/CD pipeline
5. Block deployments with critical vulnerabilities
6. Track and remediate findings

**Tools:**
- SAST: SonarQube, Checkmarx, Veracode
- DAST: OWASP ZAP, Burp Suite, Acunetix
- SCA: Snyk, WhiteSource, Black Duck

---

### 7. No Secrets in Code

**Implementation Steps:**
1. Scan repositories for exposed secrets
2. Remove hardcoded credentials
3. Use AWS Secrets Manager or Parameter Store
4. Implement pre-commit hooks to prevent secret commits
5. Rotate any exposed credentials immediately
6. Train developers on secure secret management

**Tools:**
- git-secrets
- TruffleHog
- GitGuardian
- AWS CodeGuru Reviewer

---

### 8. Data Encryption at Rest

**Implementation Steps:**
1. Enable encryption for all data stores:
   - S3 (SSE-S3, SSE-KMS, or SSE-C)
   - EBS volumes
   - RDS databases
   - DynamoDB tables
   - EFS file systems
2. Use AWS KMS for key management
3. Implement key rotation
4. Use separate keys for different data classifications
5. Enforce encryption with SCPs

**Default Encryption:**
- Enable default encryption at account/service level
- Use SCPs to prevent unencrypted resource creation

---

### 9. Backups

**Implementation Steps:**
1. Identify critical data and systems
2. Define RPO (Recovery Point Objective) and RTO (Recovery Time Objective)
3. Implement AWS Backup for centralized backup management
4. Configure backup plans with appropriate frequency
5. Test restore procedures regularly
6. Store backups in separate account/region
7. Implement backup vault lock for immutability

**What to Backup:**
- RDS databases
- DynamoDB tables
- EBS volumes
- EFS file systems
- S3 buckets (versioning + replication)
- EC2 instances (AMIs)

---

### 10. Network Segmentation (VPCs)

**Implementation Steps:**
1. Design VPC architecture with security zones
2. Separate workloads by environment (dev, test, prod)
3. Use private subnets for application and data tiers
4. Use public subnets only for load balancers
5. Implement security groups as stateful firewalls
6. Use NACLs for additional subnet-level protection
7. Enable VPC Flow Logs for traffic analysis

**Best Practices:**
- One VPC per environment minimum
- Use Transit Gateway for multi-VPC connectivity
- Implement hub-and-spoke architecture
- Centralize egress through inspection VPC

---

## Phase 3: Efficient - Implementation Guide

### 1. DevSecOps: Security in the Pipeline

**Implementation Steps:**

**OS Hardening in Pipeline:**
1. Apply CIS benchmarks to base images
2. Use Amazon Inspector to verify CIS compliance
3. Automate hardening in image build process
4. Remove unnecessary packages and services
5. Configure secure defaults

**Application Security Testing:**
1. Integrate SAST in build stage
2. Integrate DAST in test stage
3. Scan dependencies for vulnerabilities
4. Block pipeline on critical findings
5. Generate security reports

**Security Component Deployment:**
1. Deploy WAF rules as code
2. Deploy security groups as code
3. Use AWS CodePipeline for orchestration
4. Implement infrastructure as code (CloudFormation, Terraform)
5. Version control all security configurations

**Example Pipeline:**
```
Source → Build → SAST → Test → DAST → Security Review → Deploy → Monitor
```

**Tools:**
- AWS CodePipeline
- AWS CodeBuild
- Third-party security tools integration

---

### 2. Security Champions Program

**Implementation Steps:**
1. Identify security champions in each dev team
2. Provide security training and certification
3. Define champion responsibilities
4. Create communication channels
5. Regular security champion meetings
6. Recognize and reward champions

**Champion Responsibilities:**
- Promote security awareness
- Review code for security issues
- Liaison with security team
- Share security knowledge
- Participate in threat modeling

---

### 3. Least Privilege Review

**Implementation Steps:**
1. Audit existing IAM policies
2. Use IAM Access Analyzer
3. Review last accessed information
4. Remove unused permissions
5. Implement permission boundaries
6. Use IAM Access Advisor
7. Regular access reviews (quarterly)

**Tools:**
- IAM Access Analyzer
- IAM Access Advisor
- AWS CloudTrail for usage analysis
- Third-party tools (CloudCheckr, Prisma Cloud)

---

### 4. Image Generation Pipeline

**Implementation Steps:**
1. Create golden image pipeline
2. Automate image builds
3. Scan images for vulnerabilities
4. Apply security hardening
5. Test images automatically
6. Version and catalog images
7. Deprecate old images

**Pipeline Stages:**
- Base image selection
- Package installation
- Security hardening
- Vulnerability scanning
- Compliance validation
- Image publishing
- Automated testing

---

### 5. Anti-Malware / EDR / Runtime Protection

**Implementation Steps:**
1. Deploy endpoint protection on EC2 instances
2. Enable GuardDuty Runtime Monitoring
3. Implement container runtime security
4. Configure automated response
5. Integrate with SIEM
6. Regular signature updates

**Solutions:**
- AWS GuardDuty Runtime Monitoring
- Third-party EDR (CrowdStrike, SentinelOne)
- Container security (Aqua, Sysdig)

---

### 6. Discover Sensitive Data

**Implementation Steps:**
1. Enable Amazon Macie
2. Configure automated discovery jobs
3. Classify data by sensitivity
4. Review findings regularly
5. Implement data protection controls
6. Track sensitive data locations

**What Macie Discovers:**
- PII (Personally Identifiable Information)
- Financial data
- Credentials
- Custom data patterns

---

### 7. Perform Threat Modeling

**Implementation Steps:**
1. Identify assets and data flows
2. Document architecture diagrams
3. Identify threats using STRIDE or similar
4. Assess risk and impact
5. Define mitigations
6. Document threat model
7. Review and update regularly

**When to Threat Model:**
- New application design
- Major architecture changes
- Before production deployment
- Annual reviews

---

## Phase 4: Optimized - Implementation Guide

### 1. IAM Data Perimeters

**Implementation Steps:**
1. Define your data perimeter
2. Implement identity perimeter controls
3. Implement resource perimeter controls
4. Implement network perimeter controls
5. Monitor perimeter violations
6. Automate enforcement

**Perimeter Types:**
- Identity: Only your identities access your resources
- Resource: Your identities only access your resources
- Network: Access only from expected networks

---

### 2. Temporary Elevated Access

**Implementation Steps:**
1. Implement just-in-time access system
2. Define approval workflows
3. Set time-limited permissions
4. Audit all elevated access
5. Automate access revocation
6. Monitor privileged actions

**Benefits:**
- Reduces standing privileges
- Better audit trail
- Limits blast radius
- Compliance friendly

---

### 3. Forming a Red Team

**Implementation Steps:**
1. Define red team charter
2. Hire or train red team members
3. Establish rules of engagement
4. Conduct regular exercises
5. Document findings
6. Coordinate with blue team
7. Measure improvement over time

**Red Team Activities:**
- Penetration testing
- Social engineering
- Physical security testing
- Adversary simulation

---

### 4. Forming a Blue Team

**Implementation Steps:**
1. Define blue team charter
2. Staff incident response team
3. Develop playbooks
4. Implement SOAR platform
5. Conduct regular drills
6. Measure response times
7. Continuous improvement

**Blue Team Responsibilities:**
- Incident detection
- Incident response
- Forensics
- Threat hunting
- Security monitoring

---

### 5. Chaos Engineering for Resilience

**Implementation Steps:**
1. Form chaos engineering team
2. Define chaos experiments
3. Start with non-production
4. Gradually increase scope
5. Automate chaos experiments
6. Measure and improve resilience
7. Document learnings

**Tools:**
- AWS Fault Injection Simulator
- Chaos Monkey
- Gremlin

---

## Implementation Roadmap

### Month 1-2: Quick Wins
- Enable MFA for all users
- Enable GuardDuty
- Configure CloudTrail
- Enable S3 Block Public Access
- Assign security contacts
- Set up billing alarms
- Deploy WAF with managed rules

### Month 3-6: Foundational
- Implement SCPs/RCPs
- Migrate to temporary credentials
- Enforce IMDSv2
- Integrate security in development
- Enable Amazon Inspector
- Implement secrets management
- Enable encryption at rest
- Configure backups

### Month 7-12: Efficient
- Implement DevSecOps pipeline
- Launch Security Champions program
- Conduct least privilege reviews
- Build image generation pipeline
- Deploy EDR/runtime protection
- Enable Amazon Macie
- Conduct threat modeling

### Year 2+: Optimized
- Implement IAM data perimeters
- Deploy temporary elevated access
- Form red team
- Form blue team
- Implement chaos engineering
- Advanced security automation
- Continuous optimization

---

## Key Success Factors

1. **Executive Support**: Secure leadership buy-in and budget
2. **Phased Approach**: Don't try to do everything at once
3. **Automation**: Automate security controls and remediation
4. **Training**: Invest in security training for all teams
5. **Measurement**: Track security metrics and improvements
6. **Culture**: Build a security-conscious culture
7. **Collaboration**: Break down silos between security and development
8. **Continuous Improvement**: Regularly review and update security posture

---

## Assessment Questions

Use these questions to evaluate your current maturity:

**Quick Wins:**
- Is MFA enabled for all users?
- Is GuardDuty enabled in all accounts?
- Are CloudTrail logs centralized and protected?
- Is S3 Block Public Access enabled?

**Foundational:**
- Are SCPs enforcing security invariants?
- Are you using temporary credentials everywhere?
- Is security involved early in development?
- Are vulnerabilities being tracked and remediated?

**Efficient:**
- Is security testing automated in CI/CD?
- Do you have security champions in dev teams?
- Are you regularly reviewing least privilege?
- Is sensitive data discovery automated?

**Optimized:**
- Do you have a red team?
- Do you have a blue team?
- Are you practicing chaos engineering?
- Is elevated access time-limited?

---

## Additional Resources

- [AWS Security Maturity Model](https://maturitymodel.security.aws.dev)
- [AWS Well-Architected Framework - Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)
- [AWS Cloud Adoption Framework - Security Perspective](https://docs.aws.amazon.com/whitepapers/latest/overview-aws-cloud-adoption-framework/security-perspective.html)
- [AWS Security Hub](https://aws.amazon.com/security-hub/)
- [AWS Security Blog](https://aws.amazon.com/blogs/security/)

---

## Conclusion

The AWS Security Maturity Model provides a practical, prescriptive path to improving your cloud security posture. By following the phased approach and focusing on quick wins first, you can achieve meaningful security improvements quickly while building toward a mature, optimized security program.

Remember: Security is a journey, not a destination. Start with Phase 1, build your foundation in Phase 2, optimize in Phase 3, and continuously improve in Phase 4.
