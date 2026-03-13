# Assessment Workflow

This guide walks you through assessing your AWS security posture using the Security Maturity Model framework.

## Overview

The assessment workflow helps you:
1. Retrieve current AWS security configurations
2. Compare against Security Maturity Model controls
3. Identify gaps and prioritize remediations
4. Track progress in the CSV file

## Prerequisites

- AWS CLI configured with appropriate credentials
- Read access to AWS services (SecurityAudit policy recommended)
- CSV tracking file (will be created if doesn't exist)

## Step-by-Step Assessment

### Phase 1: Account Information

**Retrieve basic account information:**

```bash
# Get account ID and caller identity
aws sts get-caller-identity

# List regions in use
aws ec2 describe-regions --all-regions --query 'Regions[?OptInStatus!=`not-opted-in`].RegionName' --output table

# Get account alias
aws iam list-account-aliases
```

**What to check:**
- Account ID is correct
- You have access to expected regions
- Account alias is set (best practice)

### Phase 2: Quick Wins Assessment

#### 1. Multi-Factor Authentication (MFA)

**Check root account MFA:**
```bash
aws iam get-account-summary | grep "AccountMFAEnabled"
```

**Check IAM users without MFA:**
```bash
aws iam get-credential-report
aws iam generate-credential-report
sleep 5
aws iam get-credential-report --output text | awk -F, '$4=="false" {print $1}'
```

**Expected result:** All users should have MFA enabled

#### 2. GuardDuty

**Check GuardDuty status:**
```bash
# Check in current region
aws guardduty list-detectors

# Check all regions
for region in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  echo "Region: $region"
  aws guardduty list-detectors --region $region
done
```

**Expected result:** GuardDuty detector enabled in all active regions

#### 3. CloudTrail

**Check CloudTrail configuration:**
```bash
# List trails
aws cloudtrail describe-trails

# Check if trail is logging
aws cloudtrail get-trail-status --name <trail-name>

# Check if multi-region trail exists
aws cloudtrail describe-trails --query 'trailList[?IsMultiRegionTrail==`true`]'
```

**Expected result:** 
- At least one multi-region trail
- Trail is actively logging
- Logs are encrypted
- Log file validation enabled

#### 4. S3 Block Public Access

**Check account-level Block Public Access:**
```bash
aws s3control get-public-access-block --account-id $(aws sts get-caller-identity --query Account --output text)
```

**Check bucket-level settings:**
```bash
# List all buckets
aws s3 ls

# Check each bucket
for bucket in $(aws s3 ls | awk '{print $3}'); do
  echo "Bucket: $bucket"
  aws s3api get-public-access-block --bucket $bucket 2>/dev/null || echo "No block public access configured"
done
```

**Expected result:** All Block Public Access settings enabled at account level

#### 5. Security Hub

**Check Security Hub status:**
```bash
aws securityhub describe-hub
```

**Get critical findings:**
```bash
aws securityhub get-findings --filters '{"SeverityLabel":[{"Value":"CRITICAL","Comparison":"EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' --query 'Findings[].{Title:Title,Severity:Severity.Label,Resource:Resources[0].Id}' --output table
```

**Expected result:** Security Hub enabled with findings being reviewed

#### 6. Risky Security Groups

**Check for overly permissive security groups:**
```bash
# Find security groups with 0.0.0.0/0 access
aws ec2 describe-security-groups --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]].{GroupId:GroupId,GroupName:GroupName,VpcId:VpcId}' --output table

# Check for SSH (22) open to world
aws ec2 describe-security-groups --filters Name=ip-permission.from-port,Values=22 Name=ip-permission.to-port,Values=22 Name=ip-permission.cidr,Values='0.0.0.0/0' --query 'SecurityGroups[].{GroupId:GroupId,GroupName:GroupName}' --output table

# Check for RDP (3389) open to world
aws ec2 describe-security-groups --filters Name=ip-permission.from-port,Values=3389 Name=ip-permission.to-port,Values=3389 Name=ip-permission.cidr,Values='0.0.0.0/0' --query 'SecurityGroups[].{GroupId:GroupId,GroupName:GroupName}' --output table
```

**Expected result:** No security groups with risky open ports to 0.0.0.0/0

#### 7. WAF

**Check WAF deployment:**
```bash
# List WAF Web ACLs (WAFv2)
aws wafv2 list-web-acls --scope REGIONAL --region us-east-1
aws wafv2 list-web-acls --scope CLOUDFRONT --region us-east-1

# Check associated resources
aws wafv2 list-resources-for-web-acl --web-acl-arn <web-acl-arn> --region us-east-1
```

**Expected result:** WAF deployed on public-facing resources (ALB, CloudFront, API Gateway)

#### 8. Billing Alarms

**Check CloudWatch billing alarms:**
```bash
aws cloudwatch describe-alarms --alarm-name-prefix "Billing" --region us-east-1
```

**Expected result:** At least one billing alarm configured

#### 9. Assign Security Contacts

**Check security alternate contact:**
```bash
aws account get-alternate-contact --alternate-contact-type SECURITY --query 'AlternateContact.{Name:Name,Title:Title,Email:EmailAddress,Phone:PhoneNumber}' --output table
```

**Check billing alternate contact:**
```bash
aws account get-alternate-contact --alternate-contact-type BILLING --query 'AlternateContact.{Name:Name,Title:Title,Email:EmailAddress,Phone:PhoneNumber}' --output table
```

**Check operations alternate contact:**
```bash
aws account get-alternate-contact --alternate-contact-type OPERATIONS --query 'AlternateContact.{Name:Name,Title:Title,Email:EmailAddress,Phone:PhoneNumber}' --output table
```

**Expected result:** All three alternate contacts (Security, Billing, Operations) are configured with valid names, email addresses, and phone numbers. The security contact should be a distribution list or team alias rather than an individual, so that notifications are not missed during absences.

#### 10. Select Regions and Block the Rest

**List currently opted-in regions:**
```bash
aws account list-regions --region-opt-status-filter ENABLED ENABLED_BY_DEFAULT --query 'Regions[].{Region:RegionName,Status:RegionOptStatus}' --output table
```

**Check for SCPs that restrict region usage:**
```bash
aws organizations list-policies --filter SERVICE_CONTROL_POLICY --query 'Policies[].{Id:Id,Name:Name}' --output table
```

**Inspect SCP content for region deny rules:**
```bash
# For each SCP ID from the previous command, check for region restrictions
for policy_id in $(aws organizations list-policies --filter SERVICE_CONTROL_POLICY --query 'Policies[].Id' --output text); do
  echo "Policy: $policy_id"
  aws organizations describe-policy --policy-id $policy_id --query 'Policy.Content' --output text | grep -i "aws:RequestedRegion" || echo "  No region restriction found"
done
```

**Expected result:** Only regions required for your workloads should be opted in. An SCP should be attached that contains a Deny statement with an `aws:RequestedRegion` condition key, blocking API calls to any region not in the approved list. If no SCP with region restrictions is found, this control is not yet implemented.

#### 11. Root Account Protection

**Check whether root access keys exist:**
```bash
aws iam get-account-summary --query 'SummaryMap.AccountAccessKeysPresent' --output text
```

**Expected result:** The value should be `0`, meaning no root access keys exist. If the value is `1`, the root account has active access keys. This is a critical risk — root access keys provide unrestricted access to the entire AWS account and cannot be scoped with IAM policies. Compromised root keys allow an attacker to perform any action, including closing the account. See remediation-workflow.md for remediation steps.

**Check whether root account has MFA enabled:**
```bash
aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled' --output text
```

**Expected result:** The value should be `1`, confirming MFA is enabled on the root account. If the value is `0`, the root account is protected only by a password, making it vulnerable to credential-stuffing and phishing attacks. See remediation-workflow.md for remediation steps.

**Check whether root account usage is recent:**
```bash
aws iam generate-credential-report > /dev/null 2>&1
sleep 3
aws iam get-credential-report --query 'Content' --output text | base64 --decode | awk -F, 'NR==2 {print "Root last used: "$5, "| Password last used: "$6}'
```

**Expected result:** The root account should show no recent usage (ideally `no_information` or a date older than 90 days). Regular root account usage indicates that day-to-day operations are being performed with the most privileged identity, increasing the blast radius of any credential compromise. See remediation-workflow.md for remediation steps.

#### 12. Identity Federation

**Check IAM Identity Center configuration:**
```bash
aws sso-admin list-instances --query 'Instances[].{InstanceArn:InstanceArn,IdentityStoreId:IdentityStoreId}' --output table
```

**Expected result:** At least one IAM Identity Center instance should be listed, indicating that centralized identity management is configured. If no instances are returned, users are likely managed as individual IAM users, which increases the risk of stale credentials, inconsistent access policies, and lack of centralized offboarding. See remediation-workflow.md for remediation steps.

**List identity providers:**
```bash
aws iam list-saml-providers --query 'SAMLProviderList[].{Arn:Arn,CreateDate:CreateDate}' --output table
```

**Check for OpenID Connect providers:**
```bash
aws iam list-open-id-connect-providers --query 'OpenIDConnectProviderList[].Arn' --output table
```

**Expected result:** At least one SAML or OIDC identity provider should be configured, confirming that federation with a corporate identity provider is in place. If no providers are found and IAM Identity Center is not enabled, all human access relies on locally managed IAM users and passwords, which bypasses corporate identity lifecycle controls (e.g., automatic deprovisioning when an employee leaves). See remediation-workflow.md for remediation steps.

#### 13. Cleanup Unintended Accesses

**Check IAM Access Analyzer findings:**
```bash
aws accessanalyzer list-analyzers --query 'analyzers[].{Name:name,Type:type,Status:status}' --output table
```

```bash
aws accessanalyzer list-findings --analyzer-arn $(aws accessanalyzer list-analyzers --query 'analyzers[0].arn' --output text) --filter '{"status":{"eq":["ACTIVE"]}}' --query 'findings[].{Resource:resource,ResourceType:resourceType,Principal:principal}' --output table 2>/dev/null || echo "No IAM Access Analyzer configured"
```

**Expected result:** An IAM Access Analyzer should exist with status `ACTIVE` and ideally zero active findings. Active findings indicate resources (S3 buckets, IAM roles, KMS keys, Lambda functions, SQS queues) that are shared with external principals — these may be intentional cross-account access or unintended public exposure. Each finding should be reviewed and either archived (if intentional) or remediated. See remediation-workflow.md for remediation steps.

**List unused IAM credentials:**
```bash
aws iam generate-credential-report > /dev/null 2>&1
sleep 3
aws iam get-credential-report --query 'Content' --output text | base64 --decode | awk -F, 'NR>1 && $4=="true" && $5=="no_information" {print "User with password never used: "$1}'
```

```bash
aws iam get-credential-report --query 'Content' --output text | base64 --decode | awk -F, 'NR>1 && $9=="true" && $11=="N/A" {print "Access key 1 never used: "$1}'
```

```bash
aws iam get-credential-report --query 'Content' --output text | base64 --decode | awk -F, 'NR>1 && $14=="true" && $16=="N/A" {print "Access key 2 never used: "$1}'
```

**Expected result:** No unused credentials should be found. Users with passwords that have never been used, or access keys that have never been used, represent dormant attack surface — these credentials could be compromised without the legitimate owner noticing. Unused credentials should be deactivated or removed. See remediation-workflow.md for remediation steps.

#### 14. Analyze Data Security Posture

**Check Amazon Macie status:**
```bash
aws macie2 get-macie-session --query '{Status:status,CreatedAt:createdAt}' --output table 2>/dev/null || echo "Amazon Macie is not enabled in this region"
```

**Check S3 bucket inventory via Macie:**
```bash
aws macie2 describe-buckets --query 'buckets[].{BucketName:bucketName,Classifiable:classifiableObjectCount,Encrypted:serverSideEncryption.type}' --output table 2>/dev/null || echo "Amazon Macie is not enabled — cannot retrieve S3 bucket inventory"
```

**Expected result:** Amazon Macie should be enabled (status `ENABLED`) and should have visibility into your S3 bucket inventory. If Macie is not enabled, you have no automated mechanism to discover and classify sensitive data (PII, financial data, credentials) stored in S3. Unclassified sensitive data increases the risk of data breaches going undetected and complicates regulatory compliance (GDPR, HIPAA, PCI-DSS). See remediation-workflow.md for remediation steps.

#### 15. Evaluate Cloud Security Posture (CSPM)

**Check Security Hub enablement:**
```bash
aws securityhub describe-hub --query '{HubArn:HubArn,SubscribedAt:SubscribedAt,AutoEnableControls:AutoEnableControls}' --output table 2>/dev/null || echo "Security Hub is not enabled in this region"
```

**List enabled security standards:**
```bash
aws securityhub get-enabled-standards --query 'StandardsSubscriptions[].{StandardArn:StandardsSubscriptionArn,Status:StandardsStatus}' --output table 2>/dev/null || echo "Security Hub is not enabled — cannot list standards"
```

**Check compliance scores for enabled standards:**
```bash
aws securityhub list-security-control-definitions --max-items 1 > /dev/null 2>&1 && \
aws securityhub get-findings --filters '{"ComplianceStatus":[{"Value":"FAILED","Comparison":"EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' --query 'length(Findings)' --output text 2>/dev/null && echo "(count of FAILED compliance findings)" || echo "Security Hub is not enabled — cannot check compliance scores"
```

```bash
aws securityhub get-findings --filters '{"ComplianceStatus":[{"Value":"PASSED","Comparison":"EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' --query 'length(Findings)' --output text 2>/dev/null && echo "(count of PASSED compliance findings)" || echo "Security Hub is not enabled — cannot check compliance scores"
```

**Expected result:** Security Hub should be enabled with at least one security standard active (e.g., AWS Foundational Security Best Practices, CIS AWS Foundations Benchmark). The ratio of PASSED to FAILED compliance findings indicates your overall security posture score — a high number of FAILED findings means significant configuration drift from best practices. If no standards are enabled, Security Hub is not performing continuous compliance monitoring. See remediation-workflow.md for remediation steps.

#### 16. Evaluate Resilience

**Check AWS Backup vault existence:**
```bash
aws backup list-backup-vaults --query 'BackupVaultList[].{VaultName:BackupVaultName,NumberOfRecoveryPoints:NumberOfRecoveryPoints,CreationDate:CreationDate}' --output table 2>/dev/null || echo "Unable to list backup vaults"
```

**Check multi-AZ deployments for RDS:**
```bash
aws rds describe-db-instances --query 'DBInstances[].{DBInstance:DBInstanceIdentifier,Engine:Engine,MultiAZ:MultiAZ,AZ:AvailabilityZone}' --output table 2>/dev/null || echo "No RDS instances found"
```

**Check Auto Scaling configurations:**
```bash
aws autoscaling describe-auto-scaling-groups --query 'AutoScalingGroups[].{GroupName:AutoScalingGroupName,MinSize:MinSize,MaxSize:MaxSize,DesiredCapacity:DesiredCapacity,AZs:AvailabilityZones|join(`, `,@)}' --output table 2>/dev/null || echo "No Auto Scaling groups found"
```

**Expected result:** At least one AWS Backup vault should exist with recovery points, confirming that backup policies are in place. RDS instances should have `MultiAZ: true` for production workloads to ensure automatic failover during AZ outages. Auto Scaling groups should span at least two Availability Zones with `MinSize` greater than or equal to 2 for high availability. If no backup vaults exist, there is no centralized backup strategy. Single-AZ RDS instances and single-AZ Auto Scaling groups represent single points of failure. See remediation-workflow.md for remediation steps.

#### 17. Act on Critical Security Findings

**Query Security Hub for CRITICAL severity active findings:**
```bash
aws securityhub get-findings --filters '{"SeverityLabel":[{"Value":"CRITICAL","Comparison":"EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' --query 'Findings[].{Title:Title,Resource:Resources[0].Id,ResourceType:Resources[0].Type,CreatedAt:CreatedAt}' --output table 2>/dev/null || echo "Security Hub is not enabled — cannot query findings"
```

**Query Security Hub for HIGH severity active findings:**
```bash
aws securityhub get-findings --filters '{"SeverityLabel":[{"Value":"HIGH","Comparison":"EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' --query 'Findings[].{Title:Title,Resource:Resources[0].Id,ResourceType:Resources[0].Type,CreatedAt:CreatedAt}' --output table 2>/dev/null || echo "Security Hub is not enabled — cannot query findings"
```

**Count CRITICAL findings by resource type:**
```bash
aws securityhub get-findings --filters '{"SeverityLabel":[{"Value":"CRITICAL","Comparison":"EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' --query 'Findings[].Resources[0].Type' --output text 2>/dev/null | tr '\t' '\n' | sort | uniq -c | sort -rn || echo "Security Hub is not enabled"
```

**Count HIGH findings by resource type:**
```bash
aws securityhub get-findings --filters '{"SeverityLabel":[{"Value":"HIGH","Comparison":"EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' --query 'Findings[].Resources[0].Type' --output text 2>/dev/null | tr '\t' '\n' | sort | uniq -c | sort -rn || echo "Security Hub is not enabled"
```

**Expected result:** Ideally there should be zero CRITICAL and zero HIGH severity active findings. Any CRITICAL findings represent immediate security risks that should be remediated urgently — these often include publicly exposed resources, missing encryption, or disabled security controls. HIGH findings should be triaged and addressed within a defined SLA. The counts by resource type help prioritize remediation efforts by identifying which resource categories have the most findings. See remediation-workflow.md for remediation steps.

### Phase 3: Foundational Controls Assessment

#### 1. Service Control Policies (SCPs)

**Check if AWS Organizations is enabled:**
```bash
aws organizations describe-organization
```

**List SCPs:**
```bash
aws organizations list-policies --filter SERVICE_CONTROL_POLICY
```

**Expected result:** SCPs enforcing security invariants

#### 2. Temporary Credentials

**Check for long-term access keys:**
```bash
aws iam get-credential-report --output text | awk -F, 'NR>1 && $9!="N/A" {print $1, $9, $14}'
```

**Check IAM roles for EC2:**
```bash
aws ec2 describe-instances --query 'Reservations[].Instances[?IamInstanceProfile==`null`].{InstanceId:InstanceId,Name:Tags[?Key==`Name`].Value|[0]}' --output table
```

**Expected result:** 
- No access keys older than 90 days
- All EC2 instances use IAM roles

#### 3. IMDSv2

**Check instances using IMDSv1:**
```bash
aws ec2 describe-instances --query 'Reservations[].Instances[?MetadataOptions.HttpTokens==`optional`].{InstanceId:InstanceId,Name:Tags[?Key==`Name`].Value|[0]}' --output table
```

**Expected result:** All instances require IMDSv2 (HttpTokens=required)

#### 4. Encryption at Rest

**Check unencrypted EBS volumes:**
```bash
aws ec2 describe-volumes --filters Name=encrypted,Values=false --query 'Volumes[].{VolumeId:VolumeId,Size:Size,State:State}' --output table
```

**Check unencrypted RDS instances:**
```bash
aws rds describe-db-instances --query 'DBInstances[?StorageEncrypted==`false`].{DBInstanceIdentifier:DBInstanceIdentifier,Engine:Engine}' --output table
```

**Check unencrypted S3 buckets:**
```bash
for bucket in $(aws s3 ls | awk '{print $3}'); do
  encryption=$(aws s3api get-bucket-encryption --bucket $bucket 2>&1)
  if [[ $encryption == *"ServerSideEncryptionConfigurationNotFoundError"* ]]; then
    echo "Unencrypted: $bucket"
  fi
done
```

**Expected result:** All data stores encrypted at rest

#### 5. Identify Security and Regulatory Requirements

**Check AWS Artifact agreements:**
```bash
aws artifact list-agreements --query 'Agreements[].{Name:Name,Status:Status,Type:Type}' --output table 2>/dev/null || echo "AWS Artifact API not available — review agreements in the AWS Artifact console"
```

**Check AWS Config conformance packs:**
```bash
aws configservice describe-conformance-packs --query 'ConformancePackDetails[].{Name:ConformancePackName,Status:ConformancePackState}' --output table 2>/dev/null || echo "AWS Config conformance packs not configured"
```

**Check conformance pack compliance summary:**
```bash
aws configservice describe-conformance-pack-compliance --conformance-pack-name <pack-name> --query 'ConformancePackRuleComplianceList[].{Rule:ConfigRuleName,Compliance:ComplianceType}' --output table 2>/dev/null || echo "No conformance pack found — replace <pack-name> with your pack name"
```

**Expected result:** At least one conformance pack deployed matching your regulatory framework (e.g., NIST, PCI-DSS, HIPAA). AWS Artifact agreements accepted for applicable compliance programs.

**Assessment questions:**
- Has the organization identified all applicable security and regulatory requirements (e.g., GDPR, HIPAA, PCI-DSS, SOC 2)?
- Is there a documented mapping between regulatory requirements and AWS controls?
- Are conformance packs aligned to the organization's compliance frameworks?
- Is there a process to review and update regulatory requirements periodically?

#### 6. Cloud Security Training Plan

**Assessment questions:**
- Does the organization have a formal cloud security training program?
- How frequently is cloud security training delivered (e.g., annually, quarterly)?
- Does the training cover AWS-specific security best practices and shared responsibility model?
- What percentage of engineering and operations staff have completed cloud security training?
- Are there role-specific training tracks (e.g., developers, operations, security team)?
- Is training completion tracked and reported to management?
- Does the training program include hands-on labs or practical exercises?

#### 7. Advanced Threat Detection

**Check GuardDuty S3 Protection:**
```bash
for detector_id in $(aws guardduty list-detectors --query 'DetectorIds[]' --output text); do
  echo "Detector: $detector_id"
  aws guardduty get-detector --detector-id $detector_id --query '{S3Logs:DataSources.S3Logs.Status}' --output table 2>/dev/null || echo "Unable to retrieve S3 protection status"
done
```

**Check GuardDuty EKS Protection:**
```bash
for detector_id in $(aws guardduty list-detectors --query 'DetectorIds[]' --output text); do
  echo "Detector: $detector_id"
  aws guardduty get-detector --detector-id $detector_id --query '{EKSAuditLogs:DataSources.Kubernetes.AuditLogs.Status}' --output table 2>/dev/null || echo "Unable to retrieve EKS protection status"
done
```

**Check GuardDuty Lambda Protection:**
```bash
for detector_id in $(aws guardduty list-detectors --query 'DetectorIds[]' --output text); do
  echo "Detector: $detector_id"
  aws guardduty get-detector --detector-id $detector_id --query '{LambdaNetworkLogs:Features[?Name==`LAMBDA_NETWORK_LOGS`].Status|[0]}' --output table 2>/dev/null || echo "Unable to retrieve Lambda protection status"
done
```

**Check GuardDuty RDS Protection:**
```bash
for detector_id in $(aws guardduty list-detectors --query 'DetectorIds[]' --output text); do
  echo "Detector: $detector_id"
  aws guardduty get-detector --detector-id $detector_id --query '{RDSLoginEvents:Features[?Name==`RDS_LOGIN_EVENTS`].Status|[0]}' --output table 2>/dev/null || echo "Unable to retrieve RDS protection status"
done
```

**Check GuardDuty Malware Protection:**
```bash
for detector_id in $(aws guardduty list-detectors --query 'DetectorIds[]' --output text); do
  echo "Detector: $detector_id"
  aws guardduty get-detector --detector-id $detector_id --query '{MalwareProtection:Features[?Name==`EBS_MALWARE_PROTECTION`].Status|[0]}' --output table 2>/dev/null || echo "Unable to retrieve Malware protection status"
done
```

**Check EKS cluster audit logging:**
```bash
aws eks list-clusters --query 'clusters[]' --output text 2>/dev/null | tr '\t' '\n' | while read cluster; do
  echo "Cluster: $cluster"
  aws eks describe-cluster --name "$cluster" --query 'cluster.logging.clusterLogging[?enabled==`true`].types[]' --output table 2>/dev/null || echo "Unable to retrieve logging config"
done
```

**Expected result:** All GuardDuty protection plans (S3, EKS Audit Logs, Lambda Network Logs, RDS Login Events, Malware Protection) should show status `ENABLED`. EKS clusters should have `audit` logging enabled. If any protection plan is not enabled, GuardDuty is not providing full threat coverage for that service. Missing EKS audit logging means Kubernetes-level threats (privilege escalation, suspicious API calls) will not be detected. See remediation-workflow.md for remediation steps.

#### 8. Manage Infrastructure Vulnerabilities

**Check Amazon Inspector enablement:**
```bash
aws inspector2 batch-get-account-status --query 'accounts[].{AccountId:accountId,EC2Status:resourceState.ec2.status,ECRStatus:resourceState.ecr.status,LambdaStatus:resourceState.lambda.status}' --output table 2>/dev/null || echo "Amazon Inspector is not enabled in this region"
```

**Check Amazon Inspector coverage:**
```bash
aws inspector2 list-coverage --query 'coveredResources[].{ResourceId:resourceId,ResourceType:resourceType,ScanStatus:scanStatus.statusCode}' --output table 2>/dev/null || echo "Amazon Inspector is not enabled — cannot retrieve coverage"
```

**Check Amazon Inspector finding counts by severity:**
```bash
aws inspector2 list-finding-aggregations --aggregation-type SEVERITY --query 'responses[].{Severity:severityCounts}' --output table 2>/dev/null || echo "Amazon Inspector is not enabled — cannot retrieve findings"
```

**Alternative — count findings by severity using list-findings:**
```bash
for severity in CRITICAL HIGH MEDIUM LOW; do
  count=$(aws inspector2 list-findings --filter-criteria "{\"severity\":[{\"comparison\":\"EQUALS\",\"value\":\"$severity\"}]}" --query 'length(findings)' --output text 2>/dev/null)
  echo "$severity: ${count:-N/A}"
done
```

**Expected result:** Amazon Inspector should be enabled for EC2, ECR, and Lambda (all showing status `ENABLED`). Coverage should include all running EC2 instances, ECR repositories, and Lambda functions. Ideally there should be zero CRITICAL findings and a low count of HIGH findings. A high number of unresolved findings indicates that infrastructure vulnerabilities are not being managed within defined SLAs. If Inspector is not enabled, there is no automated vulnerability scanning for compute resources. See remediation-workflow.md for remediation steps.

#### 9. Manage Application Vulnerabilities

**Check CodeGuru Reviewer associations:**
```bash
aws codeguru-reviewer list-repository-associations --query 'RepositoryAssociationSummaries[].{Name:Name,State:State,ProviderType:ProviderType}' --output table 2>/dev/null || echo "CodeGuru Reviewer is not available or not configured"
```

**Check ECR scan configuration:**
```bash
aws ecr describe-registry --query 'replicationConfiguration' --output table 2>/dev/null || echo "Unable to retrieve ECR registry configuration"
```

```bash
for repo in $(aws ecr describe-repositories --query 'repositories[].repositoryName' --output text 2>/dev/null); do
  echo "Repository: $repo"
  aws ecr describe-repositories --repository-names "$repo" --query 'repositories[].{Name:repositoryName,ScanOnPush:imageScanningConfiguration.scanOnPush}' --output table 2>/dev/null
done
```

**Check ECR enhanced scanning configuration:**
```bash
aws inspector2 batch-get-account-status --query 'accounts[].resourceState.ecr.status' --output text 2>/dev/null || echo "ECR enhanced scanning via Inspector is not enabled"
```

**Expected result:** CodeGuru Reviewer should have at least one repository association in `Associated` state, indicating automated code reviews are active. ECR repositories should have `scanOnPush: true` enabled, and ideally enhanced scanning via Amazon Inspector should be active for deeper vulnerability analysis. If no CodeGuru associations exist, application code is not being automatically reviewed for security issues. If ECR scan-on-push is disabled, container images may contain known vulnerabilities that go undetected. See remediation-workflow.md for remediation steps.

**Assessment questions:**
- Does the organization use Static Application Security Testing (SAST) tools in the development pipeline?
- Does the organization use Dynamic Application Security Testing (DAST) tools against running applications?
- Are SAST/DAST findings triaged and remediated within defined SLAs?
- Is there a process to track and report on application vulnerability trends over time?
- Are third-party dependencies scanned for known vulnerabilities (e.g., using Software Composition Analysis)?

#### 10. Limit Network Access

**Check Network ACLs:**
```bash
aws ec2 describe-network-acls --query 'NetworkAcls[].{NaclId:NetworkAclId,VpcId:VpcId,IsDefault:IsDefault,InboundRules:Entries[?Egress==`false`]|length(@),OutboundRules:Entries[?Egress==`true`]|length(@)}' --output table
```

**Check for NACLs allowing all traffic:**
```bash
aws ec2 describe-network-acls --query 'NetworkAcls[].{NaclId:NetworkAclId,VpcId:VpcId,AllowAllInbound:Entries[?Egress==`false`&&RuleAction==`allow`&&CidrBlock==`0.0.0.0/0`&&Protocol==`-1`]|length(@)}' --output table
```

**Check VPC endpoint configurations:**
```bash
aws ec2 describe-vpc-endpoints --query 'VpcEndpoints[].{EndpointId:VpcEndpointId,ServiceName:ServiceName,VpcId:VpcId,Type:VpcEndpointType,State:State}' --output table 2>/dev/null || echo "No VPC endpoints found"
```

**Check VPC endpoint policies:**
```bash
for endpoint_id in $(aws ec2 describe-vpc-endpoints --query 'VpcEndpoints[].VpcEndpointId' --output text 2>/dev/null); do
  echo "Endpoint: $endpoint_id"
  aws ec2 describe-vpc-endpoints --vpc-endpoint-ids "$endpoint_id" --query 'VpcEndpoints[].{ServiceName:ServiceName,PolicyDocument:PolicyDocument}' --output table 2>/dev/null
done
```

**Check security groups with unrestricted egress (0.0.0.0/0 on all ports):**
```bash
aws ec2 describe-security-groups --query 'SecurityGroups[?IpPermissionsEgress[?IpRanges[?CidrIp==`0.0.0.0/0`]&&IpProtocol==`-1`]].{GroupId:GroupId,GroupName:GroupName,VpcId:VpcId}' --output table
```

**Expected result:** NACLs should have customized rules beyond the default allow-all configuration — default NACLs that allow all inbound and outbound traffic provide no network-layer filtering. VPC endpoints should be configured for frequently used AWS services (S3, DynamoDB, CloudWatch, etc.) to keep traffic within the AWS network and enable policy-based access control. VPC endpoint policies should restrict access to specific resources rather than using the default full-access policy. Security groups should not have unrestricted egress on all protocols unless explicitly required — unrestricted outbound access allows compromised instances to exfiltrate data or communicate with command-and-control servers. See remediation-workflow.md for remediation steps.

#### 11. Secure EC2 Instances Management

**Check Systems Manager managed instance status:**
```bash
aws ssm describe-instance-information --query 'InstanceInformationList[].{InstanceId:InstanceId,PingStatus:PingStatus,PlatformType:PlatformType,PlatformName:PlatformName,AgentVersion:AgentVersion}' --output table 2>/dev/null || echo "No managed instances found in Systems Manager"
```

**Check for EC2 instances not managed by Systems Manager:**
```bash
managed=$(aws ssm describe-instance-information --query 'InstanceInformationList[].InstanceId' --output text 2>/dev/null)
all_instances=$(aws ec2 describe-instances --filters Name=instance-state-name,Values=running --query 'Reservations[].Instances[].InstanceId' --output text 2>/dev/null)
for instance in $all_instances; do
  if ! echo "$managed" | grep -q "$instance"; then
    echo "Not managed by SSM: $instance"
  fi
done
```

**Check patch compliance summary:**
```bash
aws ssm describe-instance-patch-states --query 'InstancePatchStates[].{InstanceId:InstanceId,InstalledCount:InstalledCount,MissingCount:MissingCount,FailedCount:FailedCount,OperationEndTime:OperationEndTime}' --output table 2>/dev/null || echo "No patch compliance data available"
```

**Check patch baselines:**
```bash
aws ssm describe-patch-baselines --query 'BaselineIdentities[].{BaselineId:BaselineId,BaselineName:BaselineName,OperatingSystem:OperatingSystem,DefaultBaseline:DefaultBaseline}' --output table 2>/dev/null || echo "No patch baselines configured"
```

**Expected result:** All running EC2 instances should appear in Systems Manager with `PingStatus: Online`, confirming the SSM Agent is installed and communicating. Any instances not managed by Systems Manager cannot be patched, inventoried, or remotely administered through SSM, increasing operational risk. Patch compliance should show zero `MissingCount` and zero `FailedCount` — missing patches indicate unpatched vulnerabilities, and failed patches require investigation. At least one patch baseline should be configured for each operating system in use. See remediation-workflow.md for remediation steps.

#### 12. Network Segmentation

**List VPCs:**
```bash
aws ec2 describe-vpcs --query 'Vpcs[].{VpcId:VpcId,CidrBlock:CidrBlock,IsDefault:IsDefault,Name:Tags[?Key==`Name`].Value|[0],State:State}' --output table
```

**List subnets:**
```bash
aws ec2 describe-subnets --query 'Subnets[].{SubnetId:SubnetId,VpcId:VpcId,CidrBlock:CidrBlock,AZ:AvailabilityZone,Public:MapPublicIpOnLaunch,Name:Tags[?Key==`Name`].Value|[0]}' --output table
```

**List route tables:**
```bash
aws ec2 describe-route-tables --query 'RouteTables[].{RouteTableId:RouteTableId,VpcId:VpcId,Name:Tags[?Key==`Name`].Value|[0],Routes:Routes[].{Destination:DestinationCidrBlock,Target:GatewayId||NatGatewayId||TransitGatewayId||VpcPeeringConnectionId}}' --output table
```

**Check for subnets with direct internet gateway routes (public subnets):**
```bash
for rt_id in $(aws ec2 describe-route-tables --query 'RouteTables[].RouteTableId' --output text); do
  igw_route=$(aws ec2 describe-route-tables --route-table-ids "$rt_id" --query 'RouteTables[].Routes[?GatewayId!=`null`&&starts_with(GatewayId,`igw-`)].{Destination:DestinationCidrBlock,IGW:GatewayId}' --output text 2>/dev/null)
  if [ -n "$igw_route" ]; then
    associations=$(aws ec2 describe-route-tables --route-table-ids "$rt_id" --query 'RouteTables[].Associations[].SubnetId' --output text 2>/dev/null)
    echo "Route table $rt_id has IGW route — associated subnets: ${associations:-Main route table (default)}"
  fi
done
```

**List NAT gateways:**
```bash
aws ec2 describe-nat-gateways --query 'NatGateways[].{NatGatewayId:NatGatewayId,VpcId:VpcId,SubnetId:SubnetId,State:State,ConnectivityType:ConnectivityType}' --output table 2>/dev/null || echo "No NAT gateways found"
```

**Expected result:** Workloads should be segmented across multiple VPCs or subnets based on sensitivity and function (e.g., separate VPCs for production and development, separate subnets for public-facing and internal resources). Subnets containing application servers, databases, or internal services should not have direct internet gateway routes — they should route outbound traffic through NAT gateways in public subnets. At least one NAT gateway should exist per AZ for private subnet internet access. The default VPC should ideally not be used for production workloads. See remediation-workflow.md for remediation steps.

#### 13. Multi-Account Management

**Check AWS Organizations structure:**
```bash
aws organizations describe-organization --query 'Organization.{Id:Id,MasterAccountId:MasterAccountId,FeatureSet:FeatureSet}' --output table 2>/dev/null || echo "AWS Organizations is not enabled for this account"
```

**List organizational units (OUs):**
```bash
root_id=$(aws organizations list-roots --query 'Roots[0].Id' --output text 2>/dev/null)
if [ -n "$root_id" ] && [ "$root_id" != "None" ]; then
  echo "Root: $root_id"
  aws organizations list-organizational-units-for-parent --parent-id "$root_id" --query 'OrganizationalUnits[].{Id:Id,Name:Name}' --output table 2>/dev/null
else
  echo "AWS Organizations is not enabled — cannot list OUs"
fi
```

**List accounts in the organization:**
```bash
aws organizations list-accounts --query 'Accounts[].{Id:Id,Name:Name,Email:Email,Status:Status,JoinedMethod:JoinedMethod}' --output table 2>/dev/null || echo "AWS Organizations is not enabled — cannot list accounts"
```

**Check SCPs attached to OUs:**
```bash
root_id=$(aws organizations list-roots --query 'Roots[0].Id' --output text 2>/dev/null)
if [ -n "$root_id" ] && [ "$root_id" != "None" ]; then
  for ou_id in $(aws organizations list-organizational-units-for-parent --parent-id "$root_id" --query 'OrganizationalUnits[].Id' --output text 2>/dev/null); do
    ou_name=$(aws organizations list-organizational-units-for-parent --parent-id "$root_id" --query "OrganizationalUnits[?Id=='$ou_id'].Name" --output text 2>/dev/null)
    echo "OU: $ou_name ($ou_id)"
    aws organizations list-policies-for-target --target-id "$ou_id" --filter SERVICE_CONTROL_POLICY --query 'Policies[].{Id:Id,Name:Name}' --output table 2>/dev/null
  done
else
  echo "AWS Organizations is not enabled — cannot check SCP attachments"
fi
```

**Expected result:** AWS Organizations should be enabled with `FeatureSet: ALL` to support SCPs and centralized management. The organization should have a well-defined OU structure separating workloads by environment (e.g., Production, Staging, Development), function (e.g., Security, Logging, Shared Services), or business unit. Each OU should have appropriate SCPs attached to enforce security guardrails. All accounts should show `Status: ACTIVE`. If Organizations is not enabled, the environment is operating as a single account without centralized governance, which limits the ability to enforce security policies, isolate workloads, and manage access at scale. See remediation-workflow.md for remediation steps.

#### 14. Backups

**Check AWS Backup plans:**
```bash
aws backup list-backup-plans --query 'BackupPlansList[].{BackupPlanId:BackupPlanId,BackupPlanName:BackupPlanName,CreationDate:CreationDate}' --output table 2>/dev/null || echo "No AWS Backup plans found"
```

**Check AWS Backup vaults:**
```bash
aws backup list-backup-vaults --query 'BackupVaultList[].{VaultName:BackupVaultName,NumberOfRecoveryPoints:NumberOfRecoveryPoints,CreationDate:CreationDate}' --output table 2>/dev/null || echo "No AWS Backup vaults found"
```

**Check protected resources:**
```bash
aws backup list-protected-resources --query 'Results[].{ResourceArn:ResourceArn,ResourceType:ResourceType,LastBackupTime:LastBackupTime}' --output table 2>/dev/null || echo "No protected resources found in AWS Backup"
```

**Expected result:** At least one backup plan should exist with a defined schedule and lifecycle policy. At least one backup vault should contain recovery points, confirming that backups are being created successfully. Protected resources should include critical workloads (RDS instances, DynamoDB tables, EBS volumes, EFS file systems). If no backup plans exist, there is no centralized backup strategy — data loss from accidental deletion, corruption, or ransomware would require manual recovery or may be unrecoverable. See remediation-workflow.md for remediation steps.

#### 15. No Secrets in Code

**Check Secrets Manager secret count:**
```bash
aws secretsmanager list-secrets --query 'SecretList[].{Name:Name,LastAccessedDate:LastAccessedDate,LastChangedDate:LastChangedDate}' --output table 2>/dev/null || echo "No secrets found in Secrets Manager"
```

**Check CodeGuru Reviewer status:**
```bash
aws codeguru-reviewer list-repository-associations --query 'RepositoryAssociationSummaries[].{Name:Name,State:State,ProviderType:ProviderType}' --output table 2>/dev/null || echo "CodeGuru Reviewer is not available or not configured"
```

**Expected result:** Secrets Manager should contain secrets for database credentials, API keys, and other sensitive values — this confirms that secrets are being managed centrally rather than hardcoded in application code or configuration files. CodeGuru Reviewer should have at least one repository association in `Associated` state, enabling automated detection of hardcoded secrets during code reviews. If no secrets are stored in Secrets Manager, credentials may be embedded in source code, environment variables, or configuration files, increasing the risk of exposure through version control history or log files. See remediation-workflow.md for remediation steps.

**Assessment questions:**
- Are pre-commit hooks configured to scan for secrets before code is pushed to repositories (e.g., git-secrets, detect-secrets, truffleHog)?
- Is there a process to rotate secrets automatically using Secrets Manager rotation policies?
- Are developers trained on secure credential management practices?
- Has a scan of existing repositories been performed to identify and remediate any previously committed secrets?

#### 16. Define Incident Response Playbooks

**Check Systems Manager Automation documents:**
```bash
aws ssm list-documents --document-filter-list key=DocumentType,value=Automation --query 'DocumentIdentifiers[].{Name:Name,Owner:Owner,DocumentVersion:DocumentVersion,DocumentType:DocumentType}' --output table 2>/dev/null || echo "No SSM Automation documents found"
```

**Check for custom Automation documents (non-AWS owned):**
```bash
aws ssm list-documents --document-filter-list key=DocumentType,value=Automation key=Owner,value=Self --query 'DocumentIdentifiers[].{Name:Name,DocumentVersion:DocumentVersion,PlatformTypes:PlatformTypes}' --output table 2>/dev/null || echo "No custom SSM Automation documents found"
```

**Expected result:** At least one custom SSM Automation document should exist, indicating that incident response procedures have been codified as automated runbooks. AWS-owned Automation documents (e.g., `AWS-StopEC2Instance`, `AWS-IsolateEC2Instance`) can supplement custom playbooks but should not be the only ones present. Custom documents demonstrate that the organization has defined response procedures tailored to its specific environment and threat scenarios. If no Automation documents exist, incident response relies entirely on manual procedures, which are slower and more error-prone during high-pressure security events. See remediation-workflow.md for remediation steps.

**Assessment questions:**
- Does the organization have documented incident response playbooks for common security scenarios (e.g., compromised credentials, data breach, ransomware, DDoS)?
- Are playbooks reviewed and updated at least annually or after each incident?
- Do playbooks define clear roles, responsibilities, and escalation paths?
- Have playbooks been tested through tabletop exercises or simulations?
- Is there a defined communication plan for internal and external stakeholders during an incident?

#### 17. Inventory and Configuration Monitoring

**Check AWS Config recorder status:**
```bash
aws configservice describe-configuration-recorders --query 'ConfigurationRecorders[].{Name:name,RoleARN:roleARN,AllSupported:recordingGroup.allSupported,IncludeGlobalResources:recordingGroup.includeGlobalResourceTypes}' --output table 2>/dev/null || echo "AWS Config recorder is not configured"
```

**Check AWS Config recorder delivery status:**
```bash
aws configservice describe-configuration-recorder-status --query 'ConfigurationRecordersStatus[].{Name:name,Recording:recording,LastStatus:lastStatus,LastStatusChangeTime:lastStatusChangeTime}' --output table 2>/dev/null || echo "AWS Config recorder status unavailable"
```

**Check AWS Config delivery channel:**
```bash
aws configservice describe-delivery-channels --query 'DeliveryChannels[].{Name:name,S3BucketName:s3BucketName,SnsTopicARN:snsTopicARN}' --output table 2>/dev/null || echo "No AWS Config delivery channel configured"
```

**Check conformance pack count:**
```bash
aws configservice describe-conformance-packs --query 'length(ConformancePackDetails)' --output text 2>/dev/null || echo "0"
```

**Expected result:** AWS Config recorder should be enabled with `Recording: true` and `AllSupported: true`, confirming that all resource types are being tracked. The recorder should include global resource types (IAM, CloudFront, etc.). A delivery channel should be configured with an S3 bucket for configuration history storage and optionally an SNS topic for change notifications. At least one conformance pack should be deployed to evaluate resources against a compliance framework. If AWS Config is not enabled, there is no continuous inventory of AWS resources and no mechanism to detect configuration drift from security baselines. See remediation-workflow.md for remediation steps.

#### 18. Redundancy Using Multiple Availability Zones

**Check RDS Multi-AZ status:**
```bash
aws rds describe-db-instances --query 'DBInstances[].{DBInstance:DBInstanceIdentifier,Engine:Engine,MultiAZ:MultiAZ,AZ:AvailabilityZone,Status:DBInstanceStatus}' --output table 2>/dev/null || echo "No RDS instances found"
```

**Check ELB cross-zone load balancing (ALB/NLB):**
```bash
for lb_arn in $(aws elbv2 describe-load-balancers --query 'LoadBalancers[].LoadBalancerArn' --output text 2>/dev/null); do
  lb_name=$(aws elbv2 describe-load-balancers --load-balancer-arns "$lb_arn" --query 'LoadBalancers[0].LoadBalancerName' --output text 2>/dev/null)
  cross_zone=$(aws elbv2 describe-load-balancer-attributes --load-balancer-arn "$lb_arn" --query "Attributes[?Key=='load_balancing.cross_zone.enabled'].Value|[0]" --output text 2>/dev/null)
  echo "LB: $lb_name — CrossZone: ${cross_zone:-N/A}"
done
```

**Check Classic ELB cross-zone load balancing:**
```bash
for lb_name in $(aws elb describe-load-balancers --query 'LoadBalancerDescriptions[].LoadBalancerName' --output text 2>/dev/null); do
  cross_zone=$(aws elb describe-load-balancer-attributes --load-balancer-name "$lb_name" --query 'LoadBalancerAttributes.CrossZoneLoadBalancing.Enabled' --output text 2>/dev/null)
  echo "Classic LB: $lb_name — CrossZone: ${cross_zone:-N/A}"
done
```

**Check Auto Scaling group AZ spread:**
```bash
aws autoscaling describe-auto-scaling-groups --query 'AutoScalingGroups[].{GroupName:AutoScalingGroupName,MinSize:MinSize,MaxSize:MaxSize,DesiredCapacity:DesiredCapacity,AZCount:length(AvailabilityZones),AZs:AvailabilityZones|join(`, `,@)}' --output table 2>/dev/null || echo "No Auto Scaling groups found"
```

**Expected result:** Production RDS instances should have `MultiAZ: true` to ensure automatic failover during AZ outages. Load balancers should have cross-zone load balancing enabled (`true`) to distribute traffic evenly across all registered targets in all enabled AZs. Auto Scaling groups should span at least two Availability Zones (`AZCount >= 2`) with `MinSize` of at least 2 to maintain availability during an AZ failure. Single-AZ deployments represent a single point of failure — an AZ outage would cause a complete service disruption for any workload confined to that AZ. See remediation-workflow.md for remediation steps.

#### 19. Involve Security Teams in Development

**Assessment questions:**
- Are security teams actively involved in the software development lifecycle (e.g., design reviews, code reviews, architecture discussions)?
- Is there a defined process for developers to engage security teams early in the development process?
- Do security teams participate in sprint planning or backlog grooming to identify security-relevant work?
- Are there regular touchpoints (e.g., office hours, embedded security engineers) between security and development teams?
- Is there a clear escalation path for developers to raise security concerns during development?
- Do security teams provide feedback on pull requests or design documents for security-sensitive features?

### Phase 4: Efficient Controls Assessment

#### 1. Design Your Secure Architecture

**Check Well-Architected Tool workloads:**
```bash
aws wellarchitected list-workloads --query 'WorkloadSummaries[].{WorkloadId:WorkloadId,WorkloadName:WorkloadName,RiskCounts:RiskCounts,ImprovementStatus:ImprovementStatus,UpdatedAt:UpdatedAt}' --output table 2>/dev/null || echo "No Well-Architected Tool workloads found"
```

**Check Well-Architected Tool lens reviews:**
```bash
for workload_id in $(aws wellarchitected list-workloads --query 'WorkloadSummaries[].WorkloadId' --output text 2>/dev/null); do
  echo "Workload: $workload_id"
  aws wellarchitected list-lens-reviews --workload-id "$workload_id" --query 'LensReviewSummaries[].{LensAlias:LensAlias,LensName:LensName,RiskCounts:RiskCounts,UpdatedAt:UpdatedAt}' --output table 2>/dev/null || echo "  No lens reviews found"
done
```

**Expected result:** At least one workload should be defined in the Well-Architected Tool with a completed lens review (e.g., AWS Well-Architected Framework, Security Pillar). Workloads should show recent `UpdatedAt` dates, confirming that architecture reviews are performed regularly. Risk counts should be tracked and trending downward over time. If no workloads exist, the organization is not using the Well-Architected Tool to systematically evaluate architecture decisions against AWS best practices. See remediation-workflow.md for remediation steps.

**Assessment questions:**
- Does the organization conduct formal architecture reviews for new workloads before deployment?
- Is the AWS Well-Architected Tool used to document and track architecture decisions?
- Are Well-Architected reviews performed periodically (e.g., annually) for existing workloads?
- Is there a defined process to remediate high-risk issues identified during architecture reviews?
- Are architecture review findings tracked and reported to leadership?

#### 2. Use Infrastructure as Code

**Check CloudFormation stack count:**
```bash
aws cloudformation list-stacks --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE --query 'StackSummaries[].{StackName:StackName,Status:StackStatus,CreationTime:CreationTime,LastUpdatedTime:LastUpdatedTime}' --output table 2>/dev/null || echo "No CloudFormation stacks found"
```

**Count CloudFormation stacks by status:**
```bash
aws cloudformation list-stacks --query 'StackSummaries[].StackStatus' --output text 2>/dev/null | tr '\t' '\n' | sort | uniq -c | sort -rn || echo "No CloudFormation stacks found"
```

**Check CodePipeline pipelines:**
```bash
aws codepipeline list-pipelines --query 'pipelines[].{Name:name,Created:created,Updated:updated}' --output table 2>/dev/null || echo "No CodePipeline pipelines found"
```

**Check CodePipeline pipeline execution status:**
```bash
for pipeline in $(aws codepipeline list-pipelines --query 'pipelines[].name' --output text 2>/dev/null); do
  echo "Pipeline: $pipeline"
  aws codepipeline get-pipeline-state --name "$pipeline" --query 'stageStates[].{Stage:stageName,Status:latestExecution.status}' --output table 2>/dev/null || echo "  Unable to retrieve pipeline state"
done
```

**Expected result:** CloudFormation stacks should be present, indicating that infrastructure is managed as code rather than created manually through the console. A healthy IaC practice shows multiple stacks in `CREATE_COMPLETE` or `UPDATE_COMPLETE` status with recent `LastUpdatedTime` dates. At least one CodePipeline pipeline should exist to automate infrastructure deployments. If no CloudFormation stacks are found, infrastructure may be provisioned manually, which leads to configuration drift, inconsistent environments, and difficulty reproducing or auditing changes. See remediation-workflow.md for remediation steps.

**Assessment questions:**
- What percentage of infrastructure is managed through Infrastructure as Code (CloudFormation, CDK, Terraform)?
- Are IaC templates stored in version control and subject to code review?
- Is there a CI/CD pipeline for deploying infrastructure changes?
- Are manual console changes tracked and reconciled with IaC definitions?
- Is there a policy prohibiting or limiting manual infrastructure changes in production?

#### 3. Tagging Strategy

**Check Tag Policies in Organizations:**
```bash
aws organizations list-policies --filter TAG_POLICY --query 'Policies[].{Id:Id,Name:Name,Description:Description}' --output table 2>/dev/null || echo "No Tag Policies found — AWS Organizations may not be enabled or Tag Policies are not configured"
```

**Inspect Tag Policy content:**
```bash
for policy_id in $(aws organizations list-policies --filter TAG_POLICY --query 'Policies[].Id' --output text 2>/dev/null); do
  echo "Tag Policy: $policy_id"
  aws organizations describe-policy --policy-id "$policy_id" --query 'Policy.{Name:PolicySummary.Name,Content:Content}' --output table 2>/dev/null || echo "  Unable to retrieve policy content"
done
```

**Check for untagged resources using Resource Groups Tag Editor:**
```bash
aws resourcegroupstaggingapi get-resources --query 'ResourceTagMappingList[?Tags==`[]`].{ResourceARN:ResourceARN}' --output table 2>/dev/null || echo "Unable to query Resource Groups Tagging API"
```

**Count resources by tag coverage:**
```bash
total=$(aws resourcegroupstaggingapi get-resources --query 'length(ResourceTagMappingList)' --output text 2>/dev/null || echo "0")
untagged=$(aws resourcegroupstaggingapi get-resources --query 'length(ResourceTagMappingList[?Tags==`[]`])' --output text 2>/dev/null || echo "0")
echo "Total resources: $total"
echo "Untagged resources: $untagged"
if [ "$total" -gt 0 ] 2>/dev/null; then
  echo "Tag coverage: $(( (total - untagged) * 100 / total ))%"
fi
```

**Expected result:** At least one Tag Policy should be defined in AWS Organizations, enforcing mandatory tags (e.g., `Environment`, `Owner`, `CostCenter`, `Application`) across all accounts. Tag Policies should specify allowed values for key tags to ensure consistency. The number of untagged resources should be minimal — ideally zero. High tag coverage (above 90%) indicates a mature tagging strategy. If no Tag Policies exist, there is no enforcement mechanism for consistent tagging, which undermines cost allocation, access control policies based on tags, and automated resource management. See remediation-workflow.md for remediation steps.

#### 4. Least Privilege Review

**Check IAM Access Analyzer analyzers:**
```bash
aws accessanalyzer list-analyzers --query 'analyzers[].{Name:name,Type:type,Status:status,CreatedAt:createdAt}' --output table 2>/dev/null || echo "IAM Access Analyzer is not available in this region"
```

**Check IAM Access Analyzer active findings count:**
```bash
analyzer_arn=$(aws accessanalyzer list-analyzers --query 'analyzers[0].arn' --output text 2>/dev/null)
if [ -n "$analyzer_arn" ] && [ "$analyzer_arn" != "None" ]; then
  aws accessanalyzer list-findings --analyzer-arn "$analyzer_arn" --filter '{"status":{"eq":["ACTIVE"]}}' --query 'length(findings)' --output text 2>/dev/null && echo "(count of active findings)"
else
  echo "No IAM Access Analyzer configured — cannot retrieve findings"
fi
```

**Check IAM Access Analyzer policy generation status:**
```bash
aws accessanalyzer list-policy-generations --query 'policyGenerations[].{JobId:jobId,PrincipalArn:principalArn,Status:status,StartedOn:startedOn,CompletedOn:completedOn}' --output table 2>/dev/null || echo "No policy generation jobs found — IAM Access Analyzer policy generation has not been used"
```

**Expected result:** At least one IAM Access Analyzer should exist with status `ACTIVE` and type `ACCOUNT` or `ORGANIZATION`. The active findings count should be zero or near zero — active findings indicate resources with policies that grant access to external principals, which may represent unintended public or cross-account exposure. Policy generation jobs should be present, indicating that the organization is using Access Analyzer to generate least-privilege policies based on actual access activity rather than manually authoring broad policies. If no analyzer exists, there is no automated mechanism to detect overly permissive resource policies. If policy generation has never been used, IAM policies are likely broader than necessary. See remediation-workflow.md for remediation steps.

#### 5. Customer IAM (Cognito)

**List Cognito user pools:**
```bash
aws cognito-idp list-user-pools --max-results 20 --query 'UserPools[].{Id:Id,Name:Name,CreationDate:CreationDate,LastModifiedDate:LastModifiedDate}' --output table 2>/dev/null || echo "No Cognito user pools found"
```

**Check Cognito user pool MFA configuration:**
```bash
for pool_id in $(aws cognito-idp list-user-pools --max-results 20 --query 'UserPools[].Id' --output text 2>/dev/null); do
  echo "User Pool: $pool_id"
  aws cognito-idp describe-user-pool --user-pool-id "$pool_id" --query 'UserPool.{Name:Name,MfaConfiguration:MfaConfiguration,SmsAuthenticationMessage:SmsAuthenticationMessage}' --output table 2>/dev/null || echo "  Unable to retrieve MFA configuration"
done
```

**Check Cognito user pool advanced security configuration:**
```bash
for pool_id in $(aws cognito-idp list-user-pools --max-results 20 --query 'UserPools[].Id' --output text 2>/dev/null); do
  echo "User Pool: $pool_id"
  aws cognito-idp describe-user-pool --user-pool-id "$pool_id" --query 'UserPool.{Name:Name,UserPoolAddOns:UserPoolAddOns}' --output table 2>/dev/null || echo "  Unable to retrieve advanced security configuration"
done
```

**Expected result:** Cognito user pools should have `MfaConfiguration` set to `ON` (enforced) or at minimum `OPTIONAL` (available but not required). Pools with `MfaConfiguration: OFF` leave customer accounts vulnerable to credential-stuffing and phishing attacks. Advanced security features (`UserPoolAddOns.AdvancedSecurityMode`) should be set to `ENFORCED` or `AUDIT` — this enables adaptive authentication, compromised credential detection, and risk-based authentication challenges. If no Cognito user pools exist, customer identity management may be handled by a different service or custom implementation, which should be evaluated separately. See remediation-workflow.md for remediation steps.

#### 6. Custom Threat Detection (Security Lake)

**Check Security Lake status:**
```bash
aws securitylake get-data-lake-sources --query 'dataLakeSources[].{Account:account,SourceName:sourceName}' --output table 2>/dev/null || echo "Security Lake is not enabled in this region"
```

**Check Security Lake organization configuration:**
```bash
aws securitylake get-data-lake-organization-configuration --query 'autoEnableNewAccount[].{Region:region,Sources:sources}' --output table 2>/dev/null || echo "Security Lake organization configuration is not available — Security Lake may not be enabled or this is not the delegated administrator account"
```

**List Security Lake subscribers:**
```bash
aws securitylake list-subscribers --query 'subscribers[].{SubscriberName:subscriberName,SubscriberId:subscriberId,AccessTypes:accessTypes,Sources:sources[].sourceName,CreatedAt:createdAt}' --output table 2>/dev/null || echo "No Security Lake subscribers found — Security Lake may not be enabled"
```

**Check Security Lake subscriber notification configuration:**
```bash
for subscriber_id in $(aws securitylake list-subscribers --query 'subscribers[].subscriberId' --output text 2>/dev/null); do
  echo "Subscriber: $subscriber_id"
  aws securitylake get-subscriber --subscriber-id "$subscriber_id" --query 'subscriber.{Name:subscriberName,AccessTypes:accessTypes,Status:subscriberStatus}' --output table 2>/dev/null || echo "  Unable to retrieve subscriber details"
done
```

**Expected result:** Security Lake should be enabled with data sources configured (CloudTrail, VPC Flow Logs, Route 53 DNS logs, Security Hub findings, etc.). At least one subscriber should exist, indicating that a SIEM or analytics tool is consuming the normalized security data for custom threat detection and correlation. Subscribers should show `ACTIVE` status with appropriate access types (`S3` for batch analysis or `LAKEFORMATION` for direct query access). If Security Lake is not enabled, security logs remain siloed across individual services, making cross-service threat correlation and custom detection rules difficult to implement. If no subscribers exist, the centralized security data lake is not being consumed for analysis. See remediation-workflow.md for remediation steps.

#### 7. Security Champions Program

**Assessment questions:**
- Has the organization identified security champions within each development team or business unit?
- Do security champions receive dedicated security training beyond what is provided to general engineering staff?
- Are security champions' responsibilities formally defined (e.g., triaging security findings, reviewing security-sensitive code, advocating for secure design)?
- Is there a regular cadence for security champion meetings or knowledge-sharing sessions?
- Do security champions have a direct communication channel with the central security team?
- Are security champion contributions recognized and measured (e.g., findings triaged, training delivered, reviews completed)?
- Is there a process to onboard new security champions when team composition changes?

#### 8. DevSecOps Pipeline

**Check CodePipeline pipelines for security stages:**
```bash
for pipeline in $(aws codepipeline list-pipelines --query 'pipelines[].name' --output text 2>/dev/null); do
  echo "Pipeline: $pipeline"
  aws codepipeline get-pipeline --name "$pipeline" --query 'pipeline.stages[].{StageName:name,Actions:actions[].{Name:name,Category:actionTypeId.category,Provider:actionTypeId.provider}}' --output table 2>/dev/null || echo "  Unable to retrieve pipeline details"
done
```

**Check CodeBuild projects for security scanning actions:**
```bash
aws codebuild list-projects --query 'projects[]' --output text 2>/dev/null | tr '\t' '\n' | while read project; do
  echo "Project: $project"
  aws codebuild batch-get-projects --names "$project" --query 'projects[].{Name:name,Source:source.type,BuildSpec:source.buildspec,Environment:environment.image}' --output table 2>/dev/null || echo "  Unable to retrieve project details"
done
```

**Check ECR image scan-on-push settings:**
```bash
for repo in $(aws ecr describe-repositories --query 'repositories[].repositoryName' --output text 2>/dev/null); do
  echo "Repository: $repo"
  aws ecr describe-repositories --repository-names "$repo" --query 'repositories[].{Name:repositoryName,ScanOnPush:imageScanningConfiguration.scanOnPush,TagImmutability:imageTagMutability}' --output table 2>/dev/null
done
```

**Check ECR scan findings for recent images:**
```bash
for repo in $(aws ecr describe-repositories --query 'repositories[].repositoryName' --output text 2>/dev/null); do
  latest_tag=$(aws ecr describe-images --repository-name "$repo" --query 'sort_by(imageDetails,&imagePushedAt)[-1].imageTags[0]' --output text 2>/dev/null)
  if [ -n "$latest_tag" ] && [ "$latest_tag" != "None" ]; then
    echo "Repository: $repo (tag: $latest_tag)"
    aws ecr describe-image-scan-findings --repository-name "$repo" --image-id imageTag="$latest_tag" --query 'imageScanFindings.findingSeverityCounts' --output table 2>/dev/null || echo "  No scan findings available"
  fi
done
```

**Expected result:** CodePipeline pipelines should include stages or actions for security scanning (e.g., SAST, dependency checks, container image scanning) integrated into the build or test phases. CodeBuild projects should reference build specifications that include security scanning tools. All ECR repositories should have `ScanOnPush: true` enabled, and `TagImmutability` should be set to `IMMUTABLE` to prevent image tag overwriting. Scan findings for recent images should show zero CRITICAL and zero HIGH vulnerabilities. If pipelines lack security stages, vulnerabilities may reach production undetected. If ECR scan-on-push is disabled, container images are not automatically scanned for known vulnerabilities at push time. See remediation-workflow.md for remediation steps.

#### 9. Image Generation Pipeline

**Check EC2 Image Builder pipelines:**
```bash
aws imagebuilder list-image-pipelines --query 'imagePipelineList[].{Name:name,Arn:arn,Status:status,Platform:platform,DateCreated:dateCreated,DateLastRun:dateLastRun}' --output table 2>/dev/null || echo "No EC2 Image Builder pipelines found"
```

**Check EC2 Image Builder image recipes:**
```bash
aws imagebuilder list-image-recipes --query 'imageRecipeSummaryList[].{Name:name,Arn:arn,Platform:platform,ParentImage:parentImage,DateCreated:dateCreated}' --output table 2>/dev/null || echo "No EC2 Image Builder recipes found"
```

**Check EC2 Image Builder components (security hardening):**
```bash
aws imagebuilder list-components --owner Self --query 'componentVersionList[].{Name:name,Platform:platform,Type:type,DateCreated:dateCreated}' --output table 2>/dev/null || echo "No custom Image Builder components found"
```

**Check AMI creation dates for staleness:**
```bash
aws ec2 describe-images --owners self --query 'Images[].{ImageId:ImageId,Name:Name,CreationDate:CreationDate,State:State,Platform:PlatformDetails}' --output table 2>/dev/null || echo "No custom AMIs found"
```

**Check for AMIs older than 90 days:**
```bash
cutoff_date=$(date -d '90 days ago' '+%Y-%m-%d' 2>/dev/null || date -v-90d '+%Y-%m-%d' 2>/dev/null)
if [ -n "$cutoff_date" ]; then
  aws ec2 describe-images --owners self --query "Images[?CreationDate<'${cutoff_date}'].{ImageId:ImageId,Name:Name,CreationDate:CreationDate}" --output table 2>/dev/null || echo "No stale AMIs found"
else
  echo "Unable to calculate cutoff date — manually review AMI creation dates above"
fi
```

**Expected result:** At least one EC2 Image Builder pipeline should exist with a recent `DateLastRun`, confirming that golden images are being built and refreshed regularly. Image recipes should reference hardened base images and include security-related components (e.g., CIS benchmarks, patching, agent installation). Custom AMIs should have recent creation dates — AMIs older than 90 days may contain unpatched vulnerabilities and outdated software. If no Image Builder pipelines exist, AMIs may be created manually or not refreshed regularly, leading to configuration drift and unpatched base images across the fleet. See remediation-workflow.md for remediation steps.

#### 10. Anti-Malware / EDR / Runtime Protection

**Check GuardDuty Runtime Monitoring status:**
```bash
for detector_id in $(aws guardduty list-detectors --query 'DetectorIds[]' --output text 2>/dev/null); do
  echo "Detector: $detector_id"
  aws guardduty get-detector --detector-id $detector_id --query '{RuntimeMonitoring:Features[?Name==`RUNTIME_MONITORING`].{Status:Status,EKSAddonManagement:AdditionalConfiguration[?Name==`EKS_ADDON_MANAGEMENT`].Status|[0],ECSFargateAgent:AdditionalConfiguration[?Name==`ECS_FARGATE_AGENT_MANAGEMENT`].Status|[0],EC2Agent:AdditionalConfiguration[?Name==`EC2_AGENT_MANAGEMENT`].Status|[0]}}' --output table 2>/dev/null || echo "  Unable to retrieve Runtime Monitoring status"
done
```

**Check GuardDuty ECS runtime coverage:**
```bash
for detector_id in $(aws guardduty list-detectors --query 'DetectorIds[]' --output text 2>/dev/null); do
  echo "Detector: $detector_id"
  aws guardduty list-coverage --detector-id "$detector_id" --filter-criteria '{"filterCriterion":[{"criterionKey":"RESOURCE_TYPE","filterCondition":{"equalsValue":"ECS"}}]}' --query 'resources[].{ResourceId:resourceId,CoverageStatus:coverageStatus,Issue:issue}' --output table 2>/dev/null || echo "  No ECS runtime coverage data available"
done
```

**Check GuardDuty EKS runtime coverage:**
```bash
for detector_id in $(aws guardduty list-detectors --query 'DetectorIds[]' --output text 2>/dev/null); do
  echo "Detector: $detector_id"
  aws guardduty list-coverage --detector-id "$detector_id" --filter-criteria '{"filterCriterion":[{"criterionKey":"RESOURCE_TYPE","filterCondition":{"equalsValue":"EKS"}}]}' --query 'resources[].{ResourceId:resourceId,CoverageStatus:coverageStatus,Issue:issue}' --output table 2>/dev/null || echo "  No EKS runtime coverage data available"
done
```

**Check GuardDuty EC2 runtime coverage:**
```bash
for detector_id in $(aws guardduty list-detectors --query 'DetectorIds[]' --output text 2>/dev/null); do
  echo "Detector: $detector_id"
  aws guardduty list-coverage --detector-id "$detector_id" --filter-criteria '{"filterCriterion":[{"criterionKey":"RESOURCE_TYPE","filterCondition":{"equalsValue":"EC2"}}]}' --query 'resources[].{ResourceId:resourceId,CoverageStatus:coverageStatus,Issue:issue}' --output table 2>/dev/null || echo "  No EC2 runtime coverage data available"
done
```

**Expected result:** GuardDuty Runtime Monitoring should show `Status: ENABLED` with agent management enabled for EKS, ECS Fargate, and EC2 workloads. Coverage resources should show `CoverageStatus: HEALTHY` for all monitored workloads — any `UNHEALTHY` status indicates the GuardDuty security agent is not properly deployed or communicating. Runtime Monitoring provides OS-level visibility into process execution, network connections, and file access, enabling detection of malware, cryptomining, container escape attempts, and other runtime threats that network-level monitoring cannot detect. If Runtime Monitoring is not enabled, there is no agent-based threat detection for compute workloads, leaving a significant gap in defense against post-exploitation activity. See remediation-workflow.md for remediation steps.

#### 11. Outbound Traffic Control

**Check NAT gateways:**
```bash
aws ec2 describe-nat-gateways --query 'NatGateways[].{NatGatewayId:NatGatewayId,VpcId:VpcId,SubnetId:SubnetId,State:State,ConnectivityType:ConnectivityType}' --output table 2>/dev/null || echo "No NAT gateways found"
```

**Check Network Firewall deployments:**
```bash
aws network-firewall list-firewalls --query 'Firewalls[].{FirewallName:FirewallName,FirewallArn:FirewallArn}' --output table 2>/dev/null || echo "No Network Firewall deployments found"
```

**Check Network Firewall policies:**
```bash
for fw_name in $(aws network-firewall list-firewalls --query 'Firewalls[].FirewallName' --output text 2>/dev/null); do
  echo "Firewall: $fw_name"
  aws network-firewall describe-firewall --firewall-name "$fw_name" --query 'Firewall.{FirewallName:FirewallName,VpcId:VpcId,FirewallPolicyArn:FirewallPolicyArn,SubnetMappings:SubnetMappings[].SubnetId}' --output table 2>/dev/null || echo "  Unable to retrieve firewall details"
done
```

**Check Network Firewall rule groups:**
```bash
aws network-firewall list-rule-groups --query 'RuleGroups[].{Name:Name,Arn:Arn,Type:Type}' --output table 2>/dev/null || echo "No Network Firewall rule groups found"
```

**Check VPC egress-only internet gateways (IPv6):**
```bash
aws ec2 describe-egress-only-internet-gateways --query 'EgressOnlyInternetGateways[].{EgressOnlyIgwId:EgressOnlyInternetGatewayId,Attachments:Attachments[].{VpcId:VpcId,State:State}}' --output table 2>/dev/null || echo "No egress-only internet gateways found"
```

**Check route tables for outbound traffic paths:**
```bash
aws ec2 describe-route-tables --query 'RouteTables[].{RouteTableId:RouteTableId,VpcId:VpcId,NATRoutes:Routes[?NatGatewayId!=`null`].{Destination:DestinationCidrBlock,NatGateway:NatGatewayId},FWRoutes:Routes[?starts_with(VpcEndpointId||``,`vpce-`)].{Destination:DestinationCidrBlock,Endpoint:VpcEndpointId}}' --output table 2>/dev/null || echo "Unable to retrieve route table details"
```

**Expected result:** NAT gateways should be present in public subnets to provide controlled outbound internet access for private subnets. For environments requiring deep packet inspection and domain-based filtering, AWS Network Firewall should be deployed with firewall policies and rule groups that restrict outbound traffic to approved destinations. Network Firewall rule groups should include stateful rules for domain allow-listing or protocol-based filtering. Egress-only internet gateways should be configured for VPCs using IPv6 to allow outbound-only IPv6 traffic. Route tables should show private subnet traffic routed through NAT gateways or Network Firewall endpoints rather than directly through internet gateways. If no NAT gateways or Network Firewall deployments exist, private subnets either lack internet access (potentially breaking updates and API calls) or route traffic through unrestricted paths. Without outbound traffic filtering, compromised instances can freely communicate with command-and-control servers and exfiltrate data. See remediation-workflow.md for remediation steps.

#### 12. Discover Sensitive Data

**Check Macie enablement:**
```bash
aws macie2 get-macie-session --query '{Status:status,CreatedAt:createdAt,ServiceRole:serviceRole}' --output table 2>/dev/null || echo "Amazon Macie is not enabled in this region"
```

**Check Macie classification jobs:**
```bash
aws macie2 list-classification-jobs --query 'items[].{JobId:jobId,Name:name,JobType:jobType,JobStatus:jobStatus,CreatedAt:createdAt}' --output table 2>/dev/null || echo "Amazon Macie is not enabled — cannot list classification jobs"
```

**Check Macie classification job details:**
```bash
for job_id in $(aws macie2 list-classification-jobs --query 'items[].jobId' --output text 2>/dev/null); do
  echo "Job: $job_id"
  aws macie2 describe-classification-job --job-id "$job_id" --query '{Name:name,JobType:jobType,JobStatus:jobStatus,S3BucketCount:s3JobDefinition.bucketDefinitions|length(@),ManagedDataIdentifiers:managedDataIdentifierSelector}' --output table 2>/dev/null || echo "  Unable to retrieve job details"
done
```

**Check Macie finding counts by severity:**
```bash
aws macie2 get-finding-statistics --group-by "severity.description" --query 'countsBySeverity[].{Severity:groupKey,Count:count}' --output table 2>/dev/null || echo "Amazon Macie is not enabled — cannot retrieve finding statistics"
```

**Check Macie finding counts by type:**
```bash
aws macie2 get-finding-statistics --group-by "type" --query 'countsBySeverity[].{FindingType:groupKey,Count:count}' --output table 2>/dev/null || echo "Amazon Macie is not enabled — cannot retrieve finding statistics"
```

**Expected result:** Amazon Macie should be enabled (status `ENABLED`) with at least one classification job in `RUNNING` or `COMPLETE` status. Classification jobs should target S3 buckets containing potentially sensitive data and use managed data identifiers for PII, financial data, and credentials. Finding statistics should be reviewed regularly — a high count of HIGH or CRITICAL severity findings indicates sensitive data exposure that requires immediate remediation. If Macie is enabled but no classification jobs exist, sensitive data discovery is not being performed proactively. If finding counts are unknown, the organization has no visibility into where sensitive data resides in S3, increasing the risk of data breaches and regulatory non-compliance (GDPR, HIPAA, PCI-DSS). See remediation-workflow.md for remediation steps.

#### 13. Perform Threat Modeling

**Assessment questions:**
- Does the organization perform threat modeling for new applications and significant changes to existing systems?
- What threat modeling methodology is used (e.g., STRIDE, PASTA, Attack Trees, LINDDUN)?
- How frequently are threat models reviewed and updated (e.g., per release, quarterly, annually)?
- Are threat modeling results documented and tracked as actionable findings?
- Are development teams trained on threat modeling techniques?
- Is there a defined process to prioritize and remediate threats identified during threat modeling?
- Are threat models reviewed by the security team before major architectural decisions?
- Does the organization maintain a catalog of common threats and mitigations specific to its technology stack?

#### 14. WAF with Custom Rules

**List WAF rule groups (Regional):**
```bash
aws wafv2 list-rule-groups --scope REGIONAL --query 'RuleGroups[].{Name:Name,Id:Id,ARN:ARN}' --output table 2>/dev/null || echo "No regional WAF rule groups found"
```

**List WAF rule groups (CloudFront):**
```bash
aws wafv2 list-rule-groups --scope CLOUDFRONT --region us-east-1 --query 'RuleGroups[].{Name:Name,Id:Id,ARN:ARN}' --output table 2>/dev/null || echo "No CloudFront WAF rule groups found"
```

**Check Web ACLs for custom rules beyond managed rule sets:**
```bash
for acl_arn in $(aws wafv2 list-web-acls --scope REGIONAL --query 'WebACLs[].ARN' --output text 2>/dev/null); do
  acl_name=$(echo "$acl_arn" | awk -F'/' '{print $NF}')
  echo "Web ACL: $acl_name"
  aws wafv2 get-web-acl --scope REGIONAL --name "$acl_name" --id "$(echo "$acl_arn" | awk -F'/' '{print $(NF-1)}')" --query 'WebACL.Rules[].{Name:Name,Priority:Priority,ManagedRuleGroup:Statement.ManagedRuleGroupStatement.Name,CustomRule:Statement.RateBasedStatement||Statement.ByteMatchStatement||Statement.RegexPatternSetReferenceStatement||Statement.IPSetReferenceStatement}' --output table 2>/dev/null || echo "  Unable to retrieve Web ACL details"
done
```

**Check CloudFront Web ACLs for custom rules:**
```bash
for acl_arn in $(aws wafv2 list-web-acls --scope CLOUDFRONT --region us-east-1 --query 'WebACLs[].ARN' --output text 2>/dev/null); do
  acl_name=$(echo "$acl_arn" | awk -F'/' '{print $NF}')
  echo "Web ACL: $acl_name"
  aws wafv2 get-web-acl --scope CLOUDFRONT --region us-east-1 --name "$acl_name" --id "$(echo "$acl_arn" | awk -F'/' '{print $(NF-1)}')" --query 'WebACL.Rules[].{Name:Name,Priority:Priority,ManagedRuleGroup:Statement.ManagedRuleGroupStatement.Name,CustomRule:Statement.RateBasedStatement||Statement.ByteMatchStatement||Statement.RegexPatternSetReferenceStatement||Statement.IPSetReferenceStatement}' --output table 2>/dev/null || echo "  Unable to retrieve Web ACL details"
done
```

**List available managed rule groups for comparison:**
```bash
aws wafv2 list-available-managed-rule-groups --scope REGIONAL --query 'ManagedRuleGroups[].{Vendor:VendorName,Name:Name}' --output table 2>/dev/null || echo "Unable to list managed rule groups"
```

**Expected result:** At least one custom WAF rule group should exist (Regional or CloudFront scope), indicating that the organization has implemented application-specific WAF rules beyond the AWS Managed Rule Sets. Web ACLs should contain a mix of managed rule groups (e.g., AWSManagedRulesCommonRuleSet, AWSManagedRulesSQLiRuleSet) and custom rules (rate-based rules, IP set rules, regex pattern rules, or byte match rules) tailored to the application's threat profile. If only managed rule groups are present with no custom rules, the WAF configuration provides generic protection but does not address application-specific attack patterns such as business logic abuse, API rate limiting, or geo-based restrictions. Custom rules demonstrate a mature WAF posture where the organization actively tunes protections based on observed traffic patterns and threat intelligence. See remediation-workflow.md for remediation steps.

#### 15. Advanced DDoS Mitigation

**Check Shield Advanced subscription status:**
```bash
aws shield describe-subscription --query 'Subscription.{StartTime:StartTime,EndTime:EndTime,AutoRenew:AutoRenew,ProactiveEngagementStatus:ProactiveEngagementStatus}' --output table 2>/dev/null || echo "AWS Shield Advanced is not enabled — only Shield Standard (free) is active"
```

**List Shield Advanced protected resources:**
```bash
aws shield list-protections --query 'Protections[].{Id:Id,Name:Name,ResourceArn:ResourceArn}' --output table 2>/dev/null || echo "AWS Shield Advanced is not enabled — cannot list protected resources"
```

**Check Shield Advanced protection details:**
```bash
for protection_id in $(aws shield list-protections --query 'Protections[].Id' --output text 2>/dev/null); do
  echo "Protection: $protection_id"
  aws shield describe-protection --protection-id "$protection_id" --query 'Protection.{Name:Name,ResourceArn:ResourceArn,HealthCheckIds:HealthCheckIds}' --output table 2>/dev/null || echo "  Unable to retrieve protection details"
done
```

**Check Shield Advanced emergency contact list:**
```bash
aws shield describe-emergency-contact-settings --query 'EmergencyContactList[].{Email:EmailAddress,Phone:PhoneNumber,Notes:ContactNotes}' --output table 2>/dev/null || echo "AWS Shield Advanced is not enabled — cannot retrieve emergency contacts"
```

**Check Shield Advanced DDoS response team (DRT) access:**
```bash
aws shield describe-drt-access --query '{RoleArn:RoleArn,LogBucketList:LogBucketList}' --output table 2>/dev/null || echo "AWS Shield Advanced is not enabled or DRT access is not configured"
```

**Expected result:** Shield Advanced subscription should be active with `AutoRenew: ENABLED` and `ProactiveEngagementStatus: ENABLED` for maximum DDoS protection. Protected resources should include all internet-facing resources (CloudFront distributions, Application Load Balancers, Elastic IPs, Global Accelerator accelerators, Route 53 hosted zones). Each protection should have associated Route 53 health checks for proactive engagement. Emergency contacts should be configured so the AWS Shield Response Team (SRT) can reach the organization during an active DDoS event. DRT access should be configured with an IAM role and log bucket list to allow the SRT to investigate and mitigate attacks on your behalf. If Shield Advanced is not enabled, the organization relies solely on Shield Standard, which provides basic DDoS protection but lacks advanced mitigation, cost protection, and access to the SRT. If protections exist but lack health checks, proactive engagement cannot function effectively. See remediation-workflow.md for remediation steps.

#### 16. Run TableTop Exercises

**Assessment questions:**
- Does the organization conduct tabletop exercises for security incident scenarios?
- How frequently are tabletop exercises performed (e.g., annually, semi-annually, quarterly)?
- Do tabletop exercises cover a range of scenarios (e.g., ransomware, data breach, account compromise, insider threat, DDoS)?
- Are tabletop exercises facilitated by an independent party or internal security team?
- Do exercises include participants from all relevant teams (security, engineering, legal, communications, executive leadership)?
- Are findings and action items from tabletop exercises documented and tracked to completion?
- Has the organization conducted a tabletop exercise within the last 12 months?
- Are lessons learned from real incidents incorporated into future tabletop scenarios?

**Expected result:** The organization should conduct tabletop exercises at least annually, covering multiple incident scenarios. Exercises should involve cross-functional participation and produce documented action items that are tracked to completion. If no tabletop exercises have been conducted, the organization has not validated its incident response procedures under simulated conditions, increasing the risk of confusion and delays during a real incident.

#### 17. Automate Critical Playbooks

**Check Systems Manager Automation documents:**
```bash
aws ssm list-documents --document-filter-list key=DocumentType,value=Automation --query 'DocumentIdentifiers[].{Name:Name,Owner:Owner,DocumentVersion:DocumentVersion}' --output table 2>/dev/null || echo "Unable to list SSM Automation documents"
```

**Check for custom (self-owned) Automation documents:**
```bash
aws ssm list-documents --document-filter-list key=DocumentType,value=Automation key=Owner,value=Self --query 'DocumentIdentifiers[].{Name:Name,DocumentVersion:DocumentVersion,PlatformTypes:PlatformTypes|join(`, `,@)}' --output table 2>/dev/null || echo "No custom SSM Automation documents found"
```

**Check EventBridge rules targeting remediation actions:**
```bash
aws events list-rules --query 'Rules[].{Name:Name,State:State,Description:Description}' --output table 2>/dev/null || echo "Unable to list EventBridge rules"
```

**Check EventBridge rules targeting SSM Automation:**
```bash
for rule_name in $(aws events list-rules --query 'Rules[].Name' --output text 2>/dev/null); do
  targets=$(aws events list-targets-by-rule --rule "$rule_name" --query 'Targets[?contains(Arn,`automation`)].{Id:Id,Arn:Arn}' --output text 2>/dev/null)
  if [ -n "$targets" ]; then
    echo "Rule: $rule_name -> $targets"
  fi
done
```

**Check EventBridge rules targeting Lambda remediation functions:**
```bash
for rule_name in $(aws events list-rules --query 'Rules[].Name' --output text 2>/dev/null); do
  targets=$(aws events list-targets-by-rule --rule "$rule_name" --query 'Targets[?contains(Arn,`lambda`)].{Id:Id,Arn:Arn}' --output text 2>/dev/null)
  if [ -n "$targets" ]; then
    echo "Rule: $rule_name -> $targets"
  fi
done
```

**Expected result:** At least several custom SSM Automation documents (Owner: `Self`) should exist, indicating the organization has codified incident response playbooks as automated runbooks. EventBridge rules should be configured to trigger SSM Automation or Lambda functions in response to security events (e.g., GuardDuty findings, Security Hub findings, Config compliance changes). If no custom Automation documents exist, playbooks are manual and depend on human execution speed during incidents. If no EventBridge rules target remediation actions, security events require manual triage and response, increasing mean time to respond (MTTR). See remediation-workflow.md for remediation steps.

#### 18. Security Investigations

**Check Amazon Detective enablement:**
```bash
aws detective list-graphs --query 'GraphList[].{GraphArn:Arn,CreatedTime:CreatedTime}' --output table 2>/dev/null || echo "Amazon Detective is not enabled in this region"
```

**Check Amazon Detective member accounts:**
```bash
graph_arn=$(aws detective list-graphs --query 'GraphList[0].Arn' --output text 2>/dev/null)
if [ -n "$graph_arn" ] && [ "$graph_arn" != "None" ]; then
  aws detective list-members --graph-arn "$graph_arn" --query 'MemberDetails[].{AccountId:AccountId,Status:Status,InvitedTime:InvitedTime}' --output table 2>/dev/null || echo "Unable to list Detective members"
else
  echo "Amazon Detective is not enabled — no behavior graph found"
fi
```

**Check CloudTrail Lake event data stores:**
```bash
aws cloudtrail list-event-data-stores --query 'EventDataStores[].{Name:Name,Status:Status,RetentionPeriod:RetentionPeriod,CreatedTimestamp:CreatedTimestamp}' --output table 2>/dev/null || echo "No CloudTrail Lake event data stores found"
```

**Check CloudTrail Lake saved queries:**
```bash
aws cloudtrail list-queries --event-data-store $(aws cloudtrail list-event-data-stores --query 'EventDataStores[0].EventDataStoreArn' --output text 2>/dev/null) --query 'Queries[].{QueryId:QueryId,QueryStatus:QueryStatus,CreationTime:CreationTime}' --output table 2>/dev/null || echo "No CloudTrail Lake event data store found — cannot list queries"
```

**Expected result:** Amazon Detective should be enabled with an active behavior graph, providing automated investigation capabilities that correlate GuardDuty findings, CloudTrail logs, and VPC Flow Logs into a unified security graph. Member accounts should be invited and active for multi-account investigation coverage. CloudTrail Lake should have at least one event data store with status `ENABLED`, providing SQL-based query capability over CloudTrail events for forensic investigations. If Detective is not enabled, security investigations require manual correlation across multiple log sources, significantly increasing investigation time. If CloudTrail Lake is not configured, historical event analysis is limited to S3-based log file searches, which are slower and less flexible than SQL queries. See remediation-workflow.md for remediation steps.

#### 19. Create Your Compliance Reports

**Check Security Hub compliance standards scores:**
```bash
aws securityhub get-enabled-standards --query 'StandardsSubscriptions[].{StandardArn:StandardsSubscriptionArn,Status:StandardsStatus}' --output table 2>/dev/null || echo "Security Hub is not enabled — cannot list compliance standards"
```

**Check Security Hub compliance summary by standard:**
```bash
for standard_arn in $(aws securityhub get-enabled-standards --query 'StandardsSubscriptions[].StandardsSubscriptionArn' --output text 2>/dev/null); do
  echo "Standard: $standard_arn"
  passed=$(aws securityhub get-findings --filters "{\"ComplianceStatus\":[{\"Value\":\"PASSED\",\"Comparison\":\"EQUALS\"}],\"ProductFields\":[{\"Key\":\"StandardsArn\",\"Value\":\"$standard_arn\",\"Comparison\":\"EQUALS\"}],\"RecordState\":[{\"Value\":\"ACTIVE\",\"Comparison\":\"EQUALS\"}]}" --query 'length(Findings)' --output text 2>/dev/null)
  failed=$(aws securityhub get-findings --filters "{\"ComplianceStatus\":[{\"Value\":\"FAILED\",\"Comparison\":\"EQUALS\"}],\"ProductFields\":[{\"Key\":\"StandardsArn\",\"Value\":\"$standard_arn\",\"Comparison\":\"EQUALS\"}],\"RecordState\":[{\"Value\":\"ACTIVE\",\"Comparison\":\"EQUALS\"}]}" --query 'length(Findings)' --output text 2>/dev/null)
  echo "  PASSED: ${passed:-N/A} | FAILED: ${failed:-N/A}"
done
```

**Check AWS Audit Manager assessment status:**
```bash
aws auditmanager list-assessments --query 'assessmentMetadata[].{Name:name,Status:status,ComplianceType:complianceType,CreationTime:creationTime}' --output table 2>/dev/null || echo "AWS Audit Manager is not enabled or no assessments configured"
```

**Check Audit Manager assessment frameworks:**
```bash
aws auditmanager list-assessment-frameworks --framework-type Custom --query 'frameworkMetadataList[].{Name:name,Type:type,ComplianceType:complianceType}' --output table 2>/dev/null || echo "No custom Audit Manager frameworks found"
```

**Check Audit Manager evidence collection status:**
```bash
for assessment_id in $(aws auditmanager list-assessments --query 'assessmentMetadata[].id' --output text 2>/dev/null); do
  echo "Assessment: $assessment_id"
  aws auditmanager get-assessment --assessment-id "$assessment_id" --query 'assessment.metadata.{Name:name,Status:status,Scope:scope.awsAccounts|length(@)}' --output table 2>/dev/null || echo "  Unable to retrieve assessment details"
done
```

**Expected result:** Security Hub should have at least one compliance standard enabled (e.g., AWS Foundational Security Best Practices, CIS AWS Foundations Benchmark, PCI-DSS) with a high ratio of PASSED to FAILED findings. AWS Audit Manager should have at least one active assessment configured, with evidence collection running against the relevant compliance framework. Custom frameworks indicate the organization has tailored compliance requirements beyond standard templates. If no Audit Manager assessments exist, compliance evidence gathering is manual and audit-preparation is reactive rather than continuous. If Security Hub compliance scores show a high number of FAILED findings, there is significant configuration drift from compliance baselines. See remediation-workflow.md for remediation steps.

#### 20. Disaster Recovery Plan

**Check cross-region replication for S3:**
```bash
for bucket in $(aws s3api list-buckets --query 'Buckets[].Name' --output text 2>/dev/null); do
  replication=$(aws s3api get-bucket-replication --bucket "$bucket" --query 'ReplicationConfiguration.Rules[].{Status:Status,Destination:Destination.Bucket}' --output table 2>/dev/null)
  if [ -n "$replication" ]; then
    echo "Bucket: $bucket"
    echo "$replication"
  fi
done || echo "Unable to check S3 replication configurations"
```

**Check cross-region replication for RDS:**
```bash
aws rds describe-db-instances --query 'DBInstances[?ReadReplicaDBInstanceIdentifiers!=`[]`].{DBInstance:DBInstanceIdentifier,Engine:Engine,ReadReplicas:ReadReplicaDBInstanceIdentifiers|join(`, `,@)}' --output table 2>/dev/null || echo "No RDS instances with read replicas found"
```

**Check cross-region replication for DynamoDB:**
```bash
for table in $(aws dynamodb list-tables --query 'TableNames[]' --output text 2>/dev/null); do
  replicas=$(aws dynamodb describe-table --table-name "$table" --query 'Table.Replicas[].{Region:RegionName,Status:ReplicaStatus}' --output table 2>/dev/null)
  if [ -n "$replicas" ]; then
    echo "Table: $table"
    echo "$replicas"
  fi
done || echo "Unable to check DynamoDB global tables"
```

**Check Route 53 health checks:**
```bash
aws route53 list-health-checks --query 'HealthChecks[].{Id:Id,Type:HealthCheckConfig.Type,FQDN:HealthCheckConfig.FullyQualifiedDomainName,IPAddress:HealthCheckConfig.IPAddress,Port:HealthCheckConfig.Port}' --output table 2>/dev/null || echo "No Route 53 health checks configured"
```

**Check Route 53 failover records:**
```bash
for zone_id in $(aws route53 list-hosted-zones --query 'HostedZones[].Id' --output text 2>/dev/null | sed 's|/hostedzone/||g'); do
  failover=$(aws route53 list-resource-record-sets --hosted-zone-id "$zone_id" --query 'ResourceRecordSets[?Failover!=`null`].{Name:Name,Type:Type,Failover:Failover,HealthCheckId:HealthCheckId}' --output table 2>/dev/null)
  if [ -n "$failover" ]; then
    echo "Hosted Zone: $zone_id"
    echo "$failover"
  fi
done || echo "No Route 53 failover records found"
```

**Expected result:** Critical data stores should have cross-region replication configured — S3 buckets with replication rules in `Enabled` status, RDS instances with cross-region read replicas, and DynamoDB global tables with replicas in the DR region. Route 53 should have health checks monitoring the availability of primary endpoints, and failover routing records should be configured to redirect traffic to the DR region when health checks fail. If no cross-region replication is configured, a regional outage could result in data loss. If no Route 53 health checks or failover records exist, there is no automated DNS failover mechanism, requiring manual intervention to redirect traffic during a disaster. See remediation-workflow.md for remediation steps.

**Assessment questions:**
- Does the organization have a documented Disaster Recovery (DR) plan?
- Does the DR plan define Recovery Time Objective (RTO) and Recovery Point Objective (RPO) for critical workloads?
- Has the DR plan been tested within the last 12 months?
- Does the DR plan cover all critical workloads and data stores?
- Are DR procedures automated (e.g., infrastructure-as-code for DR region deployment)?
- Is there a documented communication plan for disaster scenarios?
- Are DR roles and responsibilities clearly assigned?
- Does the organization conduct regular DR drills to validate failover and failback procedures?

### Phase 5: Optimized Controls Assessment

#### 1. Sharing Security Work and Responsibility

**Assessment questions:**
- Does the organization have a formal model for shared security ownership across teams (e.g., security champions, embedded security engineers)?
- Are security responsibilities clearly documented and assigned for each workload or product team?
- Is there a cross-functional security governance committee or working group that meets regularly?
- Do application teams have defined security objectives or KPIs that they are accountable for?
- Is there a documented RACI matrix for security responsibilities across development, operations, and security teams?
- Are security review outcomes shared transparently across teams to promote collective learning?
- Does the organization measure and report on the distribution of security work across teams?

#### 2. IAM Data Perimeters

**Check VPC endpoint policies:**
```bash
for endpoint_id in $(aws ec2 describe-vpc-endpoints --query 'VpcEndpoints[].VpcEndpointId' --output text 2>/dev/null); do
  echo "Endpoint: $endpoint_id"
  aws ec2 describe-vpc-endpoints --vpc-endpoint-ids "$endpoint_id" --query 'VpcEndpoints[].{EndpointId:VpcEndpointId,ServiceName:ServiceName,PolicyDocument:PolicyDocument}' --output table 2>/dev/null || echo "  Unable to retrieve endpoint policy"
done
```

**Check S3 bucket policies for aws:PrincipalOrgID condition keys:**
```bash
for bucket in $(aws s3 ls | awk '{print $3}'); do
  policy=$(aws s3api get-bucket-policy --bucket "$bucket" --query 'Policy' --output text 2>/dev/null)
  if [ -n "$policy" ]; then
    if echo "$policy" | grep -q "aws:PrincipalOrgID"; then
      echo "Bucket: $bucket — aws:PrincipalOrgID condition found"
    else
      echo "Bucket: $bucket — no aws:PrincipalOrgID condition"
    fi
  else
    echo "Bucket: $bucket — no bucket policy"
  fi
done
```

**Check SCPs for data perimeter enforcement:**
```bash
for policy_id in $(aws organizations list-policies --filter SERVICE_CONTROL_POLICY --query 'Policies[].Id' --output text 2>/dev/null); do
  echo "SCP: $policy_id"
  aws organizations describe-policy --policy-id "$policy_id" --query 'Policy.Content' --output text 2>/dev/null | grep -i "aws:PrincipalOrgID\|aws:ResourceOrgID\|aws:PrincipalOrgPaths" || echo "  No data perimeter conditions found"
done
```

**Check Resource Control Policies (RCPs) for perimeter enforcement:**
```bash
aws organizations list-policies --filter RESOURCE_CONTROL_POLICY --query 'Policies[].{Id:Id,Name:Name}' --output table 2>/dev/null || echo "No Resource Control Policies found — RCPs may not be enabled"
```

**Expected result:** VPC endpoint policies should include explicit `Allow` or `Deny` statements scoped to the organization (using `aws:PrincipalOrgID`), preventing data exfiltration through AWS service endpoints. S3 bucket policies should include `aws:PrincipalOrgID` condition keys to restrict access to principals within the organization. SCPs should enforce data perimeter controls using condition keys such as `aws:PrincipalOrgID`, `aws:ResourceOrgID`, or `aws:PrincipalOrgPaths`. If no data perimeter conditions are found, resources may be accessible to principals outside the organization, increasing the risk of unauthorized data access or exfiltration. See remediation-workflow.md for remediation steps.

#### 3. IAM Policy Generation Pipeline

**Check IAM Access Analyzer policy generation status:**
```bash
aws accessanalyzer list-analyzers --query 'analyzers[].{Name:name,Type:type,Status:status}' --output table 2>/dev/null || echo "No IAM Access Analyzer configured"
```

**Check for policy generation requests:**
```bash
analyzer_arn=$(aws accessanalyzer list-analyzers --query 'analyzers[0].arn' --output text 2>/dev/null)
if [ -n "$analyzer_arn" ] && [ "$analyzer_arn" != "None" ]; then
  aws accessanalyzer list-access-preview-findings --access-preview-id $(aws accessanalyzer list-access-previews --analyzer-arn "$analyzer_arn" --query 'accessPreviews[0].id' --output text 2>/dev/null) --analyzer-arn "$analyzer_arn" --query 'findings[].{Resource:resource,ResourceType:resourceType,Status:status}' --output table 2>/dev/null || echo "No access preview findings found"
else
  echo "No IAM Access Analyzer configured — cannot check policy generation"
fi
```

**Check CodePipeline configurations for IAM automation:**
```bash
for pipeline in $(aws codepipeline list-pipelines --query 'pipelines[].name' --output text 2>/dev/null); do
  stages=$(aws codepipeline get-pipeline --name "$pipeline" --query 'pipeline.stages[].actions[].configuration' --output text 2>/dev/null)
  if echo "$stages" | grep -qi "iam\|access-analyzer\|policy"; then
    echo "Pipeline: $pipeline — contains IAM-related actions"
  fi
done || echo "No CodePipeline pipelines found"
```

**Expected result:** IAM Access Analyzer should be active with status `ACTIVE`, confirming that policy generation and access analysis capabilities are available. Access previews should be used to validate policy changes before deployment. At least one CodePipeline pipeline should include IAM-related actions (e.g., policy validation, access preview checks), indicating that IAM policy changes are automated through a CI/CD pipeline rather than applied manually. If no IAM automation pipeline exists, policy changes are likely manual and error-prone, increasing the risk of overly permissive policies being deployed without review. See remediation-workflow.md for remediation steps.

#### 4. Temporary Elevated Access

**Check IAM Identity Center permission sets with session duration:**
```bash
instance_arn=$(aws sso-admin list-instances --query 'Instances[0].InstanceArn' --output text 2>/dev/null)
if [ -n "$instance_arn" ] && [ "$instance_arn" != "None" ]; then
  aws sso-admin list-permission-sets --instance-arn "$instance_arn" --query 'PermissionSets[]' --output text 2>/dev/null | while read ps_arn; do
    echo "Permission Set: $ps_arn"
    aws sso-admin describe-permission-set --instance-arn "$instance_arn" --permission-set-arn "$ps_arn" --query 'PermissionSet.{Name:Name,SessionDuration:SessionDuration,Description:Description}' --output table 2>/dev/null
  done
else
  echo "IAM Identity Center is not configured — cannot check permission sets"
fi
```

**Check for permission sets with elevated privileges:**
```bash
instance_arn=$(aws sso-admin list-instances --query 'Instances[0].InstanceArn' --output text 2>/dev/null)
if [ -n "$instance_arn" ] && [ "$instance_arn" != "None" ]; then
  for ps_arn in $(aws sso-admin list-permission-sets --instance-arn "$instance_arn" --query 'PermissionSets[]' --output text 2>/dev/null); do
    name=$(aws sso-admin describe-permission-set --instance-arn "$instance_arn" --permission-set-arn "$ps_arn" --query 'PermissionSet.Name' --output text 2>/dev/null)
    policies=$(aws sso-admin list-managed-policies-in-permission-set --instance-arn "$instance_arn" --permission-set-arn "$ps_arn" --query 'AttachedManagedPolicies[].Name' --output text 2>/dev/null)
    if echo "$policies" | grep -qi "AdministratorAccess\|PowerUserAccess"; then
      session=$(aws sso-admin describe-permission-set --instance-arn "$instance_arn" --permission-set-arn "$ps_arn" --query 'PermissionSet.SessionDuration' --output text 2>/dev/null)
      echo "ELEVATED: $name — Policies: $policies — Session Duration: $session"
    fi
  done
else
  echo "IAM Identity Center is not configured — cannot check elevated permission sets"
fi
```

**Expected result:** Permission sets with elevated privileges (e.g., AdministratorAccess, PowerUserAccess) should have short session durations (e.g., `PT1H` for 1 hour or `PT2H` for 2 hours) to limit the window of elevated access. All permission sets should have explicitly configured session durations rather than relying on the default 1-hour session. If elevated permission sets have long session durations (e.g., `PT12H`), users retain high-privilege access for extended periods, increasing the blast radius of credential compromise. See remediation-workflow.md for remediation steps.

**Assessment questions:**
- Does the organization have a just-in-time (JIT) access workflow for granting temporary elevated privileges?
- Is there an approval process required before elevated access is granted?
- Are elevated access sessions automatically revoked after a defined time period?
- Is all elevated access usage logged and auditable?
- Are there alerts configured for when elevated access is requested or used?
- Does the organization regularly review who has access to elevated permission sets?
- Is there a break-glass procedure documented for emergency access scenarios?

#### 5. Threat Intelligence

**Check GuardDuty threat intelligence lists:**
```bash
detector_id=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text 2>/dev/null)
if [ -n "$detector_id" ] && [ "$detector_id" != "None" ]; then
  aws guardduty list-threat-intel-sets --detector-id "$detector_id" --query 'ThreatIntelSetIds[]' --output text 2>/dev/null | while read tip_id; do
    echo "Threat Intel Set: $tip_id"
    aws guardduty get-threat-intel-set --detector-id "$detector_id" --threat-intel-set-id "$tip_id" --query '{Name:Name,Format:Format,Status:Status,Location:Location}' --output table 2>/dev/null
  done
  if [ -z "$(aws guardduty list-threat-intel-sets --detector-id "$detector_id" --query 'ThreatIntelSetIds[]' --output text 2>/dev/null)" ]; then
    echo "No custom threat intelligence lists configured in GuardDuty"
  fi
else
  echo "GuardDuty is not enabled — cannot check threat intelligence lists"
fi
```

**Check Security Lake custom sources:**
```bash
aws securitylake list-data-lakes --query 'dataLakes[].{Region:region,Status:createStatus}' --output table 2>/dev/null || echo "Security Lake is not enabled"
```

```bash
aws securitylake list-log-sources --query 'sources[].{Account:account,Source:source}' --output table 2>/dev/null || echo "Unable to list Security Lake log sources"
```

```bash
aws securitylake get-data-lake-sources --query 'dataLakeSources[].{SourceName:sourceName,SourceStatus:sourceStatuses[].{Resource:resource,Status:status}}' --output table 2>/dev/null || echo "Unable to retrieve Security Lake data sources — custom sources may not be configured"
```

**Expected result:** GuardDuty should have at least one custom threat intelligence list configured with status `ACTIVE`, indicating the organization supplements GuardDuty's built-in threat intelligence with their own indicators of compromise (IOCs). Security Lake should be enabled with custom sources configured beyond the default AWS log sources, demonstrating centralized threat intelligence aggregation. If no custom threat intelligence lists exist, the organization relies solely on AWS-managed threat feeds and may miss threats specific to their industry or environment. See remediation-workflow.md for remediation steps.

#### 6. Network Flows Analysis (VPC Flow Logs)

**Check VPC Flow Log configurations across VPCs:**
```bash
for vpc_id in $(aws ec2 describe-vpcs --query 'Vpcs[].VpcId' --output text 2>/dev/null); do
  echo "VPC: $vpc_id"
  flow_logs=$(aws ec2 describe-flow-logs --filter "Name=resource-id,Values=$vpc_id" --query 'FlowLogs[].{FlowLogId:FlowLogId,Status:FlowLogStatus,TrafficType:TrafficType,LogDestinationType:LogDestinationType,MaxAggregationInterval:MaxAggregationInterval}' --output table 2>/dev/null)
  if [ -n "$flow_logs" ]; then
    echo "$flow_logs"
  else
    echo "  No VPC Flow Logs configured for this VPC"
  fi
done
```

**Verify Flow Log destinations and delivery status:**
```bash
aws ec2 describe-flow-logs --query 'FlowLogs[].{FlowLogId:FlowLogId,ResourceId:ResourceId,LogDestination:LogDestination,LogDestinationType:LogDestinationType,DeliverLogsStatus:DeliverLogsStatus,LogFormat:LogFormat}' --output table 2>/dev/null || echo "No VPC Flow Logs found"
```

**Expected result:** Every VPC should have VPC Flow Logs enabled with `FlowLogStatus` of `ACTIVE` and `DeliverLogsStatus` of `SUCCESS`. Flow Logs should capture `ALL` traffic (not just `ACCEPT` or `REJECT`) for comprehensive network flow analysis. Log destinations should be configured to a centralized location (e.g., S3 bucket or CloudWatch Logs) for analysis. The `MaxAggregationInterval` should be set to `60` seconds for near-real-time analysis. If any VPC lacks Flow Logs, network traffic in that VPC is not being monitored, creating blind spots for threat detection and forensic investigation. See remediation-workflow.md for remediation steps.

#### 7. Vulnerability Management Team

**Assessment questions:**
- Does the organization have a dedicated vulnerability management team or function with clearly defined roles and responsibilities?
- Is there a documented vulnerability management policy that defines severity classifications, SLAs for remediation, and escalation procedures?
- What are the defined SLAs for vulnerability remediation by severity (e.g., Critical: 24 hours, High: 7 days, Medium: 30 days, Low: 90 days)?
- Does the team track vulnerability metrics such as mean time to remediate (MTTR), vulnerability aging, and SLA compliance rates?
- Is there a centralized vulnerability tracking system or dashboard that provides visibility into the current vulnerability posture?
- Does the team conduct regular vulnerability review meetings to prioritize and assign remediation efforts?
- Are vulnerability scan results from multiple sources (Inspector, GuardDuty, Security Hub, third-party tools) aggregated into a single view?
- Does the team have established processes for exception handling when vulnerabilities cannot be remediated within SLA?
- Is there a defined process for validating that vulnerabilities have been successfully remediated after fixes are applied?
- Does the team produce regular reports on vulnerability trends, SLA adherence, and overall risk posture for leadership review?

#### 8. Zero Trust Access

**Check Verified Access instances:**
```bash
aws ec2 describe-verified-access-instances --query 'VerifiedAccessInstances[].{InstanceId:VerifiedAccessInstanceId,CreationTime:CreationTime,Description:Description}' --output table 2>/dev/null || echo "Verified Access is not configured in this region"
```

**Check Verified Access trust providers:**
```bash
aws ec2 describe-verified-access-trust-providers --query 'VerifiedAccessTrustProviders[].{ProviderId:VerifiedAccessTrustProviderId,Type:TrustProviderType,UserTrustProvider:UserTrustProviderType,DeviceTrustProvider:DeviceTrustProviderType}' --output table 2>/dev/null || echo "No Verified Access trust providers configured"
```

**Check Verified Access groups:**
```bash
aws ec2 describe-verified-access-groups --query 'VerifiedAccessGroups[].{GroupId:VerifiedAccessGroupId,InstanceId:VerifiedAccessInstanceId,Description:Description}' --output table 2>/dev/null || echo "No Verified Access groups configured"
```

**Expected result:** At least one Verified Access instance should exist with associated trust providers (user-based and/or device-based) and access groups. Trust providers should be configured to integrate with your identity provider (e.g., IAM Identity Center, OIDC) and optionally a device management solution. If no Verified Access instances are found, the organization has not adopted AWS-native zero trust network access, and application access likely relies on traditional VPN or network-perimeter-based controls. See remediation-workflow.md for remediation steps.

**Assessment questions:**
- Has the organization adopted a zero trust architecture strategy that eliminates implicit trust based on network location?
- Are application access decisions based on identity, device posture, and context rather than network perimeter alone?
- Is there a roadmap to migrate legacy VPN-based access to zero trust network access (e.g., AWS Verified Access)?
- Are access policies continuously evaluated and enforced at the application level rather than the network level?
- Does the organization enforce device trust verification (e.g., managed device, patch level, endpoint protection) before granting access?

#### 9. Use Abstract Services

**Inventory Lambda functions:**
```bash
aws lambda list-functions --query 'Functions[].{FunctionName:FunctionName,Runtime:Runtime,MemorySize:MemorySize,LastModified:LastModified}' --output table 2>/dev/null || echo "No Lambda functions found"
```

**Count Lambda functions:**
```bash
aws lambda list-functions --query 'length(Functions)' --output text 2>/dev/null || echo "0"
```

**Inventory Fargate tasks:**
```bash
for cluster in $(aws ecs list-clusters --query 'clusterArns[]' --output text 2>/dev/null); do
  cluster_name=$(echo "$cluster" | awk -F/ '{print $NF}')
  fargate_count=$(aws ecs list-services --cluster "$cluster_name" --launch-type FARGATE --query 'length(serviceArns)' --output text 2>/dev/null)
  echo "Cluster: $cluster_name — Fargate services: ${fargate_count:-0}"
done
```

**Count EC2 instances (traditional compute):**
```bash
aws ec2 describe-instances --filters Name=instance-state-name,Values=running --query 'length(Reservations[].Instances[])' --output text 2>/dev/null || echo "0"
```

**Check for managed database services versus self-managed:**
```bash
echo "--- Managed databases (RDS/Aurora) ---"
aws rds describe-db-instances --query 'length(DBInstances)' --output text 2>/dev/null || echo "0"
echo "--- Managed caches (ElastiCache) ---"
aws elasticache describe-cache-clusters --query 'length(CacheClusters)' --output text 2>/dev/null || echo "0"
echo "--- Managed search (OpenSearch) ---"
aws opensearch list-domain-names --query 'length(DomainNames)' --output text 2>/dev/null || echo "0"
```

**Expected result:** A mature organization should show a high ratio of serverless and managed services (Lambda functions, Fargate tasks, RDS, ElastiCache, OpenSearch) relative to EC2 instances. Heavy reliance on EC2 indicates that the organization is managing undifferentiated infrastructure (patching, scaling, availability) instead of leveraging abstract services where AWS handles operational burden. If the EC2 count significantly exceeds the combined Lambda and Fargate count, there may be opportunities to modernize workloads to reduce operational overhead and improve security posture. See remediation-workflow.md for remediation steps.

#### 10. Encryption in Transit

**Check ALB listener protocols:**
```bash
for alb_arn in $(aws elbv2 describe-load-balancers --query 'LoadBalancers[?Type==`application`].LoadBalancerArn' --output text 2>/dev/null); do
  alb_name=$(echo "$alb_arn" | awk -F/ '{print $(NF-1)}')
  echo "ALB: $alb_name"
  aws elbv2 describe-listeners --load-balancer-arn "$alb_arn" --query 'Listeners[].{Port:Port,Protocol:Protocol,SslPolicy:SslPolicy}' --output table 2>/dev/null
done
```

**Check NLB listener protocols:**
```bash
for nlb_arn in $(aws elbv2 describe-load-balancers --query 'LoadBalancers[?Type==`network`].LoadBalancerArn' --output text 2>/dev/null); do
  nlb_name=$(echo "$nlb_arn" | awk -F/ '{print $(NF-1)}')
  echo "NLB: $nlb_name"
  aws elbv2 describe-listeners --load-balancer-arn "$nlb_arn" --query 'Listeners[].{Port:Port,Protocol:Protocol,SslPolicy:SslPolicy}' --output table 2>/dev/null
done
```

**Check CloudFront viewer protocol policies:**
```bash
aws cloudfront list-distributions --query 'DistributionList.Items[].{Id:Id,DomainName:DomainName,ViewerProtocolPolicy:DefaultCacheBehavior.ViewerProtocolPolicy}' --output table 2>/dev/null || echo "No CloudFront distributions found"
```

**Check RDS SSL enforcement:**
```bash
aws rds describe-db-instances --query 'DBInstances[].{DBInstance:DBInstanceIdentifier,Engine:Engine}' --output text 2>/dev/null | while read -r db_id engine; do
  echo "DB: $db_id (Engine: $engine)"
  aws rds describe-db-parameters --db-parameter-group-name $(aws rds describe-db-instances --db-instance-identifier "$db_id" --query 'DBInstances[0].DBParameterGroups[0].DBParameterGroupName' --output text 2>/dev/null) --query "Parameters[?ParameterName=='rds.force_ssl'].{Name:ParameterName,Value:ParameterValue}" --output table 2>/dev/null || echo "  Unable to check SSL enforcement"
done
```

**Expected result:** All ALB listeners should use `HTTPS` protocol (port 443) with a modern SSL policy (e.g., `ELBSecurityPolicy-TLS13-1-2-2021-06` or newer). NLB listeners handling sensitive traffic should use `TLS` protocol. CloudFront distributions should have `ViewerProtocolPolicy` set to `redirect-to-https` or `https-only` — a value of `allow-all` means unencrypted HTTP traffic is permitted. RDS instances should have `rds.force_ssl` set to `1` to enforce encrypted connections. If any load balancer listeners use `HTTP` without redirection, or CloudFront allows `allow-all`, data in transit is exposed to interception. See remediation-workflow.md for remediation steps.

#### 11. GenAI Data Protection

**Check Bedrock guardrail configurations:**
```bash
aws bedrock list-guardrails --query 'guardrails[].{GuardrailId:id,Name:name,Status:status,Version:version}' --output table 2>/dev/null || echo "No Bedrock guardrails configured or Bedrock is not available in this region"
```

**Check Bedrock guardrail details:**
```bash
for guardrail_id in $(aws bedrock list-guardrails --query 'guardrails[].id' --output text 2>/dev/null); do
  echo "Guardrail: $guardrail_id"
  aws bedrock get-guardrail --guardrail-identifier "$guardrail_id" --query '{Name:name,Status:status,ContentPolicy:contentPolicy,SensitiveInformationPolicy:sensitiveInformationPolicy,TopicPolicy:topicPolicy}' --output table 2>/dev/null
done
```

**Check model invocation logging status:**
```bash
aws bedrock get-model-invocation-logging-configuration --query 'loggingConfig.{TextDataDeliveryEnabled:textDataDeliveryEnabled,ImageDataDeliveryEnabled:imageDataDeliveryEnabled,S3Config:s3Config.bucketName,CloudWatchConfig:cloudWatchConfig.logGroupName}' --output table 2>/dev/null || echo "Model invocation logging is not configured or Bedrock is not available in this region"
```

**Expected result:** At least one Bedrock guardrail should be configured with content filtering policies, sensitive information filters (PII detection), and topic restrictions appropriate to the organization's use cases. Guardrails should be in `READY` status. Model invocation logging should be enabled with both text and image data delivery configured to an S3 bucket and/or CloudWatch Logs for audit and compliance purposes. If no guardrails are configured, GenAI applications may generate harmful content, leak sensitive data in prompts or responses, or operate without content safety boundaries. If invocation logging is disabled, there is no audit trail of model interactions for compliance, debugging, or abuse detection. See remediation-workflow.md for remediation steps.

#### 12. Forming a Red Team (Attacker's Point of View)

**Assessment questions:**
- Does the organization have a formally chartered red team or regularly engage external red team services to simulate adversarial attacks against AWS workloads?
- Is there a defined scope and rules of engagement document for red team exercises that covers cloud-specific attack vectors (e.g., IAM privilege escalation, cross-account access, metadata service exploitation)?
- How frequently are red team exercises conducted (e.g., quarterly, semi-annually, annually)?
- Are red team findings tracked in a centralized system with severity ratings, remediation owners, and SLAs for resolution?
- Does the red team test both technical controls (network, IAM, application) and social engineering vectors (phishing, credential harvesting)?
- Are red team exercise results shared with blue team and security leadership to drive improvements in detection and response capabilities?
- Does the organization conduct purple team exercises where red and blue teams collaborate to validate detection coverage and improve response procedures?
- Is there a formal process to validate that vulnerabilities discovered during red team exercises have been successfully remediated?

#### 13. Forming a Blue Team (Incident Response)

**Assessment questions:**
- Does the organization have a dedicated incident response team (blue team) with clearly defined roles, responsibilities, and escalation procedures for cloud security incidents?
- Is there a documented incident response plan that covers AWS-specific scenarios (e.g., compromised IAM credentials, unauthorized resource provisioning, data exfiltration via S3)?
- Does the blue team have 24/7 on-call coverage or defined response time SLAs for security incidents?
- Is a Security Orchestration, Automation, and Response (SOAR) platform in use to automate incident triage, enrichment, and response workflows?
- Does the blue team conduct regular incident response drills and post-incident reviews to continuously improve response capabilities?
- Are incident response metrics tracked (e.g., mean time to detect, mean time to respond, mean time to contain) and reported to leadership?
- Does the blue team have access to centralized logging and security tooling (Security Hub, GuardDuty, Detective, CloudTrail) for investigation and response?

**Check Security Hub automated response actions:**
```bash
aws securityhub list-automation-rules --query 'AutomationRulesMetadata[].{RuleArn:RuleArn,RuleName:RuleName,RuleStatus:RuleStatus,Description:Description}' --output table 2>/dev/null || echo "No Security Hub automation rules configured"
```

**Check Security Hub action targets (custom actions for response):**
```bash
aws securityhub describe-action-targets --query 'ActionTargets[].{ActionTargetArn:ActionTargetArn,Name:Name,Description:Description}' --output table 2>/dev/null || echo "No Security Hub custom action targets configured"
```

**Expected result:** Security Hub should have automation rules configured with `RuleStatus` of `ENABLED` to automatically triage, suppress, or escalate findings based on defined criteria. Custom action targets should be configured to enable analysts to trigger response workflows (e.g., isolate instance, revoke credentials, notify on-call) directly from the Security Hub console. If no automation rules or custom actions exist, incident response relies entirely on manual processes, increasing mean time to respond and risk of human error during security incidents. See remediation-workflow.md for remediation steps.

#### 14. Advanced Security Automations

**Check EventBridge rules for security automation:**
```bash
aws events list-rules --query 'Rules[?contains(Name, `security`) || contains(Name, `Security`) || contains(Name, `sec-`) || contains(Name, `incident`) || contains(Name, `remediat`)].{Name:Name,State:State,Description:Description,EventBusName:EventBusName}' --output table 2>/dev/null || echo "No security-related EventBridge rules found"
```

**Check Lambda functions with security-related names:**
```bash
aws lambda list-functions --query 'Functions[?contains(FunctionName, `security`) || contains(FunctionName, `Security`) || contains(FunctionName, `remediat`) || contains(FunctionName, `incident`) || contains(FunctionName, `automate`)].{FunctionName:FunctionName,Runtime:Runtime,LastModified:LastModified,Description:Description}' --output table 2>/dev/null || echo "No security-related Lambda functions found"
```

**Check Step Functions state machines for security workflows:**
```bash
aws stepfunctions list-state-machines --query 'stateMachines[?contains(name, `security`) || contains(name, `Security`) || contains(name, `incident`) || contains(name, `remediat`) || contains(name, `response`)].{Name:name,StateMachineArn:stateMachineArn,CreationDate:creationDate}' --output table 2>/dev/null || echo "No security-related Step Functions state machines found"
```

**Expected result:** The organization should have EventBridge rules in `ENABLED` state that trigger automated security responses to events such as GuardDuty findings, Security Hub findings, Config compliance changes, and IAM policy modifications. Lambda functions with security-related names should exist to perform automated remediation actions (e.g., revoking compromised credentials, isolating instances, blocking malicious IPs). Step Functions state machines should orchestrate multi-step security workflows that coordinate across multiple AWS services. If no security automation infrastructure exists, all security responses are manual, leading to slower response times and inconsistent remediation. See remediation-workflow.md for remediation steps.

#### 15. Security Orchestration and Ticketing

**Check Security Hub custom actions:**
```bash
aws securityhub describe-action-targets --query 'ActionTargets[].{ActionTargetArn:ActionTargetArn,Name:Name,Description:Description}' --output table 2>/dev/null || echo "No Security Hub custom actions configured"
```

**Check EventBridge rules targeting ticketing or notification integrations:**
```bash
aws events list-rules --query 'Rules[?contains(Name, `ticket`) || contains(Name, `Ticket`) || contains(Name, `jira`) || contains(Name, `Jira`) || contains(Name, `servicenow`) || contains(Name, `ServiceNow`) || contains(Name, `pagerduty`) || contains(Name, `PagerDuty`) || contains(Name, `opsgenie`) || contains(Name, `sns-security`)].{Name:Name,State:State,Description:Description}' --output table 2>/dev/null || echo "No ticketing integration EventBridge rules found"
```

**Check EventBridge rules triggered by Security Hub custom actions:**
```bash
aws events list-rules --query 'Rules[].Name' --output text 2>/dev/null | tr '\t' '\n' | while read rule_name; do
  pattern=$(aws events describe-rule --name "$rule_name" --query 'EventPattern' --output text 2>/dev/null)
  if echo "$pattern" | grep -q "securityhub" 2>/dev/null; then
    echo "Rule: $rule_name"
    echo "  Pattern: $pattern"
    targets=$(aws events list-targets-by-rule --rule "$rule_name" --query 'Targets[].{Id:Id,Arn:Arn}' --output table 2>/dev/null)
    echo "  Targets: $targets"
  fi
done
```

**Expected result:** Security Hub custom actions should be configured to allow analysts to trigger ticketing and notification workflows from the Security Hub console. EventBridge rules should exist that route Security Hub findings and custom action events to external ticketing systems (e.g., Jira, ServiceNow, PagerDuty, OpsGenie) via SNS, Lambda, or API Destination targets. If no custom actions or ticketing integrations exist, security findings remain siloed in Security Hub without integration into the organization's incident management and ticketing workflows, reducing visibility and accountability for remediation. See remediation-workflow.md for remediation steps.

#### 16. Automate Deviation Correction in Configurations

**Check AWS Config auto-remediation rules:**
```bash
aws configservice describe-remediation-configurations --query 'RemediationConfigurations[].{ConfigRuleName:ConfigRuleName,TargetId:TargetId,TargetType:TargetType,Automatic:Automatic,MaximumAutomaticAttempts:MaximumAutomaticAttempts,RetryAttemptSeconds:RetryAttemptSeconds}' --output table 2>/dev/null || echo "No AWS Config remediation configurations found"
```

**Check Config rules with auto-remediation enabled:**
```bash
aws configservice describe-config-rules --query 'ConfigRules[].ConfigRuleName' --output text 2>/dev/null | tr '\t' '\n' | while read rule_name; do
  remediation=$(aws configservice describe-remediation-configurations --config-rule-names "$rule_name" --query 'RemediationConfigurations[?Automatic==`true`].{ConfigRuleName:ConfigRuleName,TargetId:TargetId}' --output text 2>/dev/null)
  if [ -n "$remediation" ]; then
    echo "Auto-remediation enabled: $rule_name -> $remediation"
  fi
done
```

**Check Systems Manager Automation associations for remediation:**
```bash
aws ssm list-associations --query 'Associations[?contains(Name, `AWS-`) || contains(Name, `Remediat`) || contains(Name, `remediat`)].{AssociationId:AssociationId,Name:Name,Status:Overview.Status,LastExecutionDate:LastExecutionDate,Targets:Targets}' --output table 2>/dev/null || echo "No Systems Manager Automation associations found"
```

**Expected result:** AWS Config should have remediation configurations with `Automatic` set to `true` for critical compliance rules, enabling automatic correction of configuration deviations without manual intervention. The `TargetType` should be `SSM_DOCUMENT` pointing to Systems Manager Automation documents that perform the remediation actions. Systems Manager Automation associations should exist for common remediation tasks (e.g., enabling encryption, restricting public access, enforcing tagging). If no auto-remediation rules are configured, configuration deviations require manual detection and correction, increasing the window of non-compliance and risk exposure. See remediation-workflow.md for remediation steps.

#### 17. Automate Evidence Gathering

**Check AWS Audit Manager assessments:**
```bash
aws auditmanager list-assessments --query 'assessmentMetadata[].{AssessmentId:id,Name:name,Status:status,ComplianceType:complianceType,CreationTime:creationTime}' --output table 2>/dev/null || echo "AWS Audit Manager is not configured or no assessments exist"
```

**Check Audit Manager evidence collection status:**
```bash
for assessment_id in $(aws auditmanager list-assessments --query 'assessmentMetadata[].id' --output text 2>/dev/null); do
  echo "Assessment: $assessment_id"
  aws auditmanager get-assessment --assessment-id "$assessment_id" --query 'assessment.{Name:metadata.name,Status:metadata.status,Framework:framework.metadata.name,ControlSetsCount:framework.controlSets|length(@)}' --output table 2>/dev/null
  echo "Evidence folders:"
  aws auditmanager get-evidence-folders-by-assessment --assessment-id "$assessment_id" --query 'evidenceFolders[].{Name:name,ControlSetId:controlSetId,TotalEvidence:totalEvidence,EvidenceByType:evidenceByTypeComplianceCheckCount}' --output table 2>/dev/null
done
```

**Expected result:** AWS Audit Manager should have at least one active assessment with `status` of `ACTIVE`, configured with a compliance framework relevant to the organization's requirements (e.g., AWS Audit Manager framework for SOC 2, PCI DSS, HIPAA, or a custom framework). Evidence folders should show automated evidence collection with `totalEvidence` counts greater than zero, indicating that Audit Manager is actively gathering compliance evidence from AWS services. If no assessments exist or evidence collection is empty, the organization is gathering compliance evidence manually, which is time-consuming, error-prone, and difficult to scale. See remediation-workflow.md for remediation steps.

#### 18. Multi-Region Disaster Recovery Automation

**Check cross-region replication configurations (S3):**
```bash
for bucket in $(aws s3api list-buckets --query 'Buckets[].Name' --output text 2>/dev/null); do
  replication=$(aws s3api get-bucket-replication --bucket "$bucket" --query 'ReplicationConfiguration.Rules[].{Status:Status,Destination:Destination.Bucket,StorageClass:Destination.StorageClass}' --output table 2>/dev/null)
  if [ -n "$replication" ]; then
    echo "Bucket: $bucket"
    echo "$replication"
  fi
done
```

**Check Route 53 failover records:**
```bash
for zone_id in $(aws route53 list-hosted-zones --query 'HostedZones[].Id' --output text 2>/dev/null | sed 's|/hostedzone/||g'); do
  failover_records=$(aws route53 list-resource-record-sets --hosted-zone-id "$zone_id" --query 'ResourceRecordSets[?Failover!=`null`].{Name:Name,Type:Type,Failover:Failover,SetIdentifier:SetIdentifier,HealthCheckId:HealthCheckId}' --output table 2>/dev/null)
  if [ -n "$failover_records" ]; then
    echo "Hosted Zone: $zone_id"
    echo "$failover_records"
  fi
done
```

**Check CloudFormation StackSets for multi-region deployments:**
```bash
aws cloudformation list-stack-sets --status ACTIVE --query 'Summaries[].{StackSetName:StackSetName,Status:Status,Description:Description,PermissionModel:PermissionModel}' --output table 2>/dev/null || echo "No active CloudFormation StackSets found"
```

**Check StackSet instances across regions:**
```bash
for stackset_name in $(aws cloudformation list-stack-sets --status ACTIVE --query 'Summaries[].StackSetName' --output text 2>/dev/null); do
  echo "StackSet: $stackset_name"
  aws cloudformation list-stack-instances --stack-set-name "$stackset_name" --query 'Summaries[].{Account:Account,Region:Region,Status:Status,StatusReason:StatusReason}' --output table 2>/dev/null
done
```

**Expected result:** Critical S3 buckets should have cross-region replication rules with `Status` of `Enabled`, replicating data to a bucket in a different AWS region for disaster recovery. Route 53 should have failover routing records configured with associated health checks to automatically redirect traffic to a secondary region when the primary region is unavailable. CloudFormation StackSets should be deployed with `ACTIVE` status across multiple regions, ensuring infrastructure consistency and enabling rapid recovery in a secondary region. If no cross-region replication, failover records, or multi-region StackSets exist, the organization lacks automated disaster recovery capabilities and may face extended downtime during regional outages. See remediation-workflow.md for remediation steps.

#### 19. Chaos Engineering

**Check AWS Fault Injection Simulator experiment templates:**
```bash
aws fis list-experiment-templates --query 'experimentTemplates[].{Id:id,Description:description,CreationTime:creationTime,Tags:tags}' --output table 2>/dev/null || echo "No FIS experiment templates found — chaos engineering is not configured"
```

**Check FIS experiment template details:**
```bash
for template_id in $(aws fis list-experiment-templates --query 'experimentTemplates[].id' --output text 2>/dev/null); do
  echo "Template: $template_id"
  aws fis get-experiment-template --id "$template_id" --query '{Description:description,Actions:actions,Targets:targets,StopConditions:stopConditions}' --output json 2>/dev/null
done
```

**Check completed FIS experiments:**
```bash
aws fis list-experiments --query 'experiments[].{ExperimentId:id,TemplateId:experimentTemplateId,State:state.status,CreationTime:creationTime,EndTime:endTime}' --output table 2>/dev/null || echo "No FIS experiments have been executed"
```

**Expected result:** AWS Fault Injection Simulator should have experiment templates defined that test the resilience of critical workloads against common failure scenarios (e.g., EC2 instance termination, AZ outage, network latency injection, API throttling). Templates should include appropriate stop conditions to limit blast radius during experiments. Completed experiments should show a history of regular chaos engineering practice with `state.status` of `completed`, demonstrating that the organization actively validates its resilience posture. If no experiment templates exist, the organization has not adopted chaos engineering practices and may have untested assumptions about system resilience. See remediation-workflow.md for remediation steps.

### Phase 6: Update CSV Tracking

After completing the assessment, update the CSV file with findings:

**For each control assessed:**
1. Update Status: "Not Started", "In Progress", or "Completed"
2. Add Notes: Document findings, issues, or implementation details
3. Update Last Updated: Current date
4. Adjust Priority if needed based on findings

**Example CSV updates:**
```csv
Domain,Control,Phase,Status,Priority,Notes,Last Updated
Threat Detection,Detect Common Threats (GuardDuty),Quick Wins,Completed,Critical,"Enabled in all 3 active regions",2024-02-02
Data Protection,Block Public Access (S3),Quick Wins,In Progress,Critical,"Account-level enabled, 2 buckets need bucket-level config",2024-02-02
Infrastructure Protection,Cleanup risky open ports,Quick Wins,Not Started,High,"Found 5 security groups with 0.0.0.0/0 SSH access",2024-02-02
```

## Assessment Report Template

After completing the assessment, generate a report:

```
AWS Security Maturity Assessment Report
========================================
Date: [Current Date]
Account: [Account ID]
Assessed By: [Your Name]

Overall Maturity: [X]%

Phase 1 (Quick Wins): [X]% Complete
- Completed: [X] controls
- In Progress: [X] controls
- Not Started: [X] controls

Phase 2 (Foundational): [X]% Complete
- Completed: [X] controls
- In Progress: [X] controls
- Not Started: [X] controls

Phase 3 (Efficient): [X]% Complete
- Total Controls: 20
- Completed: [X] controls
- In Progress: [X] controls
- Not Started: [X] controls
- Domains: Security Governance (3), IAM (2), Threat Detection (1), Vulnerability Management (2), Infrastructure Protection (3), Data Protection (1), Application Security (3), Incident Response (3), Security Assurance (1), Resiliency (1)

Phase 4 (Optimized): [X]% Complete
- Total Controls: 19
- Completed: [X] controls
- In Progress: [X] controls
- Not Started: [X] controls
- Domains: Security Governance (1), IAM (3), Threat Detection (2), Vulnerability Management (1), Infrastructure Protection (2), Data Protection (2), Application Security (1), Incident Response (5), Security Assurance (1), Resiliency (2)

Critical Findings:
1. [Finding 1]
2. [Finding 2]
3. [Finding 3]

High Priority Gaps:
1. [Gap 1]
2. [Gap 2]
3. [Gap 3]

Recommendations:
1. [Recommendation 1]
2. [Recommendation 2]
3. [Recommendation 3]

Next Steps:
1. [Next step 1]
2. [Next step 2]
3. [Next step 3]
```

## Automation Tips

**Create assessment script:**
```bash
#!/bin/bash
# save as assess-security.sh

echo "Starting AWS Security Assessment..."
echo "=================================="

# Account info
echo "Account ID: $(aws sts get-caller-identity --query Account --output text)"

# GuardDuty
echo "Checking GuardDuty..."
aws guardduty list-detectors --query 'DetectorIds' --output text

# CloudTrail
echo "Checking CloudTrail..."
aws cloudtrail describe-trails --query 'trailList[].Name' --output text

# S3 Block Public Access
echo "Checking S3 Block Public Access..."
aws s3control get-public-access-block --account-id $(aws sts get-caller-identity --query Account --output text)

# --- Phase 2: Quick Wins Checks ---
# Security Governance: Security Contacts, Region Restrictions
# IAM: Root Account Protection, Identity Federation, Cleanup Unintended Accesses
# Detection: GuardDuty, CloudTrail (see above)
# Data: Analyze Data Security Posture (Macie)
# Assurance: Evaluate CSPM (Security Hub standards/compliance)
# Resiliency: Evaluate Resilience (Backup, Multi-AZ, Auto Scaling)
# Incident Response: Act on Critical Security Findings

# --- Phase 3: Foundational Controls Checks ---
# Security Governance: Identify Security/Regulatory Requirements, Cloud Security Training
# Threat Detection: Advanced Threat Detection (GuardDuty protection plans)
# Vulnerability Management: Infrastructure Vulnerabilities (Inspector), Application Vulnerabilities (CodeGuru, ECR)
# Infrastructure Protection: Limit Network Access, Secure EC2 Management, Network Segmentation, Multi-Account Management
# Data Protection: Backups (Backup plans/vaults), No Secrets in Code (Secrets Manager)
# Application Security: Involve Security Teams in Development
# Incident Response: Define Incident Response Playbooks (SSM Automation)
# Assurance: Inventory and Configuration Monitoring (AWS Config)
# Resiliency: Redundancy Using Multiple AZs (RDS, ELB, ASG)

# --- Phase 4: Efficient Controls Checks ---
# Security Governance: Secure Architecture Design (Well-Architected Tool)
# Security Governance: Infrastructure as Code (CloudFormation, CodePipeline)
# Security Governance: Tagging Strategy (Tag Policies, Resource Groups)
# IAM: Least Privilege Review (IAM Access Analyzer)
# IAM: Customer IAM / Cognito (User Pools, MFA, Advanced Security)
# Threat Detection: Custom Threat Detection / Security Lake
# Vulnerability Management: Security Champions Program (assessment questions)
# Vulnerability Management: DevSecOps Pipeline (CodePipeline, CodeBuild, ECR scan-on-push)
# Vulnerability Management: Image Generation Pipeline (EC2 Image Builder)
# Infrastructure Protection: Anti-Malware / EDR (GuardDuty Runtime Monitoring)
# Infrastructure Protection: Outbound Traffic Control (NAT Gateway, Network Firewall)
# Data Protection: Discover Sensitive Data (Macie jobs/findings)
# Application Security: Perform Threat Modeling (assessment questions)
# Application Security: WAF Custom Rules (WAF rule groups)
# Application Security: Advanced DDoS / Shield Advanced
# Incident Response: TableTop Exercises (assessment questions)
# Incident Response: Automate Playbooks (SSM Automation, EventBridge)
# Incident Response: Security Investigations (Detective, CloudTrail Lake)
# Assurance: Compliance Reports (Security Hub scores, Audit Manager)
# Resiliency: Disaster Recovery Plan (cross-region replication, Route 53)

# --- Phase 5: Optimized Controls Checks ---
# Security Governance: Sharing Security Work / Shared Responsibility (assessment questions)
# IAM: Data Perimeters (VPC endpoint policies, S3 bucket policy conditions, SCPs/RCPs)
# IAM: Policy Generation Pipeline (IAM Access Analyzer policy generation, CodePipeline)
# IAM: Temporary Elevated Access (IAM Identity Center permission sets, time-based sessions)
# Threat Detection: Threat Intelligence (GuardDuty threat intel lists, Security Lake custom sources)
# Threat Detection: Network Flows / VPC Flow Logs (Flow Log configs, log destinations)
# Vulnerability Management: Vulnerability Management Team (assessment questions)
# Infrastructure Protection: Zero Trust Access (Verified Access instances, trust providers)
# Infrastructure Protection: Use Abstract Services (Lambda, Fargate inventory)
# Data Protection: Encryption in Transit (ALB/NLB/CloudFront protocols, RDS SSL)
# Data Protection: GenAI Data Protection (Bedrock guardrails, model invocation logging)
# Application Security: Red Team Exercises (assessment questions)
# Application Security: Blue Team / SOC Capabilities (Security Hub automated responses)
# Incident Response: Advanced Security Automations (EventBridge, Lambda, Step Functions)
# Incident Response: Security Orchestration (Security Hub custom actions, ticketing integration)
# Assurance: Automate Deviation Correction (Config auto-remediation, SSM Automation)
# Assurance: Automate Evidence Gathering (Audit Manager assessments, evidence collection)
# Resiliency: Multi-Region DR Automation (cross-region replication, Route 53 failover, StackSets)
# Resiliency: Chaos Engineering (FIS experiment templates, completed experiments)

# Add more checks as needed...

echo "Assessment complete!"
```

## Common Issues

**Issue: Access Denied errors**
- Solution: Ensure IAM user/role has SecurityAudit policy or equivalent read permissions

**Issue: Some services not available in region**
- Solution: Check service availability in your region, some services are global (IAM, CloudFront)

**Issue: Too many resources to check manually**
- Solution: Use AWS Config, Security Hub, or third-party CSPM tools for automated assessment

## Next Steps

After completing the assessment:
1. Review the CSV file for gaps
2. Prioritize remediations (start with Quick Wins)
3. Use the remediation-workflow.md guide to implement controls
4. Schedule regular assessments (monthly recommended)
