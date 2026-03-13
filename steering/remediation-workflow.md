# Remediation Workflow

This guide provides step-by-step instructions for implementing security controls identified in your assessment.

## ⚠️ User Approval Required for All Actions

**Every AWS CLI command in this guide that creates, modifies, or deletes resources requires explicit user approval before execution.** The agent MUST:

1. Present the exact command to the user
2. Explain what it will do and what resources it affects
3. Ask: "Would you like me to execute this command?"
4. Wait for explicit confirmation before proceeding
5. Never batch multiple write commands — each requires separate approval

This guide contains write commands (create, modify, delete, enable, attach, revoke, etc.) that change your AWS environment. None of these should be executed automatically.

## Overview

The remediation workflow helps you:
1. Prioritize security gaps
2. Implement controls with AWS CLI or Console
3. Verify implementation
4. Update tracking CSV
5. Monitor for regressions

## Well-Architected Security Tools for Remediation

Before starting remediation, use the Well-Architected Security MCP server tools to get context:

- **AnalyzeSecurityPosture** — Get a prioritized list of security improvements with recommendations aligned to the Well-Architected Framework
- **GetSecurityFindings** — Review current findings by severity to validate which controls need attention
- **GetResourceComplianceStatus** — Check which resources are non-compliant to scope remediation effort
- **CheckSecurityServices** — Verify which security services are already enabled before attempting to enable them

After implementing a remediation, use **CheckSecurityServices** and **GetSecurityFindings** to verify the fix took effect.

## Prioritization Framework

**Priority Order:**
1. **Critical Quick Wins** - High impact, low effort (implement immediately)
2. **High Priority Quick Wins** - High impact, medium effort (implement within 1 week)
3. **Critical Foundational** - High impact, higher effort (implement within 1 month)
4. **Other controls** - Follow phased approach

**Consider:**
- Current risk exposure
- Compliance requirements
- Dependencies between controls
- Available resources and expertise

## Quick Wins Remediations

### 1. Enable Multi-Factor Authentication (MFA)

**For Root Account:**

Console Method:
1. Sign in as root user
2. Go to IAM → Dashboard → Security Status
3. Click "Activate MFA on your root account"
4. Choose MFA device type (Virtual MFA recommended)
5. Follow setup wizard

CLI Method (for IAM users):
```bash
# Create virtual MFA device
aws iam create-virtual-mfa-device --virtual-mfa-device-name root-account-mfa --outfile QRCode.png --bootstrap-method QRCodePNG

# Enable MFA (requires MFA codes from authenticator app)
aws iam enable-mfa-device --user-name <username> --serial-number <mfa-arn> --authentication-code-1 <code1> --authentication-code-2 <code2>
```

**For IAM Users:**
```bash
# List users without MFA
aws iam get-credential-report --output text | awk -F, '$4=="false" {print $1}'

# For each user, enable MFA (they must do this themselves or admin can enforce via policy)
```

**Verification:**
```bash
# Check root MFA
aws iam get-account-summary | grep AccountMFAEnabled

# Check user MFA
aws iam list-mfa-devices --user-name <username>
```

**Update CSV:**
```csv
Identity and Access Management,Multi-Factor Authentication,Quick Wins,Completed,Critical,"MFA enabled for root and all 15 IAM users",2024-02-02
```

---

### 2. Enable Amazon GuardDuty

**Single Region:**
```bash
# Enable GuardDuty
aws guardduty create-detector --enable

# Get detector ID
DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)

# Enable S3 protection
aws guardduty update-detector --detector-id $DETECTOR_ID --enable --data-sources S3Logs={Enable=true}

# Enable EKS protection
aws guardduty update-detector --detector-id $DETECTOR_ID --enable --data-sources Kubernetes={AuditLogs={Enable=true}}
```

**All Regions (Recommended):**
```bash
#!/bin/bash
for region in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  echo "Enabling GuardDuty in $region"
  aws guardduty create-detector --enable --region $region
done
```

**Console Method:**
1. Navigate to GuardDuty console
2. Click "Get Started"
3. Click "Enable GuardDuty"
4. Repeat for each region

**Verification:**
```bash
# Check detector status
aws guardduty get-detector --detector-id $DETECTOR_ID

# Verify findings are being generated
aws guardduty list-findings --detector-id $DETECTOR_ID
```

**Update CSV:**
```csv
Threat Detection,Detect Common Threats (GuardDuty),Quick Wins,Completed,Critical,"Enabled in all 5 active regions with S3 and EKS protection",2024-02-02
```

---

### 3. Configure AWS CloudTrail

**Create Organization Trail (Recommended):**
```bash
# Create S3 bucket for logs
aws s3 mb s3://my-org-cloudtrail-logs-$(aws sts get-caller-identity --query Account --output text)

# Apply bucket policy
cat > bucket-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSCloudTrailAclCheck",
      "Effect": "Allow",
      "Principal": {"Service": "cloudtrail.amazonaws.com"},
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::my-org-cloudtrail-logs-$(aws sts get-caller-identity --query Account --output text)"
    },
    {
      "Sid": "AWSCloudTrailWrite",
      "Effect": "Allow",
      "Principal": {"Service": "cloudtrail.amazonaws.com"},
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::my-org-cloudtrail-logs-$(aws sts get-caller-identity --query Account --output text)/*",
      "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}}
    }
  ]
}
EOF

aws s3api put-bucket-policy --bucket my-org-cloudtrail-logs-$(aws sts get-caller-identity --query Account --output text) --policy file://bucket-policy.json

# Create trail
aws cloudtrail create-trail \
  --name my-organization-trail \
  --s3-bucket-name my-org-cloudtrail-logs-$(aws sts get-caller-identity --query Account --output text) \
  --is-multi-region-trail \
  --enable-log-file-validation \
  --is-organization-trail

# Start logging
aws cloudtrail start-logging --name my-organization-trail
```

**Console Method:**
1. Navigate to CloudTrail console
2. Click "Create trail"
3. Enter trail name
4. Select "Apply trail to all regions"
5. Create new S3 bucket or select existing
6. Enable log file validation
7. Enable for organization (if applicable)
8. Click "Create trail"

**Verification:**
```bash
# Check trail status
aws cloudtrail get-trail-status --name my-organization-trail

# Verify logs are being delivered
aws cloudtrail lookup-events --max-results 10
```

**Update CSV:**
```csv
Threat Detection,Audit API calls (CloudTrail),Quick Wins,Completed,Critical,"Multi-region trail configured with log file validation and centralized logging",2024-02-02
```

---

### 4. Enable S3 Block Public Access

**Account Level (Recommended):**
```bash
# Enable all Block Public Access settings
aws s3control put-public-access-block \
  --account-id $(aws sts get-caller-identity --query Account --output text) \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

**Bucket Level:**
```bash
# For specific bucket
aws s3api put-public-access-block \
  --bucket my-bucket-name \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# For all buckets
for bucket in $(aws s3 ls | awk '{print $3}'); do
  echo "Blocking public access for $bucket"
  aws s3api put-public-access-block \
    --bucket $bucket \
    --public-access-block-configuration \
      BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
done
```

**Console Method:**
1. Navigate to S3 console
2. Click "Block Public Access settings for this account"
3. Click "Edit"
4. Check all four options
5. Click "Save changes"
6. Type "confirm" and click "Confirm"

**Verification:**
```bash
# Check account-level settings
aws s3control get-public-access-block --account-id $(aws sts get-caller-identity --query Account --output text)

# Check bucket-level settings
aws s3api get-public-access-block --bucket my-bucket-name
```

**Update CSV:**
```csv
Data Protection,Block Public Access (S3),Quick Wins,Completed,Critical,"Account-level Block Public Access enabled for all settings",2024-02-02
```

---

### 5. Cleanup Risky Security Groups

**Identify risky rules:**
```bash
# Find security groups with 0.0.0.0/0 SSH access
aws ec2 describe-security-groups \
  --filters Name=ip-permission.from-port,Values=22 Name=ip-permission.to-port,Values=22 Name=ip-permission.cidr,Values='0.0.0.0/0' \
  --query 'SecurityGroups[].{GroupId:GroupId,GroupName:GroupName,VpcId:VpcId}' \
  --output table
```

**Remove risky rules:**
```bash
# Remove SSH from 0.0.0.0/0
aws ec2 revoke-security-group-ingress \
  --group-id sg-xxxxxxxxx \
  --protocol tcp \
  --port 22 \
  --cidr 0.0.0.0/0

# Add restricted SSH access (replace with your IP)
aws ec2 authorize-security-group-ingress \
  --group-id sg-xxxxxxxxx \
  --protocol tcp \
  --port 22 \
  --cidr YOUR_IP/32
```

**Console Method:**
1. Navigate to EC2 → Security Groups
2. Select security group
3. Click "Inbound rules" tab
4. Click "Edit inbound rules"
5. Remove or modify risky rules
6. Click "Save rules"

**Verification:**
```bash
# Verify no 0.0.0.0/0 SSH access remains
aws ec2 describe-security-groups \
  --filters Name=ip-permission.from-port,Values=22 Name=ip-permission.to-port,Values=22 Name=ip-permission.cidr,Values='0.0.0.0/0' \
  --query 'SecurityGroups[].GroupId'
```

**Update CSV:**
```csv
Infrastructure Protection,Cleanup risky open ports,Quick Wins,Completed,High,"Removed 0.0.0.0/0 access from 5 security groups, restricted to specific IPs",2024-02-02
```

---

## Foundational Controls Remediations

### 1. Implement Service Control Policies (SCPs)

**Prerequisites:**
- AWS Organizations enabled
- Organizational units (OUs) created

**Example SCP - Require MFA:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyAllExceptListedIfNoMFA",
      "Effect": "Deny",
      "NotAction": [
        "iam:CreateVirtualMFADevice",
        "iam:EnableMFADevice",
        "iam:GetUser",
        "iam:ListMFADevices",
        "iam:ListVirtualMFADevices",
        "iam:ResyncMFADevice",
        "sts:GetSessionToken"
      ],
      "Resource": "*",
      "Condition": {
        "BoolIfExists": {
          "aws:MultiFactorAuthPresent": "false"
        }
      }
    }
  ]
}
```

**Apply SCP:**
```bash
# Create policy
aws organizations create-policy \
  --name RequireMFA \
  --description "Require MFA for all actions" \
  --content file://require-mfa-policy.json \
  --type SERVICE_CONTROL_POLICY

# Attach to OU
aws organizations attach-policy \
  --policy-id p-xxxxxxxxx \
  --target-id ou-xxxx-xxxxxxxx
```

**More SCP Examples:**

**Deny Region Restriction:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyAllOutsideApprovedRegions",
      "Effect": "Deny",
      "NotAction": [
        "cloudfront:*",
        "iam:*",
        "route53:*",
        "support:*"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:RequestedRegion": [
            "us-east-1",
            "us-west-2"
          ]
        }
      }
    }
  ]
}
```

**Update CSV:**
```csv
Identity and Access Management,GuardRails: Organizational Policies with SCPs/RCPs,Foundational,Completed,High,"Implemented 3 SCPs: RequireMFA, RegionRestriction, PreventSecurityServiceDisabling",2024-02-02
```

---

### 2. Enforce IMDSv2

**For existing instances:**
```bash
# Modify instance to require IMDSv2
aws ec2 modify-instance-metadata-options \
  --instance-id i-xxxxxxxxx \
  --http-tokens required \
  --http-put-response-hop-limit 1
```

**For all instances:**
```bash
#!/bin/bash
for instance in $(aws ec2 describe-instances --query 'Reservations[].Instances[].InstanceId' --output text); do
  echo "Updating $instance to require IMDSv2"
  aws ec2 modify-instance-metadata-options \
    --instance-id $instance \
    --http-tokens required \
    --http-put-response-hop-limit 1
done
```

**For new instances (Launch Template):**
```bash
aws ec2 create-launch-template \
  --launch-template-name my-template \
  --launch-template-data '{
    "MetadataOptions": {
      "HttpTokens": "required",
      "HttpPutResponseHopLimit": 1
    }
  }'
```

**Verification:**
```bash
# Check instance metadata options
aws ec2 describe-instances \
  --instance-ids i-xxxxxxxxx \
  --query 'Reservations[].Instances[].MetadataOptions'
```

**Update CSV:**
```csv
Identity and Access Management,Instance Metadata Service (IMDS) v2,Foundational,Completed,High,"All 23 EC2 instances updated to require IMDSv2",2024-02-02
```

---

## Verification Checklist

After implementing each control:

- [ ] Control implemented as documented
- [ ] Verification command executed successfully
- [ ] No errors or warnings in implementation
- [ ] Tested in non-production first (if applicable)
- [ ] Documentation updated
- [ ] CSV tracking updated
- [ ] Team notified of changes
- [ ] Monitoring configured for the control

## Rollback Procedures

If a remediation causes issues:

**GuardDuty:**
```bash
aws guardduty delete-detector --detector-id $DETECTOR_ID
```

**S3 Block Public Access:**
```bash
aws s3control put-public-access-block \
  --account-id $(aws sts get-caller-identity --query Account --output text) \
  --public-access-block-configuration \
    BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false
```

**Security Group Rule:**
```bash
aws ec2 authorize-security-group-ingress \
  --group-id sg-xxxxxxxxx \
  --protocol tcp \
  --port 22 \
  --cidr 0.0.0.0/0
```

## Common Issues

**Issue: Permission denied**
- Solution: Ensure IAM user/role has appropriate permissions for the service

**Issue: Resource already exists**
- Solution: Check if control was previously implemented, verify configuration

**Issue: Service not available in region**
- Solution: Check service availability, use supported region

**Issue: Dependency not met**
- Solution: Implement prerequisite controls first

## Next Steps

1. Verify all implementations
2. Update CSV tracking file
3. Schedule next assessment
4. Monitor for any issues
5. Continue with next priority controls
