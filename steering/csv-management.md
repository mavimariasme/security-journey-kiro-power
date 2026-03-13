# CSV Management Guide

This guide explains how to manage and update the security maturity tracking CSV file.

## CSV Structure

The CSV file tracks your security maturity progress with the following columns:

| Column | Description | Valid Values |
|--------|-------------|--------------|
| Domain | Security domain | Security Governance, Identity and Access Management, Threat Detection, Vulnerability Management, Infrastructure Protection, Data Protection, Application Security, Incident Response, Security Assurance, Resiliency |
| Control | Specific security control | Control name from AWS Security Maturity Model |
| Phase | Maturity phase | Quick Wins, Foundational, Efficient, Optimized |
| Status | Implementation status | Not Started, In Progress, Completed |
| Priority | Priority level | Critical, High, Medium, Low |
| Notes | Implementation notes | Free text |
| Last Updated | Last update timestamp | YYYY-MM-DD format |

## Reading the CSV

**Using the agent:**
```
Ask: "Read my security maturity CSV and show me all controls that are Not Started"
Ask: "Show me all Critical priority controls"
Ask: "What's my completion percentage for Quick Wins?"
```

**Using command line:**
```bash
# View all controls
cat aws-security-maturity-tracking.csv | column -t -s,

# Filter by status
grep "Not Started" aws-security-maturity-tracking.csv

# Filter by phase
grep "Quick Wins" aws-security-maturity-tracking.csv

# Filter by priority
grep "Critical" aws-security-maturity-tracking.csv

# Count completed controls
grep -c "Completed" aws-security-maturity-tracking.csv
```

**Using Python:**
```python
import pandas as pd

# Read CSV
df = pd.read_csv('aws-security-maturity-tracking.csv')

# Show summary
print(df['Status'].value_counts())
print(df.groupby(['Phase', 'Status']).size())

# Filter not started critical controls
critical_gaps = df[(df['Status'] == 'Not Started') & (df['Priority'] == 'Critical')]
print(critical_gaps[['Domain', 'Control', 'Phase']])
```

## Updating the CSV

### After Assessment

When you complete an assessment, update the CSV with findings:

**Example updates:**
```csv
# Control found to be implemented
Domain,Control,Phase,Status,Priority,Notes,Last Updated
Threat Detection,Detect Common Threats (GuardDuty),Quick Wins,Completed,Critical,"Enabled in all 3 regions",2024-02-02

# Control partially implemented
Data Protection,Block Public Access (S3),Quick Wins,In Progress,Critical,"Account-level enabled, 2 buckets need configuration",2024-02-02

# Control not implemented with findings
Infrastructure Protection,Cleanup risky open ports,Quick Wins,Not Started,High,"Found 5 SGs with 0.0.0.0/0 SSH access",2024-02-02
```

**Using the agent:**
```
Ask: "Update the CSV: GuardDuty is completed, enabled in all regions"
Ask: "Mark S3 Block Public Access as In Progress with note: account-level enabled"
Ask: "Add finding to Cleanup risky open ports: found 5 security groups with open SSH"
```

### After Remediation

When you implement a control, update the status:

```csv
# Before
Infrastructure Protection,Cleanup risky open ports,Quick Wins,Not Started,High,"Found 5 SGs with 0.0.0.0/0 SSH access",2024-02-02

# After
Infrastructure Protection,Cleanup risky open ports,Quick Wins,Completed,High,"Removed 0.0.0.0/0 from all 5 SGs, restricted to specific IPs",2024-02-05
```

**Using the agent:**
```
Ask: "Update CSV: Cleanup risky open ports is now Completed"
Ask: "Add note to Cleanup risky open ports: Removed 0.0.0.0/0 from all 5 security groups"
```

### Bulk Updates

**Using command line (sed):**
```bash
# Update all Quick Wins GuardDuty to Completed
sed -i '' 's/Detect Common Threats (GuardDuty),Quick Wins,Not Started/Detect Common Threats (GuardDuty),Quick Wins,Completed/' aws-security-maturity-tracking.csv

# Update last updated date for all In Progress
sed -i '' 's/In Progress,\(.*\),\(.*\),.*$/In Progress,\1,\2,2024-02-02/' aws-security-maturity-tracking.csv
```

**Using Python:**
```python
import pandas as pd
from datetime import datetime

# Read CSV
df = pd.read_csv('aws-security-maturity-tracking.csv')

# Update specific control
df.loc[df['Control'] == 'Detect Common Threats (GuardDuty)', 'Status'] = 'Completed'
df.loc[df['Control'] == 'Detect Common Threats (GuardDuty)', 'Last Updated'] = datetime.now().strftime('%Y-%m-%d')

# Save
df.to_csv('aws-security-maturity-tracking.csv', index=False)
```

## Generating Reports

### Progress Summary

**Using the agent:**
```
Ask: "Generate a security maturity progress summary from the CSV"
Ask: "Show me completion percentage by phase"
Ask: "What's my overall security maturity score?"
```

**Using Python:**
```python
import pandas as pd

df = pd.read_csv('aws-security-maturity-tracking.csv')

# Overall progress
total = len(df)
completed = len(df[df['Status'] == 'Completed'])
in_progress = len(df[df['Status'] == 'In Progress'])
not_started = len(df[df['Status'] == 'Not Started'])

print(f"Overall Progress: {completed/total*100:.1f}%")
print(f"Completed: {completed} ({completed/total*100:.1f}%)")
print(f"In Progress: {in_progress} ({in_progress/total*100:.1f}%)")
print(f"Not Started: {not_started} ({not_started/total*100:.1f}%)")

# By phase
phase_summary = df.groupby(['Phase', 'Status']).size().unstack(fill_value=0)
print("\nProgress by Phase:")
print(phase_summary)

# By domain
domain_summary = df.groupby(['Domain', 'Status']).size().unstack(fill_value=0)
print("\nProgress by Domain:")
print(domain_summary)
```

### Gap Analysis

**Identify highest priority gaps:**
```python
import pandas as pd

df = pd.read_csv('aws-security-maturity-tracking.csv')

# Critical gaps
critical_gaps = df[(df['Status'] == 'Not Started') & (df['Priority'] == 'Critical')]
print("Critical Gaps:")
print(critical_gaps[['Domain', 'Control', 'Phase']])

# Quick Wins not started
quick_wins_gaps = df[(df['Phase'] == 'Quick Wins') & (df['Status'] == 'Not Started')]
print("\nQuick Wins Not Started:")
print(quick_wins_gaps[['Control', 'Priority']])
```

### Trend Analysis

**Compare assessments over time:**
```python
import pandas as pd
import matplotlib.pyplot as plt

# Read multiple CSV snapshots
df_jan = pd.read_csv('aws-security-maturity-tracking-2024-01.csv')
df_feb = pd.read_csv('aws-security-maturity-tracking-2024-02.csv')

# Calculate completion rates
jan_completion = len(df_jan[df_jan['Status'] == 'Completed']) / len(df_jan) * 100
feb_completion = len(df_feb[df_feb['Status'] == 'Completed']) / len(df_feb) * 100

print(f"January: {jan_completion:.1f}%")
print(f"February: {feb_completion:.1f}%")
print(f"Improvement: +{feb_completion - jan_completion:.1f}%")

# Plot trend
months = ['January', 'February']
completion = [jan_completion, feb_completion]
plt.plot(months, completion, marker='o')
plt.ylabel('Completion %')
plt.title('Security Maturity Progress')
plt.show()
```

## CSV Maintenance

### Backup

**Create timestamped backups:**
```bash
# Manual backup
cp aws-security-maturity-tracking.csv aws-security-maturity-tracking-$(date +%Y-%m-%d).csv

# Automated backup script
#!/bin/bash
BACKUP_DIR="./backups"
mkdir -p $BACKUP_DIR
cp aws-security-maturity-tracking.csv $BACKUP_DIR/aws-security-maturity-tracking-$(date +%Y-%m-%d-%H%M%S).csv
echo "Backup created: $BACKUP_DIR/aws-security-maturity-tracking-$(date +%Y-%m-%d-%H%M%S).csv"
```

### Version Control

**Track changes with Git:**
```bash
# Initialize repo
git init
git add aws-security-maturity-tracking.csv
git commit -m "Initial security maturity tracking"

# After updates
git add aws-security-maturity-tracking.csv
git commit -m "Updated GuardDuty and CloudTrail status to Completed"

# View history
git log --oneline aws-security-maturity-tracking.csv

# Compare versions
git diff HEAD~1 aws-security-maturity-tracking.csv
```

### Validation

**Validate CSV structure:**
```python
import pandas as pd

def validate_csv(filepath):
    """Validate security maturity CSV structure and values"""
    
    # Read CSV
    df = pd.read_csv(filepath)
    
    # Check required columns
    required_columns = ['Domain', 'Control', 'Phase', 'Status', 'Priority', 'Notes', 'Last Updated']
    missing_columns = set(required_columns) - set(df.columns)
    if missing_columns:
        print(f"ERROR: Missing columns: {missing_columns}")
        return False
    
    # Validate domains
    valid_domains = [
        'Security Governance', 'Identity and Access Management', 
        'Threat Detection', 'Vulnerability Management',
        'Infrastructure Protection', 'Data Protection',
        'Application Security', 'Incident Response',
        'Security Assurance', 'Resiliency'
    ]
    invalid_domains = df[~df['Domain'].isin(valid_domains)]['Domain'].unique()
    if len(invalid_domains) > 0:
        print(f"WARNING: Invalid domains: {invalid_domains}")
    
    # Validate phases
    valid_phases = ['Quick Wins', 'Foundational', 'Efficient', 'Optimized']
    invalid_phases = df[~df['Phase'].isin(valid_phases)]['Phase'].unique()
    if len(invalid_phases) > 0:
        print(f"WARNING: Invalid phases: {invalid_phases}")
    
    # Validate status
    valid_statuses = ['Not Started', 'In Progress', 'Completed']
    invalid_statuses = df[~df['Status'].isin(valid_statuses)]['Status'].unique()
    if len(invalid_statuses) > 0:
        print(f"WARNING: Invalid statuses: {invalid_statuses}")
    
    # Validate priority
    valid_priorities = ['Critical', 'High', 'Medium', 'Low']
    invalid_priorities = df[~df['Priority'].isin(valid_priorities)]['Priority'].unique()
    if len(invalid_priorities) > 0:
        print(f"WARNING: Invalid priorities: {invalid_priorities}")
    
    print("CSV validation complete!")
    return True

# Run validation
validate_csv('aws-security-maturity-tracking.csv')
```

## Best Practices

1. **Update Immediately**: Update CSV right after assessment or remediation
2. **Be Specific in Notes**: Include details like "Enabled in 3 regions" not just "Enabled"
3. **Use Consistent Dates**: Use YYYY-MM-DD format for Last Updated
4. **Backup Regularly**: Create backups before major updates
5. **Version Control**: Use Git to track changes over time
6. **Validate Regularly**: Run validation to catch errors
7. **Review Monthly**: Review and update CSV during monthly assessments
8. **Document Decisions**: Use Notes field to explain why controls are not implemented
9. **Track Dependencies**: Note when controls depend on others
10. **Share with Team**: Keep team informed of progress

## Troubleshooting

**Issue: CSV file corrupted**
- Solution: Restore from backup, validate structure

**Issue: Duplicate entries**
- Solution: Use Python/Excel to identify and remove duplicates

**Issue: Inconsistent values**
- Solution: Run validation script, standardize values

**Issue: Can't open CSV**
- Solution: Check file permissions, ensure proper encoding (UTF-8)

## Integration with Tools

### Export to Excel

```python
import pandas as pd

df = pd.read_csv('aws-security-maturity-tracking.csv')
df.to_excel('aws-security-maturity-tracking.xlsx', index=False, sheet_name='Security Maturity')
```

### Import from Security Hub

```python
import boto3
import pandas as pd

# Get Security Hub findings
securityhub = boto3.client('securityhub')
findings = securityhub.get_findings(
    Filters={'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}]}
)

# Map findings to controls
# (Custom logic based on your control mapping)

# Update CSV
df = pd.read_csv('aws-security-maturity-tracking.csv')
# Update based on findings...
df.to_csv('aws-security-maturity-tracking.csv', index=False)
```

### Dashboard Integration

```python
import pandas as pd
import plotly.express as px

df = pd.read_csv('aws-security-maturity-tracking.csv')

# Create dashboard
fig = px.sunburst(
    df, 
    path=['Phase', 'Domain', 'Status'],
    title='Security Maturity Dashboard'
)
fig.show()
```
