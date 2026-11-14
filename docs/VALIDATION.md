# Validation checklist

A step-by-step script that proves each requirement works in a deployed account. It doubles as a live demo.
Each section lists the commands, what you should see, and the point it proves.

**Time:** about 45–60 minutes. Do sections 1–4 first. AWS Config needs about 15 minutes after the deploy
for its first evaluations, and CloudTrail delivers log files every 5–15 minutes.

**Shell:** PowerShell, AWS CLI v2, Session Manager plugin, and an IAM admin identity signed in with MFA (not root).

---

## 0. Setup (right after `cdk deploy --all`)

- [ ] **Confirm the SNS subscription.** Click the link in the "AWS Notification – Subscription Confirmation"
      email. Until you do, no alerts are delivered.
- [ ] Load the stack outputs into variables. Every later step uses these:

```powershell
$env:AWS_REGION = "us-east-1"; $env:AWS_PAGER = ""
function Out-Of($stack, $key) {
  aws cloudformation describe-stacks --stack-name $stack `
    --query "Stacks[0].Outputs[?OutputKey=='$key'].OutputValue" --output text
}
$InstanceId = Out-Of secure-foundation-workload InstanceId
$VpcId      = Out-Of secure-foundation-network  VpcId
$LogBucket  = Out-Of secure-foundation-security-baseline LogBucketName
$BreakGlassUrl = Out-Of secure-foundation-security-baseline BreakGlassSwitchRoleUrl
$AuditorUrl    = Out-Of secure-foundation-security-baseline AuditorSwitchRoleUrl
$InstanceId; $VpcId; $LogBucket
```

---

## 1. Private EC2, Session Manager only

**Requirement:** a private EC2 instance with no public IP, reachable only through Session Manager.

```powershell
aws ssm describe-instance-information --query "InstanceInformationList[].{id:InstanceId,ping:PingStatus}"
aws ec2 describe-instances --instance-ids $InstanceId `
  --query "Reservations[].Instances[].{publicIp:PublicIpAddress,keyPair:KeyName,imds:MetadataOptions.HttpTokens,sg:SecurityGroups[0].GroupId}"
$Sg = aws ec2 describe-instances --instance-ids $InstanceId --query "Reservations[0].Instances[0].SecurityGroups[0].GroupId" --output text
aws ec2 describe-security-groups --group-ids $Sg --query "SecurityGroups[0].{inbound:IpPermissions,outbound:IpPermissionsEgress[].{port:FromPort,cidr:IpRanges[0].CidrIp}}"
```

- [ ] `PingStatus` is `Online`
- [ ] `publicIp` and `keyPair` are both `null` (no IP to reach and no SSH key)
- [ ] `imds` is `required` (IMDSv2 only)
- [ ] The security group has **no inbound rules** (`[]`) and exactly one outbound rule: TCP 443

Open a session and test egress from inside:

```powershell
aws ssm start-session --target $InstanceId
```
```bash
curl -sI https://aws.amazon.com | head -1          # HTTP/2 200: HTTPS out through the NAT works
curl -m 5 http://example.com                       # times out: port 80 is blocked (SG + NACL)
curl -s -o /dev/null -w "%{http_code}\n" http://169.254.169.254/latest/meta-data/   # 401: IMDSv1 is off
exit
```

- [ ] HTTPS succeeds, plain HTTP times out, and IMDSv1 returns `401`

> **Point to make:** there is no inbound path from the internet. The only way in is an IAM-authenticated, MFA-backed
> Session Manager session, and outbound traffic is limited to HTTPS.

---

## 2. Session logging and encryption

**Requirement:** sessions are encrypted with a CMK, and their transcripts are kept.

```powershell
aws logs tail /secure-foundation/ssm/sessions --since 30m
aws logs describe-log-groups --log-group-name-prefix /secure-foundation/ssm --query "logGroups[].{name:logGroupName,kms:kmsKeyId,days:retentionInDays}"
aws ssm get-document --name SSM-SessionManagerRunShell --query Content --output text
```

- [ ] The tail shows the commands you typed in section 1
- [ ] The log group has a `kmsKeyId` (the `logs` CMK) and 30-day retention
- [ ] The preferences document has a `kmsKeyId` (the `data` CMK), `cloudWatchEncryptionEnabled: true`,
      and a 20-minute idle timeout

> **Point to make:** every admin action on the instance is recorded and encrypted at rest. The session
> channel itself is wrapped in a second KMS layer on top of TLS.

---

## 3. CloudTrail and the encrypted log archive

**Requirement:** a multi-region CloudTrail writing to an encrypted, versioned, private S3 bucket using a CMK.

```powershell
aws cloudtrail get-trail-status --name secure-foundation-trail --query "{logging:IsLogging,lastDelivery:LatestDeliveryTime,lastError:LatestDeliveryError}"
aws cloudtrail describe-trails --trail-name-list secure-foundation-trail `
  --query "trailList[].{multiRegion:IsMultiRegionTrail,globalEvents:IncludeGlobalServiceEvents,kms:KmsKeyId,validation:LogFileValidationEnabled}"
aws s3api get-bucket-encryption   --bucket $LogBucket
aws s3api get-bucket-versioning   --bucket $LogBucket
aws s3api get-public-access-block --bucket $LogBucket
aws s3api get-bucket-ownership-controls --bucket $LogBucket
aws s3api get-bucket-policy --bucket $LogBucket --query Policy --output text | ConvertFrom-Json | Select-Object -Expand Statement | Select-Object Sid, Effect
aws s3api get-bucket-logging --bucket $LogBucket
foreach ($k in "logs", "data") {   # get-key-rotation-status needs a key ID, not an alias
  $id = aws kms describe-key --key-id "alias/secure-foundation/$k" --query KeyMetadata.KeyId --output text
  aws kms get-key-rotation-status --key-id $id --query "{key:'$k',rotation:KeyRotationEnabled,days:RotationPeriodInDays}"
}
aws s3 ls "s3://$LogBucket/cloudtrail/AWSLogs/" --recursive | Select-Object -First 5
```

- [ ] `logging: true`, with no `lastError`
- [ ] Multi-region and global service events are on, a `KmsKeyId` is set, and log file validation is on
- [ ] Bucket encryption is `aws:kms` with the CMK and a bucket key (`BlockedEncryptionTypes: SSE-C` is the S3 default for new buckets)
- [ ] Versioning is `Enabled`, and all four Block Public Access settings are `true`
- [ ] Ownership is `BucketOwnerEnforced` (ACLs are disabled)
- [ ] The bucket policy's first statement is an unnamed **Deny**. It is the TLS-only rule
      (`aws:SecureTransport = false`), followed by `FlowLogs*` and `Config*` service-delivery statements
- [ ] Server access logging goes to the separate access-log bucket under `log-bucket/`
- [ ] `rotation: True` for both CMKs (yearly: `days: 365`)
- [ ] Log files are appearing under `cloudtrail/`. This takes up to 15 minutes after the deploy.

**Optional tamper-evidence proof.** Run this at the end: digest files are written hourly.
```powershell
$TrailArn = aws cloudtrail describe-trails --trail-name-list secure-foundation-trail --query "trailList[0].TrailARN" --output text
aws cloudtrail validate-logs --trail-arn $TrailArn --start-time (Get-Date).ToUniversalTime().AddHours(-2).ToString("yyyy-MM-ddTHH:mm:ssZ")
```
- [ ] Reports the files as `valid`

> **Point to make:** the logs are encrypted with keys this account controls, versioned so nothing can be
> silently overwritten, impossible to make public, TLS-only, and cryptographically verifiable.

---

## 4. GuardDuty, end to end

**Requirement:** GuardDuty is enabled, and high-severity findings reach a human.

```powershell
$Det = aws guardduty list-detectors --query "DetectorIds[0]" --output text
aws guardduty get-detector --detector-id $Det --query "{status:Status,features:Features[?Status=='ENABLED'].Name}"
aws guardduty create-sample-findings --detector-id $Det --finding-types "Backdoor:EC2/C&CActivity.B!DNS"
```

- [ ] The detector is `ENABLED`, with `S3_DATA_EVENTS` among the enabled features
- [ ] Within about 5 minutes an email arrives from *secure-foundation security alerts* that reads
      "GuardDuty finding Backdoor:EC2/C&CActivity.B!DNS (severity 8) in us-east-1 …"

> **Point to make:** this tests the whole pipeline, not just the detector: GuardDuty, then an EventBridge rule
> (severity 7 and above), then a KMS-encrypted SNS topic, then email.

---

## 5. AWS Config compliance (at least 15 minutes after the deploy)

**Requirement:** AWS Config (or Security Hub) evaluates the account continuously.

```powershell
aws configservice describe-configuration-recorder-status --query "ConfigurationRecordersStatus[].{recording:recording,lastStatus:lastStatus}"
aws configservice describe-compliance-by-config-rule `
  --query "ComplianceByConfigRules[].{rule:ConfigRuleName,status:Compliance.ComplianceType}" --output table
```

- [ ] The recorder is `recording: true` with `lastStatus: SUCCESS`
- [ ] All 13 rules are listed (named `secure-foundation-<managed-rule-id>`), and most are `COMPLIANT`.
      `INSUFFICIENT_DATA` means the first evaluation hasn't finished yet. Wait a few minutes and re-run.

Show what each non-compliant rule flagged:
```powershell
foreach ($r in (aws configservice describe-compliance-by-config-rule --compliance-types NON_COMPLIANT --query "ComplianceByConfigRules[].ConfigRuleName" --output text) -split "\s+" | Where-Object { $_ }) {
  "$r -> " + ((aws configservice get-compliance-details-by-config-rule --config-rule-name $r --compliance-types NON_COMPLIANT `
    --query "EvaluationResults[].EvaluationResultIdentifier.EvaluationResultQualifier.ResourceId" --output text) -join ' ')
}
aws ec2 describe-vpcs --filters Name=is-default,Values=true --query "Vpcs[].VpcId" --output text   # the account's default VPC, if any
```

**Expected, documented exceptions.** These are worth explaining rather than hiding:

| Rule | Flags | Why it's acceptable |
|------|-------|---------------------|
| `secure-foundation-ec2-instance-no-public-ip` | The NAT instance | A NAT needs a public IP. In production, use `egress_mode=nat-gateway` (a managed service, not an EC2 instance). A replaced or terminated NAT can also appear until Config re-evaluates. |
| `secure-foundation-vpc-flow-logs-enabled` | The account's **default VPC** | It's not part of this project. It shows Config evaluates the *whole* account, not just what we deployed. Fix: delete the default VPC (README §1.4). |
| `secure-foundation-vpc-default-security-group-closed` | The default VPC's default security group | Same cause and fix as above. The project VPC's default SG has no rules. |
| `secure-foundation-root-account-mfa-enabled` | Only if root MFA is missing | Shows `COMPLIANT` once the manual hardening in README §1.1 is done. |

`secure-foundation-ec2-instance-managed-by-ssm` reports the workload instance as `COMPLIANT`. It doesn't evaluate the NAT
instance, because the NAT never registers with Systems Manager.

> **Point to make:** compliance is evaluated continuously. The known exceptions also show that the rules
> really evaluate this account's resources.

---

## 6. Break-glass admin role

**Requirement:** a break-glass admin role that is MFA-gated and alerts whenever it is used.

1. Sign in to the console as your IAM user **with MFA**.
2. Open `$BreakGlassUrl` (run `$BreakGlassUrl` in PowerShell to print it) and choose **Switch role**.

- [ ] The switch succeeds, and the session is limited to 1 hour
- [ ] Within a few minutes an alert email arrives containing the CloudTrail `AssumeRole` event (the JSON shows who, the source IP and the time)
- [ ] *(Negative test)* The switch is **denied** from a session signed in without MFA, or whose MFA sign-in is more than an hour old

> **Point to make:** admin rights exist for emergencies only. Using them requires recent MFA, a session lasts at
> most an hour, and every use triggers an alert.

---

## 7. Read-only security auditor role

**Requirement:** an auditor role that can see everything security-related and change nothing.

Open `$AuditorUrl` and switch role, then try these in the console:

| Action | Expected |
|--------|----------|
| View GuardDuty findings, Config rules, CloudTrail event history | Allowed |
| Browse and download objects in the log bucket | Allowed |
| EC2 → select the instance → **Stop instance** | *You are not authorized* |
| S3 → log bucket → **Delete** an object | *Access Denied* |
| Systems Manager → **Start session** on the instance | Denied |

- [ ] Every row behaves as expected

> **Point to make:** least privilege. The auditor has broad visibility through the AWS-managed SecurityAudit policy plus
> read access to the log archive, and no write access.

---

## 8. Network layers

**Requirement:** a multi-AZ VPC with public and private subnets, controlled egress, and least-privilege SGs and NACLs.

```powershell
aws ec2 describe-subnets --filters Name=vpc-id,Values=$VpcId `
  --query "Subnets[].{az:AvailabilityZone,cidr:CidrBlock,autoPublicIp:MapPublicIpOnLaunch}" --output table
aws ec2 describe-network-acls --filters Name=vpc-id,Values=$VpcId Name=default,Values=false `
  --query "NetworkAcls[].Entries[?RuleAction=='allow'].{rule:RuleNumber,egress:Egress,cidr:CidrBlock,from:PortRange.From,to:PortRange.To}" --output table
aws ec2 describe-route-tables --filters Name=vpc-id,Values=$VpcId `
  --query "RouteTables[].Routes[?DestinationCidrBlock=='0.0.0.0/0'].{gw:GatewayId,nat:NatGatewayId,eni:NetworkInterfaceId}"
aws ec2 describe-flow-logs --filter Name=resource-id,Values=$VpcId --query "FlowLogs[].{status:FlowLogStatus,dest:LogDestination,traffic:TrafficType}"
aws ec2 describe-security-groups --filters Name=vpc-id,Values=$VpcId Name=group-name,Values=default --query "SecurityGroups[0].{in:IpPermissions,out:IpPermissionsEgress}"
```

- [ ] 4 subnets across 2 AZs. Only the public subnets auto-assign public IPs.
- [ ] The NACLs allow only TCP 443 and the ephemeral return range (1024–65535)
- [ ] Public subnets route `0.0.0.0/0` to the internet gateway (`igw-…`). Private subnets route it to the NAT
      instance's ENI (`eni-…`). One entry is `[]`: that's the VPC's unused main route table, which has no default route.
- [ ] Flow logs are `ACTIVE`, capture `ALL` traffic, and deliver to the log archive bucket
- [ ] The default security group has no rules

> **Point to make:** defence in depth. Stateful security groups and stateless NACLs are independent layers,
> and the flow logs feed both GuardDuty and forensic investigation.

---

## 9. Account guardrails and budget

```powershell
$Acct = aws sts get-caller-identity --query Account --output text
aws s3control get-public-access-block --account-id $Acct
aws ec2 get-ebs-encryption-by-default
aws accessanalyzer list-analyzers --query "analyzers[].{name:name,status:status}"
aws budgets describe-budgets --account-id $Acct --query "Budgets[].{name:BudgetName,limit:BudgetLimit.Amount}"
```

- [ ] Account-level S3 Block Public Access is all `true`, and EBS encryption by default is `true`
- [ ] IAM Access Analyzer is `ACTIVE`
- [ ] The project budget exists alongside your own zero-spend budget

---

## 10. *(Optional)* Root activity alert

Sign in as root briefly (with MFA) and sign straight out.

- [ ] An alert email arrives containing the `ConsoleLogin` event for `Root`

Skipping this is also a defensible answer: "I'd verify it in a sandbox, but root stays locked away."

---

## After validation

- Tear down with README §4: `cdk destroy --all`, then `scripts/cleanup_leftovers.py --apply`, then `--include-bootstrap`.
- After 24–48 hours, check Billing → Bills to confirm the run-rate has dropped to $0.
