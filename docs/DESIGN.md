# Design document: Secure AWS foundation

*Also available as an image: [design.png](design.png). Architecture diagram: [architecture.png](architecture.png).*

## 1. Scope and principles

This is a single-account, single-region foundation with a multi-region audit trail. It covers networking, logging, threat detection, encryption, private compute access, identity and configuration monitoring. The design rests on four principles:

1. **Everything in code.** The only manual steps are ones AWS does not expose to IaC, such as root MFA. Those are listed in the README.
2. **Defense in depth over single controls.** Routing, NACLs and security groups each restrict egress. Bucket policies and KMS key policies each restrict log access.
3. **Detect, then alert.** Every preventive control has a detective counterpart: Config rules, GuardDuty and EventBridge alerts.
4. **Cost is a design input.** The default deployment costs about $12–15 a month. Where a control is expensive, the cheaper equivalent is the default and the expensive one is a flag.

## 2. Stack layout

| Stack | Contents | Why separate |
|-------|----------|--------------|
| `security-baseline` | KMS CMKs, log archive and access-log buckets, CloudTrail, GuardDuty, Config and rules, optional Security Hub, IAM roles and groups, Access Analyzer, alerting, budget, account guardrails | Longest lifecycle and owned by security. In a multi-account setup this splits into the Log Archive and Audit accounts. |
| `network` | VPC, NAT, NACLs, flow logs, endpoints | Owned by the platform/network team. Changes rarely. |
| `workload` | EC2 instance, instance role, Session Manager preferences | Changes most often. Can be torn down and rebuilt freely. |

Dependencies flow one way only: workload depends on network, which depends on baseline. `cdk destroy --all` therefore removes them in the right order.

## 3. Key decisions and rationale

### Networking
* **Two AZs with public and private /24 subnets.** This meets the multi-AZ requirement at the smallest size. The private tier has no route to the Internet Gateway.
* **Controlled egress: a NAT instance, not a NAT Gateway (default).** A t4g.nano NAT instance with a public IPv4 costs about $7 a month. A NAT Gateway costs about $33 a month plus data processing. The NAT instance's security group accepts only TCP 443 from the VPC CIDR. The public NACL allows only 443 outbound. The trade-offs are a single AZ and self-managed patching, so `-c egress_mode=nat-gateway` switches to a managed gateway. `-c egress_mode=none` removes internet egress entirely: private subnets become isolated and reach SSM, KMS and Logs through PrivateLink.
* **Interface endpoints are optional and in one AZ.** Five endpoints across two AZs would cost about $73 a month, which is more than the rest of the deployment combined. In production I would enable them in every AZ and remove the NAT path for management traffic.
* **The S3 gateway endpoint is always on (free).** It keeps package-repository and SSM-agent S3 traffic off the NAT.
* **Least-privilege security groups.** The instance SG has *no* inbound rules and allows outbound 443 only. The endpoint SG allows inbound 443 from the VPC and nothing outbound. The default SG is stripped of all rules by `restrict_default_security_group`.
* **Stateless NACLs as a second layer.** Only 443 plus ephemeral return ports are allowed, so SSH, RDP and every other protocol are blocked at the subnet edge even if someone misconfigures an SG.
* **VPC flow logs (ALL) go to S3, not CloudWatch Logs.** Vended-log delivery to S3 is about half the ingestion price and lands in the same immutable archive as CloudTrail.

### Logging
* **One multi-region CloudTrail trail** with global service events and log-file integrity validation. It records management events only. The first copy of management events is free, while data events and CloudTrail Insights are the main cost drivers. In production I would add S3 and Lambda data events for sensitive buckets.
* **Log archive bucket:** SSE-KMS with the logs CMK and an S3 Bucket Key (about 99% fewer KMS calls). It is versioned, has Block Public Access on all four settings, uses BucketOwnerEnforced (ACLs disabled), denies non-TLS requests, and has a lifecycle rule (365-day expiry, 30 days for noncurrent versions). Service writes are scoped with `aws:SourceAccount`/`aws:SourceArn`.
* **Server access logs for the archive** go to a separate SSE-S3 bucket. S3 access logging cannot target SSE-KMS buckets.
* **Not implemented and why:** S3 Object Lock (WORM) would make teardown impossible within the exercise window. It is the first thing I would add in production, in compliance mode inside a dedicated Log Archive account.

### Encryption
* **Two CMKs with automatic rotation:** `logs` for CloudTrail, Config, flow logs, SNS and CloudWatch Logs, and `data` for EBS and Session Manager sessions. Splitting by data class lets the two key policies differ. For example, auditors can decrypt logs (`kms:ViaService` = S3) but have no access to workload data. Each key costs $1 a month, so more keys would add cost without adding value at this scale.
* **Key policies grant service principals only what they need**, with encryption-context or source conditions. The account root statement delegates human access to IAM.
* **Account guardrails applied through SDK custom resources** (no native CloudFormation type exists): EBS encryption by default, and S3 account-level Block Public Access.

### Threat detection
* **GuardDuty** with foundational sources (CloudTrail, VPC flow, DNS) plus S3 Protection. The other protection plans (EKS, RDS, Lambda, Malware, Runtime) are set to DISABLED explicitly. That keeps cost predictable and documents intent. Each plan is a one-line change when a matching workload appears.
* **Findings with severity 7 or higher** go through EventBridge to an encrypted SNS topic and then to email.
* **Root user activity and break-glass role assumption** also trigger alerts. Both rules use `ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS`, because console sign-ins and `AssumeRole` are read-only events that EventBridge does not otherwise receive.

### Secure access
* **EC2 in a private subnet:** no public IP, IMDSv2 required, CMK-encrypted gp3 root volume, and Amazon Linux 2023 (SSM agent preinstalled).
* **Session Manager is the only way in.** There is no key pair, no SSH, and no bastion. Session Manager preferences are in code: sessions are KMS-encrypted end to end, transcripts stream to a KMS-encrypted CloudWatch log group (30-day retention), idle timeout is 20 minutes and maximum session length is 60 minutes. Every `StartSession` is also in CloudTrail.
* **The instance role is `AmazonSSMManagedInstanceCore`**, plus write access to its own log group and decrypt on the data key. It has no other permissions.

### Identity
* **Break-glass admin role:** `AdministratorAccess`. Assuming it requires MFA that is less than an hour old. Sessions last at most 1 hour, and every assumption raises an alert.
* **Security auditor role:** `SecurityAudit`, plus read on the log archive and decrypt via S3 only. It cannot change anything or read workload data.
* **By default the roles trust the account**, so only principals with an explicit `sts:AssumeRole` grant can use them. IAM groups provide that grant. `trusted_admin_principal_arns` narrows trust to named principals.
* **Root:** MFA and no access keys (manual, see README), monitored by two Config rules and the root-activity alert.
* **IAM Access Analyzer** (account zone of trust, free) flags any resource shared outside the account.

### Configuration monitoring
* **AWS Config** records all supported resource types, plus IAM in the home region. Snapshots are delivered daily to the encrypted archive.
* **13 managed rules** map directly to the controls above: root MFA and keys, multi-region trail, trail encryption, S3 public access, EBS encryption, no inbound SSH, no public IP on EC2, IMDSv2, managed by SSM, default SG closed, flow logs, and GuardDuty.
* **One expected finding:** `EC2_INSTANCE_NO_PUBLIC_IP` flags the NAT instance. This is a documented exception that `egress_mode=none` removes. It is a useful walkthrough example of finding triage.
* **Security Hub with CIS v3.0.0 is a flag (`enable_security_hub`)** and off by default. Its per-check pricing adds cost, and the Config rules already cover the highest-value CIS controls.

## 4. Cost summary (us-east-1, default flags, approximate)

| Item | Monthly |
|------|---------|
| NAT instance t4g.nano + public IPv4 + 8 GB gp3 | ~$7.30 |
| Private EC2 t4g.nano + 8 GB gp3 | ~$3.70 |
| 2 KMS CMKs | $2.00 |
| AWS Config (initial items, then low churn, 13 rules) | ~$1–3 |
| GuardDuty (30-day free trial, then a low-volume account) | $0 then ~$1–3 |
| CloudTrail management events, S3, flow logs, SNS, CloudWatch | < $1 |
| **Total** | **~$12–15 / month (~$0.45 / day)** |

Optional add-ons: NAT Gateway +$33, interface endpoints +$36 (one AZ), Security Hub CIS about +$1–5.

## 5. Evolving to a multi-account strategy

Target: **AWS Organizations + Control Tower (Landing Zone)**, with CDK pipelines for everything above the landing zone.

```
Root (management account: billing, Organizations, Control Tower only, no workloads)
├── Security OU
│   ├── Log Archive   ← org CloudTrail, Config, flow logs; Object Lock; tightly limited readers
│   └── Audit / Security Tooling ← GuardDuty, Security Hub, Config aggregator, Access Analyzer,
│                                  Detective, Inspector delegated admin; break-glass and auditor roles
├── Infrastructure OU
│   ├── Network       ← Transit Gateway or VPC Lattice, centralized egress (NAT and Network Firewall),
│   │                    centralized interface endpoints, Route 53 Resolver rules, shared through RAM
│   └── Shared Services ← CI/CD (CDK Pipelines), artifact repositories, AMI pipeline
├── Workloads OU
│   ├── Prod OU    ├── NonProd OU   (one account per workload per environment)
└── Sandbox / Suspended OUs
```

How each component here maps across:

| This repo | Multi-account equivalent |
|-----------|--------------------------|
| Account trail | Control Tower **organization trail** into the Log Archive account. Member accounts cannot disable it. |
| Log bucket and logs CMK | Lives in Log Archive. The bucket and key policies use `aws:PrincipalOrgID`. Object Lock in compliance mode. |
| GuardDuty / Security Hub / Config | **Delegated administrator** in Audit, with auto-enable for new accounts in all regions, plus a Config aggregator and conformance packs. |
| IAM roles and groups | **IAM Identity Center** permission sets (BreakGlass, SecurityAuditor, ReadOnly, Developer) mapped to IdP groups. Break-glass becomes a sealed IAM user with a hardware MFA token in the management account, with alarms. |
| Guardrails (EBS default encryption, S3 BPA) | **SCPs** (deny leaving the org, deny disabling CloudTrail/GuardDuty/Config, region deny-list, deny root, deny unencrypted EBS) and **RCPs** for data perimeters. Control Tower proactive (CloudFormation Hooks) and detective controls. |
| NAT instance per VPC | Centralized inspected egress in the Network account (TGW + Network Firewall + NAT Gateway in each AZ). Workload VPCs get no IGW. |
| `cdk deploy` from a laptop | **CDK Pipelines** in Shared Services. Deploys cross-account through bootstrap trust (`cdk bootstrap --trust`) with a custom, least-privilege CloudFormation execution policy instead of AdministratorAccess. cdk-nag and unit tests act as pipeline gates. Stacks become reusable L3 constructs, published as an internal construct library. |
| New account baseline | Account Factory (or AFT / Account Factory for CDK customizations). The `network` and `workload` stacks become the per-account blueprint. |

**Trade-offs:** Control Tower gives fast, opinionated, AWS-supported guardrails and drift detection, but it is less flexible and its lifecycle is partly outside our IaC. The alternative is Organizations plus a custom landing zone built fully in CDK: more control and reviewability, but more to build and own. For a regulated environment I would choose Control Tower for the landing zone and keep everything above it in CDK, so that the auditable baseline is AWS-supported and our differentiating controls are code-reviewed.

## 6. Operating this in a regulated environment (walkthrough topics)

* **Change control:** pull request, then CI (`pytest`, `cdk synth -c nag=true`, `cdk diff`), then approval, then a pipeline deploy. No console changes, and Config plus CloudFormation drift detection catch any that happen.
* **Incident response:** GuardDuty alerts arrive through SNS (later into a SIEM or ticketing system). The runbook is: isolate the instance by swapping to a deny-all SG, snapshot the EBS volume, and investigate with the auditor role. Break-glass use is alerted and reviewed.
* **Evidence:** CloudTrail with file validation, Config history and the compliance timeline, and session transcripts, all in the KMS-encrypted archive.
* **Next controls:** Object Lock, Security Hub with CIS and FSBP standards, Inspector for EC2 vulnerabilities, Patch Manager baselines, an IAM password policy, CloudTrail data events for the log bucket, Detective, and an egress firewall with domain allow-lists.
