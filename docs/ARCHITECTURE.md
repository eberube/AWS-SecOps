# Architecture and trust boundaries

![Architecture and trust boundaries](architecture.png)

The PNG above is the primary diagram, generated from [src/architecture.html](src/architecture.html) by `python scripts/render_docs.py`. The Mermaid version below renders natively on GitHub.

Dashed boxes are trust boundaries. Arrows show data and control flow. Everything inside the account boundary is defined in this repo except the root user and the operator's own IAM identity.

```mermaid
flowchart TB
    subgraph EXT["Trust boundary 0: outside AWS"]
        OP["Operator workstation<br/>AWS CLI + Session Manager plugin"]
        INET["Internet<br/>(package repos, AWS public endpoints)"]
        MAIL["Security / billing email"]
    end

    subgraph ACCT["Trust boundary 1: AWS account (single region deployment, multi-region trail)"]
        direction TB

        subgraph IDN["Identity plane (IAM, global)"]
            ROOT["Root user<br/>MFA, no access keys, never used<br/>(manual hardening)"]
            DEP["Operator IAM identity<br/>MFA"]
            BG["Role: break-glass-admin<br/>AdministratorAccess, MFA under 1h old, 1h session"]
            AUD["Role: security-auditor<br/>SecurityAudit + read log archive, MFA"]
            AA["IAM Access Analyzer"]
        end

        subgraph SEC["Security services plane (AWS managed, regional)"]
            CT["CloudTrail<br/>multi-region, global events,<br/>log file validation"]
            GD["GuardDuty<br/>foundational + S3 protection"]
            CFG["AWS Config<br/>recorder + 13 managed rules"]
            EB["EventBridge rules<br/>GuardDuty sev 7+, root activity,<br/>break-glass AssumeRole"]
            SNS["SNS topic (KMS)"]
            BUD["AWS Budgets"]
            SSM["Systems Manager<br/>Session Manager"]
        end

        subgraph DATA["Data protection plane"]
            KL["KMS CMK: logs<br/>rotation on"]
            KD["KMS CMK: data<br/>rotation on"]
            LB[("S3 log archive<br/>SSE-KMS, versioned, TLS-only,<br/>Block Public Access, bucket-owner-enforced")]
            AL[("S3 access-log bucket<br/>SSE-S3")]
            CWL[("CloudWatch Logs<br/>session transcripts (KMS)")]
        end

        subgraph VPC["Trust boundary 2: VPC 10.20.0.0/16 (2 AZs), flow logs to S3"]
            IGW["Internet Gateway"]
            subgraph PUB["Public subnets (AZ-a, AZ-b), public NACL"]
                NAT["NAT instance t4g.nano (AZ-a)<br/>SG: 443 in from VPC only"]
            end
            subgraph PRIV["Trust boundary 3: private subnets (AZ-a, AZ-b), private NACL"]
                EC2["EC2 t4g.nano (AL2023)<br/>no public IP, IMDSv2,<br/>SG: no inbound, 443 out only,<br/>EBS encrypted with data CMK"]
                VPCE["Optional interface endpoints<br/>ssm, ssmmessages, ec2messages, logs, kms"]
            end
            S3GW["S3 gateway endpoint"]
        end
    end

    OP -- "HTTPS, SigV4, MFA session" --> DEP
    DEP -- "sts:AssumeRole + MFA" --> BG
    DEP -- "sts:AssumeRole + MFA" --> AUD
    OP -- "ssm start-session (TLS, KMS-encrypted session)" --> SSM
    SSM <-- "agent connects outbound on 443 only" --> EC2
    EC2 -- "443" --> NAT --> IGW --> INET
    EC2 -. "443 (endpoint mode)" .-> VPCE
    EC2 -- "443" --> S3GW
    EC2 -- "session logs" --> CWL

    CT -- "SSE-KMS" --> LB
    CFG -- "snapshots/history" --> LB
    VPC -- "flow logs" --> LB
    LB -- "server access logs" --> AL
    KL -.-> LB & CWL & SNS
    KD -.-> EC2 & SSM

    GD --> EB
    CT --> EB
    EB --> SNS --> MAIL
    BUD --> MAIL
    AUD -. "read-only" .-> LB & GD & CFG
```

## Trust boundaries explained

| # | Boundary | What crosses it | Controls |
|---|----------|-----------------|----------|
| 0 to 1 | Internet / operator to AWS account | Signed API calls, console sign-in | IAM authentication with MFA, root locked away, MFA-gated role assumption, every root action and break-glass use alerts |
| 1 to 2 | AWS control plane to VPC | Nothing inbound. The only ingress path is return traffic | No public-facing resources apart from the NAT instance, NACLs, SGs, flow logs, GuardDuty VPC/DNS analysis |
| 2 to 3 | Public subnets to private subnets | HTTPS from private to NAT, ephemeral return traffic | Private subnets have no IGW route. NACLs allow only 443 plus ephemeral ports. The instance SG has zero inbound rules |
| Service principals | AWS services writing into our resources | CloudTrail, Config, flow log delivery, EventBridge to SNS, CloudWatch Logs | KMS key policy and bucket policy statements scoped by `aws:SourceAccount` / `aws:SourceArn` / encryption context |
