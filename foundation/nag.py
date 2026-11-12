"""cdk-nag (AwsSolutions) suppressions, each with the justification a reviewer would ask for.

Suppressions are metadata only; they matter when synthesizing with `-c nag=true`.
Keep this list short: every entry is a conscious, documented exception.
"""

from __future__ import annotations

from aws_cdk import Stack
from cdk_nag import NagPackSuppression, NagSuppressions
from constructs import IConstruct

# CDK's singleton Lambda that backs AwsCustomResource.
AWS_CUSTOM_RESOURCE_LAMBDA = "AWS679f53fac002430cb0da5b7982bd2287"


def suppress(construct: IConstruct, *rules: tuple[str, str], children: bool = True) -> None:
    NagSuppressions.add_resource_suppressions(
        construct, [NagPackSuppression(id=rule, reason=reason) for rule, reason in rules], apply_to_children=children
    )


def suppress_path(stack: Stack, path: str, *rules: tuple[str, str]) -> None:
    NagSuppressions.add_resource_suppressions_by_path(
        stack, f"/{stack.stack_name}/{path}", [NagPackSuppression(id=rule, reason=reason) for rule, reason in rules]
    )


def baseline_suppressions(stack) -> None:
    suppress(stack.break_glass_role, (
        "AwsSolutions-IAM4",
        "Break-glass role is by definition full admin; compensated by MFA (<1h old), 1h sessions and an alert on every use.",
    ))
    suppress(stack.auditor_role,
        ("AwsSolutions-IAM4", "SecurityAudit is the AWS-maintained read-only security metadata policy; it tracks new services."),
        ("AwsSolutions-IAM5", "Object wildcard is limited to the single audit log archive bucket (read-only)."),
    )
    suppress(stack.node.find_child("ConfigRole"),
        ("AwsSolutions-IAM4", "AWS_ConfigRole is the AWS-recommended policy for the Config recorder to read resource configuration."),
        ("AwsSolutions-IAM5", "Write access is limited to the Config delivery prefix of the log archive bucket."),
    )
    for cr_id in ("AccountS3BlockPublicAccess", "EbsEncryptionByDefault"):
        suppress(stack.node.find_child(cr_id), (
            "AwsSolutions-IAM5",
            "Account-level APIs (s3:PutAccountPublicAccessBlock, ec2:EnableEbsEncryptionByDefault) do not support resource-level permissions.",
        ))
    suppress_path(stack, f"{AWS_CUSTOM_RESOURCE_LAMBDA}/ServiceRole/Resource", (
        "AwsSolutions-IAM4",
        "CDK-managed custom resource Lambda uses AWSLambdaBasicExecutionRole for its own CloudWatch logs only.",
    ))
    if stack.node.try_find_child(AWS_CUSTOM_RESOURCE_LAMBDA) is not None:
        suppress(stack.node.find_child(AWS_CUSTOM_RESOURCE_LAMBDA), (
            "AwsSolutions-L1", "CDK-managed custom resource Lambda; runtime is controlled by the aws-cdk-lib version.",
        ))


def network_suppressions(stack) -> None:
    suppress(stack, (
        "AwsSolutions-VPC3",
        "NACLs are an explicit requirement: a stateless second layer (443 + ephemeral only) beneath the security groups.",
    ))
    if stack.cfg.egress_mode == "nat-instance":
        suppress_path(stack, "Vpc/publicSubnet1/NatInstance/Resource",
            ("AwsSolutions-EC26", "Root volume is encrypted by the account-level EBS-encryption-by-default setting (security baseline stack)."),
            ("AwsSolutions-EC28", "Detailed monitoring omitted for cost; basic 5-minute metrics are sufficient for a NAT instance in this exercise."),
            ("AwsSolutions-EC29", "No termination protection so the environment tears down cleanly; production would use NAT Gateways."),
        )


def workload_suppressions(stack) -> None:
    suppress(stack.instance,
        ("AwsSolutions-EC28", "Detailed monitoring omitted for cost; basic 5-minute metrics are sufficient for this exercise."),
        ("AwsSolutions-EC29", "No termination protection so the environment tears down cleanly (ephemeral, rebuildable workload)."),
    )
    suppress(stack.node.find_child("InstanceRole"),
        ("AwsSolutions-IAM4", "AmazonSSMManagedInstanceCore is the AWS-maintained minimum policy for Session Manager."),
        ("AwsSolutions-IAM5", "Log stream wildcard is scoped to the session log group; logs:DescribeLogGroups has no resource-level support."),
    )
