"""Private EC2 instance reachable only through SSM Session Manager (no SSH, no public IP)."""

from __future__ import annotations

from aws_cdk import (
    CfnOutput,
    RemovalPolicy,
    Stack,
    aws_ec2 as ec2,
    aws_iam as iam,
    aws_kms as kms,
    aws_logs as logs,
    aws_ssm as ssm,
)
from constructs import Construct

from foundation.config import FoundationConfig


class WorkloadStack(Stack):
    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        cfg: FoundationConfig,
        vpc: ec2.IVpc,
        private_subnet_type: ec2.SubnetType,
        data_key: kms.IKey,
        logs_key: kms.IKey,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)
        removal = RemovalPolicy.RETAIN if cfg.retain_data else RemovalPolicy.DESTROY

        sg = ec2.SecurityGroup(
            self,
            "InstanceSg",
            vpc=vpc,
            description="Session Manager managed instance: no inbound rules, HTTPS egress only",
            allow_all_outbound=False,
        )
        sg.add_egress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(443), "HTTPS to SSM, AWS APIs and package repositories")

        role = iam.Role(
            self,
            "InstanceRole",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            description="Private instance role: SSM core only, plus session log delivery",
            managed_policies=[iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSSMManagedInstanceCore")],
        )

        cpu = ec2.AmazonLinuxCpuType.ARM_64 if cfg.is_arm_instance else ec2.AmazonLinuxCpuType.X86_64
        self.instance = ec2.Instance(
            self,
            "PrivateInstance",
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(subnet_type=private_subnet_type),
            instance_type=ec2.InstanceType(cfg.instance_type),
            machine_image=ec2.MachineImage.latest_amazon_linux2023(cpu_type=cpu),  # SSM agent preinstalled
            security_group=sg,
            role=role,
            require_imdsv2=True,
            associate_public_ip_address=False,
            detailed_monitoring=False,
            block_devices=[ec2.BlockDevice(
                device_name="/dev/xvda",
                volume=ec2.BlockDeviceVolume.ebs(
                    8,
                    encrypted=True,
                    kms_key=data_key,
                    volume_type=ec2.EbsDeviceVolumeType.GP3,
                    delete_on_termination=True,
                ),
            )],
        )

        if cfg.enable_session_manager_prefs:
            self._session_manager_preferences(cfg, role, data_key, logs_key, removal)

        CfnOutput(self, "InstanceId", value=self.instance.instance_id)
        CfnOutput(
            self,
            "StartSessionCommand",
            value=f"aws ssm start-session --target {self.instance.instance_id} --region {self.region}",
        )

    def _session_manager_preferences(
        self,
        cfg: FoundationConfig,
        role: iam.Role,
        data_key: kms.IKey,
        logs_key: kms.IKey,
        removal: RemovalPolicy,
    ) -> None:
        """Account/region Session Manager preferences: KMS-encrypted sessions, logged to CloudWatch."""
        log_group = logs.LogGroup(
            self,
            "SessionLogs",
            log_group_name=f"/{cfg.project}/ssm/sessions",
            retention=logs.RetentionDays.ONE_MONTH,
            encryption_key=logs_key,
            removal_policy=removal,
        )

        # Instance needs to stream session transcripts and decrypt the session data key.
        role.add_to_policy(iam.PolicyStatement(
            actions=["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"],
            resources=[log_group.log_group_arn, f"{log_group.log_group_arn}:*"],
        ))
        role.add_to_policy(iam.PolicyStatement(actions=["logs:DescribeLogGroups"], resources=["*"]))
        role.add_to_policy(iam.PolicyStatement(actions=["kms:Decrypt"], resources=[data_key.key_arn]))

        # "SSM-SessionManagerRunShell" is the well-known name Session Manager reads its preferences from.
        ssm.CfnDocument(
            self,
            "SessionManagerPreferences",
            name="SSM-SessionManagerRunShell",
            document_type="Session",
            document_format="JSON",
            update_method="NewVersion",
            content={
                "schemaVersion": "1.0",
                "description": "Session Manager preferences managed by CDK",
                "sessionType": "Standard_Stream",
                "inputs": {
                    "s3BucketName": "",
                    "s3KeyPrefix": "",
                    "s3EncryptionEnabled": True,
                    "cloudWatchLogGroupName": log_group.log_group_name,
                    "cloudWatchEncryptionEnabled": True,
                    "cloudWatchStreamingEnabled": True,
                    "kmsKeyId": data_key.key_arn,
                    "runAsEnabled": False,
                    "runAsDefaultUser": "",
                    "idleSessionTimeout": "20",
                    "maxSessionDuration": "60",
                    "shellProfile": {"windows": "", "linux": ""},
                },
            },
        )
        CfnOutput(self, "SessionLogGroup", value=log_group.log_group_name)
