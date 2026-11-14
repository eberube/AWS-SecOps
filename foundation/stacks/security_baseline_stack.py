"""Account-level security baseline: encryption, audit logging, detection, posture and identity.

This stack has the longest lifecycle. Network and workload stacks consume its keys and log bucket.
"""

from __future__ import annotations

from aws_cdk import (
    CfnOutput,
    Duration,
    RemovalPolicy,
    Stack,
    aws_accessanalyzer as accessanalyzer,
    aws_budgets as budgets,
    aws_cloudtrail as cloudtrail,
    aws_config as config,
    aws_events as events,
    aws_events_targets as targets,
    aws_guardduty as guardduty,
    aws_iam as iam,
    aws_kms as kms,
    aws_s3 as s3,
    aws_securityhub as securityhub,
    aws_sns as sns,
    aws_sns_subscriptions as subs,
    custom_resources as cr,
)
from constructs import Construct

from foundation.config import FoundationConfig

# A deliberately small set of high-signal AWS Config managed rules (source identifiers).
CONFIG_RULES = {
    "RootMfaEnabled": "ROOT_ACCOUNT_MFA_ENABLED",
    "RootNoAccessKeys": "IAM_ROOT_ACCESS_KEY_CHECK",
    "MultiRegionTrail": "MULTI_REGION_CLOUD_TRAIL_ENABLED",
    "TrailEncrypted": "CLOUD_TRAIL_ENCRYPTION_ENABLED",
    "S3BucketPublicAccessBlocked": "S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED",
    "EbsVolumesEncrypted": "ENCRYPTED_VOLUMES",
    "NoInboundSsh": "INCOMING_SSH_DISABLED",
    "Ec2NoPublicIp": "EC2_INSTANCE_NO_PUBLIC_IP",
    "Ec2Imdsv2": "EC2_IMDSV2_CHECK",
    "Ec2ManagedBySsm": "EC2_INSTANCE_MANAGED_BY_SSM",
    "DefaultSgClosed": "VPC_DEFAULT_SECURITY_GROUP_CLOSED",
    "VpcFlowLogsEnabled": "VPC_FLOW_LOGS_ENABLED",
    "GuardDutyEnabled": "GUARDDUTY_ENABLED_CENTRALIZED",
}

def _cloudtrail_summary(title: str, extra_path: str, extra_label: str) -> events.RuleTargetInput:
    """Alert text built from selected CloudTrail fields only.

    Forwarding the raw event would email whatever the API response contained (for AssumeRole, the
    issued access key ID and session token). Full detail stays in the encrypted trail.
    """
    field = lambda path: events.EventField.from_path(f"$.detail.{path}")  # noqa: E731
    return events.RuleTargetInput.from_multiline_text(
        f"{title}\n"
        f"Event:      {field('eventName')}\n"
        f"Principal:  {field('userIdentity.arn')}\n"
        f"Source IP:  {field('sourceIPAddress')}\n"
        f"User agent: {field('userAgent')}\n"
        f"Time (UTC): {field('eventTime')}\n"
        f"Region:     {field('awsRegion')}\n"
        f"{extra_label.capitalize() + ':':<11} {field(extra_path)}\n"
        f"Event ID:   {field('eventID')} (full record in the CloudTrail log archive)"
    )


FLOW_LOG_PREFIX = "vpc-flow-logs"
CONFIG_PREFIX = "config"
TRAIL_PREFIX = "cloudtrail"


class SecurityBaselineStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, *, cfg: FoundationConfig, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        self.cfg = cfg
        self.removal = RemovalPolicy.RETAIN if cfg.retain_data else RemovalPolicy.DESTROY
        self.trail_name = f"{cfg.project}-trail"

        self._keys()
        self._log_buckets()
        self._cloudtrail()
        self._alerting()
        self._guardduty()
        self._aws_config()
        if cfg.enable_security_hub:
            self._security_hub()
        self._identity()
        self._account_guardrails()
        if cfg.alert_email:
            self._budget()

    # ------------------------------------------------------------------ KMS
    def _keys(self) -> None:
        account, region, partition = self.account, self.region, self.partition
        source_account = {"StringEquals": {"aws:SourceAccount": account}}

        # Key 1: everything audit/log related (CloudTrail, Config, flow logs, alerts, session logs).
        self.logs_key = kms.Key(
            self,
            "LogsKey",
            alias=f"alias/{self.cfg.project}/logs",
            description="CMK for audit and security logs (CloudTrail, Config, VPC flow logs, alerts)",
            enable_key_rotation=True,
            pending_window=Duration.days(7),
            removal_policy=self.removal,
        )
        k = self.logs_key
        k.add_to_resource_policy(iam.PolicyStatement(
            sid="CloudTrailEncryptLogs",
            principals=[iam.ServicePrincipal("cloudtrail.amazonaws.com")],
            actions=["kms:GenerateDataKey*"],
            resources=["*"],
            conditions={
                "StringEquals": {
                    "aws:SourceArn": f"arn:{partition}:cloudtrail:{region}:{account}:trail/{self.trail_name}"
                },
                "StringLike": {
                    "kms:EncryptionContext:aws:cloudtrail:arn": f"arn:{partition}:cloudtrail:*:{account}:trail/*"
                },
            },
        ))
        k.add_to_resource_policy(iam.PolicyStatement(
            sid="CloudTrailDescribeKey",
            principals=[iam.ServicePrincipal("cloudtrail.amazonaws.com")],
            actions=["kms:DescribeKey"],
            resources=["*"],
        ))
        k.add_to_resource_policy(iam.PolicyStatement(
            sid="ConfigDelivery",
            principals=[iam.ServicePrincipal("config.amazonaws.com")],
            actions=["kms:Decrypt", "kms:GenerateDataKey"],
            resources=["*"],
            conditions=source_account,
        ))
        k.add_to_resource_policy(iam.PolicyStatement(
            sid="VpcFlowLogDelivery",
            principals=[iam.ServicePrincipal("delivery.logs.amazonaws.com")],
            actions=["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey"],
            resources=["*"],
            conditions=source_account,
        ))
        k.add_to_resource_policy(iam.PolicyStatement(
            sid="EventBridgeToEncryptedSns",
            principals=[iam.ServicePrincipal("events.amazonaws.com")],
            actions=["kms:Decrypt", "kms:GenerateDataKey*"],
            resources=["*"],
            conditions=source_account,
        ))
        k.add_to_resource_policy(iam.PolicyStatement(
            sid="CloudWatchLogsEncryption",
            principals=[iam.ServicePrincipal(f"logs.{region}.amazonaws.com")],
            actions=["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"],
            resources=["*"],
            conditions={
                "ArnLike": {
                    "kms:EncryptionContext:aws:logs:arn": f"arn:{partition}:logs:{region}:{account}:log-group:*"
                }
            },
        ))

        # Key 2: workload data (EBS volumes, Session Manager session encryption).
        self.data_key = kms.Key(
            self,
            "DataKey",
            alias=f"alias/{self.cfg.project}/data",
            description="CMK for workload data (EBS volumes, Session Manager session encryption)",
            enable_key_rotation=True,
            pending_window=Duration.days(7),
            removal_policy=self.removal,
        )

    # ------------------------------------------------------------- S3 logs
    def _log_buckets(self) -> None:
        auto_delete = not self.cfg.retain_data

        # Server access logs for the log bucket. SSE-S3 because S3 access logging cannot target SSE-KMS.
        self.access_logs_bucket = s3.Bucket(
            self,
            "AccessLogsBucket",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            object_ownership=s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
            enforce_ssl=True,
            versioned=True,
            lifecycle_rules=[s3.LifecycleRule(
                id="expire",
                expiration=Duration.days(90),
                noncurrent_version_expiration=Duration.days(30),
                abort_incomplete_multipart_upload_after=Duration.days(7),
            )],
            removal_policy=self.removal,
            auto_delete_objects=auto_delete,
        )

        self.log_bucket = s3.Bucket(
            self,
            "LogBucket",
            encryption=s3.BucketEncryption.KMS,
            encryption_key=self.logs_key,
            bucket_key_enabled=True,  # cuts KMS request costs by ~99%
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            object_ownership=s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
            enforce_ssl=True,
            versioned=True,
            server_access_logs_bucket=self.access_logs_bucket,
            server_access_logs_prefix="log-bucket/",
            lifecycle_rules=[s3.LifecycleRule(
                id="expire",
                expiration=Duration.days(365),
                noncurrent_version_expiration=Duration.days(30),
                abort_incomplete_multipart_upload_after=Duration.days(7),
            )],
            removal_policy=self.removal,
            auto_delete_objects=auto_delete,
        )

        b = self.log_bucket
        acct, region, partition = self.account, self.region, self.partition
        # Explicit service delivery policies (so AWS never edits this policy out-of-band).
        b.add_to_resource_policy(iam.PolicyStatement(
            sid="FlowLogsAclCheck",
            principals=[iam.ServicePrincipal("delivery.logs.amazonaws.com")],
            actions=["s3:GetBucketAcl", "s3:ListBucket"],
            resources=[b.bucket_arn],
            conditions={
                "StringEquals": {"aws:SourceAccount": acct},
                "ArnLike": {"aws:SourceArn": f"arn:{partition}:logs:{region}:{acct}:*"},
            },
        ))
        b.add_to_resource_policy(iam.PolicyStatement(
            sid="FlowLogsWrite",
            principals=[iam.ServicePrincipal("delivery.logs.amazonaws.com")],
            actions=["s3:PutObject"],
            resources=[b.arn_for_objects(f"{FLOW_LOG_PREFIX}/AWSLogs/{acct}/*")],
            conditions={
                "StringEquals": {"aws:SourceAccount": acct, "s3:x-amz-acl": "bucket-owner-full-control"},
                "ArnLike": {"aws:SourceArn": f"arn:{partition}:logs:{region}:{acct}:*"},
            },
        ))
        b.add_to_resource_policy(iam.PolicyStatement(
            sid="ConfigAclCheck",
            principals=[iam.ServicePrincipal("config.amazonaws.com")],
            actions=["s3:GetBucketAcl", "s3:ListBucket"],
            resources=[b.bucket_arn],
            conditions={"StringEquals": {"aws:SourceAccount": acct}},
        ))
        b.add_to_resource_policy(iam.PolicyStatement(
            sid="ConfigWrite",
            principals=[iam.ServicePrincipal("config.amazonaws.com")],
            actions=["s3:PutObject"],
            resources=[b.arn_for_objects(f"{CONFIG_PREFIX}/AWSLogs/{acct}/Config/*")],
            conditions={"StringEquals": {"aws:SourceAccount": acct, "s3:x-amz-acl": "bucket-owner-full-control"}},
        ))

    # ----------------------------------------------------------- CloudTrail
    def _cloudtrail(self) -> None:
        self.trail = cloudtrail.Trail(
            self,
            "Trail",
            trail_name=self.trail_name,
            bucket=self.log_bucket,
            s3_key_prefix=TRAIL_PREFIX,
            encryption_key=self.logs_key,
            is_multi_region_trail=True,
            include_global_service_events=True,
            enable_file_validation=True,
            management_events=cloudtrail.ReadWriteType.ALL,
            # CloudWatch Logs delivery and data/insight events are omitted on purpose: they are the
            # main CloudTrail cost drivers. Management events on the first trail are free.
            send_to_cloud_watch_logs=False,
        )
        self.trail.node.add_dependency(self.logs_key)

    # ------------------------------------------------------------- Alerting
    def _alerting(self) -> None:
        self.alerts_topic = sns.Topic(
            self,
            "SecurityAlerts",
            display_name=f"{self.cfg.project} security alerts",
            master_key=self.logs_key,
            enforce_ssl=True,
        )
        if self.cfg.alert_email:
            self.alerts_topic.add_subscription(subs.EmailSubscription(self.cfg.alert_email))

        # Root user activity (API calls and console sign-ins).
        root_rule = events.Rule(
            self,
            "RootActivityRule",
            description="Alert on any root user activity",
            event_pattern=events.EventPattern(
                detail_type=["AWS API Call via CloudTrail", "AWS Console Sign In via CloudTrail"],
                detail={"userIdentity": {"type": ["Root"]}},
            ),
            targets=[targets.SnsTopic(self.alerts_topic, message=_cloudtrail_summary(
                "ROOT USER ACTIVITY", "eventSource", "service",
            ))],
        )
        # Include read-only management events (e.g. a root user just browsing the console).
        root_rule.node.default_child.add_property_override("State", "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS")

    # ------------------------------------------------------------ GuardDuty
    def _guardduty(self) -> None:
        def feature(name: str, enabled: bool):
            return guardduty.CfnDetector.CFNFeatureConfigurationProperty(
                name=name, status="ENABLED" if enabled else "DISABLED"
            )

        guardduty.CfnDetector(
            self,
            "GuardDuty",
            enable=True,
            finding_publishing_frequency="FIFTEEN_MINUTES",
            # Foundational sources (CloudTrail mgmt events, VPC flow logs, DNS logs) are always on.
            # Optional protection plans are explicit so cost is predictable; turn on as workloads appear.
            features=[
                feature("S3_DATA_EVENTS", True),
                feature("EKS_AUDIT_LOGS", False),
                feature("EBS_MALWARE_PROTECTION", False),
                feature("RDS_LOGIN_EVENTS", False),
                feature("LAMBDA_NETWORK_LOGS", False),
                feature("RUNTIME_MONITORING", False),
            ],
        )

        events.Rule(
            self,
            "GuardDutyHighSeverityRule",
            description="Forward HIGH/CRITICAL GuardDuty findings (severity >= 7) to the security alerts topic",
            event_pattern=events.EventPattern(
                source=["aws.guardduty"],
                detail_type=["GuardDuty Finding"],
                detail={"severity": [{"numeric": [">=", 7]}]},
            ),
            targets=[targets.SnsTopic(
                self.alerts_topic,
                message=events.RuleTargetInput.from_text(
                    f"GuardDuty finding {events.EventField.from_path('$.detail.type')} "
                    f"(severity {events.EventField.from_path('$.detail.severity')}) in "
                    f"{events.EventField.from_path('$.region')}: "
                    f"{events.EventField.from_path('$.detail.title')}"
                ),
            )],
        )

    # ----------------------------------------------------------- AWS Config
    def _aws_config(self) -> None:
        role = iam.Role(
            self,
            "ConfigRole",
            assumed_by=iam.ServicePrincipal("config.amazonaws.com"),
            managed_policies=[iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWS_ConfigRole")],
        )
        role.add_to_policy(iam.PolicyStatement(
            actions=["s3:PutObject"],
            resources=[self.log_bucket.arn_for_objects(f"{CONFIG_PREFIX}/AWSLogs/{self.account}/Config/*")],
            conditions={"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}},
        ))
        role.add_to_policy(iam.PolicyStatement(
            actions=["s3:GetBucketAcl", "s3:ListBucket"],
            resources=[self.log_bucket.bucket_arn],
        ))
        role.add_to_policy(iam.PolicyStatement(
            actions=["kms:Decrypt", "kms:GenerateDataKey"],
            resources=[self.logs_key.key_arn],
        ))

        recorder = config.CfnConfigurationRecorder(
            self,
            "ConfigRecorder",
            role_arn=role.role_arn,
            recording_group=config.CfnConfigurationRecorder.RecordingGroupProperty(
                all_supported=True,
                include_global_resource_types=True,  # IAM is global: record it in the home region only
            ),
        )

        channel = config.CfnDeliveryChannel(
            self,
            "ConfigDeliveryChannel",
            s3_bucket_name=self.log_bucket.bucket_name,
            s3_key_prefix=CONFIG_PREFIX,
            s3_kms_key_arn=self.logs_key.key_arn,
            config_snapshot_delivery_properties=config.CfnDeliveryChannel.ConfigSnapshotDeliveryPropertiesProperty(
                delivery_frequency="TwentyFour_Hours"
            ),
        )
        # No dependency between the recorder and the channel: CloudFormation's recorder handler
        # creates the recorder and then keeps retrying StartConfigurationRecorder until a delivery
        # channel exists. Making the channel wait for the recorder deadlocks the deploy
        # (NoAvailableDeliveryChannelException, then "did not stabilize"), so they create in parallel.
        channel.node.add_dependency(role)
        channel.node.add_dependency(self.log_bucket)

        for rule_id, identifier in CONFIG_RULES.items():
            rule = config.ManagedRule(
                self, f"Rule{rule_id}", identifier=identifier,
                # Readable names (e.g. secure-foundation-ec2-instance-no-public-ip) instead of generated ones.
                config_rule_name=f"{self.cfg.project}-{identifier.lower().replace('_', '-')}",
            )
            rule.node.add_dependency(recorder)
            rule.node.add_dependency(channel)

    # --------------------------------------------------------- Security Hub
    def _security_hub(self) -> None:
        hub = securityhub.CfnHub(
            self,
            "SecurityHub",
            enable_default_standards=False,
            control_finding_generator="SECURITY_CONTROL",
            auto_enable_controls=True,
        )
        cis = securityhub.CfnStandard(
            self,
            "CisStandard",
            standards_arn=f"arn:{self.partition}:securityhub:{self.region}::standards/cis-aws-foundations-benchmark/v/3.0.0",
        )
        cis.add_resource_dependency(hub)

    # -------------------------------------------------------------- Identity
    def _identity(self) -> None:
        trusted = [iam.ArnPrincipal(a) for a in self.cfg.trusted_admin_principal_arns] or [iam.AccountRootPrincipal()]
        mfa = {
            "Bool": {"aws:MultiFactorAuthPresent": "true"},
            "NumericLessThan": {"aws:MultiFactorAuthAge": "3600"},
        }

        def role_with_mfa_trust(construct_id: str, **props) -> iam.Role:
            role = iam.Role(self, construct_id, assumed_by=trusted[0].with_conditions(mfa), **props)
            for extra in trusted[1:]:
                role.assume_role_policy.add_statements(iam.PolicyStatement(
                    actions=["sts:AssumeRole"], principals=[extra], conditions=mfa
                ))
            return role

        # Break-glass admin: full admin, MFA within the last hour, 1h sessions, every use alerts.
        self.break_glass_role = role_with_mfa_trust(
            "BreakGlassAdminRole",
            role_name=f"{self.cfg.project}-break-glass-admin",
            description="Emergency administrator access. MFA required. Every assumption raises an alert.",
            max_session_duration=Duration.hours(1),
            managed_policies=[iam.ManagedPolicy.from_aws_managed_policy_name("AdministratorAccess")],
        )

        # Security auditor: read-only security metadata plus read access to the audit log archive.
        self.auditor_role = role_with_mfa_trust(
            "SecurityAuditorRole",
            role_name=f"{self.cfg.project}-security-auditor",
            description="Read-only security auditor. Can read security configuration and the audit log archive.",
            max_session_duration=Duration.hours(4),
            managed_policies=[iam.ManagedPolicy.from_aws_managed_policy_name("SecurityAudit")],
        )
        self.auditor_role.add_to_policy(iam.PolicyStatement(
            sid="ReadAuditLogArchive",
            actions=["s3:GetObject", "s3:GetObjectVersion", "s3:ListBucket", "s3:ListBucketVersions"],
            resources=[self.log_bucket.bucket_arn, self.log_bucket.arn_for_objects("*")],
        ))
        self.auditor_role.add_to_policy(iam.PolicyStatement(
            sid="DecryptAuditLogs",
            actions=["kms:Decrypt"],
            resources=[self.logs_key.key_arn],
            conditions={"StringEquals": {"kms:ViaService": f"s3.{self.region}.amazonaws.com"}},
        ))
        # Groups so humans get the right to *request* a role; the role trust still enforces MFA.
        for group_id, role in (("BreakGlassGroup", self.break_glass_role), ("SecurityAuditorsGroup", self.auditor_role)):
            group = iam.Group(self, group_id, group_name=f"{self.cfg.project}-{group_id.replace('Group', '').lower()}")
            group.add_to_policy(iam.PolicyStatement(actions=["sts:AssumeRole"], resources=[role.role_arn]))

        # Alert whenever the break-glass role is assumed. AssumeRole is a read-only event,
        # hence the ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS rule state.
        bg_rule = events.Rule(
            self,
            "BreakGlassUsedRule",
            description="Alert when the break-glass admin role is assumed",
            event_pattern=events.EventPattern(
                source=["aws.sts"],
                detail_type=["AWS API Call via CloudTrail"],
                detail={"eventName": ["AssumeRole"], "requestParameters": {"roleArn": [self.break_glass_role.role_arn]}},
            ),
            # A summary, not the raw event: the raw AssumeRole event carries the issued access key ID
            # and session token in responseElements, which must not leave the account by email.
            targets=[targets.SnsTopic(self.alerts_topic, message=_cloudtrail_summary(
                "BREAK-GLASS ROLE ASSUMED", "requestParameters.roleSessionName", "session",
            ))],
        )
        bg_rule.node.default_child.add_property_override("State", "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS")

        # IAM Access Analyzer (account zone of trust) - free, flags resources shared outside the account.
        accessanalyzer.CfnAnalyzer(self, "AccessAnalyzer", type="ACCOUNT", analyzer_name=f"{self.cfg.project}-account")

        switch = "https://signin.aws.amazon.com/switchrole?account={}&roleName={}"
        CfnOutput(self, "BreakGlassRoleArn", value=self.break_glass_role.role_arn)
        CfnOutput(self, "BreakGlassSwitchRoleUrl", value=switch.format(self.account, self.break_glass_role.role_name))
        CfnOutput(self, "AuditorRoleArn", value=self.auditor_role.role_arn)
        CfnOutput(self, "AuditorSwitchRoleUrl", value=switch.format(self.account, self.auditor_role.role_name))
        CfnOutput(self, "LogBucketName", value=self.log_bucket.bucket_name)

    # ------------------------------------------------ Account-wide guardrails
    def _account_guardrails(self) -> None:
        """Settings that have no native CloudFormation resource, applied with SDK calls.

        Both are intentionally left in place on stack deletion (secure, free) - see README.
        """
        cr.AwsCustomResource(
            self,
            "AccountS3BlockPublicAccess",
            on_update=cr.AwsSdkCall(
                service="S3Control",
                action="putPublicAccessBlock",
                parameters={
                    "AccountId": self.account,
                    "PublicAccessBlockConfiguration": {
                        "BlockPublicAcls": True,
                        "IgnorePublicAcls": True,
                        "BlockPublicPolicy": True,
                        "RestrictPublicBuckets": True,
                    },
                },
                physical_resource_id=cr.PhysicalResourceId.of(f"{self.cfg.project}-account-s3-bpa"),
            ),
            policy=cr.AwsCustomResourcePolicy.from_statements([
                iam.PolicyStatement(actions=["s3:PutAccountPublicAccessBlock"], resources=["*"])
            ]),
            install_latest_aws_sdk=False,
        )
        cr.AwsCustomResource(
            self,
            "EbsEncryptionByDefault",
            on_update=cr.AwsSdkCall(
                service="EC2",
                action="enableEbsEncryptionByDefault",
                parameters={},
                physical_resource_id=cr.PhysicalResourceId.of(f"{self.cfg.project}-ebs-default-encryption"),
            ),
            policy=cr.AwsCustomResourcePolicy.from_statements([
                iam.PolicyStatement(actions=["ec2:EnableEbsEncryptionByDefault"], resources=["*"])
            ]),
            install_latest_aws_sdk=False,
        )

    # ---------------------------------------------------------------- Budget
    def _budget(self) -> None:
        def notify(threshold: float, kind: str):
            return budgets.CfnBudget.NotificationWithSubscribersProperty(
                notification=budgets.CfnBudget.NotificationProperty(
                    comparison_operator="GREATER_THAN",
                    notification_type=kind,
                    threshold=threshold,
                    threshold_type="PERCENTAGE",
                ),
                subscribers=[budgets.CfnBudget.SubscriberProperty(
                    address=self.cfg.alert_email, subscription_type="EMAIL"
                )],
            )

        budgets.CfnBudget(
            self,
            "MonthlyCostBudget",
            budget=budgets.CfnBudget.BudgetDataProperty(
                budget_name=f"{self.cfg.project}-monthly",
                budget_type="COST",
                time_unit="MONTHLY",
                budget_limit=budgets.CfnBudget.SpendProperty(amount=self.cfg.monthly_budget_usd, unit="USD"),
            ),
            notifications_with_subscribers=[
                notify(25, "ACTUAL"),
                notify(50, "ACTUAL"),
                notify(80, "ACTUAL"),
                notify(100, "FORECASTED"),
            ],
        )
