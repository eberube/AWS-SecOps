"""Synth-time security assertions. Run with `pytest` (no AWS credentials needed)."""

import json
from pathlib import Path

import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Match, Template

from foundation.config import FoundationConfig
from foundation.stacks.network_stack import NetworkStack
from foundation.stacks.security_baseline_stack import SecurityBaselineStack
from foundation.stacks.workload_stack import WorkloadStack


CDK_CONTEXT = json.loads((Path(__file__).resolve().parents[1] / "cdk.json").read_text())["context"]


def build(**overrides):
    cfg = FoundationConfig(alert_email="secops@example.com", **overrides)
    # Same feature flags as `cdk synth` (cdk.json), otherwise CDK falls back to legacy defaults.
    app = cdk.App(context=CDK_CONTEXT)
    baseline = SecurityBaselineStack(app, "b", cfg=cfg)
    network = NetworkStack(app, "n", cfg=cfg, log_bucket=baseline.log_bucket)
    workload = WorkloadStack(
        app, "w", cfg=cfg, vpc=network.vpc, private_subnet_type=network.private_subnet_type,
        data_key=baseline.data_key, logs_key=baseline.logs_key,
    )
    return (Template.from_stack(baseline), Template.from_stack(network), Template.from_stack(workload))


@pytest.fixture(scope="module")
def templates():
    return build()


def test_trail_is_multi_region_encrypted_and_validated(templates):
    baseline, _, _ = templates
    baseline.has_resource_properties("AWS::CloudTrail::Trail", {
        "IsMultiRegionTrail": True,
        "IncludeGlobalServiceEvents": True,
        "EnableLogFileValidation": True,
        "KMSKeyId": Match.any_value(),
    })


def test_log_bucket_kms_versioned_private(templates):
    baseline, _, _ = templates
    baseline.has_resource_properties("AWS::S3::Bucket", {
        "BucketEncryption": {"ServerSideEncryptionConfiguration": [Match.object_like({
            "ServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms", "KMSMasterKeyID": Match.any_value()},
            "BucketKeyEnabled": True,
        })]},
        "VersioningConfiguration": {"Status": "Enabled"},
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True, "BlockPublicPolicy": True,
            "IgnorePublicAcls": True, "RestrictPublicBuckets": True,
        },
        "LoggingConfiguration": Match.any_value(),
    })


def test_kms_keys_rotate(templates):
    baseline, _, _ = templates
    keys = baseline.find_resources("AWS::KMS::Key")
    assert len(keys) == 2
    assert all(k["Properties"]["EnableKeyRotation"] for k in keys.values())


def test_guardduty_and_config(templates):
    baseline, _, _ = templates
    baseline.has_resource_properties("AWS::GuardDuty::Detector", {"Enable": True})
    baseline.resource_count_is("AWS::Config::ConfigurationRecorder", 1)
    baseline.resource_count_is("AWS::Config::DeliveryChannel", 1)
    assert len(baseline.find_resources("AWS::Config::ConfigRule")) >= 10


def test_config_channel_does_not_wait_for_recorder(templates):
    # The recorder handler retries StartConfigurationRecorder until a channel exists; if the channel
    # DependsOn the recorder, the deploy deadlocks and the recorder "did not stabilize".
    baseline, _, _ = templates
    (recorder_id,) = baseline.find_resources("AWS::Config::ConfigurationRecorder")
    (channel,) = baseline.find_resources("AWS::Config::DeliveryChannel").values()
    assert recorder_id not in channel.get("DependsOn", [])
    for rule in baseline.find_resources("AWS::Config::ConfigRule").values():
        assert recorder_id in rule["DependsOn"]


def test_nat_instance_adds_swap_before_yum(templates):
    # t4g.nano (512 MiB) OOM-kills `yum install iptables-services` without swap -> no NAT, no egress.
    _, network, _ = templates
    (nat,) = network.find_resources("AWS::EC2::Instance", {"Properties": {"SourceDestCheck": False}}).values()
    script = json.dumps(nat["Properties"]["UserData"])
    assert script.index("mkswap /swapfile") < script.index("yum install iptables-services")


def test_alerts_never_forward_raw_events(templates):
    # Raw CloudTrail AssumeRole events include the issued access key ID and session token.
    baseline, _, _ = templates
    rules = baseline.find_resources("AWS::Events::Rule")
    assert len(rules) == 3
    for rule in rules.values():
        for target in rule["Properties"]["Targets"]:
            assert "InputTransformer" in target, "alert targets must send a summary, not the raw event"
            assert "responseElements" not in json.dumps(target)


def test_roles_require_mfa(templates):
    baseline, _, _ = templates
    for name in ("secure-foundation-break-glass-admin", "secure-foundation-security-auditor"):
        baseline.has_resource_properties("AWS::IAM::Role", {
            "RoleName": name,
            "AssumeRolePolicyDocument": {"Statement": [Match.object_like({
                "Condition": Match.object_like({"Bool": {"aws:MultiFactorAuthPresent": "true"}}),
            })]},
        })


def test_no_security_group_allows_inbound_ssh_or_world(templates):
    for template in templates:
        for sg in template.find_resources("AWS::EC2::SecurityGroup").values():
            for rule in sg["Properties"].get("SecurityGroupIngress", []):
                assert rule.get("CidrIp") != "0.0.0.0/0", rule
                assert rule.get("FromPort") != 22, rule
        for rule in template.find_resources("AWS::EC2::SecurityGroupIngress").values():
            assert rule["Properties"].get("FromPort") != 22
            assert rule["Properties"].get("CidrIp") != "0.0.0.0/0"


def test_instance_private_imdsv2_encrypted(templates):
    _, _, workload = templates
    workload.has_resource_properties("AWS::EC2::Instance", {
        "BlockDeviceMappings": [Match.object_like({"Ebs": Match.object_like({"Encrypted": True, "KmsKeyId": Match.any_value()})})],
    })
    for instance in workload.find_resources("AWS::EC2::Instance").values():
        for eni in instance["Properties"].get("NetworkInterfaces", []):
            assert eni.get("AssociatePublicIpAddress") is False
    workload.has_resource_properties("AWS::EC2::LaunchTemplate", {
        "LaunchTemplateData": {"MetadataOptions": {"HttpTokens": "required"}},
    })


def test_private_subnets_never_map_public_ips(templates):
    _, network, _ = templates
    for subnet in network.find_resources("AWS::EC2::Subnet").values():
        tags = {t["Key"]: t["Value"] for t in subnet["Properties"].get("Tags", [])}
        if tags.get("aws-cdk:subnet-type") != "Public":
            assert subnet["Properties"].get("MapPublicIpOnLaunch") in (None, False)


def test_flow_logs_and_nacls(templates):
    _, network, _ = templates
    network.has_resource_properties("AWS::EC2::FlowLog", {"LogDestinationType": "s3", "TrafficType": "ALL"})
    network.resource_count_is("AWS::EC2::NetworkAcl", 2)


def test_isolated_mode_uses_endpoints_and_no_nat():
    _, network, _ = build(egress_mode="none")
    network.resource_count_is("AWS::EC2::NatGateway", 0)
    assert len(network.find_resources("AWS::EC2::VPCEndpoint")) == 6  # 5 interface + S3 gateway


def test_default_mode_has_no_paid_nat_gateway(templates):
    _, network, _ = templates
    network.resource_count_is("AWS::EC2::NatGateway", 0)
