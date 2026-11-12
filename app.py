#!/usr/bin/env python3
"""CDK entry point: three stacks with independent lifecycles.

  <project>-security-baseline   KMS, log archive, CloudTrail, GuardDuty, Config, IAM, alerting, budget
  <project>-network             VPC, NAT/egress, NACLs, flow logs, endpoints
  <project>-workload            Private EC2 instance + Session Manager preferences
"""

import os

import aws_cdk as cdk

from foundation.config import FoundationConfig
from foundation.stacks.network_stack import NetworkStack
from foundation.stacks.security_baseline_stack import SecurityBaselineStack
from foundation.stacks.workload_stack import WorkloadStack

app = cdk.App()
cfg = FoundationConfig.from_context(app.node)

env = cdk.Environment(
    account=os.environ.get("CDK_DEFAULT_ACCOUNT"),
    region=os.environ.get("CDK_DEFAULT_REGION"),
)

baseline = SecurityBaselineStack(
    app, f"{cfg.project}-security-baseline", cfg=cfg, env=env,
    description="Secure foundation: encryption, audit logging, threat detection, posture, identity",
)
network = NetworkStack(
    app, f"{cfg.project}-network", cfg=cfg, log_bucket=baseline.log_bucket, env=env,
    description="Secure foundation: multi-AZ VPC with controlled egress",
)
workload = WorkloadStack(
    app, f"{cfg.project}-workload", cfg=cfg, env=env,
    vpc=network.vpc,
    private_subnet_type=network.private_subnet_type,
    data_key=baseline.data_key,
    logs_key=baseline.logs_key,
    description="Secure foundation: private EC2 instance managed via SSM Session Manager",
)
network.add_stack_dependency(baseline)
workload.add_stack_dependency(network)

for key, value in {"Project": cfg.project, "Environment": "assignment", "ManagedBy": "cdk"}.items():
    cdk.Tags.of(app).add(key, value)

if cfg.nag:
    # Opt-in policy-as-code review: `cdk synth -c nag=true`. Fails synth on any unsuppressed error.
    from cdk_nag import AwsSolutionsChecks

    from foundation.nag import baseline_suppressions, network_suppressions, workload_suppressions

    baseline_suppressions(baseline)
    network_suppressions(network)
    workload_suppressions(workload)
    cdk.Aspects.of(app).add(AwsSolutionsChecks(verbose=True))

app.synth()
