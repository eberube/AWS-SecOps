"""Multi-AZ VPC with public/private tiers, controlled egress, NACLs, flow logs and endpoints."""

from __future__ import annotations

from aws_cdk import Aspects, CfnOutput, Stack, aws_ec2 as ec2, aws_s3 as s3
from constructs import Construct

from foundation.config import FoundationConfig
from foundation.stacks.security_baseline_stack import FLOW_LOG_PREFIX

ANY_IPV4 = "0.0.0.0/0"
EPHEMERAL = ec2.AclTraffic.tcp_port_range(1024, 65535)
HTTPS = ec2.AclTraffic.tcp_port(443)


class NetworkStack(Stack):
    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        cfg: FoundationConfig,
        log_bucket: s3.IBucket,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)
        self.cfg = cfg

        nat_provider: ec2.NatProvider | None = None
        if cfg.egress_mode == "nat-instance":
            # ~$3/month t4g.nano NAT instance instead of a ~$33/month NAT Gateway. Single AZ (see DESIGN.md).
            nat_provider = ec2.NatProvider.instance_v2(
                instance_type=ec2.InstanceType("t4g.nano"),
                machine_image=ec2.MachineImage.latest_amazon_linux2023(cpu_type=ec2.AmazonLinuxCpuType.ARM_64),
                default_allowed_traffic=ec2.NatTrafficDirection.OUTBOUND_ONLY,
            )
        elif cfg.egress_mode == "nat-gateway":
            nat_provider = ec2.NatProvider.gateway()

        self.private_subnet_type = (
            ec2.SubnetType.PRIVATE_WITH_EGRESS if cfg.has_internet_egress else ec2.SubnetType.PRIVATE_ISOLATED
        )

        self.vpc = ec2.Vpc(
            self,
            "Vpc",
            ip_addresses=ec2.IpAddresses.cidr(cfg.vpc_cidr),
            max_azs=2,
            nat_gateways=1 if nat_provider else 0,
            nat_gateway_provider=nat_provider,
            restrict_default_security_group=True,  # strips all rules from the default SG
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="public",
                    subnet_type=ec2.SubnetType.PUBLIC,
                    cidr_mask=24,
                    # Only the NAT instance lives here and it needs a public IP.
                    map_public_ip_on_launch=cfg.egress_mode == "nat-instance",
                ),
                ec2.SubnetConfiguration(name="private", subnet_type=self.private_subnet_type, cidr_mask=24),
            ],
        )

        if cfg.egress_mode == "nat-instance":
            # NAT instance accepts only HTTPS from inside the VPC.
            nat_provider.connections.allow_from(ec2.Peer.ipv4(cfg.vpc_cidr), ec2.Port.tcp(443), "HTTPS from VPC")
            # Enforce IMDSv2 on the NAT instance too.
            Aspects.of(self).add(ec2.InstanceRequireImdsv2Aspect())

        # S3 gateway endpoint is free: keeps S3 traffic (package repos, SSM agent updates) off the NAT.
        self.vpc.add_gateway_endpoint("S3Endpoint", service=ec2.GatewayVpcEndpointAwsService.S3)

        if cfg.needs_interface_endpoints:
            self._interface_endpoints()

        self._nacls()

        # VPC flow logs (ALL traffic) to the central KMS-encrypted log bucket. S3 delivery is much
        # cheaper than CloudWatch Logs ingestion.
        self.vpc.add_flow_log(
            "FlowLogs",
            destination=ec2.FlowLogDestination.to_s3(log_bucket, f"{FLOW_LOG_PREFIX}/"),
            traffic_type=ec2.FlowLogTrafficType.ALL,
            max_aggregation_interval=ec2.FlowLogMaxAggregationInterval.TEN_MINUTES,
        )

        CfnOutput(self, "VpcId", value=self.vpc.vpc_id)
        CfnOutput(self, "EgressMode", value=cfg.egress_mode)

    def _private_subnets(self) -> list[ec2.ISubnet]:
        return self.vpc.private_subnets if self.cfg.has_internet_egress else self.vpc.isolated_subnets

    def _interface_endpoints(self) -> None:
        sg = ec2.SecurityGroup(
            self,
            "EndpointSg",
            vpc=self.vpc,
            description="Interface endpoints: HTTPS from the VPC only",
            allow_all_outbound=False,
        )
        sg.add_ingress_rule(ec2.Peer.ipv4(self.cfg.vpc_cidr), ec2.Port.tcp(443), "HTTPS from VPC")

        # Endpoints are ~$7.30/month each *per AZ*; one AZ keeps the cost down (cross-AZ use is fine).
        single_az = ec2.SubnetSelection(subnets=[self._private_subnets()[0]])
        services = {
            "Ssm": ec2.InterfaceVpcEndpointAwsService.SSM,
            "SsmMessages": ec2.InterfaceVpcEndpointAwsService.SSM_MESSAGES,
            "Ec2Messages": ec2.InterfaceVpcEndpointAwsService.EC2_MESSAGES,
            "Logs": ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_LOGS,
            "Kms": ec2.InterfaceVpcEndpointAwsService.KMS,
        }
        for name, service in services.items():
            self.vpc.add_interface_endpoint(
                f"{name}Endpoint",
                service=service,
                subnets=single_az,
                security_groups=[sg],
                open=False,  # the SG above already allows 443 from the VPC; avoid a duplicate rule
                private_dns_enabled=True,
            )

    def _nacls(self) -> None:
        """Stateless subnet-level guardrails, layered under the stateful security groups.

        Traffic to the Amazon DNS resolver, the instance metadata service and Amazon Time Sync is not
        evaluated by NACLs, so no rules are needed for those.
        """
        vpc_cidr = ec2.AclCidr.ipv4(self.cfg.vpc_cidr)
        anywhere = ec2.AclCidr.ipv4(ANY_IPV4)
        allow = ec2.Action.ALLOW
        ingress, egress = ec2.TrafficDirection.INGRESS, ec2.TrafficDirection.EGRESS

        public = ec2.NetworkAcl(
            self, "PublicNacl", vpc=self.vpc,
            subnet_selection=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
        )
        public.add_entry("InHttpsFromVpc", rule_number=100, cidr=vpc_cidr, traffic=HTTPS, direction=ingress, rule_action=allow)
        public.add_entry("InEphemeral", rule_number=110, cidr=anywhere, traffic=EPHEMERAL, direction=ingress, rule_action=allow)
        public.add_entry("OutHttps", rule_number=100, cidr=anywhere, traffic=HTTPS, direction=egress, rule_action=allow)
        public.add_entry("OutEphemeralToVpc", rule_number=110, cidr=vpc_cidr, traffic=EPHEMERAL, direction=egress, rule_action=allow)

        private = ec2.NetworkAcl(
            self, "PrivateNacl", vpc=self.vpc,
            subnet_selection=ec2.SubnetSelection(subnet_type=self.private_subnet_type),
        )
        # Return traffic for outbound HTTPS (via NAT, S3 gateway endpoint or interface endpoints).
        private.add_entry("InEphemeral", rule_number=100, cidr=anywhere, traffic=EPHEMERAL, direction=ingress, rule_action=allow)
        # 0.0.0.0/0 is required even without a NAT: S3 gateway endpoint traffic targets public S3 IPs.
        # Without a NAT route there is still no path to the internet.
        private.add_entry("OutHttps", rule_number=100, cidr=anywhere, traffic=HTTPS, direction=egress, rule_action=allow)
        if self.cfg.needs_interface_endpoints:
            # Instances in the other AZ reach the endpoint ENIs across subnets.
            private.add_entry("InHttpsFromVpc", rule_number=110, cidr=vpc_cidr, traffic=HTTPS, direction=ingress, rule_action=allow)
            private.add_entry("OutEphemeralToVpc", rule_number=110, cidr=vpc_cidr, traffic=EPHEMERAL, direction=egress, rule_action=allow)
