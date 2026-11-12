"""Typed, validated configuration read from CDK context (cdk.json or `-c key=value`)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from constructs import Node

EGRESS_MODES = ("nat-instance", "nat-gateway", "none")


def _bool(value: Any, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _list(value: Any) -> list[str]:
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    text = str(value).strip()
    if text.startswith("["):
        return [str(v) for v in json.loads(text)]
    return [v.strip() for v in text.split(",") if v.strip()]


@dataclass(frozen=True)
class FoundationConfig:
    project: str = "secure-foundation"
    alert_email: str = ""
    monthly_budget_usd: float = 25.0
    egress_mode: str = "nat-instance"
    enable_interface_endpoints: bool = False
    enable_security_hub: bool = False
    enable_session_manager_prefs: bool = True
    vpc_cidr: str = "10.20.0.0/16"
    instance_type: str = "t4g.nano"
    trusted_admin_principal_arns: list[str] = field(default_factory=list)
    retain_data: bool = False
    nag: bool = False

    @property
    def is_arm_instance(self) -> bool:
        # Graviton families carry a "g" right after the generation number: t4g, m7g, c7gn, r8g ...
        return re.match(r"^[a-z]+\d+g", self.instance_type.split(".")[0]) is not None

    @property
    def has_internet_egress(self) -> bool:
        return self.egress_mode in ("nat-instance", "nat-gateway")

    @property
    def needs_interface_endpoints(self) -> bool:
        # Without a NAT path the SSM agent can only reach SSM through PrivateLink.
        return self.enable_interface_endpoints or not self.has_internet_egress

    @staticmethod
    def from_context(node: Node) -> "FoundationConfig":
        d = FoundationConfig()
        get = node.try_get_context
        cfg = FoundationConfig(
            project=str(get("project") or d.project),
            alert_email=str(get("alert_email") or ""),
            monthly_budget_usd=float(get("monthly_budget_usd") or d.monthly_budget_usd),
            egress_mode=str(get("egress_mode") or d.egress_mode),
            enable_interface_endpoints=_bool(get("enable_interface_endpoints"), d.enable_interface_endpoints),
            enable_security_hub=_bool(get("enable_security_hub"), d.enable_security_hub),
            enable_session_manager_prefs=_bool(get("enable_session_manager_prefs"), d.enable_session_manager_prefs),
            vpc_cidr=str(get("vpc_cidr") or d.vpc_cidr),
            instance_type=str(get("instance_type") or d.instance_type),
            trusted_admin_principal_arns=_list(get("trusted_admin_principal_arns")),
            retain_data=_bool(get("retain_data"), d.retain_data),
            nag=_bool(get("nag"), d.nag),
        )
        cfg.validate()
        return cfg

    def validate(self) -> None:
        if not re.fullmatch(r"[a-z][a-z0-9-]{2,24}", self.project):
            raise ValueError("project must be 3-25 chars of lowercase letters, digits and hyphens")
        if self.egress_mode not in EGRESS_MODES:
            raise ValueError(f"egress_mode must be one of {EGRESS_MODES}")
        if self.alert_email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", self.alert_email):
            raise ValueError("alert_email does not look like an email address")
        for arn in self.trusted_admin_principal_arns:
            if not arn.startswith("arn:"):
                raise ValueError(f"trusted_admin_principal_arns entry is not an ARN: {arn}")
