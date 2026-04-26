"""Core dataclasses for tenant.chat."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class CheckType(str, Enum):
    PRESENCE   = "presence"
    VALUE      = "value"
    THRESHOLD  = "threshold"
    COVERAGE   = "coverage"
    STALENESS  = "staleness"


class CheckStatus(str, Enum):
    PASS    = "pass"
    FAIL    = "fail"
    PARTIAL = "partial"
    UNKNOWN = "unknown"


@dataclass
class BaselineControl:
    """A single control from a security baseline."""
    control_id:        str
    framework:         str
    title:             str
    description:       str
    check_type:        CheckType
    severity:          Severity
    effort:            str           # low / medium / high
    graph_endpoint:    str
    graph_filter:      str = ""
    graph_select:      str = ""
    graph_expand:      str = ""
    expected:          Any = None
    blast_radius:      list[str] = field(default_factory=list)
    community_ref:     str = ""
    references:        list[str] = field(default_factory=list)


@dataclass
class CheckResult:
    """Result of running a single baseline control check."""
    control_id:         str
    framework:          str
    title:              str
    severity:           Severity
    effort:             str
    status:             CheckStatus
    expected:           Any = None
    actual:             Any = None
    delta:              str = ""
    drift_score:        float = 1.0   # 1.0 = no drift
    affected_objects:   list[str] = field(default_factory=list)
    affected_count:     int = 0
    blast_radius:       list[str] = field(default_factory=list)
    community_ref:      str = ""
    explanation:        str = ""
    fix_instructions:   str = ""
    checked_at:         Optional[datetime] = None


@dataclass
class TenantState:
    """Collected configuration state from a tenant."""
    tenant_id:          str
    tenant_domain:      str
    collected_at:       datetime
    ca_policies:        list[dict] = field(default_factory=list)
    users:              list[dict] = field(default_factory=list)
    guests:             list[dict] = field(default_factory=list)
    admins:             list[dict] = field(default_factory=list)
    mfa_registration:   list[dict] = field(default_factory=list)
    managed_devices:    list[dict] = field(default_factory=list)
    compliance_policies:list[dict] = field(default_factory=list)
    config_profiles:    list[dict] = field(default_factory=list)
    secure_score:       dict = field(default_factory=dict)
    alerts:             list[dict] = field(default_factory=list)
    auth_policies:      list[dict] = field(default_factory=list)
    domains:            list[dict] = field(default_factory=list)
    roles:              list[dict] = field(default_factory=list)
    service_principals: list[dict] = field(default_factory=list)
    sharing_policy:     dict = field(default_factory=dict)
    audit_config:       dict = field(default_factory=dict)


@dataclass
class AssessmentResult:
    """Full assessment result for a tenant."""
    tenant_id:       str
    tenant_domain:   str
    assessed_at:     datetime
    posture_score:   float = 0.0
    frameworks:      list[str] = field(default_factory=list)
    findings:        list[CheckResult] = field(default_factory=list)
    critical_count:  int = 0
    high_count:      int = 0
    medium_count:    int = 0
    low_count:       int = 0
    pass_count:      int = 0
    total_controls:  int = 0


@dataclass
class AuthState:
    """Persisted authentication state."""
    tenant_id:      str = ""
    client_id:      str = ""
    account:        str = ""
    scopes:         list[str] = field(default_factory=list)
    authenticated:  bool = False


@dataclass
class UserCluster:
    """A K-means cluster of users with similar risk profile."""
    cluster_id:     int
    label:          str
    risk_level:     str
    user_count:     int
    characteristics:list[str] = field(default_factory=list)
    recommended_action: str = ""
    user_tokens:    list[str] = field(default_factory=list)


@dataclass
class BlastRadiusResult:
    """Blast radius analysis for a proposed change."""
    change_description: str
    affected_objects:   list[dict] = field(default_factory=list)
    risk_level:         str = "unknown"
    sequence:           list[str] = field(default_factory=list)
    fix_first:          list[str] = field(default_factory=list)
