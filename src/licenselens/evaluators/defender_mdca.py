"""Defender for Cloud Apps Conditional Access App Control evaluator."""

from __future__ import annotations

from typing import Any

from licenselens.collectors import conditional_access as ca
from licenselens.evaluators.common import Evaluation
from licenselens.models import CheckDefinition, Confidence, FindingStatus

__all__ = ["evaluate_mdca_ca_session_control"]

_ENFORCING_SESSION_TYPES: frozenset[str] = frozenset({"blockdownloads", "mcasconfigured"})


def evaluate_mdca_ca_session_control(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    policies = list(evidence.get("ca_policies") or [])
    enabled = [p for p in policies if ca.is_enabled(p) and _has_cloud_app_security(p)]
    report_only = [p for p in policies if ca.is_report_only(p) and _has_cloud_app_security(p)]

    enforcing_broad = [
        p for p in enabled if _is_enforcing_session_control(p) and _has_meaningful_scope(p)
    ]
    narrow_scope = [
        p for p in enabled if _is_enforcing_session_control(p) and not _has_meaningful_scope(p)
    ]
    monitor_only = [p for p in enabled if not _is_enforcing_session_control(p)]

    def _names(items: list[dict[str, Any]]) -> list[str]:
        return [str(p.get("displayName") or p.get("id") or "?") for p in items]

    evidence_out = {
        "enabled_session_policies": _names(enabled),
        "enforcing_session_policies": _names(enforcing_broad),
        "monitor_only_session_policies": _names(monitor_only),
        "narrow_scope_session_policies": _names(narrow_scope),
        "report_only_session_policies": _names(report_only),
        "enabled_count": len(enabled),
        "enforcing_count": len(enforcing_broad),
        "monitor_only_count": len(monitor_only),
        "narrow_scope_count": len(narrow_scope),
        "report_only_count": len(report_only),
    }
    limitations = [
        "This check reads Conditional Access sessionControls.cloudAppSecurity only.",
        "MDCA portal policy catalogs are not available via Microsoft Graph.",
        (
            "MDCA file policies retire on 2027-01-06; migrate file protection to "
            "Microsoft Purview DLP and auto-labeling."
        ),
    ]

    if enforcing_broad:
        return Evaluation(
            status=FindingStatus.OK,
            summary=(
                f"{len(enforcing_broad)} enabled Conditional Access policy(ies) enforce "
                "Defender for Cloud Apps session control across all users."
            ),
            evidence=evidence_out,
            customer_summary="Cloud app sessions are enforced by Conditional Access App Control.",
            confidence=Confidence.HIGH,
            data_sources=["graph.identity.conditionalAccess"],
            limitations=limitations,
        )
    if narrow_scope:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                f"{len(narrow_scope)} enabled Conditional Access policy(ies) enforce "
                "Defender for Cloud Apps session control, but only for a narrow user/app scope."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Cloud App Security session control is enforced only for a pilot or narrow scope."
            ),
            confidence=Confidence.HIGH,
            data_sources=["graph.identity.conditionalAccess"],
            limitations=limitations
            + ["Expand user scope beyond a pilot subset to realize tenant-wide protection."],
        )
    if monitor_only:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                f"{len(monitor_only)} enabled Conditional Access policy(ies) use "
                "Defender for Cloud Apps session control in monitor-only or unconfirmed mode."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Cloud App Security session control is monitor-only and does not "
                "block risky actions."
            ),
            confidence=Confidence.HIGH,
            data_sources=["graph.identity.conditionalAccess"],
            limitations=limitations
            + [
                "cloudAppSecurityType=monitorOnly observes sessions without blocking downloads "
                "or enforcing custom MDCA session policies."
            ],
        )
    if report_only:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                f"{len(report_only)} report-only Conditional Access policy(ies) use "
                "Defender for Cloud Apps session control, but none are enforced."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Cloud App Security session control exists only in report-only mode."
            ),
            confidence=Confidence.HIGH,
            data_sources=["graph.identity.conditionalAccess"],
            limitations=limitations,
        )
    return Evaluation(
        status=FindingStatus.GAP,
        summary="No Conditional Access policy uses Defender for Cloud Apps session control.",
        evidence=evidence_out,
        customer_summary=(
            "You appear to pay for Defender for Cloud Apps, but no Conditional Access "
            "App Control session policy is enforcing it."
        ),
        confidence=Confidence.HIGH,
        data_sources=["graph.identity.conditionalAccess"],
        limitations=limitations,
    )


def _cloud_app_security(policy: dict[str, Any]) -> dict[str, Any] | None:
    session = policy.get("sessionControls") or {}
    if not isinstance(session, dict):
        return None
    cloud = session.get("cloudAppSecurity")
    if not isinstance(cloud, dict):
        return None
    if cloud.get("isEnabled") is False:
        return None
    return cloud


def _has_cloud_app_security(policy: dict[str, Any]) -> bool:
    cloud = _cloud_app_security(policy)
    if cloud is None:
        return False
    # Presence of the control object with a type, or explicit enablement, counts.
    return bool(cloud.get("cloudAppSecurityType") or cloud.get("isEnabled") is True)


def _is_enforcing_session_control(policy: dict[str, Any]) -> bool:
    cloud = _cloud_app_security(policy)
    if cloud is None:
        return False
    control_type = str(cloud.get("cloudAppSecurityType") or "").strip().lower()
    return control_type in _ENFORCING_SESSION_TYPES


def _has_meaningful_scope(policy: dict[str, Any]) -> bool:
    """True when the policy targets all users and at least one cloud application."""
    if not ca.includes_all_users(policy):
        return False
    conditions = policy.get("conditions") or {}
    if not isinstance(conditions, dict):
        return False
    apps = conditions.get("applications") or {}
    if not isinstance(apps, dict):
        return False
    include_apps = [str(a).strip().lower() for a in (apps.get("includeApplications") or []) if a]
    return bool(include_apps) and "none" not in include_apps
