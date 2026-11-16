"""Defender for Cloud Apps Conditional Access App Control evaluator."""

from __future__ import annotations

from typing import Any

from licenselens.collectors import conditional_access as ca
from licenselens.evaluators.common import Evaluation
from licenselens.models import CheckDefinition, Confidence, FindingStatus

__all__ = ["evaluate_mdca_ca_session_control"]


def evaluate_mdca_ca_session_control(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    policies = list(evidence.get("ca_policies") or [])
    enabled = [p for p in policies if ca.is_enabled(p) and _has_cloud_app_security(p)]
    report_only = [p for p in policies if ca.is_report_only(p) and _has_cloud_app_security(p)]
    evidence_out = {
        "enabled_session_policies": [
            str(p.get("displayName") or p.get("id") or "?") for p in enabled
        ],
        "report_only_session_policies": [
            str(p.get("displayName") or p.get("id") or "?") for p in report_only
        ],
        "enabled_count": len(enabled),
        "report_only_count": len(report_only),
    }
    limitations = [
        "This check reads Conditional Access sessionControls.cloudAppSecurity only.",
        "MDCA portal policy catalogs are not available via Microsoft Graph.",
    ]

    if enabled:
        return Evaluation(
            status=FindingStatus.OK,
            summary=(
                f"{len(enabled)} enabled Conditional Access policy(ies) use "
                "Defender for Cloud Apps session control."
            ),
            evidence=evidence_out,
            customer_summary="Cloud app sessions are covered by Conditional Access App Control.",
            confidence=Confidence.HIGH,
            data_sources=["graph.identity.conditionalAccess"],
            limitations=limitations,
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


def _has_cloud_app_security(policy: dict[str, Any]) -> bool:
    session = policy.get("sessionControls") or {}
    if not isinstance(session, dict):
        return False
    cloud = session.get("cloudAppSecurity")
    if not isinstance(cloud, dict):
        return False
    if cloud.get("isEnabled") is False:
        return False
    # Presence of the control object with a type, or explicit enablement, counts.
    return bool(cloud.get("cloudAppSecurityType") or cloud.get("isEnabled") is True)
