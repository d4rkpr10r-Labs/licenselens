"""Entra Global Secure Access forwarding-profile evaluators."""

from __future__ import annotations

from typing import Any

from licenselens.evaluators.common import Evaluation
from licenselens.models import CheckDefinition, Confidence, FindingStatus

__all__ = [
    "evaluate_gsa_internet_access_enabled",
    "evaluate_gsa_private_access_enabled",
]

_BETA_LIMITATIONS = (
    "Evidence comes from Microsoft Graph beta networkAccess APIs.",
    "Requires NetworkAccess.Read.All; missing permission stays unresolved.",
)


def evaluate_gsa_internet_access_enabled(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    return _evaluate_forwarding_type(
        evidence,
        traffic_type="internet",
        label="Internet Access",
    )


def evaluate_gsa_private_access_enabled(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    return _evaluate_forwarding_type(
        evidence,
        traffic_type="private",
        label="Private Access",
    )


def _evaluate_forwarding_type(
    evidence: dict[str, Any],
    *,
    traffic_type: str,
    label: str,
) -> Evaluation:
    bundle = evidence.get("gsa_network_access")
    if not isinstance(bundle, dict):
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=f"Entra {label} forwarding profiles could not be read.",
            evidence={"api_version": "beta"},
            customer_summary=f"We could not confirm whether Entra {label} is turned on.",
            confidence=Confidence.LOW,
            data_sources=["graph.beta.networkAccess.forwardingProfiles"],
            limitations=list(_BETA_LIMITATIONS)
            + ["Forwarding-profile evidence was missing or malformed."],
        )
    if bundle.get("error"):
        return Evaluation(
            status=FindingStatus.ERROR,
            summary=f"Entra {label} forwarding profiles could not be read.",
            evidence={"error": bundle.get("error"), "api_version": "beta"},
            customer_summary=f"We could not confirm whether Entra {label} is turned on.",
            confidence=Confidence.LOW,
            data_sources=["graph.beta.networkAccess.forwardingProfiles"],
            limitations=list(_BETA_LIMITATIONS) + [str(bundle.get("error"))],
        )

    profiles = [p for p in (bundle.get("forwarding_profiles") or []) if isinstance(p, dict)]
    matching = [
        p
        for p in profiles
        if str(p.get("trafficForwardingType") or "").lower() == traffic_type.lower()
    ]
    enabled = [p for p in matching if _is_enabled(p)]
    assigned = [p for p in enabled if _has_assignment(p)]
    count_key = f"{traffic_type}_profile_count"
    enabled_key = f"{traffic_type}_profiles_enabled"
    evidence_out = {
        count_key: len(matching),
        enabled_key: len(enabled),
        f"{traffic_type}_profiles_assigned": len(assigned),
        "api_version": bundle.get("api_version") or "beta",
        "matching_profile_names": [
            str(p.get("name") or p.get("displayName") or p.get("id") or "?") for p in matching
        ],
    }
    limitations = list(_BETA_LIMITATIONS) + list(bundle.get("limitations") or [])

    if assigned:
        return Evaluation(
            status=FindingStatus.OK,
            summary=(
                f"Entra {label} has {len(assigned)} enabled forwarding profile(s) "
                "with user or group assignment."
            ),
            evidence=evidence_out,
            customer_summary=f"Entra {label} traffic forwarding is enabled and assigned.",
            confidence=Confidence.HIGH,
            data_sources=["graph.beta.networkAccess.forwardingProfiles"],
            limitations=limitations,
        )
    if enabled:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                f"Entra {label} forwarding profile(s) are enabled but have no "
                "user or group assignment evidence."
            ),
            evidence=evidence_out,
            customer_summary=(
                f"Entra {label} is turned on, but nobody appears assigned yet — "
                "traffic will not be acquired until users or groups are assigned."
            ),
            confidence=Confidence.MEDIUM,
            data_sources=["graph.beta.networkAccess.forwardingProfiles"],
            limitations=limitations
            + [
                "Enabled without associations does not prove traffic acquisition.",
            ],
        )
    if matching:
        return Evaluation(
            status=FindingStatus.GAP,
            summary=f"Entra {label} forwarding profile(s) exist but are not enabled.",
            evidence=evidence_out,
            customer_summary=f"Entra {label} is licensed but the traffic profile is not enabled.",
            confidence=Confidence.HIGH,
            data_sources=["graph.beta.networkAccess.forwardingProfiles"],
            limitations=limitations,
        )
    return Evaluation(
        status=FindingStatus.GAP,
        summary=f"No Entra {label} forwarding profile was returned.",
        evidence=evidence_out,
        customer_summary=f"Entra {label} does not appear to be turned on yet.",
        confidence=Confidence.MEDIUM,
        data_sources=["graph.beta.networkAccess.forwardingProfiles"],
        limitations=limitations
        + ["Absence of a matching profile may also mean the feature is not provisioned."],
    )


def _is_enabled(profile: dict[str, Any]) -> bool:
    state = str(profile.get("state") or profile.get("status") or "").lower()
    if state in {"enabled", "on", "active"}:
        return True
    if profile.get("enabled") is True:
        return True
    return False


def _has_assignment(profile: dict[str, Any]) -> bool:
    """True when the profile shows at least one user/group association."""
    associations = profile.get("associations")
    if isinstance(associations, list) and associations:
        return True
    assigned_to = profile.get("assignedTo") or profile.get("assignments")
    if isinstance(assigned_to, list) and assigned_to:
        return True
    if profile.get("isAssigned") is True:
        return True
    return False
