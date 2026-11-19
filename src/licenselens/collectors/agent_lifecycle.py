"""Collect Entra Agent ID automated lifecycle policies from Microsoft Graph v1.0."""

from __future__ import annotations

from typing import Any

from licenselens.graph import GraphClient

__all__ = [
    "DEMO_AGENT_LIFECYCLE_POLICIES_BUNDLE",
    "collect_agent_lifecycle_policies_bundle",
]

_PATH = "/identityGovernance/lifecycleWorkflows/lifecyclePolicies"


def _is_agent_lifecycle_policy(item: dict[str, Any]) -> bool:
    """Retain agentIdentityLifecyclePolicy items; exclude guest or unrelated subtypes."""
    odata_type = str(item.get("@odata.type") or "").strip().lower()
    if odata_type:
        return "agentidentitylifecyclepolicy" in odata_type
    policy_kind = str(item.get("policyType") or item.get("category") or "").strip().lower()
    return "guest" not in policy_kind


def collect_agent_lifecycle_policies_bundle(
    client: GraphClient,
    *,
    max_pages: int = 20,
) -> dict[str, Any]:
    """GET /v1.0/identityGovernance/lifecycleWorkflows/lifecyclePolicies (read-only)."""
    result = client.get_list_result(_PATH, max_pages=max_pages)
    raw_items = [item for item in result.items if isinstance(item, dict)]
    policies = [item for item in raw_items if _is_agent_lifecycle_policy(item)]
    return {
        "policies": policies,
        "count": len(policies),
        "total_policies_returned": len(raw_items),
        "filtered_out_non_agent_policies": len(raw_items) - len(policies),
        "truncated": result.truncated,
        "pages_read": result.pages_read,
        "max_pages": result.max_pages,
        "api_version": "v1.0",
        "limitations": [
            "Requires LifecyclePolicies-AgentId.Read.All (Graph v1.0, commercial cloud).",
            (
                "Distinguishing Microsoft's built-in default agent inactivity policy from "
                "customer-authored policies relies on documented Graph v1.0 lifecyclePolicy "
                "fields (lifecyclePolicySource, isDefault, displayName/rule markers)."
            ),
        ],
    }


DEMO_AGENT_LIFECYCLE_POLICIES_BUNDLE: dict[str, Any] = {
    "policies": [
        {
            "@odata.type": "#microsoft.graph.identityGovernance.agentIdentityLifecyclePolicy",
            "id": "demo-agent-default-inactivity",
            "displayName": "Default agent inactivity policy",
            "status": "enabled",
            "isDefault": True,
            "lifecyclePolicySource": "default",
        },
        {
            "@odata.type": "#microsoft.graph.identityGovernance.agentIdentityLifecyclePolicy",
            "id": "demo-agent-custom-governance",
            "displayName": "Demo: Production agent sponsor and attestation lifecycle",
            "status": "enabled",
            "isDefault": False,
            "lifecyclePolicySource": "custom",
            "rules": [
                {"ruleType": "sponsorPresence", "isEnabled": True},
                {"ruleType": "periodicAttestation", "isEnabled": True},
            ],
        },
    ],
    "count": 2,
    "total_policies_returned": 2,
    "filtered_out_non_agent_policies": 0,
    "truncated": False,
    "pages_read": 1,
    "max_pages": 20,
    "api_version": "v1.0",
    "limitations": [
        "Demo fixture — not a live tenant read.",
        "Requires LifecyclePolicies-AgentId.Read.All (Graph v1.0, commercial cloud).",
    ],
}
