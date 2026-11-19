"""Collect Entra ID Governance Lifecycle Workflows from Microsoft Graph v1.0."""

from __future__ import annotations

from typing import Any

from licenselens.graph import GraphClient

__all__ = [
    "DEMO_LIFECYCLE_WORKFLOWS_BUNDLE",
    "collect_lifecycle_workflows_bundle",
]

_PATH = "/identityGovernance/lifecycleWorkflows/workflows"


def collect_lifecycle_workflows_bundle(
    client: GraphClient,
    *,
    max_pages: int = 20,
) -> dict[str, Any]:
    """GET /v1.0/identityGovernance/lifecycleWorkflows/workflows (read-only)."""
    result = client.get_list_result(_PATH, max_pages=max_pages)
    workflows = [item for item in result.items if isinstance(item, dict)]
    return {
        "workflows": workflows,
        "count": len(workflows),
        "truncated": result.truncated,
        "pages_read": result.pages_read,
        "max_pages": result.max_pages,
        "api_version": "v1.0",
        "limitations": [
            "Requires LifecycleWorkflows.Read.All (Graph v1.0, commercial cloud).",
        ],
    }


DEMO_LIFECYCLE_WORKFLOWS_BUNDLE: dict[str, Any] = {
    "workflows": [
        {
            "id": "demo-workflow-leaver-1",
            "displayName": "Demo: Offboard departing employees",
            "category": "leaver",
            "isEnabled": True,
            "isSchedulingEnabled": True,
        }
    ],
    "count": 1,
    "truncated": False,
    "pages_read": 1,
    "max_pages": 20,
    "api_version": "v1.0",
    "limitations": [
        "Demo fixture — not a live tenant read.",
        "Requires LifecycleWorkflows.Read.All (Graph v1.0, commercial cloud).",
    ],
}
