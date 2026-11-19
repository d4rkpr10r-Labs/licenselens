"""Security Copilot Graph beta workspace reads."""

from __future__ import annotations

from typing import Any

from licenselens.graph import GraphClient

__all__ = [
    "DEMO_SECURITY_COPILOT_BUNDLE",
    "collect_security_copilot_bundle",
]


def collect_security_copilot_bundle(
    client: GraphClient,
    *,
    max_pages: int = 5,
) -> dict[str, Any]:
    """List Security Copilot workspaces (Graph beta)."""
    result = client.get_list_result("/security/securityCopilot/workspaces", max_pages=max_pages)
    workspaces = [w for w in result.items if isinstance(w, dict)]
    limitations = [
        "Graph securityCopilot APIs are beta; schema may change.",
        "Requires SecurityCopilotWorkspaces.Read.All.",
        "E5/E7 inclusion is phased; empty workspaces may mean not yet enabled.",
    ]
    if result.truncated:
        limitations.append(
            f"Workspace list was truncated after {result.pages_read} page(s) "
            f"(max_pages={result.max_pages})."
        )
    return {
        "workspaces": workspaces,
        "truncated": result.truncated,
        "pages_read": result.pages_read,
        "max_pages": result.max_pages,
        "api_version": "beta",
        "limitations": limitations,
    }


DEMO_SECURITY_COPILOT_BUNDLE: dict[str, Any] = {
    "workspaces": [
        {
            "id": "default",
            "displayName": "SecurityCopilot_Workspace",
        }
    ],
    "truncated": False,
    "api_version": "beta",
    "limitations": [
        "Demo fixture — not a live tenant read.",
        "Graph securityCopilot APIs are beta.",
    ],
}
