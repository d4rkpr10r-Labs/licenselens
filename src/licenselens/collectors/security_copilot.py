"""Security Copilot Graph beta workspace reads."""

from __future__ import annotations

from typing import Any

from licenselens.graph import GraphClient

__all__ = [
    "DEMO_SECURITY_COPILOT_BUNDLE",
    "collect_security_copilot_bundle",
]


def collect_security_copilot_bundle(client: GraphClient) -> dict[str, Any]:
    """List Security Copilot workspaces (Graph beta)."""
    workspaces = client.get_list("/security/securityCopilot/workspaces", max_pages=5)
    return {
        "workspaces": [w for w in workspaces if isinstance(w, dict)],
        "api_version": "beta",
        "limitations": [
            "Graph securityCopilot APIs are beta; schema may change.",
            "Requires SecurityCopilotWorkspaces.Read.All.",
            "E5/E7 inclusion is phased; empty workspaces may mean not yet enabled.",
        ],
    }


DEMO_SECURITY_COPILOT_BUNDLE: dict[str, Any] = {
    "workspaces": [
        {
            "id": "default",
            "displayName": "SecurityCopilot_Workspace",
        }
    ],
    "api_version": "beta",
    "limitations": [
        "Demo fixture — not a live tenant read.",
        "Graph securityCopilot APIs are beta.",
    ],
}
