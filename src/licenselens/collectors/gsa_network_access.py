"""Global Secure Access (Entra Internet / Private Access) Graph beta reads."""

from __future__ import annotations

from typing import Any

from licenselens.graph import GraphClient

__all__ = [
    "DEMO_GSA_NETWORK_ACCESS_BUNDLE",
    "collect_gsa_network_access_bundle",
]


def collect_gsa_network_access_bundle(
    client: GraphClient,
    *,
    max_pages: int = 10,
) -> dict[str, Any]:
    """Collect forwarding profiles from Graph beta networkAccess APIs."""
    result = client.get_list_result("/networkAccess/forwardingProfiles", max_pages=max_pages)
    profiles = [p for p in result.items if isinstance(p, dict)]
    limitations = [
        "Graph networkAccess APIs are beta; schema may change.",
        "Requires NetworkAccess.Read.All.",
    ]
    if result.truncated:
        limitations.append(
            f"Forwarding profile list was truncated after {result.pages_read} page(s) "
            f"(max_pages={result.max_pages})."
        )
    return {
        "forwarding_profiles": profiles,
        "truncated": result.truncated,
        "pages_read": result.pages_read,
        "max_pages": result.max_pages,
        "api_version": "beta",
        "limitations": limitations,
    }


DEMO_GSA_NETWORK_ACCESS_BUNDLE: dict[str, Any] = {
    "forwarding_profiles": [
        {
            "id": "demo-internet",
            "name": "Internet traffic forwarding",
            "trafficForwardingType": "internet",
            "state": "enabled",
            "associations": [{"id": "demo-group", "@odata.type": "#microsoft.graph.group"}],
        },
        {
            "id": "demo-private",
            "name": "Private access traffic forwarding",
            "trafficForwardingType": "private",
            "state": "disabled",
        },
    ],
    "truncated": False,
    "api_version": "beta",
    "limitations": [
        "Demo fixture — not a live tenant read.",
        "Graph networkAccess APIs are beta.",
    ],
}
