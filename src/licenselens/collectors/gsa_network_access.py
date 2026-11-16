"""Global Secure Access (Entra Internet / Private Access) Graph beta reads."""

from __future__ import annotations

from typing import Any

from licenselens.graph import GraphClient

__all__ = [
    "DEMO_GSA_NETWORK_ACCESS_BUNDLE",
    "collect_gsa_network_access_bundle",
]


def collect_gsa_network_access_bundle(client: GraphClient) -> dict[str, Any]:
    """Collect forwarding profiles from Graph beta networkAccess APIs."""
    profiles = client.get_list("/networkAccess/forwardingProfiles", max_pages=10)
    return {
        "forwarding_profiles": [p for p in profiles if isinstance(p, dict)],
        "api_version": "beta",
        "limitations": [
            "Graph networkAccess APIs are beta; schema may change.",
            "Requires NetworkAccess.Read.All.",
        ],
    }


DEMO_GSA_NETWORK_ACCESS_BUNDLE: dict[str, Any] = {
    "forwarding_profiles": [
        {
            "id": "demo-internet",
            "name": "Internet traffic forwarding",
            "trafficForwardingType": "internet",
            "state": "enabled",
        },
        {
            "id": "demo-private",
            "name": "Private access traffic forwarding",
            "trafficForwardingType": "private",
            "state": "disabled",
        },
    ],
    "api_version": "beta",
    "limitations": [
        "Demo fixture — not a live tenant read.",
        "Graph networkAccess APIs are beta.",
    ],
}
