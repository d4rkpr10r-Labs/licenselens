"""Security Copilot workspace provisioning evaluator."""

from __future__ import annotations

from typing import Any

from licenselens.evaluators.common import Evaluation
from licenselens.models import CheckDefinition, Confidence, FindingStatus

__all__ = ["evaluate_sec_copilot_workspace_provisioned"]

_PHASED = (
    "Security Copilot inclusion for Microsoft 365 E5/E7 is phased; "
    "an empty workspace list may mean Microsoft has not enabled the tenant yet."
)


def evaluate_sec_copilot_workspace_provisioned(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = evidence.get("security_copilot")
    if not isinstance(bundle, dict):
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary="Security Copilot workspaces could not be read.",
            evidence={"api_version": "beta"},
            customer_summary="We could not confirm whether Security Copilot is provisioned.",
            confidence=Confidence.LOW,
            data_sources=["graph.beta.security.securityCopilot.workspaces"],
            limitations=[
                "Graph securityCopilot APIs are beta.",
                "Requires SecurityCopilotWorkspaces.Read.All.",
                _PHASED,
            ],
        )
    if bundle.get("error"):
        return Evaluation(
            status=FindingStatus.ERROR,
            summary="Security Copilot workspaces could not be read.",
            evidence={"error": bundle.get("error"), "api_version": "beta"},
            customer_summary="We could not confirm whether Security Copilot is provisioned.",
            confidence=Confidence.LOW,
            data_sources=["graph.beta.security.securityCopilot.workspaces"],
            limitations=[str(bundle.get("error")), _PHASED],
        )

    workspaces = [w for w in (bundle.get("workspaces") or []) if isinstance(w, dict)]
    names = [str(w.get("displayName") or w.get("id") or "?") for w in workspaces]
    evidence_out = {
        "workspace_count": len(workspaces),
        "workspace_names": names,
        "api_version": bundle.get("api_version") or "beta",
    }
    limitations = list(bundle.get("limitations") or []) + [
        "Graph securityCopilot APIs are beta.",
        _PHASED,
    ]

    if workspaces:
        return Evaluation(
            status=FindingStatus.OK,
            summary=f"{len(workspaces)} Security Copilot workspace(s) present.",
            evidence=evidence_out,
            customer_summary="A Security Copilot workspace is available for included capacity.",
            confidence=Confidence.HIGH,
            data_sources=["graph.beta.security.securityCopilot.workspaces"],
            limitations=limitations,
        )

    # Never emit a hard gap: phased enablement can look identical to "unused".
    return Evaluation(
        status=FindingStatus.PARTIAL,
        summary="No Security Copilot workspace was returned.",
        evidence=evidence_out,
        customer_summary=(
            "No Security Copilot workspace is visible yet. Confirm Message Center "
            "eligibility before treating this as unused inclusion capacity."
        ),
        confidence=Confidence.LOW,
        data_sources=["graph.beta.security.securityCopilot.workspaces"],
        limitations=limitations,
    )
