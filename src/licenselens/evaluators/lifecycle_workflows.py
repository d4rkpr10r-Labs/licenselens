"""Entra ID Governance Lifecycle Workflows evaluator (Graph v1.0)."""

from __future__ import annotations

from typing import Any

from licenselens.evaluators.common import Evaluation
from licenselens.models import CheckDefinition, Confidence, FindingStatus

__all__ = [
    "evaluate_lifecycle_workflows_enabled",
]

_DATA_SOURCES = ["graph.v1.identityGovernance.lifecycleWorkflows.workflows"]


def _workflow_label(workflow: dict[str, Any]) -> str:
    return str(workflow.get("displayName") or workflow.get("id") or "?")


def evaluate_lifecycle_workflows_enabled(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """Verify at least one enabled, scheduled Entra ID Governance Lifecycle Workflow."""
    del check

    if evidence.get("lifecycle_workflows_error"):
        err = str(evidence["lifecycle_workflows_error"])
        return Evaluation(
            status=FindingStatus.ERROR,
            summary=f"Entra ID Governance Lifecycle Workflows could not be read: {err}",
            evidence={"error": err, "api_version": "v1.0"},
            customer_summary=(
                "We could not verify whether automated Joiner/Mover/Leaver lifecycle "
                "workflows are enabled in Microsoft Entra."
            ),
            confidence=Confidence.LOW,
            data_sources=list(_DATA_SOURCES),
            limitations=[
                "Requires LifecycleWorkflows.Read.All; missing permission stays unresolved.",
                err,
            ],
        )

    bundle = evidence.get("lifecycle_workflows")
    if not isinstance(bundle, dict):
        return Evaluation(
            status=FindingStatus.ERROR,
            summary="Entra ID Governance Lifecycle Workflows evidence was missing or malformed.",
            evidence={"api_version": "v1.0"},
            customer_summary=(
                "We could not verify whether automated Joiner/Mover/Leaver lifecycle "
                "workflows are enabled in Microsoft Entra."
            ),
            confidence=Confidence.LOW,
            data_sources=list(_DATA_SOURCES),
            limitations=["Lifecycle workflow evidence was missing or malformed."],
        )

    if bundle.get("error"):
        err = str(bundle["error"])
        return Evaluation(
            status=FindingStatus.ERROR,
            summary=f"Entra ID Governance Lifecycle Workflows could not be read: {err}",
            evidence={"error": err, "api_version": bundle.get("api_version") or "v1.0"},
            customer_summary=(
                "We could not verify whether automated Joiner/Mover/Leaver lifecycle "
                "workflows are enabled in Microsoft Entra."
            ),
            confidence=Confidence.LOW,
            data_sources=list(_DATA_SOURCES),
            limitations=[*list(bundle.get("limitations") or []), err],
        )

    workflows = [w for w in (bundle.get("workflows") or []) if isinstance(w, dict)]
    truncated = bool(bundle.get("truncated"))

    enabled = [w for w in workflows if w.get("isEnabled") is True]
    scheduled_enabled = [w for w in enabled if w.get("isSchedulingEnabled") is True]
    unscheduled_enabled = [w for w in enabled if w.get("isSchedulingEnabled") is not True]
    categories_covered = sorted(
        {
            str(w.get("category")).strip().lower()
            for w in scheduled_enabled
            if str(w.get("category") or "").strip()
        }
    )

    evidence_out: dict[str, Any] = {
        "workflow_count": len(workflows),
        "enabled_workflow_count": len(enabled),
        "scheduled_enabled_workflow_count": len(scheduled_enabled),
        "unscheduled_enabled_workflow_count": len(unscheduled_enabled),
        "categories_covered": categories_covered,
        "scheduled_workflow_names": [_workflow_label(w) for w in scheduled_enabled[:10]],
        "truncated": truncated,
        "api_version": bundle.get("api_version") or "v1.0",
    }

    limitations = list(bundle.get("limitations") or [])
    if truncated:
        limitations.append(
            "Graph response was truncated by the page budget; "
            "total workflow counts may be incomplete."
        )

    if scheduled_enabled:
        cats_text = f" ({', '.join(categories_covered)})" if categories_covered else ""
        return Evaluation(
            status=FindingStatus.OK,
            summary=(
                f"Found {len(scheduled_enabled)} enabled, scheduled Lifecycle "
                f"Workflow{'s' if len(scheduled_enabled) != 1 else ''}{cats_text}."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Automated Joiner/Mover/Leaver lifecycle workflows are turned on and "
                "scheduled to run automatically."
            ),
            confidence=Confidence.MEDIUM if truncated else Confidence.HIGH,
            data_sources=list(_DATA_SOURCES),
            limitations=limitations,
        )

    if unscheduled_enabled:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                f"Found {len(unscheduled_enabled)} enabled Lifecycle "
                f"Workflow{'s' if len(unscheduled_enabled) != 1 else ''}, but "
                "scheduled execution (isSchedulingEnabled) is not turned on."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Lifecycle workflows are enabled, but automatic scheduling is off — "
                "onboarding and offboarding tasks will only run when triggered manually."
            ),
            confidence=Confidence.MEDIUM,
            data_sources=list(_DATA_SOURCES),
            limitations=limitations,
        )

    if truncated:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                "Lifecycle Workflows listing was truncated before any enabled, "
                "scheduled workflow was observed."
            ),
            evidence=evidence_out,
            customer_summary=(
                "We could not read every lifecycle workflow because the list was "
                "truncated, so automated Joiner/Mover/Leaver coverage could not be ruled out."
            ),
            confidence=Confidence.LOW,
            data_sources=list(_DATA_SOURCES),
            limitations=limitations,
        )

    if workflows:
        return Evaluation(
            status=FindingStatus.GAP,
            summary=(
                f"Found {len(workflows)} Lifecycle "
                f"Workflow{'s' if len(workflows) != 1 else ''}, but none is enabled."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Lifecycle workflows have been created, but none is enabled to automate "
                "employee onboarding, role changes, or offboarding."
            ),
            confidence=Confidence.HIGH,
            data_sources=list(_DATA_SOURCES),
            limitations=limitations,
        )

    return Evaluation(
        status=FindingStatus.GAP,
        summary=(
            "No enabled Entra ID Governance Lifecycle Workflows were found. Paid "
            "Joiner/Mover/Leaver automation is unused."
        ),
        evidence=evidence_out,
        customer_summary=(
            "Your Entra ID Governance license includes automated onboarding and "
            "offboarding workflows, but none are configured yet."
        ),
        confidence=Confidence.HIGH,
        data_sources=list(_DATA_SOURCES),
        limitations=limitations,
    )
