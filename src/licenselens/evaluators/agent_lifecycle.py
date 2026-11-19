"""Entra Agent ID automated lifecycle policy evaluator (Graph v1.0)."""

from __future__ import annotations

from typing import Any

from licenselens.evaluators.common import Evaluation
from licenselens.models import CheckDefinition, Confidence, FindingStatus

__all__ = [
    "evaluate_agent_lifecycle_policy_configured",
]

_DATA_SOURCES = ["graph.v1.identityGovernance.lifecycleWorkflows.lifecyclePolicies"]

_SCHEMA_LIMITATION = (
    "Detection of Microsoft's built-in default agent inactivity policy relies on "
    "documented Graph v1.0 lifecyclePolicy fields (lifecyclePolicySource, isDefault, "
    "displayName, and rule metadata) rather than a live tenant export."
)

_DEFAULT_SOURCE_VALUES: frozenset[str] = frozenset(
    {
        "default",
        "builtin",
        "built_in",
        "built-in",
        "microsoft",
        "system",
        "microsoftdefault",
        "tenantdefault",
    }
)

_CUSTOM_SOURCE_VALUES: frozenset[str] = frozenset(
    {
        "custom",
        "customer",
        "tenant",
        "user",
        "admin",
        "organization",
    }
)

_RULE_KEYS: tuple[str, ...] = (
    "rules",
    "lifecycleRules",
    "policyRules",
    "inactivityRules",
    "sponsorRules",
    "attestationRules",
    "triggers",
    "settings",
)

_PAID_RULE_KEYS: tuple[str, ...] = (
    "sponsorRules",
    "attestationRules",
)

_PAID_RULE_MARKERS: tuple[str, ...] = (
    "sponsor",
    "attest",
    "owner",
)


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _is_enabled(policy: dict[str, Any]) -> bool:
    if isinstance(policy.get("isEnabled"), bool):
        return bool(policy["isEnabled"])
    raw_state = str(policy.get("status") or policy.get("state") or "").strip().lower()
    return raw_state in {"enabled", "active", "on"}


def _source_token(policy: dict[str, Any]) -> str:
    return (
        str(
            policy.get("lifecyclePolicySource")
            or policy.get("policySource")
            or policy.get("source")
            or ""
        )
        .strip()
        .lower()
    )


def _is_default_policy(policy: dict[str, Any]) -> bool:
    """Defensively identify Microsoft's free built-in default agent inactivity policy."""
    if (
        policy.get("isDefault") is True
        or policy.get("isBuiltIn") is True
        or policy.get("isSystemDefault") is True
    ):
        return True
    source = _source_token(policy)
    if source in _DEFAULT_SOURCE_VALUES:
        return True
    if source in _CUSTOM_SOURCE_VALUES or policy.get("isDefault") is False:
        return False
    name = str(policy.get("displayName") or policy.get("name") or "").strip().lower()
    if "default" in name and ("inactivity" in name or "microsoft" in name or "agent" in name):
        return True
    return False


def _rule_metadata(policy: dict[str, Any]) -> tuple[bool, bool, bool]:
    """Return (has_rule_keys, has_active_rules, has_paid_governance_rule)."""
    has_rule_keys = False
    has_active_rules = False
    has_paid_governance_rule = False

    for key in _RULE_KEYS:
        if key not in policy:
            continue
        has_rule_keys = True
        value = policy.get(key)
        if isinstance(value, list):
            active_items = [
                item
                for item in value
                if not (isinstance(item, dict) and item.get("isEnabled") is False)
            ]
            if active_items:
                has_active_rules = True
                if key in _PAID_RULE_KEYS:
                    has_paid_governance_rule = True
                for item in active_items:
                    text = str(item).lower()
                    if any(marker in text for marker in _PAID_RULE_MARKERS):
                        has_paid_governance_rule = True
        elif isinstance(value, dict) and value:
            if value.get("isEnabled") is not False:
                has_active_rules = True
                if key in _PAID_RULE_KEYS:
                    has_paid_governance_rule = True
                text = str(value).lower()
                if any(marker in text for marker in _PAID_RULE_MARKERS):
                    has_paid_governance_rule = True

    return has_rule_keys, has_active_rules, has_paid_governance_rule


def _classify_enabled_policy(policy: dict[str, Any]) -> str:
    """Classify an enabled agent lifecycle policy as 'default', 'custom', or 'unclassified'."""
    if _is_default_policy(policy):
        return "default"

    source = _source_token(policy)
    explicit_custom = source in _CUSTOM_SOURCE_VALUES or policy.get("isDefault") is False
    has_rule_keys, has_active_rules, has_paid_rule = _rule_metadata(policy)

    if explicit_custom:
        if has_rule_keys and not has_active_rules:
            return "unclassified"
        return "custom"

    if has_paid_rule:
        return "custom"

    return "unclassified"


def _policy_label(policy: dict[str, Any]) -> str:
    return str(policy.get("displayName") or policy.get("name") or policy.get("id") or "?")


def evaluate_agent_lifecycle_policy_configured(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """Verify at least one enabled customer-authored Entra Agent ID lifecycle policy."""
    del check

    if evidence.get("agent_lifecycle_policies_error"):
        err = str(evidence["agent_lifecycle_policies_error"])
        return Evaluation(
            status=FindingStatus.ERROR,
            summary=f"Entra Agent ID lifecycle policies could not be read: {err}",
            evidence={"error": err, "api_version": "v1.0"},
            customer_summary=(
                "We could not verify whether automated AI agent lifecycle policies "
                "are configured in Microsoft Entra."
            ),
            confidence=Confidence.LOW,
            data_sources=list(_DATA_SOURCES),
            limitations=[
                "Requires LifecyclePolicies-AgentId.Read.All; missing permission stays unresolved.",
                err,
            ],
        )

    bundle = evidence.get("agent_lifecycle_policies")
    if not isinstance(bundle, dict):
        return Evaluation(
            status=FindingStatus.ERROR,
            summary="Entra Agent ID lifecycle policies evidence was missing or malformed.",
            evidence={"api_version": "v1.0"},
            customer_summary=(
                "We could not verify whether automated AI agent lifecycle policies "
                "are configured in Microsoft Entra."
            ),
            confidence=Confidence.LOW,
            data_sources=list(_DATA_SOURCES),
            limitations=[
                _SCHEMA_LIMITATION,
                "Agent lifecycle policy evidence was missing or malformed.",
            ],
        )

    if bundle.get("error"):
        err = str(bundle["error"])
        return Evaluation(
            status=FindingStatus.ERROR,
            summary=f"Entra Agent ID lifecycle policies could not be read: {err}",
            evidence={"error": err, "api_version": bundle.get("api_version") or "v1.0"},
            customer_summary=(
                "We could not verify whether automated AI agent lifecycle policies "
                "are configured in Microsoft Entra."
            ),
            confidence=Confidence.LOW,
            data_sources=list(_DATA_SOURCES),
            limitations=_dedupe([_SCHEMA_LIMITATION, *list(bundle.get("limitations") or []), err]),
        )

    policies = [p for p in (bundle.get("policies") or []) if isinstance(p, dict)]
    truncated = bool(bundle.get("truncated"))
    enabled = [p for p in policies if _is_enabled(p)]

    custom_enabled: list[dict[str, Any]] = []
    default_enabled: list[dict[str, Any]] = []
    unclassified_enabled: list[dict[str, Any]] = []

    for policy in enabled:
        kind = _classify_enabled_policy(policy)
        if kind == "custom":
            custom_enabled.append(policy)
        elif kind == "default":
            default_enabled.append(policy)
        else:
            unclassified_enabled.append(policy)

    evidence_out: dict[str, Any] = {
        "agent_policy_count": len(policies),
        "enabled_agent_policy_count": len(enabled),
        "custom_enabled_policy_count": len(custom_enabled),
        "default_enabled_policy_count": len(default_enabled),
        "unclassified_enabled_policy_count": len(unclassified_enabled),
        "custom_policy_names": [_policy_label(p) for p in custom_enabled[:10]],
        "default_policy_names": [_policy_label(p) for p in default_enabled[:10]],
        "truncated": truncated,
        "api_version": bundle.get("api_version") or "v1.0",
    }

    limitations = _dedupe([_SCHEMA_LIMITATION, *list(bundle.get("limitations") or [])])
    if truncated:
        limitations.append(
            "Graph response was truncated by the page budget; "
            "total policy counts may be incomplete."
        )

    if custom_enabled:
        return Evaluation(
            status=FindingStatus.OK,
            summary=(
                f"Found {len(custom_enabled)} enabled custom Entra Agent ID lifecycle "
                f"polic{'y' if len(custom_enabled) == 1 else 'ies'}."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Custom automated lifecycle policies are active to govern AI agent "
                "identities beyond Microsoft's free default inactivity rule."
            ),
            confidence=Confidence.MEDIUM if truncated else Confidence.HIGH,
            data_sources=list(_DATA_SOURCES),
            limitations=limitations,
        )

    if default_enabled and not unclassified_enabled:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                f"Only Microsoft's built-in default agent inactivity policy is enabled "
                f"({len(default_enabled)} default policy); no customer-authored Agent 365 "
                "lifecycle policy is active."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Only Microsoft's free default agent inactivity policy is turned on. "
                "Your paid Agent 365 governance controls (custom sponsor, attestation, "
                "or tailored lifecycle rules) are not yet configured."
            ),
            confidence=Confidence.MEDIUM,
            data_sources=list(_DATA_SOURCES),
            limitations=limitations,
        )

    if unclassified_enabled:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                f"Found {len(unclassified_enabled)} enabled agent lifecycle "
                f"polic{'y' if len(unclassified_enabled) == 1 else 'ies'}, but "
                "distinguishing source or active rule metadata could not be confirmed."
            ),
            evidence=evidence_out,
            customer_summary=(
                "An agent lifecycle policy appears enabled, but we could not confirm "
                "whether it is a customer-authored policy with active governance rules "
                "rather than Microsoft's built-in default."
            ),
            confidence=Confidence.MEDIUM,
            data_sources=list(_DATA_SOURCES),
            limitations=_dedupe(
                limitations
                + [
                    "Enabled policies lacked clear custom source or active rule fields to "
                    "confirm paid Agent 365 governance customization."
                ]
            ),
        )

    if truncated:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                "Agent lifecycle policy listing was truncated before any enabled "
                "custom policy was observed."
            ),
            evidence=evidence_out,
            customer_summary=(
                "We could not read every agent lifecycle policy because the list was "
                "truncated, so custom agent governance could not be ruled out."
            ),
            confidence=Confidence.LOW,
            data_sources=list(_DATA_SOURCES),
            limitations=limitations,
        )

    if policies:
        return Evaluation(
            status=FindingStatus.GAP,
            summary=(
                f"Found {len(policies)} Entra Agent ID lifecycle "
                f"polic{'y' if len(policies) == 1 else 'ies'}, but none is enabled."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Agent lifecycle policies exist in Microsoft Entra, but none is turned on "
                "to govern AI agents."
            ),
            confidence=Confidence.HIGH,
            data_sources=list(_DATA_SOURCES),
            limitations=limitations,
        )

    return Evaluation(
        status=FindingStatus.GAP,
        summary=(
            "No Entra Agent ID lifecycle policies are enabled. Paid Agent 365 "
            "automated agent lifecycle governance is unused."
        ),
        evidence=evidence_out,
        customer_summary=(
            "Your license includes automated lifecycle governance for AI agents, "
            "but no agent lifecycle policies are active yet."
        ),
        confidence=Confidence.HIGH,
        data_sources=list(_DATA_SOURCES),
        limitations=limitations,
    )
