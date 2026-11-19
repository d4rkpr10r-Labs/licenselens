"""Intune endpoint-security baseline, policy coverage, and MDE connector evaluators."""

from __future__ import annotations

from typing import Any, Final

from licenselens.evaluators.common import Evaluation
from licenselens.evaluators.endpoint_lib import (
    antivirus_policies,
    atp_state,
    configuration_policies,
    direct_meta,
    intune_bundle,
    managed_devices,
    surface_error,
    unavailable,
)
from licenselens.models import CheckDefinition, Confidence, FindingStatus

__all__ = [
    "evaluate_endpoint_mde_ai_agent_runtime_protection",
    "evaluate_endpoint_mde_connector",
    "evaluate_endpoint_security_baseline",
    "evaluate_endpoint_security_policy_coverage",
    "evaluate_intune_epm_policy_present",
]

_EPM_FAMILY = "endpointsecurityendpointprivilegemanagement"
_AI_AGENT_BETA_SOURCE: Final = "graph.beta.deviceManagement.configurationPolicies"
_AI_AGENT_DEVICES_SOURCE: Final = "graph.deviceManagement.managedDevices"
_AI_AGENT_BETA_NOTE: Final = (
    "Intune Settings Catalog configurationPolicies is a Microsoft Graph beta surface."
)
_AI_AGENT_NON_INTUNE_NOTE: Final = (
    "Settings applied outside Intune Settings Catalog (Group Policy, PowerShell "
    "Set-MpPreference, or Microsoft Defender portal security settings management "
    "without Intune sync) are outside this check's visibility."
)
_AI_AGENT_SCHEMA_CAVEAT: Final = (
    "Setting extraction relies on documented Defender CSP settingDefinitionId "
    "conventions (AiAgentProtection, AiAgentNetworkInspection; 0=Disabled, 1=Block, "
    "2=Audit) and should be confirmed against live Intune policy exports."
)

_EXPECTED_FAMILIES: Final = {
    "antivirus": "antivirus",
    "firewall": "firewall",
    "disk_encryption": "disk encryption",
    "attack_surface_reduction": "attack surface reduction",
}


def evaluate_endpoint_security_baseline(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """An endpoint-security baseline profile is configured."""
    del check
    bundle = intune_bundle(evidence)
    error = surface_error(bundle, "configuration_policies")
    if error:
        return unavailable(
            "Intune endpoint-security policies could not be read; treated as unresolved.",
            surface="configuration_policies",
            customer_summary=(
                "We could not confirm whether an endpoint-security baseline is applied."
            ),
        )
    policies = configuration_policies(bundle)
    baselines = [p for p in policies if "baseline" in _family(p).lower()]
    evidence_out = {
        "configuration_policy_count": len(policies),
        "baseline_policy_count": len(baselines),
    }
    if not baselines:
        return Evaluation(
            status=FindingStatus.GAP,
            summary="No Intune endpoint-security baseline profile is configured.",
            evidence=evidence_out,
            customer_summary=(
                "No security baseline is applied, so device hardening settings are not enforced."
            ),
            **direct_meta(),
        )
    return Evaluation(
        status=FindingStatus.OK,
        summary=f"{len(baselines)} endpoint-security baseline profile(s) configured.",
        evidence=evidence_out,
        customer_summary="A security baseline is applied to managed devices.",
        **direct_meta(),
    )


def evaluate_endpoint_security_policy_coverage(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """Antivirus, firewall, disk-encryption, and ASR policy coverage."""
    del check
    bundle = intune_bundle(evidence)
    error = surface_error(bundle, "configuration_policies")
    if error:
        return unavailable(
            "Intune endpoint-security policies could not be read; treated as unresolved.",
            surface="configuration_policies",
            customer_summary="We could not confirm endpoint-security policy coverage.",
        )
    policies = configuration_policies(bundle)
    families = {_family(p).lower() for p in policies}
    present = [label for key, label in _EXPECTED_FAMILIES.items() if _family_hit(key, families)]
    evidence_out = {
        "expected_families": sorted(_EXPECTED_FAMILIES.values()),
        "covered_families": present,
        "coverage_ratio": len(present) / len(_EXPECTED_FAMILIES),
    }
    if not present:
        return Evaluation(
            status=FindingStatus.GAP,
            summary="No antivirus, firewall, disk-encryption, or ASR policies are configured.",
            evidence=evidence_out,
            customer_summary="Core endpoint protections are not configured for managed devices.",
            **direct_meta(),
        )
    if len(present) < len(_EXPECTED_FAMILIES):
        missing = sorted(set(_EXPECTED_FAMILIES.values()) - set(present))
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                f"Endpoint-security policy coverage is incomplete — missing: {', '.join(missing)}."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Some core endpoint protections are configured, but others are missing."
            ),
            confidence=Confidence.MEDIUM,
            data_sources=["graph.deviceManagement"],
            limitations=["Not every core endpoint-security family is covered."],
        )
    return Evaluation(
        status=FindingStatus.OK,
        summary="Antivirus, firewall, disk-encryption, and ASR policies are all configured.",
        evidence=evidence_out,
        customer_summary="Core endpoint protections are configured for managed devices.",
        **direct_meta(),
    )


def evaluate_intune_epm_policy_present(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """At least one Intune Endpoint Privilege Management policy exists."""
    del check
    bundle = intune_bundle(evidence)
    error = surface_error(bundle, "configuration_policies")
    if error:
        return unavailable(
            "Intune configuration policies could not be read; EPM state is unresolved.",
            surface="configuration_policies",
            customer_summary=(
                "We could not confirm whether Endpoint Privilege Management is configured."
            ),
        )
    policies = configuration_policies(bundle)
    epm = [p for p in policies if _is_epm_policy(p)]
    assigned = [p for p in epm if _is_assigned_policy(p)]
    evidence_out = {
        "epm_policy_count": len(epm),
        "epm_assigned_count": len(assigned),
        "epm_policy_names": [
            str(p.get("name") or p.get("displayName") or p.get("id") or "?") for p in epm
        ],
        "configuration_policy_count": len(policies),
    }
    if not epm:
        return Evaluation(
            status=FindingStatus.GAP,
            summary="No Intune Endpoint Privilege Management configuration policy was found.",
            evidence=evidence_out,
            customer_summary=("EPM appears licensed but no elevation policy is configured."),
            **direct_meta(),
        )
    if not assigned:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                f"{len(epm)} Intune Endpoint Privilege Management policy(ies) exist "
                "but none are assigned to devices or users."
            ),
            evidence=evidence_out,
            customer_summary=(
                "EPM policies are defined but not assigned, so elevation rules are not "
                "reaching managed devices yet."
            ),
            **direct_meta(),
        )
    return Evaluation(
        status=FindingStatus.OK,
        summary=(
            f"{len(assigned)} Intune Endpoint Privilege Management policy(ies) "
            "configured and assigned."
        ),
        evidence=evidence_out,
        customer_summary="Endpoint Privilege Management policies are present and assigned.",
        **direct_meta(),
    )


def evaluate_endpoint_mde_connector(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """Intune-MDE connector is active (devices onboarded to Defender for Endpoint)."""
    del check
    bundle = intune_bundle(evidence)
    error = surface_error(bundle, "atp_onboarding_state")
    if error:
        return unavailable(
            "Intune-MDE connector status could not be read; treated as unresolved.",
            surface="atp_onboarding_state",
            customer_summary=(
                "We could not confirm whether Intune is connected to Defender for Endpoint."
            ),
        )
    atp = atp_state(bundle)
    if atp is None:
        return unavailable(
            "Intune-MDE connector onboarding summary was not returned.",
            surface="atp_onboarding_state",
            customer_summary="We could not confirm the Intune-MDE connector.",
        )
    onboarded = _int_field(atp, "onboardedDeviceCount")
    unknown = _int_field(atp, "unknownDeviceCount")
    unhealthy = _int_field(atp, "unhealthyDeviceCount")
    evidence_out = {
        "onboarded_device_count": onboarded,
        "unknown_device_count": unknown,
        "unhealthy_device_count": unhealthy,
    }
    if onboarded and onboarded > 0:
        return Evaluation(
            status=FindingStatus.OK,
            summary=f"Intune-MDE connector is active ({onboarded} device(s) onboarded).",
            evidence=evidence_out,
            customer_summary="Devices are flowing from Intune into Defender for Endpoint.",
            **direct_meta(),
        )
    if unknown and unknown > 0:
        return Evaluation(
            status=FindingStatus.GAP,
            summary=(
                f"No devices onboarded to Defender for Endpoint via Intune "
                f"({unknown} device(s) in unknown state)."
            ),
            evidence=evidence_out,
            customer_summary=(
                "You appear to pay for device protection, but no devices are onboarded "
                "to Defender for Endpoint through Intune."
            ),
            **direct_meta(),
        )
    return Evaluation(
        status=FindingStatus.PARTIAL,
        summary="No applicable devices to prove Intune-MDE connector state.",
        evidence=evidence_out,
        customer_summary=(
            "We could not confirm the Intune-MDE connector; there may be no applicable devices."
        ),
        confidence=Confidence.MEDIUM,
        data_sources=["graph.deviceManagement"],
        limitations=["No onboarded or unknown devices to confirm connector state."],
    )


def evaluate_endpoint_mde_ai_agent_runtime_protection(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """Defender for Endpoint P2 local AI agent runtime protection via Intune Antivirus policy."""
    del check
    bundle = intune_bundle(evidence)
    if bundle is None:
        err = str(evidence.get("intune_bundle_error") or "Intune evidence was not collected.")
        return Evaluation(
            status=FindingStatus.ERROR,
            summary=(
                "Intune configuration policies could not be read; "
                "AI agent runtime protection state is unresolved."
            ),
            evidence={
                "api_version": "beta",
                "surface": "configuration_policies",
                "readable": False,
                "error": err,
            },
            customer_summary=(
                "We could not confirm whether Defender AI agent runtime protection is configured."
            ),
            confidence=Confidence.LOW,
            data_sources=[_AI_AGENT_BETA_SOURCE],
            limitations=[
                _AI_AGENT_BETA_NOTE,
                err,
            ],
        )

    policy_error = surface_error(bundle, "antivirus_policies") or surface_error(
        bundle, "configuration_policies"
    )
    if policy_error:
        return Evaluation(
            status=FindingStatus.ERROR,
            summary=(
                "Intune Antivirus configuration policies could not be read; "
                "AI agent runtime protection state is unresolved."
            ),
            evidence={
                "api_version": "beta",
                "surface": "configuration_policies",
                "readable": False,
                "error": policy_error,
            },
            customer_summary=(
                "We could not confirm whether Defender AI agent runtime protection is configured."
            ),
            confidence=Confidence.LOW,
            data_sources=[_AI_AGENT_BETA_SOURCE],
            limitations=[
                _AI_AGENT_BETA_NOTE,
                policy_error,
            ],
        )

    av_policies = antivirus_policies(bundle)
    devices = managed_devices(bundle)
    windows_devices = [
        d for d in devices if "windows" in str(d.get("operatingSystem") or "").lower()
    ]
    devices_error = surface_error(bundle, "managed_devices")
    truncated = _ai_agent_read_truncated(bundle, av_policies)

    assigned_block: list[dict[str, Any]] = []
    assigned_audit: list[dict[str, Any]] = []
    unassigned_enabled: list[dict[str, Any]] = []
    block_modes: set[str] = set()
    audit_modes: set[str] = set()
    matched_defs: set[str] = set()

    for policy in av_policies:
        for def_id in policy.get("matched_setting_definition_ids") or []:
            if isinstance(def_id, str) and def_id:
                matched_defs.add(def_id)
        is_assigned = _is_assigned_policy(policy)
        native_mode = _ai_agent_mode(policy.get("ai_agent_protection"))
        network_mode = _ai_agent_mode(policy.get("ai_agent_network_inspection"))
        has_block = native_mode == 1 or network_mode == 1
        has_audit = native_mode == 2 or network_mode == 2
        if is_assigned:
            if native_mode == 1:
                block_modes.add("AiAgentProtection")
            elif native_mode == 2:
                audit_modes.add("AiAgentProtection")
            if network_mode == 1:
                block_modes.add("AiAgentNetworkInspection")
            elif network_mode == 2:
                audit_modes.add("AiAgentNetworkInspection")
            if has_block:
                assigned_block.append(policy)
            elif has_audit:
                assigned_audit.append(policy)
        elif has_block or has_audit:
            unassigned_enabled.append(policy)

    evidence_out: dict[str, Any] = {
        "api_version": "beta",
        "antivirus_policy_count": len(av_policies),
        "assigned_block_policy_count": len(assigned_block),
        "assigned_audit_policy_count": len(assigned_audit),
        "unassigned_enabled_policy_count": len(unassigned_enabled),
        "block_modes": sorted(block_modes),
        "audit_modes": sorted(audit_modes),
        "managed_windows_device_count": len(windows_devices),
        "truncated": truncated,
        "policy_names": [
            str(p.get("displayName") or p.get("name") or p.get("id") or "?") for p in av_policies
        ],
        "matched_setting_definition_ids": sorted(matched_defs),
    }
    advisory = [_AI_AGENT_BETA_NOTE, _AI_AGENT_NON_INTUNE_NOTE, _AI_AGENT_SCHEMA_CAVEAT]
    sources = [_AI_AGENT_BETA_SOURCE, _AI_AGENT_DEVICES_SOURCE]

    if assigned_block:
        if truncated:
            return Evaluation(
                status=FindingStatus.PARTIAL,
                summary=(
                    f"{len(assigned_block)} assigned Intune Antivirus policy(ies) enforce "
                    f"Defender AI agent runtime protection in Block mode "
                    f"({', '.join(sorted(block_modes))}), but the Intune inventory read "
                    "was truncated."
                ),
                evidence=evidence_out,
                customer_summary=(
                    "An assigned AI agent protection policy in Block mode was found, "
                    "but Intune results were truncated before full coverage could be confirmed."
                ),
                confidence=Confidence.MEDIUM,
                data_sources=sources,
                limitations=advisory
                + ["Intune policy or managed-device inventory was truncated by collection caps."],
            )
        return Evaluation(
            status=FindingStatus.OK,
            summary=(
                f"{len(assigned_block)} assigned Intune Antivirus policy(ies) enforce "
                f"Defender AI agent runtime protection in Block mode "
                f"({', '.join(sorted(block_modes))})."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Defender local AI agent runtime protection is assigned and enforcing "
                "in Block mode on managed Windows devices."
            ),
            confidence=Confidence.HIGH,
            data_sources=sources,
            limitations=advisory,
        )

    if any(p.get("settings_error") for p in av_policies) or any(
        p.get("assignments_error") for p in av_policies
    ):
        evidence_out["readable"] = False
        return Evaluation(
            status=FindingStatus.ERROR,
            summary=(
                "One or more Intune Antivirus policy settings or assignments could not be "
                "read; AI agent runtime protection state is unresolved."
            ),
            evidence=evidence_out,
            customer_summary=(
                "We found Antivirus policies in Intune but could not read all settings "
                "or assignments to confirm AI agent runtime protection."
            ),
            confidence=Confidence.LOW,
            data_sources=sources,
            limitations=advisory
            + ["One or more Antivirus policy settings or assignments were not readable."],
        )

    if assigned_audit:
        extra = (
            ["Intune policy or managed-device inventory was truncated by collection caps."]
            if truncated
            else []
        )
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                f"{len(assigned_audit)} assigned Intune Antivirus policy(ies) configure "
                f"Defender AI agent runtime protection in Audit mode only "
                f"({', '.join(sorted(audit_modes))}); Block mode (1) is not enforced."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Local AI agent runtime protection is only logging detections in Audit "
                "mode and is not yet blocking prompt-injection actions."
            ),
            confidence=Confidence.LOW if truncated else Confidence.MEDIUM,
            data_sources=sources,
            limitations=advisory + extra,
        )

    if unassigned_enabled:
        extra = (
            ["Intune policy or managed-device inventory was truncated by collection caps."]
            if truncated
            else []
        )
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                f"{len(unassigned_enabled)} Intune Antivirus policy(ies) configure "
                "Defender AI agent runtime protection but none are assigned to devices."
            ),
            evidence=evidence_out,
            customer_summary=(
                "AI agent runtime protection policies exist in Intune, but they are not "
                "assigned to managed Windows devices yet."
            ),
            confidence=Confidence.LOW if truncated else Confidence.MEDIUM,
            data_sources=sources,
            limitations=advisory + extra,
        )

    if devices_error:
        evidence_out["readable"] = False
        evidence_out["error"] = devices_error
        return Evaluation(
            status=FindingStatus.ERROR,
            summary=(
                "Intune managed devices could not be read; Windows endpoint applicability "
                "for AI agent runtime protection is unresolved."
            ),
            evidence=evidence_out,
            customer_summary=(
                "We could not read Intune managed devices to confirm whether Windows "
                "endpoints require AI agent runtime protection."
            ),
            confidence=Confidence.LOW,
            data_sources=sources,
            limitations=advisory + [devices_error],
        )

    if truncated:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                "Intune Antivirus configuration policies or device inventory were "
                "truncated before an enabled AI agent runtime protection policy was confirmed."
            ),
            evidence=evidence_out,
            customer_summary=(
                "We could not read every Intune Antivirus policy or device record, so "
                "AI agent runtime protection cannot be ruled out."
            ),
            confidence=Confidence.LOW,
            data_sources=sources,
            limitations=advisory
            + ["Intune policy or managed-device inventory was truncated by collection caps."],
        )

    if not windows_devices:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                "No Intune-managed Windows devices were observed; Defender local AI agent "
                "runtime protection applicability is unproven."
            ),
            evidence=evidence_out,
            customer_summary=(
                "No managed Windows devices were found in Intune, so local AI agent "
                "runtime protection does not apply to any observed Intune device."
            ),
            confidence=Confidence.MEDIUM,
            data_sources=sources,
            limitations=advisory
            + ["No Intune-managed Windows devices were observed in managedDevices."],
        )

    return Evaluation(
        status=FindingStatus.GAP,
        summary=(
            "Managed Windows devices exist, Intune Antivirus policies were read cleanly, "
            "and neither AiAgentProtection nor AiAgentNetworkInspection is enabled."
        ),
        evidence=evidence_out,
        customer_summary=(
            "You license Defender for Endpoint Plan 2 and manage Windows devices, but no "
            "assigned Intune Antivirus policy turns on local AI agent runtime protection."
        ),
        confidence=Confidence.MEDIUM,
        data_sources=sources,
        limitations=advisory,
    )


def _family(policy: dict[str, Any]) -> str:
    ref = policy.get("templateReference") or {}
    if isinstance(ref, dict):
        return str(ref.get("templateFamily") or "")
    return ""


def _is_epm_policy(policy: dict[str, Any]) -> bool:
    """Match EPM by template family / technologies only — never by display name."""
    family = _family(policy).lower().replace("_", "")
    if _EPM_FAMILY in family:
        return True
    technologies = str(policy.get("technologies") or "").lower().replace("_", "")
    return "endpointprivilegemanagement" in technologies


def _is_assigned_policy(policy: dict[str, Any]) -> bool:
    if policy.get("isAssigned") is True or policy.get("assigned") is True:
        return True
    assignments = policy.get("assignments")
    return isinstance(assignments, list) and bool(assignments)


def _family_hit(key: str, families: set[str]) -> bool:
    return any(key.replace("_", "") in family.replace("_", "") for family in families)


def _int_field(mapping: dict[str, Any], name: str) -> int:
    value = mapping.get(name)
    try:
        return int(value) if value is not None else 0
    except (TypeError, ValueError):
        return 0


def _ai_agent_mode(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value in {0, 1, 2}:
        return value
    if isinstance(value, str):
        text = value.strip().lower()
        if text in {"0", "disabled"}:
            return 0
        if text in {"1", "block"}:
            return 1
        if text in {"2", "audit"}:
            return 2
    return None


def _ai_agent_read_truncated(
    bundle: dict[str, Any],
    av_policies: list[dict[str, Any]],
) -> bool:
    has_granular = any(
        key in bundle
        for key in (
            "antivirus_policies_truncated",
            "configuration_policies_truncated",
            "managed_devices_truncated",
        )
    )
    if has_granular:
        return (
            bool(bundle.get("antivirus_policies_truncated"))
            or bool(bundle.get("configuration_policies_truncated"))
            or bool(bundle.get("managed_devices_truncated"))
            or any(bool(p.get("settings_truncated")) for p in av_policies)
        )
    return bool(bundle.get("truncated")) or any(
        bool(p.get("settings_truncated")) for p in av_policies
    )
