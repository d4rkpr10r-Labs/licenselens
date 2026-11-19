"""Intune policy/assignment/connector collection bundle (Todo 22).

Collects compliance-policy assignment and noncompliance-action detail, endpoint
security configuration policies, managed-device inventory, and the Intune-MDE
onboarding summary. Each surface is collected best-effort and surfaced through
an ``errors`` map so evaluators can downgrade to manual/partial instead of
fabricating a gap when an API proves nothing.
"""

from __future__ import annotations

from typing import Any

from licenselens.collectors.contracts import CloudEnvironment
from licenselens.errors import GraphError
from licenselens.graph import GraphClient
from licenselens.models import SubscribedSku

__all__ = [
    "DEMO_INTUNE_EVIDENCE_BUNDLE",
    "INTUNE_PLAN_HINTS",
    "INTUNE_SKU_HINTS",
    "collect_intune_atp_onboarding_state",
    "collect_intune_evidence_bundle",
    "intune_licensed_units",
]

INTUNE_PLAN_HINTS: tuple[str, ...] = (
    "INTUNE_A",
    "INTUNE_A_VL",
    "MDM_SALES_COLLABORATION",
)

INTUNE_SKU_HINTS: tuple[str, ...] = (
    "SPE_E3",
    "SPE_E5",
    "ENTERPRISEPACK",
    "ENTERPRISEPREMIUM",
    "EMSPREMIUM",
    "INTUNE_A",
)

_MAX_POLICY_DETAIL = 15
_MAX_TAMPER_DEVICES = 10

_ASR_RULE_KEY = "attacksurfacereductionrules"
_ANTIVIRUS_FAMILY_TOKEN = "endpointsecurityantivirus"
_AI_AGENT_PROTECTION_KEY = "aiagentprotection"
_AI_AGENT_NETWORK_INSPECTION_KEY = "aiagentnetworkinspection"
_AI_AGENT_MODE_LABELS: dict[int, str] = {
    0: "disabled",
    1: "block",
    2: "audit",
}

_SURFACES = (
    "managed_devices",
    "compliance_policies",
    "configuration_policies",
    "antivirus_policies",
    "atp_onboarding_state",
    "device_configurations",
    "asr_policies",
    "compliance_state_summary",
    "app_protection_policies",
    "tamper_device_state",
)


def intune_licensed_units(skus: list[SubscribedSku]) -> int | None:
    """Best-effort prepaid units attributable to Intune across active SKUs."""
    total = 0
    found = False
    for sku in skus:
        part = (sku.sku_part_number or "").upper()
        plans = {p.service_plan_name.upper() for p in sku.service_plans if p.service_plan_name}
        if part in INTUNE_SKU_HINTS or bool(plans & set(INTUNE_PLAN_HINTS)):
            found = True
            if sku.prepaid_units is not None:
                total += int(sku.prepaid_units)
    return total if found else None


def collect_intune_atp_onboarding_state(client: GraphClient) -> dict[str, Any]:
    """Intune-MDE connector onboarding summary (single resource)."""
    data = client.get("/deviceManagement/advancedThreatProtectionOnboardingStateSummary")
    return data if isinstance(data, dict) else {}


def collect_intune_evidence_bundle(
    client: GraphClient,
    *,
    licensed_units: int | None = None,
    max_policy_detail: int = _MAX_POLICY_DETAIL,
) -> dict[str, Any]:
    """Collect Intune surfaces best-effort; per-surface failures live in ``errors``."""
    errors: dict[str, str] = {surface: "" for surface in _SURFACES}

    if getattr(client, "cloud", None) is CloudEnvironment.CHINA:
        for surface in _SURFACES:
            errors[surface] = "Intune device management is not supported in this cloud."
        return _bundle(
            [],
            [],
            [],
            [],
            None,
            [],
            [],
            None,
            [],
            _EMPTY_TAMPER_STATE,
            licensed_units,
            False,
            errors,
            antivirus_policies_truncated=False,
            configuration_policies_truncated=False,
            managed_devices_truncated=False,
        )

    devices_truncated = False
    try:
        devices, devices_truncated = _get_list_with_truncation(
            client, "/deviceManagement/managedDevices", max_pages=20
        )
    except GraphError as exc:
        devices = []
        errors["managed_devices"] = str(exc)

    try:
        compliance = client.get_list("/deviceManagement/deviceCompliancePolicies", max_pages=30)
    except GraphError as exc:
        compliance = []
        errors["compliance_policies"] = str(exc)

    config_truncated = False
    try:
        config, config_truncated = _get_list_with_truncation(
            client, "/deviceManagement/configurationPolicies", max_pages=30
        )
    except GraphError as exc:
        config = []
        errors["configuration_policies"] = str(exc)

    try:
        device_configs = client.get_list("/deviceManagement/deviceConfigurations", max_pages=30)
    except GraphError as exc:
        device_configs = []
        errors["device_configurations"] = str(exc)

    atp: dict[str, Any] | None = None
    try:
        atp = collect_intune_atp_onboarding_state(client)
    except GraphError as exc:
        errors["atp_onboarding_state"] = str(exc)

    antivirus_policy_entries, antivirus_truncated, antivirus_error = _collect_antivirus_policies(
        client,
        config,
        max_policy_detail,
        config_truncated=config_truncated,
        config_error=errors["configuration_policies"],
    )
    if antivirus_error:
        errors["antivirus_policies"] = antivirus_error

    asr_policy_entries, asr_error = _collect_asr_policies(
        client,
        config,
        max_policy_detail,
        config_error=errors["configuration_policies"],
    )
    if asr_error:
        errors["asr_policies"] = asr_error

    state_summary: dict[str, Any] | None = None
    try:
        data = client.get("/deviceManagement/deviceCompliancePolicyDeviceStateSummary")
        state_summary = data if isinstance(data, dict) else None
    except GraphError as exc:
        errors["compliance_state_summary"] = str(exc)

    try:
        app_protections = client.get_list(
            "/deviceAppManagement/managedAppProtections", max_pages=30
        )
    except GraphError as exc:
        app_protections = []
        errors["app_protection_policies"] = str(exc)

    tamper_state = _collect_tamper_device_state(client, devices)

    enriched = [
        _enrich_compliance_policy(client, policy) for policy in compliance[:max_policy_detail]
    ]
    enriched_configs = [
        _enrich_device_configuration(client, cfg) for cfg in device_configs[:max_policy_detail]
    ]
    enriched_app_protections = [
        _enrich_app_protection(client, policy) for policy in app_protections[:max_policy_detail]
    ]
    truncated = (
        len(compliance) > max_policy_detail
        or devices_truncated
        or config_truncated
        or antivirus_truncated
    )
    return _bundle(
        devices,
        enriched,
        config,
        antivirus_policy_entries,
        atp,
        enriched_configs,
        asr_policy_entries,
        state_summary,
        enriched_app_protections,
        tamper_state,
        licensed_units,
        truncated,
        errors,
        antivirus_policies_truncated=antivirus_truncated,
        configuration_policies_truncated=config_truncated,
        managed_devices_truncated=devices_truncated,
    )


def _bundle(
    devices: list[dict[str, Any]],
    compliance: list[dict[str, Any]],
    config: list[dict[str, Any]],
    antivirus_policies: list[dict[str, Any]],
    atp: dict[str, Any] | None,
    device_configs: list[dict[str, Any]],
    asr_policies: list[dict[str, Any]],
    state_summary: dict[str, Any] | None,
    app_protections: list[dict[str, Any]],
    tamper_state: dict[str, Any],
    licensed_units: int | None,
    truncated: bool,
    errors: dict[str, str],
    *,
    antivirus_policies_truncated: bool = False,
    configuration_policies_truncated: bool = False,
    managed_devices_truncated: bool = False,
) -> dict[str, Any]:
    return {
        "managed_devices": devices,
        "compliance_policies": compliance,
        "configuration_policies": config,
        "antivirus_policies": antivirus_policies,
        "atp_onboarding_state": atp,
        "device_configurations": device_configs,
        "asr_policies": asr_policies,
        "compliance_state_summary": state_summary,
        "app_protection_policies": app_protections,
        "tamper_device_state": tamper_state,
        "licensed_units": licensed_units,
        "truncated": truncated,
        "antivirus_policies_truncated": antivirus_policies_truncated,
        "configuration_policies_truncated": configuration_policies_truncated,
        "managed_devices_truncated": managed_devices_truncated,
        "errors": errors,
    }


def _enrich_compliance_policy(client: GraphClient, policy: dict[str, Any]) -> dict[str, Any]:
    pid = str(policy.get("id") or "")
    entry: dict[str, Any] = {
        "id": pid,
        "displayName": str(policy.get("displayName") or pid),
        "platforms": str(policy.get("platforms") or ""),
        "assigned": False,
        "assignments": [],
        "assignments_error": False,
        "has_noncompliance_action": False,
        "noncompliance_actions": [],
        "noncompliance_actions_error": False,
    }
    if not pid:
        return entry
    entry["assignments"] = _safe_list(
        client, f"/deviceManagement/deviceCompliancePolicies/{pid}/assignments"
    )
    entry["assignments_error"] = entry["assignments"] is None
    entry["assignments"] = entry["assignments"] or []
    entry["assigned"] = bool(entry["assignments"])

    entry["noncompliance_actions"] = _safe_list(
        client, f"/deviceManagement/deviceCompliancePolicies/{pid}/scheduledActionsForRule"
    )
    entry["noncompliance_actions_error"] = entry["noncompliance_actions"] is None
    entry["noncompliance_actions"] = entry["noncompliance_actions"] or []
    entry["has_noncompliance_action"] = bool(entry["noncompliance_actions"])
    return entry


def _get_list_with_truncation(
    client: GraphClient,
    path: str,
    *,
    max_pages: int = 30,
) -> tuple[list[dict[str, Any]], bool]:
    """Read a paged Graph collection and return ``(items, truncated)``."""
    if hasattr(client, "get_list_result"):
        result = client.get_list_result(path, max_pages=max_pages)
        return list(result.items), bool(result.truncated)
    return client.get_list(path, max_pages=max_pages), False


def _safe_list_with_truncation(
    client: GraphClient,
    path: str,
    *,
    max_pages: int = 5,
) -> tuple[list[dict[str, Any]] | None, bool]:
    """Return ``(items, truncated)``, or ``(None, False)`` when the read failed."""
    try:
        return _get_list_with_truncation(client, path, max_pages=max_pages)
    except GraphError:
        return None, False


def _safe_list(client: GraphClient, path: str) -> list[dict[str, Any]] | None:
    """Return the list, or ``None`` when the read failed (unreadable detail)."""
    items, _ = _safe_list_with_truncation(client, path, max_pages=5)
    return items


_EMPTY_TAMPER_STATE: dict[str, Any] = {
    "sampled": 0,
    "enabled": 0,
    "disabled": 0,
    "unknown": 0,
    "unreadable": 0,
}


def _configuration_policies_by_family(
    config: list[dict[str, Any]],
    family_token: str,
) -> list[dict[str, Any]]:
    """Filter settings-catalog ``configurationPolicies`` by templateFamily token."""
    token = family_token.lower()
    out: list[dict[str, Any]] = []
    for policy in config:
        ref = policy.get("templateReference") or {}
        family = str(ref.get("templateFamily") or "") if isinstance(ref, dict) else ""
        if token in family.lower():
            out.append(policy)
    return out


def _read_configuration_policy_assignment(
    client: GraphClient,
    policy: dict[str, Any],
) -> tuple[bool, list[dict[str, Any]], bool]:
    """Resolve assignment state for a settings-catalog configuration policy."""
    pid = str(policy.get("id") or "")
    if "isAssigned" in policy:
        return bool(policy.get("isAssigned")), [], False
    if not pid:
        return False, [], False
    assignments = _safe_list(client, f"/deviceManagement/configurationPolicies/{pid}/assignments")
    if assignments is None:
        return False, [], True
    return bool(assignments), assignments, False


def _read_configuration_policy_settings(
    client: GraphClient,
    pid: str,
    *,
    truncated_flag: list[bool] | None = None,
) -> list[dict[str, Any]] | None:
    """Read settings entries for one settings-catalog configuration policy."""
    if not pid:
        return []
    items, is_truncated = _safe_list_with_truncation(
        client, f"/deviceManagement/configurationPolicies/{pid}/settings"
    )
    if truncated_flag is not None and is_truncated:
        truncated_flag.append(True)
    return items


def _collect_antivirus_policies(
    client: GraphClient,
    config: list[dict[str, Any]],
    max_policy_detail: int,
    *,
    config_truncated: bool = False,
    config_error: str = "",
) -> tuple[list[dict[str, Any]], bool, str]:
    """Enrich settings-catalog ``endpointSecurityAntivirus`` policies with
    Defender local AI agent runtime protection settings (Graph beta)."""
    if config_error:
        return [], False, config_error
    candidates = _configuration_policies_by_family(config, _ANTIVIRUS_FAMILY_TOKEN)
    entries = [
        _enrich_configuration_antivirus_policy(client, policy)
        for policy in candidates[:max_policy_detail]
    ]
    truncated = (
        config_truncated
        or len(candidates) > max_policy_detail
        or any(bool(entry.get("settings_truncated")) for entry in entries)
    )
    return entries, truncated, ""


def _enrich_configuration_antivirus_policy(
    client: GraphClient,
    policy: dict[str, Any],
) -> dict[str, Any]:
    pid = str(policy.get("id") or "")
    assigned, assignments, assignments_error = _read_configuration_policy_assignment(client, policy)
    entry: dict[str, Any] = {
        "id": pid,
        "displayName": str(policy.get("name") or policy.get("displayName") or pid),
        "source": "configurationPolicies",
        "api_version": "beta",
        "isAssigned": assigned,
        "assigned": assigned,
        "assignments": assignments,
        "assignments_error": assignments_error,
        "ai_agent_protection": None,
        "ai_agent_network_inspection": None,
        "ai_agent_protection_mode": None,
        "ai_agent_network_inspection_mode": None,
        "matched_setting_definition_ids": [],
        "settings_error": False,
        "settings_truncated": False,
    }
    if not pid:
        return entry
    truncated_flag: list[bool] = []
    settings = _read_configuration_policy_settings(client, pid, truncated_flag=truncated_flag)
    if settings is None:
        entry["settings_error"] = True
        return entry
    entry["settings_truncated"] = bool(truncated_flag)
    entry.update(_extract_ai_agent_runtime_settings(settings))
    return entry


def _extract_ai_agent_runtime_settings(settings: list[dict[str, Any]]) -> dict[str, Any]:
    """Extract Defender CSP AiAgentProtection & AiAgentNetworkInspection modes.

    Values follow the documented Defender CSP / Set-MpPreference enum:
    ``0=Disabled``, ``1=Block``, ``2=Audit``.
    """
    protection: int | None = None
    network_inspection: int | None = None
    matched_defs: set[str] = set()

    for node in _iter_setting_instances(settings):
        raw_def = str(node.get("settingDefinitionId") or "").strip()
        if not raw_def:
            continue
        lowered_def = raw_def.lower()
        if _matches_setting_key(lowered_def, _AI_AGENT_PROTECTION_KEY):
            matched_defs.add(raw_def)
            parsed = _extract_ai_agent_mode_from_node(node)
            if parsed is not None:
                protection = _merge_mode(protection, parsed)
        elif _matches_setting_key(lowered_def, _AI_AGENT_NETWORK_INSPECTION_KEY):
            matched_defs.add(raw_def)
            parsed = _extract_ai_agent_mode_from_node(node)
            if parsed is not None:
                network_inspection = _merge_mode(network_inspection, parsed)

    return {
        "ai_agent_protection": protection,
        "ai_agent_network_inspection": network_inspection,
        "ai_agent_protection_mode": _AI_AGENT_MODE_LABELS.get(protection)
        if protection is not None
        else None,
        "ai_agent_network_inspection_mode": _AI_AGENT_MODE_LABELS.get(network_inspection)
        if network_inspection is not None
        else None,
        "matched_setting_definition_ids": sorted(matched_defs),
    }


def _matches_setting_key(definition_id: str, key: str) -> bool:
    return (
        definition_id == key
        or definition_id.endswith(f"_{key}")
        or definition_id.endswith(f"/{key}")
    )


def _extract_ai_agent_mode_from_node(node: dict[str, Any]) -> int | None:
    choice = node.get("choiceSettingValue")
    if isinstance(choice, dict):
        parsed = _parse_ai_agent_mode_value(choice.get("value"))
        if parsed is not None:
            return parsed
    simple = node.get("simpleSettingValue")
    if isinstance(simple, dict):
        parsed = _parse_ai_agent_mode_value(simple.get("value"))
        if parsed is not None:
            return parsed
    if "value" in node:
        return _parse_ai_agent_mode_value(node.get("value"))
    return None


def _parse_ai_agent_mode_value(raw: Any) -> int | None:
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw if raw in _AI_AGENT_MODE_LABELS else None
    if isinstance(raw, str):
        text = raw.strip().lower()
        if text in {"0", "disabled"} or text.endswith("_0") or text.endswith("_disabled"):
            return 0
        if text in {"1", "block"} or text.endswith("_1") or text.endswith("_block"):
            return 1
        if text in {"2", "audit"} or text.endswith("_2") or text.endswith("_audit"):
            return 2
    return None


def _merge_mode(existing: int | None, incoming: int) -> int:
    if existing is None:
        return incoming
    # Prefer Block (1) > Audit (2) > Disabled (0) if duplicate instances exist.
    order = {1: 2, 2: 1, 0: 0}
    return incoming if order.get(incoming, -1) > order.get(existing, -1) else existing


def _collect_asr_policies(
    client: GraphClient,
    config: list[dict[str, Any]],
    max_policy_detail: int,
    *,
    config_error: str = "",
) -> tuple[list[dict[str, Any]], str]:
    """Collect ASR policies from settings-catalog ``configurationPolicies`` first,
    falling back to legacy preview ``endpointSecurity/attackSurfaceReductionPolicies``
    only when no settings-catalog ASR policies are present."""
    asr_candidates = _configuration_policies_by_family(config, "attacksurfacereduction")
    if asr_candidates:
        return (
            [
                _enrich_configuration_asr_policy(client, policy)
                for policy in asr_candidates[:max_policy_detail]
            ],
            "",
        )

    asr_raw: list[dict[str, Any]] | None = None
    read_error = ""
    try:
        asr_raw = client.get_list(
            "/deviceManagement/endpointSecurity/attackSurfaceReductionPolicies", max_pages=30
        )
    except GraphError as exc:
        asr_raw = None
        read_error = str(exc)

    if asr_raw:
        return (
            [
                _enrich_endpoint_security_asr_policy(client, policy)
                for policy in asr_raw[:max_policy_detail]
            ],
            "",
        )

    if config_error:
        detail = f"; legacy fallback: {read_error}" if read_error else ""
        return [], f"ASR policy surfaces unreadable: {config_error}{detail}"
    return [], ""


def _enrich_endpoint_security_asr_policy(
    client: GraphClient, policy: dict[str, Any]
) -> dict[str, Any]:
    pid = str(policy.get("id") or "")
    entry: dict[str, Any] = {
        "id": pid,
        "displayName": str(policy.get("displayName") or pid),
        "source": "endpointSecurity",
        "legacy_fallback": True,
        "assigned": False,
        "assignments": [],
        "assignments_error": False,
        "rule_count": 0,
        "rules_error": False,
    }
    if not pid:
        return entry
    base = f"/deviceManagement/endpointSecurity/attackSurfaceReductionPolicies/{pid}"
    entry["assignments"] = _safe_list(client, f"{base}/assignments")
    entry["assignments_error"] = entry["assignments"] is None
    entry["assignments"] = entry["assignments"] or []
    entry["assigned"] = bool(entry["assignments"])

    settings = policy.get("settings") if isinstance(policy.get("settings"), list) else None
    if settings is None:
        settings = _safe_list(client, f"{base}/settings")
    if settings is None:
        entry["rules_error"] = True
    else:
        entry["rule_count"] = _count_asr_rules(settings)
    return entry


def _enrich_configuration_asr_policy(client: GraphClient, policy: dict[str, Any]) -> dict[str, Any]:
    pid = str(policy.get("id") or "")
    assigned, assignments, assignments_error = _read_configuration_policy_assignment(client, policy)
    entry: dict[str, Any] = {
        "id": pid,
        "displayName": str(policy.get("name") or pid),
        "source": "configurationPolicies",
        "assigned": assigned,
        "assignments": assignments,
        "assignments_error": assignments_error,
        "rule_count": 0,
        "rules_error": False,
    }
    if not pid:
        return entry
    settings = _read_configuration_policy_settings(client, pid)
    if settings is None:
        entry["rules_error"] = True
    else:
        entry["rule_count"] = _count_asr_rules(settings)
    return entry


def _iter_setting_instances(settings: list[dict[str, Any]]):
    """Yield every setting instance dict (top-level and nested children)."""
    for setting in settings:
        if not isinstance(setting, dict):
            continue
        instance = setting.get("settingInstance")
        for candidate in (instance, setting):
            if isinstance(candidate, dict):
                yield candidate
                yield from _iter_setting_children(candidate)


def _count_asr_rules(settings: list[dict[str, Any]]) -> int:
    """Count distinct ASR rule setting definitions inside a policy's settings."""
    seen: set[str] = set()
    for node in _iter_setting_instances(settings):
        definition_id = str(node.get("settingDefinitionId") or "").lower()
        if _is_asr_rule_definition(definition_id):
            seen.add(definition_id)
    return len(seen)


def _is_asr_rule_definition(definition_id: str) -> bool:
    marker = definition_id.find(_ASR_RULE_KEY)
    return marker >= 0 and len(definition_id) > marker + len(_ASR_RULE_KEY)


def _iter_setting_children(instance: Any):
    stack = [instance]
    while stack:
        node = stack.pop()
        if not isinstance(node, dict):
            continue
        for container in ("groupSettingCollectionValue", "children"):
            children = node.get(container)
            if isinstance(children, list):
                for child in children:
                    if isinstance(child, dict):
                        yield child
                        stack.append(child)
        choice_val = node.get("choiceSettingValue")
        if isinstance(choice_val, dict):
            choice_children = choice_val.get("children")
            if isinstance(choice_children, list):
                for child in choice_children:
                    if isinstance(child, dict):
                        yield child
                        stack.append(child)


def _enrich_device_configuration(client: GraphClient, cfg: dict[str, Any]) -> dict[str, Any]:
    cid = str(cfg.get("id") or "")
    entry: dict[str, Any] = {
        "id": cid,
        "displayName": str(cfg.get("displayName") or cid),
        "odata_type": str(cfg.get("@odata.type") or ""),
        "bitLockerEncryptDevice": cfg.get("bitLockerEncryptDevice"),
        "assigned": False,
        "assignments": [],
        "assignments_error": False,
    }
    if not cid:
        return entry
    entry["assignments"] = _safe_list(
        client, f"/deviceManagement/deviceConfigurations/{cid}/assignments"
    )
    entry["assignments_error"] = entry["assignments"] is None
    entry["assignments"] = entry["assignments"] or []
    entry["assigned"] = bool(entry["assignments"])
    return entry


def _enrich_app_protection(client: GraphClient, policy: dict[str, Any]) -> dict[str, Any]:
    pid = str(policy.get("id") or "")
    odata = str(policy.get("@odata.type") or "")
    entry: dict[str, Any] = {
        "id": pid,
        "displayName": str(policy.get("displayName") or pid),
        "odata_type": odata,
        "assignment_mode": "targeted",
        "assigned": False,
        "assignments": [],
        "assignments_error": False,
    }
    lowered = odata.lower()
    if "defaultmanagedappprotection" in lowered:
        # Default policies apply org-wide; there is no assignment list.
        entry["assignment_mode"] = "default"
        entry["assigned"] = True
        return entry
    base = ""
    if "androidmanagedappprotection" in lowered:
        base = "androidManagedAppProtections"
    elif "iosmanagedappprotection" in lowered:
        base = "iosManagedAppProtections"
    if not base:
        entry["assignment_mode"] = "unknown"
        return entry
    if not pid:
        return entry
    entry["assignments"] = _safe_list(client, f"/deviceAppManagement/{base}/{pid}/assignments")
    entry["assignments_error"] = entry["assignments"] is None
    entry["assignments"] = entry["assignments"] or []
    entry["assigned"] = bool(entry["assignments"])
    return entry


def _collect_tamper_device_state(
    client: GraphClient, devices: list[dict[str, Any]]
) -> dict[str, Any]:
    """Aggregate tamperProtectionEnabled from a bounded sample of Windows devices."""
    state: dict[str, Any] = dict(_EMPTY_TAMPER_STATE)
    windows = [
        device
        for device in devices
        if "windows" in str(device.get("operatingSystem") or "").lower()
    ]
    for device in windows[:_MAX_TAMPER_DEVICES]:
        did = str(device.get("id") or "")
        if not did:
            continue
        state["sampled"] += 1
        try:
            data = client.get(f"/deviceManagement/managedDevices/{did}/windowsProtectionState")
        except GraphError:
            state["unreadable"] += 1
            state["unknown"] += 1
            continue
        flag = data.get("tamperProtectionEnabled") if isinstance(data, dict) else None
        if flag is True:
            state["enabled"] += 1
        elif flag is False:
            state["disabled"] += 1
        else:
            state["unknown"] += 1
    return state


DEMO_INTUNE_EVIDENCE_BUNDLE: dict[str, Any] = {
    "managed_devices": [
        {
            "id": "dev-1",
            "deviceName": "LAPTOP-1",
            "complianceState": "compliant",
            "operatingSystem": "Windows",
        },
        {
            "id": "dev-2",
            "deviceName": "PHONE-1",
            "complianceState": "compliant",
            "operatingSystem": "iOS",
        },
    ],
    "compliance_policies": [
        {
            "id": "comp-1",
            "displayName": "Windows compliance baseline",
            "platforms": "windows10",
            "assigned": True,
            "assignments": [{"id": "a1", "target": {"groupId": "g-all"}}],
            "assignments_error": False,
            "has_noncompliance_action": True,
            "noncompliance_actions": [{"id": "sar1"}],
            "noncompliance_actions_error": False,
        },
        {
            "id": "comp-2",
            "displayName": "iOS compliance",
            "platforms": "ios",
            "assigned": True,
            "assignments": [{"id": "a2", "target": {"groupId": "g-all"}}],
            "assignments_error": False,
            "has_noncompliance_action": True,
            "noncompliance_actions": [{"id": "sar2"}],
            "noncompliance_actions_error": False,
        },
    ],
    "configuration_policies": [
        {
            "id": "ep-av",
            "name": "Endpoint security - Antivirus",
            "templateReference": {"templateFamily": "endpointSecurityAntivirus"},
        },
        {
            "id": "ep-fw",
            "name": "Endpoint security - Firewall",
            "templateReference": {"templateFamily": "endpointSecurityFirewall"},
        },
        {
            "id": "ep-de",
            "name": "Endpoint security - Disk encryption",
            "templateReference": {"templateFamily": "endpointSecurityDiskEncryption"},
        },
        {
            "id": "ep-asr",
            "name": "Endpoint security - ASR",
            "templateReference": {"templateFamily": "endpointSecurityAttackSurfaceReduction"},
        },
        {
            "id": "ep-bl",
            "name": "Endpoint security - Security baseline",
            "templateReference": {"templateFamily": "endpointSecuritySecurityBaselines"},
        },
    ],
    "antivirus_policies": [
        {
            "id": "ep-av",
            "displayName": "Endpoint security - Antivirus",
            "source": "configurationPolicies",
            "api_version": "beta",
            "isAssigned": True,
            "assigned": True,
            "assignments": [{"id": "ava1", "target": {"groupId": "g-all"}}],
            "assignments_error": False,
            "ai_agent_protection": None,
            "ai_agent_network_inspection": None,
            "ai_agent_protection_mode": None,
            "ai_agent_network_inspection_mode": None,
            "matched_setting_definition_ids": [],
            "settings_error": False,
            "settings_truncated": False,
        }
    ],
    "atp_onboarding_state": {
        "onboardedDeviceCount": 2,
        "unknownDeviceCount": 0,
        "unhealthyDeviceCount": 0,
    },
    "device_configurations": [
        {
            "id": "cfg-bl",
            "displayName": "BitLocker encryption",
            "odata_type": "#microsoft.graph.windows10EndpointProtectionConfiguration",
            "bitLockerEncryptDevice": True,
            "assigned": True,
            "assignments": [{"id": "ba1", "target": {"groupId": "g-all"}}],
            "assignments_error": False,
        },
        {
            "id": "cfg-atp",
            "displayName": "Defender ATP config",
            "odata_type": "#microsoft.graph.windowsDefenderAdvancedThreatProtectionConfiguration",
            "bitLockerEncryptDevice": None,
            "assigned": True,
            "assignments": [{"id": "ba2", "target": {"groupId": "g-all"}}],
            "assignments_error": False,
        },
    ],
    "asr_policies": [
        {
            "id": "asr-1",
            "displayName": "Endpoint security - ASR rules",
            "source": "configurationPolicies",
            "assigned": True,
            "assignments": [{"id": "aa1", "target": {"groupId": "g-all"}}],
            "assignments_error": False,
            "rule_count": 3,
            "rules_error": False,
        }
    ],
    "compliance_state_summary": {
        "id": "state-summary",
        "compliantDeviceCount": 90,
        "nonCompliantDeviceCount": 0,
        "unknownDeviceCount": 0,
        "errorDeviceCount": 0,
        "conflictDeviceCount": 0,
        "inGracePeriodCount": 0,
        "notApplicableDeviceCount": 8,
    },
    "app_protection_policies": [
        {
            "id": "mam-ios",
            "displayName": "iOS app protection",
            "odata_type": "#microsoft.graph.iosManagedAppProtection",
            "assignment_mode": "targeted",
            "assigned": True,
            "assignments": [{"id": "ma1", "target": {"groupId": "g-all"}}],
            "assignments_error": False,
        },
        {
            "id": "mam-android",
            "displayName": "Android app protection",
            "odata_type": "#microsoft.graph.androidManagedAppProtection",
            "assignment_mode": "targeted",
            "assigned": True,
            "assignments": [{"id": "ma2", "target": {"groupId": "g-all"}}],
            "assignments_error": False,
        },
    ],
    "tamper_device_state": {
        "sampled": 2,
        "enabled": 2,
        "disabled": 0,
        "unknown": 0,
        "unreadable": 0,
    },
    "licensed_units": 100,
    "truncated": False,
    "antivirus_policies_truncated": False,
    "configuration_policies_truncated": False,
    "managed_devices_truncated": False,
    "errors": {
        "managed_devices": "",
        "compliance_policies": "",
        "configuration_policies": "",
        "antivirus_policies": "",
        "atp_onboarding_state": "",
        "device_configurations": "",
        "asr_policies": "",
        "compliance_state_summary": "",
        "app_protection_policies": "",
        "tamper_device_state": "",
    },
}
