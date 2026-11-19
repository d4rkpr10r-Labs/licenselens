"""Tests for Defender for Endpoint P2 local AI agent runtime protection (PR 3)."""

from __future__ import annotations

import copy
from typing import Any

from licenselens.auth import AuthContext, AuthMode
from licenselens.collectors.contracts import CloudEnvironment, EvidenceHealth
from licenselens.collectors.intune_policy import (
    DEMO_INTUNE_EVIDENCE_BUNDLE,
    collect_intune_evidence_bundle,
)
from licenselens.collectors.runtime_collect_endpoint import collect_intune_bundle_runtime
from licenselens.engine.collection_context import ScanCollectionContext
from licenselens.engine.loader import load_checks
from licenselens.engine.planner import CollectionContext
from licenselens.engine.registry import default_registry
from licenselens.engine.runner import run_scan
from licenselens.engine.runner_findings import from_evaluation, not_licensed_finding
from licenselens.evaluators.endpoint_intune_policy import (
    evaluate_endpoint_mde_ai_agent_runtime_protection,
)
from licenselens.models import CheckDefinition, CheckTier, Confidence, FindingStatus, Workload
from licenselens.schema_contracts import EvaluationMode
from tests.fake_clients import FakeGraphClient, error, ok, paginated

CHECK_ID = "endpoint-mde-ai-agent-runtime-protection"


def _check() -> CheckDefinition:
    return next(c for c in load_checks() if c.id == CHECK_ID)


def _base_bundle(**overrides: Any) -> dict[str, Any]:
    bundle = copy.deepcopy(DEMO_INTUNE_EVIDENCE_BUNDLE)
    bundle.update(overrides)
    return bundle


def _seed_minimal_intune(
    fake: FakeGraphClient,
    *,
    config_policies: list[dict[str, Any]] | None = None,
    managed_devices: list[dict[str, Any]] | None = None,
) -> None:
    fake.register_list(
        "/deviceManagement/managedDevices",
        ok(
            {
                "value": managed_devices
                if managed_devices is not None
                else [{"id": "d1", "operatingSystem": "Windows"}]
            }
        ),
    )
    fake.register_list("/deviceManagement/deviceCompliancePolicies", ok({"value": []}))
    fake.register_list(
        "/deviceManagement/configurationPolicies",
        ok({"value": config_policies if config_policies is not None else []}),
    )
    fake.register_list("/deviceManagement/deviceConfigurations", ok({"value": []}))
    fake.register_get(
        "/deviceManagement/advancedThreatProtectionOnboardingStateSummary",
        ok({"onboardedDeviceCount": 1}),
    )
    fake.register_list(
        "/deviceManagement/endpointSecurity/attackSurfaceReductionPolicies",
        error(404, "legacy ASR unavailable"),
    )
    fake.register_get(
        "/deviceManagement/deviceCompliancePolicyDeviceStateSummary",
        ok({"compliantDeviceCount": 1}),
    )
    fake.register_list("/deviceAppManagement/managedAppProtections", ok({"value": []}))
    fake.register_get(
        "/deviceManagement/managedDevices/d1/windowsProtectionState",
        ok({"tamperProtectionEnabled": True}),
    )


# ---------------------------------------------------------------------------
# Collector tests
# ---------------------------------------------------------------------------


def test_collector_extracts_choice_and_simple_ai_agent_settings() -> None:
    fake = FakeGraphClient()
    _seed_minimal_intune(
        fake,
        config_policies=[
            {
                "id": "av-1",
                "name": "Defender AI Agent Protection",
                "isAssigned": True,
                "templateReference": {"templateFamily": "endpointSecurityAntivirus"},
            },
            {
                "id": "fw-1",
                "name": "Firewall",
                "isAssigned": True,
                "templateReference": {"templateFamily": "endpointSecurityFirewall"},
            },
        ],
    )
    fake.register_list(
        "/deviceManagement/configurationPolicies/av-1/settings",
        ok(
            {
                "value": [
                    {
                        "settingInstance": {
                            "@odata.type": (
                                "#microsoft.graph."
                                "deviceManagementConfigurationChoiceSettingInstance"
                            ),
                            "settingDefinitionId": (
                                "device_vendor_msft_defender_configuration_aiagentprotection"
                            ),
                            "choiceSettingValue": {
                                "value": (
                                    "device_vendor_msft_defender_configuration_aiagentprotection_1"
                                ),
                                "children": [
                                    {
                                        "@odata.type": (
                                            "#microsoft.graph."
                                            "deviceManagementConfigurationSimpleSettingInstance"
                                        ),
                                        "settingDefinitionId": (
                                            "device_vendor_msft_defender_configuration_"
                                            "aiagentnetworkinspection"
                                        ),
                                        "simpleSettingValue": {"value": 2},
                                    }
                                ],
                            },
                        }
                    }
                ]
            }
        ),
    )

    bundle = collect_intune_evidence_bundle(fake)
    assert bundle["errors"]["antivirus_policies"] == ""
    assert bundle["antivirus_policies_truncated"] is False
    assert len(bundle["antivirus_policies"]) == 1
    av = bundle["antivirus_policies"][0]
    assert av["id"] == "av-1"
    assert av["api_version"] == "beta"
    assert av["source"] == "configurationPolicies"
    assert av["isAssigned"] is True
    assert av["assigned"] is True
    assert av["ai_agent_protection"] == 1
    assert av["ai_agent_protection_mode"] == "block"
    assert av["ai_agent_network_inspection"] == 2
    assert av["ai_agent_network_inspection_mode"] == "audit"
    assert av["settings_error"] is False
    assert av["settings_truncated"] is False
    assert len(av["matched_setting_definition_ids"]) == 2


def test_collector_handles_csp_uri_string_modes_and_ignores_booleans() -> None:
    fake = FakeGraphClient()
    _seed_minimal_intune(
        fake,
        config_policies=[
            {
                "id": "av-2",
                "name": "Defender AV",
                "templateReference": {"templateFamily": "endpointSecurityAntivirus"},
            }
        ],
    )
    fake.register_list(
        "/deviceManagement/configurationPolicies/av-2/assignments",
        ok({"value": [{"id": "asg-1"}]}),
    )
    fake.register_list(
        "/deviceManagement/configurationPolicies/av-2/settings",
        ok(
            {
                "value": [
                    {
                        "settingInstance": {
                            "settingDefinitionId": (
                                "./Device/Vendor/MSFT/Defender/Configuration/AiAgentProtection"
                            ),
                            "simpleSettingValue": {"value": True},
                        }
                    },
                    {
                        "settingInstance": {
                            "settingDefinitionId": (
                                "device_vendor_msft_defender_configuration_aiagentnetworkinspection"
                            ),
                            "choiceSettingValue": {
                                "value": (
                                    "device_vendor_msft_defender_configuration_"
                                    "aiagentnetworkinspection_block"
                                )
                            },
                        }
                    },
                ]
            }
        ),
    )

    bundle = collect_intune_evidence_bundle(fake)
    av = bundle["antivirus_policies"][0]
    assert av["isAssigned"] is True
    assert av["ai_agent_protection"] is None
    assert av["ai_agent_network_inspection"] == 1
    assert av["ai_agent_network_inspection_mode"] == "block"


def test_collector_records_settings_and_assignments_403_errors() -> None:
    fake = FakeGraphClient()
    _seed_minimal_intune(
        fake,
        config_policies=[
            {
                "id": "av-denied",
                "name": "Defender AV",
                "templateReference": {"templateFamily": "endpointSecurityAntivirus"},
            }
        ],
    )
    fake.register_list(
        "/deviceManagement/configurationPolicies/av-denied/assignments",
        error(403, "Forbidden"),
    )
    fake.register_list(
        "/deviceManagement/configurationPolicies/av-denied/settings",
        error(403, "Forbidden"),
    )

    bundle = collect_intune_evidence_bundle(fake)
    av = bundle["antivirus_policies"][0]
    assert av["assignments_error"] is True
    assert av["settings_error"] is True
    assert av["isAssigned"] is False


def test_collector_propagates_truncation_from_config_policies_and_settings() -> None:
    fake = FakeGraphClient()
    _seed_minimal_intune(fake)
    # Exceed max_pages=30 for configurationPolicies
    pages = [
        [
            {
                "id": f"av-{i}",
                "name": f"AV {i}",
                "isAssigned": True,
                "templateReference": {"templateFamily": "endpointSecurityAntivirus"},
            }
        ]
        for i in range(32)
    ]
    fake.register_list("/deviceManagement/configurationPolicies", paginated(*pages))
    for i in range(15):
        fake.register_list(
            f"/deviceManagement/configurationPolicies/av-{i}/settings",
            ok({"value": []}),
        )

    bundle = collect_intune_evidence_bundle(fake, max_policy_detail=2)
    assert bundle["configuration_policies_truncated"] is True
    assert bundle["antivirus_policies_truncated"] is True
    assert bundle["truncated"] is True
    assert len(bundle["antivirus_policies"]) == 2

    ctx = ScanCollectionContext(
        scan_mode="live",
        auth=AuthContext(
            mode=AuthMode.CLIENT_SECRET,
            tenant_id="00000000-0000-0000-0000-000000000000",
        ),
        client=fake,  # type: ignore[arg-type]
        skus=[],
        warnings=[],
    )
    env = collect_intune_bundle_runtime(ctx, CollectionContext(envelopes={}))
    assert env.health is EvidenceHealth.TRUNCATED
    assert env.metadata.pagination.truncated is True


def test_collector_propagates_settings_page_truncation() -> None:
    fake = FakeGraphClient()
    _seed_minimal_intune(
        fake,
        config_policies=[
            {
                "id": "av-big",
                "name": "Big AV policy",
                "isAssigned": True,
                "templateReference": {"templateFamily": "endpointSecurityAntivirus"},
            }
        ],
    )
    fake.register_list(
        "/deviceManagement/configurationPolicies/av-big/settings",
        paginated(*[[{"id": f"s{i}", "settingInstance": {}}] for i in range(7)]),
    )

    bundle = collect_intune_evidence_bundle(fake)
    assert bundle["antivirus_policies"][0]["settings_truncated"] is True
    assert bundle["antivirus_policies_truncated"] is True
    assert bundle["truncated"] is True


def test_collector_china_cloud_marks_antivirus_policies_error() -> None:
    fake = FakeGraphClient(cloud=CloudEnvironment.CHINA)
    bundle = collect_intune_evidence_bundle(fake)
    assert bundle["errors"]["antivirus_policies"] != ""
    assert bundle["antivirus_policies"] == []


# ---------------------------------------------------------------------------
# Evaluator tests
# ---------------------------------------------------------------------------


def test_evaluator_ok_when_assigned_block_on_native_or_network() -> None:
    check = _check()
    for field, expected_mode in (
        ("ai_agent_protection", "AiAgentProtection"),
        ("ai_agent_network_inspection", "AiAgentNetworkInspection"),
    ):
        bundle = _base_bundle(
            antivirus_policies=[
                {
                    "id": "av-1",
                    "displayName": "Defender AI Agent",
                    "isAssigned": True,
                    "assigned": True,
                    "ai_agent_protection": 1 if field == "ai_agent_protection" else 0,
                    "ai_agent_network_inspection": (
                        1 if field == "ai_agent_network_inspection" else 0
                    ),
                    "settings_error": False,
                    "assignments_error": False,
                    "settings_truncated": False,
                }
            ]
        )
        res = evaluate_endpoint_mde_ai_agent_runtime_protection(check, {"intune_bundle": bundle})
        assert res.status is FindingStatus.OK
        assert res.confidence is Confidence.HIGH
        assert res.evidence["api_version"] == "beta"
        assert res.evidence["block_modes"] == [expected_mode]
        # Advisory limitations must NOT trigger quality-policy demotion on OK.
        finding = from_evaluation(check, {"defender_endpoint_p2"}, res)
        assert finding.status is FindingStatus.OK
        assert finding.confidence is Confidence.HIGH


def test_evaluator_partial_on_audit_only() -> None:
    check = _check()
    bundle = _base_bundle(
        antivirus_policies=[
            {
                "id": "av-audit",
                "displayName": "Defender AI Agent Audit",
                "isAssigned": True,
                "assigned": True,
                "ai_agent_protection": 2,
                "ai_agent_network_inspection": 0,
                "settings_error": False,
                "assignments_error": False,
                "settings_truncated": False,
            }
        ]
    )
    res = evaluate_endpoint_mde_ai_agent_runtime_protection(check, {"intune_bundle": bundle})
    assert res.status is FindingStatus.PARTIAL
    assert res.confidence is Confidence.MEDIUM
    assert res.evidence["assigned_audit_policy_count"] == 1
    assert res.evidence["audit_modes"] == ["AiAgentProtection"]


def test_evaluator_partial_on_unassigned_block_or_audit_policy() -> None:
    check = _check()
    for mode in (1, 2):
        bundle = _base_bundle(
            antivirus_policies=[
                {
                    "id": "av-unassigned",
                    "displayName": "Draft AI Agent",
                    "isAssigned": False,
                    "assigned": False,
                    "ai_agent_protection": mode,
                    "ai_agent_network_inspection": None,
                    "settings_error": False,
                    "assignments_error": False,
                    "settings_truncated": False,
                }
            ]
        )
        res = evaluate_endpoint_mde_ai_agent_runtime_protection(check, {"intune_bundle": bundle})
        assert res.status is FindingStatus.PARTIAL
        assert res.evidence["unassigned_enabled_policy_count"] == 1


def test_evaluator_partial_when_no_managed_windows_devices() -> None:
    check = _check()
    bundle = _base_bundle(
        managed_devices=[{"id": "dev-ios", "operatingSystem": "iOS"}],
        antivirus_policies=[],
    )
    res = evaluate_endpoint_mde_ai_agent_runtime_protection(check, {"intune_bundle": bundle})
    assert res.status is FindingStatus.PARTIAL
    assert res.evidence["managed_windows_device_count"] == 0


def test_evaluator_partial_when_read_truncated() -> None:
    check = _check()
    # Truncated with no enabled policy -> PARTIAL (never false GAP).
    bundle_empty = _base_bundle(
        antivirus_policies=[],
        antivirus_policies_truncated=True,
        truncated=True,
    )
    res_empty = evaluate_endpoint_mde_ai_agent_runtime_protection(
        check, {"intune_bundle": bundle_empty}
    )
    assert res_empty.status is FindingStatus.PARTIAL
    assert res_empty.evidence["truncated"] is True

    # Truncated even with a Block policy -> PARTIAL (matches requirement).
    bundle_block = _base_bundle(
        antivirus_policies=[
            {
                "id": "av-1",
                "displayName": "Defender AI Agent",
                "isAssigned": True,
                "assigned": True,
                "ai_agent_protection": 1,
                "ai_agent_network_inspection": 0,
                "settings_error": False,
                "assignments_error": False,
                "settings_truncated": False,
            }
        ],
        antivirus_policies_truncated=True,
        truncated=True,
    )
    res_block = evaluate_endpoint_mde_ai_agent_runtime_protection(
        check, {"intune_bundle": bundle_block}
    )
    assert res_block.status is FindingStatus.PARTIAL
    assert res_block.evidence["truncated"] is True


def test_evaluator_gap_with_medium_confidence_and_explicit_limitations() -> None:
    check = _check()
    bundle = _base_bundle(
        antivirus_policies=[
            {
                "id": "av-disabled",
                "displayName": "Default AV",
                "isAssigned": True,
                "assigned": True,
                "ai_agent_protection": 0,
                "ai_agent_network_inspection": 0,
                "settings_error": False,
                "assignments_error": False,
                "settings_truncated": False,
            }
        ]
    )
    res = evaluate_endpoint_mde_ai_agent_runtime_protection(check, {"intune_bundle": bundle})
    assert res.status is FindingStatus.GAP
    assert res.confidence is Confidence.MEDIUM
    assert res.evidence["api_version"] == "beta"
    assert res.evidence["managed_windows_device_count"] == 1
    joined = " ".join(res.limitations)
    assert "Group Policy" in joined and "Set-MpPreference" in joined and "Defender portal" in joined
    assert "settingDefinitionId" in joined
    assert "beta" in joined.lower()


def test_evaluator_errors_on_missing_or_403_evidence() -> None:
    check = _check()

    missing = evaluate_endpoint_mde_ai_agent_runtime_protection(
        check, {"intune_bundle_error": "Graph 403 Forbidden"}
    )
    assert missing.status is FindingStatus.ERROR
    assert missing.confidence is Confidence.LOW

    cfg_err_bundle = _base_bundle()
    cfg_err_bundle["errors"]["configuration_policies"] = "Graph 403 Forbidden"
    cfg_err = evaluate_endpoint_mde_ai_agent_runtime_protection(
        check, {"intune_bundle": cfg_err_bundle}
    )
    assert cfg_err.status is FindingStatus.ERROR

    settings_err_bundle = _base_bundle(
        antivirus_policies=[
            {
                "id": "av-1",
                "displayName": "AV",
                "isAssigned": True,
                "assigned": True,
                "ai_agent_protection": None,
                "ai_agent_network_inspection": None,
                "settings_error": True,
                "assignments_error": False,
                "settings_truncated": False,
            }
        ]
    )
    settings_err = evaluate_endpoint_mde_ai_agent_runtime_protection(
        check, {"intune_bundle": settings_err_bundle}
    )
    assert settings_err.status is FindingStatus.ERROR

    devices_err_bundle = _base_bundle(antivirus_policies=[])
    devices_err_bundle["errors"]["managed_devices"] = "Graph 403 Forbidden"
    devices_err = evaluate_endpoint_mde_ai_agent_runtime_protection(
        check, {"intune_bundle": devices_err_bundle}
    )
    assert devices_err.status is FindingStatus.ERROR


def test_check_metadata_registration_entitlement_and_demo_after() -> None:
    check = _check()
    assert check.workload is Workload.ENDPOINT
    assert check.tier is CheckTier.ACTIVATION
    assert check.required_capabilities == ["defender_endpoint_p2"]

    entry = default_registry().evaluator_for(CHECK_ID)
    assert entry.evaluation_mode is EvaluationMode.DIRECT
    assert entry.dependencies == ("intune_collector",)
    assert entry.input_models == ("intune_bundle",)
    assert "DeviceManagementConfiguration.Read.All" in entry.permissions

    # Unlicensed tenant gets NOT_LICENSED, never GAP or ERROR.
    unlicensed = not_licensed_finding(check, owned=set())
    assert unlicensed.status is FindingStatus.NOT_LICENSED

    # Dry-run demo starts at GAP and --after remediates to OK.
    demo = run_scan(AuthContext(mode=AuthMode.DRY_RUN), dry_run=True)
    demo_finding = next(f for f in demo.findings if f.check_id == CHECK_ID)
    assert demo_finding.status is FindingStatus.GAP
    assert demo_finding.confidence is Confidence.MEDIUM

    after = run_scan(AuthContext(mode=AuthMode.DRY_RUN), dry_run=True, demo_scenario="after")
    after_finding = next(f for f in after.findings if f.check_id == CHECK_ID)
    assert after_finding.status is FindingStatus.OK
    assert after_finding.confidence is Confidence.HIGH
