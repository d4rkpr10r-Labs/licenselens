"""Architect Phase 2 (2026-11) Critical/High regression coverage."""

from __future__ import annotations

import copy

from licenselens.auth import REQUIRED_GRAPH_APP_PERMISSIONS
from licenselens.catalog.loader import load_capabilities, resolve_owned_capabilities
from licenselens.collectors.gsa_network_access import DEMO_GSA_NETWORK_ACCESS_BUNDLE
from licenselens.evaluators.defender_mdo import evaluate_mdo_p2_policies
from licenselens.evaluators.gsa_network_access import evaluate_gsa_internet_access_enabled
from licenselens.evaluators.sentinel_parity import evaluate_sen_rule_telemetry_parity
from licenselens.graph_ops import all_application_permissions
from licenselens.kql.table_refs import extract_table_refs
from licenselens.models import CheckDefinition, FindingStatus, ServicePlan, SubscribedSku, Workload


def test_required_graph_permissions_are_declared_in_graph_ops() -> None:
    declared = set(all_application_permissions())
    missing = sorted(set(REQUIRED_GRAPH_APP_PERMISSIONS) - declared)
    assert missing == [], f"REQUIRED_GRAPH_APP_PERMISSIONS missing from graph_ops: {missing}"


def test_insider_risk_modern_guid_unlocks_gcc_high_e5() -> None:
    caps = load_capabilities()
    owned = set(
        resolve_owned_capabilities(
            caps,
            [
                SubscribedSku(
                    sku_part_number="SPE_E5_USGOV_GCCHIGH",
                    capability_status="Enabled",
                    service_plans=[
                        ServicePlan(
                            service_plan_name="INSIDER_RISK",
                            service_plan_id="d587c7a3-bda9-4f99-8776-9bcf59c84f75",
                            provisioning_status="Success",
                        )
                    ],
                )
            ],
            cloud="gcc_high",
        )
    )
    assert "purview_insider_risk" in owned


def test_gsa_enabled_without_assignment_is_partial() -> None:
    check = CheckDefinition(
        id="id-gsa-internet-access-enabled", title="t", workload=Workload.IDENTITY
    )
    bundle = copy.deepcopy(DEMO_GSA_NETWORK_ACCESS_BUNDLE)
    bundle["forwarding_profiles"][0].pop("associations", None)
    result = evaluate_gsa_internet_access_enabled(check, {"gsa_network_access": bundle})
    assert result.status is FindingStatus.PARTIAL


def test_mdo_allow_action_is_not_ok() -> None:
    check = CheckDefinition(id="mdo-p2-policies-default", title="t", workload=Workload.DEFENDER)
    evidence = {
        "exchange_threat_usable": True,
        "exchange_threat_policies": {
            "surfaces": {
                "safe_links": {
                    "status": "ok",
                    "items": [
                        {
                            "name": "Standard Preset Security Policy",
                            "kind": "preset_standard",
                            "enabled": True,
                            "assignments": ["All"],
                            "properties": {},
                        }
                    ],
                },
                "safe_attachments": {
                    "status": "ok",
                    "items": [
                        {
                            "name": "Standard Preset Security Policy",
                            "kind": "preset_standard",
                            "enabled": True,
                            "assignments": ["All"],
                            "properties": {"Action": "Allow"},
                        }
                    ],
                },
                "preset_security": {
                    "status": "ok",
                    "items": [
                        {
                            "name": "Standard Preset Security Policy",
                            "kind": "preset_standard",
                            "enabled": True,
                            "assignments": ["All"],
                            "properties": {"State": "Enabled"},
                        }
                    ],
                },
            }
        },
    }
    assert evaluate_mdo_p2_policies(check, evidence).status is FindingStatus.PARTIAL


def test_custom_table_cl_is_classified_as_table() -> None:
    refs = extract_table_refs("CustomApp_CL | take 1", known_tables=frozenset())
    assert "CustomApp_CL" in refs.tables
    assert "CustomApp_CL" not in refs.parsers


def test_xdr_rules_do_not_create_la_dead_rules() -> None:
    check = CheckDefinition(id="sen-rule-telemetry-parity", title="t", workload=Workload.SENTINEL)
    evidence = {
        "owned_capabilities": ["defender_xdr"],
        "telemetry_expectations": {"expectations": []},
        "la_usage_by_table": {
            "mode": "query",
            "tables": {"SigninLogs": {"rows": 10, "total_mb": 1}},
        },
        "sentinel_rules": {
            "rules_detail": [
                {
                    "kind": "Scheduled",
                    "enabled": True,
                    "displayName": "signin",
                    "query": "SigninLogs | take 1",
                    "tactics": ["InitialAccess"],
                }
            ]
        },
        "xdr_custom_detections": {
            "rules": [
                {
                    "isEnabled": True,
                    "displayName": "ah",
                    "queryText": "AlertInfo | take 1",
                }
            ]
        },
    }
    result = evaluate_sen_rule_telemetry_parity(check, evidence)
    assert result.evidence["dead_rules"] == []
    assert result.evidence["indeterminate_rules"] >= 1
