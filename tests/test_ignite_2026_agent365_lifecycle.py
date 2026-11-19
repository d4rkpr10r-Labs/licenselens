"""Ignite 2026 PR 2: agent_365 capability, v1.0 agent lifecycle & lifecycle workflows."""

from __future__ import annotations

import copy
from typing import Any

import pytest

from licenselens.auth import REQUIRED_GRAPH_APP_PERMISSIONS, AuthContext, AuthMode
from licenselens.catalog.capability_meta import CatalogCloud
from licenselens.catalog.loader import load_capabilities, resolve_owned_capabilities
from licenselens.collectors.agent_lifecycle import (
    DEMO_AGENT_LIFECYCLE_POLICIES_BUNDLE,
    collect_agent_lifecycle_policies_bundle,
)
from licenselens.collectors.contracts import CloudEnvironment, EvidenceHealth
from licenselens.collectors.graph_collect import collect_graph_operation
from licenselens.collectors.lifecycle_workflows import (
    DEMO_LIFECYCLE_WORKFLOWS_BUNDLE,
    collect_lifecycle_workflows_bundle,
)
from licenselens.collectors.runtime_specs import collect_selected_evidence
from licenselens.engine.collection_context import ScanCollectionContext
from licenselens.engine.loader import load_checks
from licenselens.engine.registry import default_registry
from licenselens.engine.runner_evaluate import evaluate_check
from licenselens.evaluators.agent_lifecycle import evaluate_agent_lifecycle_policy_configured
from licenselens.evaluators.lifecycle_workflows import evaluate_lifecycle_workflows_enabled
from licenselens.graph_ops import ApiFamily, all_application_permissions, get_operation
from licenselens.models import (
    CheckDefinition,
    Confidence,
    FindingStatus,
    ServicePlan,
    SubscribedSku,
    Workload,
)
from tests.fake_clients import FakeGraphClient, error, ok, paginated


def _sku(part: str, plans: list[tuple[str, str, str | None]]) -> SubscribedSku:
    return SubscribedSku(
        sku_part_number=part,
        capability_status="Enabled",
        service_plans=[
            ServicePlan(
                service_plan_name=name,
                service_plan_id=spid,
                provisioning_status=status,
            )
            for name, status, spid in plans
        ],
    )


def _check_by_id(check_id: str) -> CheckDefinition:
    return next(c for c in load_checks() if c.id == check_id)


# -- Capability & entitlement resolution -------------------------------------


def test_agent_365_capability_metadata_and_guid_unlock() -> None:
    caps = load_capabilities()
    by_id = {c.id: c for c in caps}
    assert "agent_365" in by_id
    cap = by_id["agent_365"]
    assert cap.entitlement_kind == "add_on"
    assert cap.clouds == ["commercial"]
    assert set(cap.service_plan_ids) == {
        "d0ce5ebb-9db0-491f-b780-8973a1d815fe",
        "a9e85e05-1687-4958-8a4c-bdacda2943db",
    }
    assert set(cap.sku_part_numbers) == {"AGENT_365", "MICROSOFT_365_E7"}

    # Standalone AGENT_365 SKU unlocks agent_365
    owned_standalone = set(
        resolve_owned_capabilities(
            caps,
            [
                _sku(
                    "AGENT_365",
                    [("AGENT_365", "Success", "d0ce5ebb-9db0-491f-b780-8973a1d815fe")],
                )
            ],
        )
    )
    assert "agent_365" in owned_standalone

    # E7 SKU with ENTRA_ID_GOV_FOR_ASSISTIVE_AGENTS unlocks agent_365
    owned_e7 = set(
        resolve_owned_capabilities(
            caps,
            [
                _sku(
                    "MICROSOFT_365_E7",
                    [
                        (
                            "ENTRA_ID_GOV_FOR_ASSISTIVE_AGENTS",
                            "Success",
                            "a9e85e05-1687-4958-8a4c-bdacda2943db",
                        )
                    ],
                )
            ],
        )
    )
    assert "agent_365" in owned_e7

    # Commercial-only cloud gating excludes GCC High
    owned_gov = set(
        resolve_owned_capabilities(
            caps,
            [
                _sku(
                    "AGENT_365",
                    [("AGENT_365", "Success", "d0ce5ebb-9db0-491f-b780-8973a1d815fe")],
                )
            ],
            cloud=CatalogCloud.GCC_HIGH,
        )
    )
    assert "agent_365" not in owned_gov


def test_e5_only_tenant_gets_not_licensed_for_agent_365_and_lifecycle_workflows() -> None:
    caps = load_capabilities()
    e5_owned = set(
        resolve_owned_capabilities(
            caps,
            [
                _sku(
                    "SPE_E5",
                    [("AAD_PREMIUM_P2", "Success", "eec0eb4f-6444-4f95-aba0-50c24d67f998")],
                )
            ],
        )
    )
    assert "agent_365" not in e5_owned
    assert "entitlement_management" not in e5_owned

    agent_finding = evaluate_check(
        _check_by_id("id-agent-lifecycle-policy-configured"),
        e5_owned,
        {},
    )
    assert agent_finding.status is FindingStatus.NOT_LICENSED

    wf_finding = evaluate_check(
        _check_by_id("id-lifecycle-workflows-enabled"),
        e5_owned,
        {},
    )
    assert wf_finding.status is FindingStatus.NOT_LICENSED


# -- Graph v1.0 ops & permissions --------------------------------------------


def test_graph_v1_operations_registered_read_only_and_public_only() -> None:
    agent_op = get_operation("agent_lifecycle_policies")
    assert agent_op.path == "/identityGovernance/lifecycleWorkflows/lifecyclePolicies"
    assert agent_op.api_version == "v1.0"
    assert agent_op.preview is False
    assert agent_op.application_permissions == ("LifecyclePolicies-AgentId.Read.All",)
    assert agent_op.delegated_permissions == ("LifecyclePolicies-AgentId.Read.All",)
    assert agent_op.supported_clouds == (CloudEnvironment.PUBLIC,)

    wf_op = get_operation("lifecycle_workflows")
    assert wf_op.path == "/identityGovernance/lifecycleWorkflows/workflows"
    assert wf_op.api_version == "v1.0"
    assert wf_op.preview is False
    assert wf_op.application_permissions == ("LifecycleWorkflows.Read.All",)
    assert wf_op.delegated_permissions == ("LifecycleWorkflows.Read.All",)
    assert wf_op.supported_clouds == (CloudEnvironment.PUBLIC,)

    declared = set(all_application_permissions(family=ApiFamily.GRAPH))
    required = set(REQUIRED_GRAPH_APP_PERMISSIONS)
    assert "LifecyclePolicies-AgentId.Read.All" in required
    assert "LifecycleWorkflows.Read.All" in required
    assert required <= declared


# -- Collectors & truncation / 403 isolation ---------------------------------


def test_agent_lifecycle_collector_filters_guest_policies_and_tracks_truncation() -> None:
    fake = FakeGraphClient()
    fake.register_list(
        "/identityGovernance/lifecycleWorkflows/lifecyclePolicies",
        paginated(
            [
                {
                    "@odata.type": "#microsoft.graph.identityGovernance.guestLifecyclePolicy",
                    "id": "guest-1",
                    "displayName": "Guest cleanup",
                    "status": "enabled",
                },
                {
                    "@odata.type": (
                        "#microsoft.graph.identityGovernance.agentIdentityLifecyclePolicy"
                    ),
                    "id": "agent-1",
                    "displayName": "Default agent inactivity policy",
                    "status": "enabled",
                    "isDefault": True,
                },
            ],
            [
                {
                    "@odata.type": (
                        "#microsoft.graph.identityGovernance.agentIdentityLifecyclePolicy"
                    ),
                    "id": "agent-2",
                    "displayName": "Custom agent sponsor rule",
                    "status": "enabled",
                    "lifecyclePolicySource": "custom",
                }
            ],
        ),
    )

    truncated_bundle = collect_agent_lifecycle_policies_bundle(fake, max_pages=1)
    assert truncated_bundle["truncated"] is True
    assert truncated_bundle["count"] == 1
    assert truncated_bundle["filtered_out_non_agent_policies"] == 1
    assert truncated_bundle["api_version"] == "v1.0"
    assert [p["id"] for p in truncated_bundle["policies"]] == ["agent-1"]


def test_lifecycle_workflows_collector_tracks_truncation() -> None:
    fake = FakeGraphClient()
    fake.register_list(
        "/identityGovernance/lifecycleWorkflows/workflows",
        paginated(
            [
                {
                    "id": "wf-1",
                    "displayName": "Joiner draft",
                    "category": "joiner",
                    "isEnabled": False,
                    "isSchedulingEnabled": False,
                }
            ],
            [
                {
                    "id": "wf-2",
                    "displayName": "Leaver scheduled",
                    "category": "leaver",
                    "isEnabled": True,
                    "isSchedulingEnabled": True,
                }
            ],
        ),
    )

    truncated_bundle = collect_lifecycle_workflows_bundle(fake, max_pages=1)
    assert truncated_bundle["truncated"] is True
    assert truncated_bundle["count"] == 1
    assert truncated_bundle["api_version"] == "v1.0"


def test_missing_permission_403_degrades_only_affected_check_to_error() -> None:
    fake = FakeGraphClient()
    fake.register_list(
        "/identityGovernance/lifecycleWorkflows/lifecyclePolicies",
        error(403, "Authorization_RequestDenied: missing LifecyclePolicies-AgentId.Read.All"),
    )
    fake.register_list(
        "/identityGovernance/lifecycleWorkflows/workflows",
        ok(
            {
                "value": [
                    {
                        "id": "wf-leaver",
                        "displayName": "Scheduled leaver",
                        "category": "leaver",
                        "isEnabled": True,
                        "isSchedulingEnabled": True,
                    }
                ]
            }
        ),
    )

    # Graph operation layer maps 403 -> DENIED
    denied_env = collect_graph_operation(fake, "agent_lifecycle_policies")
    assert denied_env.health is EvidenceHealth.DENIED

    # Runtime planner collects both; 403 degrades only agent lifecycle check to ERROR
    ctx = ScanCollectionContext(
        scan_mode="live",
        auth=AuthContext(mode=AuthMode.CLIENT_SECRET, tenant_id="t1"),
        client=fake,  # type: ignore[arg-type]
        skus=[],
        warnings=[],
    )
    evidence, _summaries, result = collect_selected_evidence(
        ctx,
        default_registry(),
        check_ids=[
            "id-agent-lifecycle-policy-configured",
            "id-lifecycle-workflows-enabled",
        ],
    )
    assert (
        result.envelopes[
            next(k for k in result.envelopes if str(k) == "agent_lifecycle_policies")
        ].health
        is EvidenceHealth.DENIED
    )

    owned = {"agent_365", "entitlement_management"}
    agent_finding = evaluate_check(
        _check_by_id("id-agent-lifecycle-policy-configured"),
        owned,
        evidence,
    )
    wf_finding = evaluate_check(
        _check_by_id("id-lifecycle-workflows-enabled"),
        owned,
        evidence,
    )
    assert agent_finding.status is FindingStatus.ERROR
    assert wf_finding.status is FindingStatus.OK


def test_runtime_truncated_envelope_preserves_bundle_for_evaluator() -> None:
    fake = FakeGraphClient()
    fake.register_list(
        "/identityGovernance/lifecycleWorkflows/workflows",
        paginated(
            *[
                [{"id": f"wf-{i}", "isEnabled": False, "isSchedulingEnabled": False}]
                for i in range(25)
            ]
        ),
    )
    ctx = ScanCollectionContext(
        scan_mode="live",
        auth=AuthContext(mode=AuthMode.CLIENT_SECRET, tenant_id="t1"),
        client=fake,  # type: ignore[arg-type]
        skus=[],
        warnings=[],
    )
    evidence, _summaries, result = collect_selected_evidence(
        ctx,
        default_registry(),
        check_ids=["id-lifecycle-workflows-enabled"],
    )
    env = result.envelopes[next(k for k in result.envelopes if str(k) == "lifecycle_workflows")]
    assert env.health is EvidenceHealth.TRUNCATED
    assert env.metadata.pagination.truncated is True
    assert isinstance(evidence["lifecycle_workflows"], dict)
    assert evidence["lifecycle_workflows"]["truncated"] is True

    finding = evaluate_check(
        _check_by_id("id-lifecycle-workflows-enabled"),
        {"entitlement_management"},
        evidence,
    )
    assert finding.status is FindingStatus.PARTIAL


# -- Evaluator unit tests: id-agent-lifecycle-policy-configured --------------


def _agent_check() -> CheckDefinition:
    return CheckDefinition(
        id="id-agent-lifecycle-policy-configured",
        title="Entra Agent ID custom lifecycle policy configured",
        workload=Workload.IDENTITY,
    )


def test_agent_lifecycle_ok_on_demo_fixture_and_custom_policy() -> None:
    res = evaluate_agent_lifecycle_policy_configured(
        _agent_check(),
        {"agent_lifecycle_policies": copy.deepcopy(DEMO_AGENT_LIFECYCLE_POLICIES_BUNDLE)},
    )
    assert res.status is FindingStatus.OK
    assert res.confidence is Confidence.HIGH
    assert res.evidence["custom_enabled_policy_count"] == 1
    assert res.evidence["default_enabled_policy_count"] == 1
    assert any("built-in default agent inactivity policy" in lim for lim in res.limitations)


@pytest.mark.parametrize(
    "policy",
    [
        {
            "id": "p-default-source",
            "displayName": "Tenant agent inactivity policy",
            "status": "enabled",
            "lifecyclePolicySource": "default",
        },
        {
            "id": "p-default-flag",
            "displayName": "Microsoft agent policy",
            "isEnabled": True,
            "isDefault": True,
        },
        {
            "id": "p-default-name",
            "displayName": "Default agent inactivity policy",
            "status": "enabled",
        },
    ],
)
def test_agent_lifecycle_partial_when_only_default_inactivity_policy_enabled(
    policy: dict[str, Any],
) -> None:
    res = evaluate_agent_lifecycle_policy_configured(
        _agent_check(),
        {
            "agent_lifecycle_policies": {
                "policies": [policy],
                "truncated": False,
                "api_version": "v1.0",
            }
        },
    )
    assert res.status is FindingStatus.PARTIAL
    assert res.evidence["default_enabled_policy_count"] == 1
    assert res.evidence["custom_enabled_policy_count"] == 0


def test_agent_lifecycle_partial_when_enabled_policy_lacks_source_or_rule_metadata() -> None:
    res = evaluate_agent_lifecycle_policy_configured(
        _agent_check(),
        {
            "agent_lifecycle_policies": {
                "policies": [
                    {
                        "id": "p-opaque",
                        "displayName": "Agent governance policy",
                        "status": "enabled",
                    }
                ],
                "truncated": False,
                "api_version": "v1.0",
            }
        },
    )
    assert res.status is FindingStatus.PARTIAL
    assert res.evidence["unclassified_enabled_policy_count"] == 1


def test_agent_lifecycle_partial_when_custom_policy_has_empty_rules() -> None:
    res = evaluate_agent_lifecycle_policy_configured(
        _agent_check(),
        {
            "agent_lifecycle_policies": {
                "policies": [
                    {
                        "id": "p-empty-rules",
                        "displayName": "Custom placeholder",
                        "status": "enabled",
                        "lifecyclePolicySource": "custom",
                        "rules": [],
                    }
                ],
                "truncated": False,
                "api_version": "v1.0",
            }
        },
    )
    assert res.status is FindingStatus.PARTIAL
    assert res.evidence["unclassified_enabled_policy_count"] == 1


def test_agent_lifecycle_partial_when_truncated_with_no_custom_match() -> None:
    res = evaluate_agent_lifecycle_policy_configured(
        _agent_check(),
        {"agent_lifecycle_policies": {"policies": [], "truncated": True, "api_version": "v1.0"}},
    )
    assert res.status is FindingStatus.PARTIAL
    assert res.confidence is Confidence.LOW
    assert res.evidence["truncated"] is True


def test_agent_lifecycle_gap_when_clean_empty_or_disabled() -> None:
    empty_res = evaluate_agent_lifecycle_policy_configured(
        _agent_check(),
        {"agent_lifecycle_policies": {"policies": [], "truncated": False, "api_version": "v1.0"}},
    )
    assert empty_res.status is FindingStatus.GAP
    assert empty_res.confidence is Confidence.HIGH

    disabled_res = evaluate_agent_lifecycle_policy_configured(
        _agent_check(),
        {
            "agent_lifecycle_policies": {
                "policies": [
                    {
                        "id": "p-disabled",
                        "displayName": "Custom agent sponsor rule",
                        "status": "disabled",
                        "lifecyclePolicySource": "custom",
                    }
                ],
                "truncated": False,
                "api_version": "v1.0",
            }
        },
    )
    assert disabled_res.status is FindingStatus.GAP


def test_agent_lifecycle_error_on_403_or_bundle_error() -> None:
    err_key = evaluate_agent_lifecycle_policy_configured(
        _agent_check(),
        {
            "agent_lifecycle_policies_error": (
                "Graph 403 — missing LifecyclePolicies-AgentId.Read.All"
            )
        },
    )
    assert err_key.status is FindingStatus.ERROR

    err_bundle = evaluate_agent_lifecycle_policy_configured(
        _agent_check(),
        {"agent_lifecycle_policies": {"error": "Graph 403 Forbidden"}},
    )
    assert err_bundle.status is FindingStatus.ERROR


# -- Evaluator unit tests: id-lifecycle-workflows-enabled --------------------


def _workflow_check() -> CheckDefinition:
    return CheckDefinition(
        id="id-lifecycle-workflows-enabled",
        title="Entra ID Governance Lifecycle Workflows enabled and scheduled",
        workload=Workload.IDENTITY,
    )


def test_lifecycle_workflows_ok_when_enabled_and_scheduled() -> None:
    res = evaluate_lifecycle_workflows_enabled(
        _workflow_check(),
        {"lifecycle_workflows": copy.deepcopy(DEMO_LIFECYCLE_WORKFLOWS_BUNDLE)},
    )
    assert res.status is FindingStatus.OK
    assert res.confidence is Confidence.HIGH
    assert res.evidence["scheduled_enabled_workflow_count"] == 1
    assert res.evidence["categories_covered"] == ["leaver"]


def test_lifecycle_workflows_partial_when_enabled_without_scheduling() -> None:
    res = evaluate_lifecycle_workflows_enabled(
        _workflow_check(),
        {
            "lifecycle_workflows": {
                "workflows": [
                    {
                        "id": "wf-manual",
                        "displayName": "On-demand joiner",
                        "category": "joiner",
                        "isEnabled": True,
                        "isSchedulingEnabled": False,
                    }
                ],
                "truncated": False,
                "api_version": "v1.0",
            }
        },
    )
    assert res.status is FindingStatus.PARTIAL
    assert res.evidence["enabled_workflow_count"] == 1
    assert res.evidence["scheduled_enabled_workflow_count"] == 0
    assert res.evidence["unscheduled_enabled_workflow_count"] == 1


def test_lifecycle_workflows_partial_when_truncated_without_scheduled_match() -> None:
    res = evaluate_lifecycle_workflows_enabled(
        _workflow_check(),
        {"lifecycle_workflows": {"workflows": [], "truncated": True, "api_version": "v1.0"}},
    )
    assert res.status is FindingStatus.PARTIAL
    assert res.confidence is Confidence.LOW
    assert res.evidence["truncated"] is True


def test_lifecycle_workflows_gap_when_clean_empty_or_disabled() -> None:
    empty_res = evaluate_lifecycle_workflows_enabled(
        _workflow_check(),
        {"lifecycle_workflows": {"workflows": [], "truncated": False, "api_version": "v1.0"}},
    )
    assert empty_res.status is FindingStatus.GAP
    assert empty_res.confidence is Confidence.HIGH

    disabled_res = evaluate_lifecycle_workflows_enabled(
        _workflow_check(),
        {
            "lifecycle_workflows": {
                "workflows": [
                    {
                        "id": "wf-off",
                        "displayName": "Disabled leaver",
                        "category": "leaver",
                        "isEnabled": False,
                        "isSchedulingEnabled": True,
                    }
                ],
                "truncated": False,
                "api_version": "v1.0",
            }
        },
    )
    assert disabled_res.status is FindingStatus.GAP


def test_lifecycle_workflows_error_on_403_or_bundle_error() -> None:
    err_key = evaluate_lifecycle_workflows_enabled(
        _workflow_check(),
        {"lifecycle_workflows_error": "Graph 403 — missing LifecycleWorkflows.Read.All"},
    )
    assert err_key.status is FindingStatus.ERROR

    err_bundle = evaluate_lifecycle_workflows_enabled(
        _workflow_check(),
        {"lifecycle_workflows": {"error": "Graph 403 Forbidden"}},
    )
    assert err_bundle.status is FindingStatus.ERROR
