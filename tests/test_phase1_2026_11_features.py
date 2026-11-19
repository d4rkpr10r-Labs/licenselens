"""Phase 1 (2026-11) entitlement and evaluator coverage."""

from __future__ import annotations

import copy

from licenselens.catalog.loader import load_capabilities, resolve_owned_capabilities
from licenselens.collectors.gsa_network_access import DEMO_GSA_NETWORK_ACCESS_BUNDLE
from licenselens.collectors.intune_policy import DEMO_INTUNE_EVIDENCE_BUNDLE
from licenselens.collectors.security_copilot import DEMO_SECURITY_COPILOT_BUNDLE
from licenselens.evaluators.defender_mdca import evaluate_mdca_ca_session_control
from licenselens.evaluators.endpoint_intune_policy import evaluate_intune_epm_policy_present
from licenselens.evaluators.gsa_network_access import (
    evaluate_gsa_internet_access_enabled,
    evaluate_gsa_private_access_enabled,
)
from licenselens.evaluators.security_copilot import evaluate_sec_copilot_workspace_provisioned
from licenselens.models import CheckDefinition, FindingStatus, ServicePlan, SubscribedSku, Workload


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


def test_e3_with_atp_unlocks_mdo_p1_not_p2() -> None:
    caps = load_capabilities()
    owned = set(
        resolve_owned_capabilities(
            caps,
            [
                _sku(
                    "SPE_E3",
                    [
                        (
                            "ATP_ENTERPRISE",
                            "Success",
                            "f20fedf3-f3c3-43c3-8267-2bfdd51c0939",
                        )
                    ],
                )
            ],
        )
    )
    assert "defender_office_p1" in owned
    assert "defender_office_p2" not in owned


def test_e7_sku_unlocks_entra_suite_and_agent_caps() -> None:
    caps = load_capabilities()
    owned = set(
        resolve_owned_capabilities(
            caps,
            [
                _sku(
                    "MICROSOFT_365_E7",
                    [
                        (
                            "Entra_Premium_Internet_Access",
                            "Success",
                            "8d23cb83-ab07-418f-8517-d7aca77307dc",
                        ),
                        (
                            "Entra_Premium_Private_Access",
                            "Success",
                            "f057aab1-b184-49b2-85c0-881b02a405c5",
                        ),
                        (
                            "THREAT_INTELLIGENCE",
                            "Success",
                            "8e0c0a52-6a6c-4d40-8370-dd62790dcd70",
                        ),
                    ],
                )
            ],
        )
    )
    assert "entra_internet_access" in owned
    assert "entra_private_access" in owned
    assert "defender_office_p2" in owned
    assert "security_copilot" in owned


def test_mdca_session_control_ok_and_gap() -> None:
    check = CheckDefinition(
        id="id-mdca-ca-session-control",
        title="t",
        workload=Workload.DEFENDER,
    )
    ok = evaluate_mdca_ca_session_control(
        check,
        {
            "ca_policies": [
                {
                    "id": "1",
                    "displayName": "MDCA",
                    "state": "enabled",
                    "sessionControls": {
                        "cloudAppSecurity": {
                            "isEnabled": True,
                            "cloudAppSecurityType": "monitorOnly",
                        }
                    },
                }
            ]
        },
    )
    assert ok.status is FindingStatus.OK
    gap = evaluate_mdca_ca_session_control(check, {"ca_policies": []})
    assert gap.status is FindingStatus.GAP


def test_epm_policy_detects_template_family() -> None:
    check = CheckDefinition(
        id="endpoint-epm-policy-present",
        title="t",
        workload=Workload.ENDPOINT,
    )
    evidence = {"intune_bundle": copy.deepcopy(DEMO_INTUNE_EVIDENCE_BUNDLE)}
    assert evaluate_intune_epm_policy_present(check, evidence).status is FindingStatus.GAP
    evidence["intune_bundle"]["configuration_policies"].append(
        {
            "id": "epm-1",
            "name": "EPM elevation rules",
            "templateReference": {"templateFamily": "endpointSecurityEndpointPrivilegeManagement"},
            "technologies": "endpointPrivilegeManagement",
            "isAssigned": True,
        }
    )
    assert evaluate_intune_epm_policy_present(check, evidence).status is FindingStatus.OK
    unassigned = copy.deepcopy(evidence)
    unassigned["intune_bundle"]["configuration_policies"][-1]["isAssigned"] = False
    assert evaluate_intune_epm_policy_present(check, unassigned).status is FindingStatus.PARTIAL


def test_gsa_internet_ok_private_gap_on_demo_fixture() -> None:
    check_i = CheckDefinition(
        id="id-gsa-internet-access-enabled", title="t", workload=Workload.IDENTITY
    )
    check_p = CheckDefinition(
        id="id-gsa-private-access-enabled", title="t", workload=Workload.IDENTITY
    )
    evidence = {"gsa_network_access": copy.deepcopy(DEMO_GSA_NETWORK_ACCESS_BUNDLE)}
    assert evaluate_gsa_internet_access_enabled(check_i, evidence).status is FindingStatus.OK
    assert evaluate_gsa_private_access_enabled(check_p, evidence).status is FindingStatus.GAP


def test_security_copilot_workspace_ok_and_empty_is_partial() -> None:
    check = CheckDefinition(
        id="xdr-sec-copilot-workspace-provisioned",
        title="t",
        workload=Workload.DEFENDER,
    )
    ok = evaluate_sec_copilot_workspace_provisioned(
        check, {"security_copilot": copy.deepcopy(DEMO_SECURITY_COPILOT_BUNDLE)}
    )
    assert ok.status is FindingStatus.OK
    empty = evaluate_sec_copilot_workspace_provisioned(
        check, {"security_copilot": {"workspaces": [], "api_version": "beta"}}
    )
    assert empty.status is FindingStatus.PARTIAL
    assert empty.confidence.name == "LOW"


def test_gsa_and_security_copilot_propagate_truncation_to_envelopes(
    monkeypatch: object,
) -> None:
    from licenselens.auth import AuthContext, AuthMode
    from licenselens.collectors.contracts import EvidenceHealth
    from licenselens.collectors.gsa_network_access import collect_gsa_network_access_bundle
    from licenselens.collectors.runtime_collect_endpoint import (
        collect_gsa_network_access_runtime,
        collect_security_copilot_runtime,
    )
    from licenselens.collectors.security_copilot import collect_security_copilot_bundle
    from licenselens.engine.collection_context import ScanCollectionContext
    from licenselens.engine.planner import CollectionContext
    from tests.fake_clients import FakeGraphClient, paginated

    fake_gsa = FakeGraphClient(allow_preview=True)
    fake_gsa.register_list(
        "/networkAccess/forwardingProfiles",
        paginated(*[[{"id": f"p{i}", "trafficForwardingType": "internet"}] for i in range(12)]),
    )
    gsa_bundle = collect_gsa_network_access_bundle(fake_gsa)
    assert gsa_bundle["truncated"] is True
    assert gsa_bundle["pages_read"] == 10
    assert len(gsa_bundle["forwarding_profiles"]) == 10

    fake_cop = FakeGraphClient(allow_preview=True)
    fake_cop.register_list(
        "/security/securityCopilot/workspaces",
        paginated(*[[{"id": f"w{i}", "displayName": f"WS {i}"}] for i in range(7)]),
    )
    cop_bundle = collect_security_copilot_bundle(fake_cop)
    assert cop_bundle["truncated"] is True
    assert cop_bundle["pages_read"] == 5
    assert len(cop_bundle["workspaces"]) == 5

    ctx = ScanCollectionContext(
        scan_mode="live",
        auth=AuthContext(
            mode=AuthMode.CLIENT_SECRET,
            tenant_id="00000000-0000-0000-0000-000000000000",
        ),
        client=fake_gsa,  # type: ignore[arg-type]
        skus=[],
        warnings=[],
    )
    monkeypatch.setattr(  # type: ignore[attr-defined]
        "licenselens.collectors.runtime_collect_endpoint._preview_client",
        lambda _ctx, _base: fake_gsa,
    )
    gsa_env = collect_gsa_network_access_runtime(ctx, CollectionContext(envelopes={}))
    assert gsa_env.health is EvidenceHealth.TRUNCATED
    assert gsa_env.metadata.pagination.truncated is True
    assert isinstance(gsa_env.value, dict) and gsa_env.value["truncated"] is True

    monkeypatch.setattr(  # type: ignore[attr-defined]
        "licenselens.collectors.runtime_collect_endpoint._preview_client",
        lambda _ctx, _base: fake_cop,
    )
    cop_env = collect_security_copilot_runtime(ctx, CollectionContext(envelopes={}))
    assert cop_env.health is EvidenceHealth.TRUNCATED
    assert cop_env.metadata.pagination.truncated is True
    assert isinstance(cop_env.value, dict) and cop_env.value["truncated"] is True

    # Truncated GSA without an assigned match demotes GAP -> PARTIAL.
    check_i = CheckDefinition(
        id="id-gsa-internet-access-enabled", title="t", workload=Workload.IDENTITY
    )
    res = evaluate_gsa_internet_access_enabled(check_i, {"gsa_network_access": gsa_bundle})
    assert res.status is FindingStatus.PARTIAL
    assert res.evidence["truncated"] is True
