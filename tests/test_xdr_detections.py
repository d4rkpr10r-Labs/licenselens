"""WS3-C: XDR custom detections collector (Graph v1.0)."""

from __future__ import annotations

import pytest

from licenselens.auth import AuthContext, AuthMode
from licenselens.collectors.contracts import EvidenceHealth
from licenselens.collectors.runtime_collect_endpoint import collect_xdr_custom_detections_runtime
from licenselens.collectors.xdr_detections import (
    QUERY_TEXT_LIMIT,
    collect_xdr_custom_detections,
)
from licenselens.engine.collection_context import ScanCollectionContext
from licenselens.engine.planner import CollectionContext
from licenselens.engine.registry import default_registry
from licenselens.graph_ops import get_operation
from tests.fake_clients import FakeGraphClient, ok, paginated


def test_collects_enabled_from_status() -> None:
    fake = FakeGraphClient()
    long_query = "DeviceProcessEvents | take 1" + ("x" * 5000)
    fake.register_list(
        "/security/rules/detectionRules",
        ok(
            {
                "value": [
                    {
                        "displayName": "on",
                        "status": "enabled",
                        "queryCondition": {"queryText": long_query},
                        "schedule": {"period": "12H"},
                    },
                    {
                        "displayName": "off",
                        "status": "disabled",
                        "queryCondition": {"queryText": "SigninLogs | take 1"},
                    },
                ]
            }
        ),
    )
    bundle = collect_xdr_custom_detections(fake)
    assert bundle["enabled_count"] == 1
    assert bundle["rules"][0]["isEnabled"] is True
    assert len(bundle["rules"][0]["queryText"]) == QUERY_TEXT_LIMIT
    assert bundle["rules"][1]["isEnabled"] is False
    assert bundle["truncated"] is False


def test_operation_is_v1() -> None:
    op = get_operation("graph_xdr_detection_rules")
    assert op.preview is False
    assert op.api_version == "v1.0"
    assert "CustomDetection.Read.All" in op.application_permissions


def test_runtime_uses_v1_client_directly(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fail_preview(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("_preview_client must not be called for Graph v1.0 detectionRules")

    monkeypatch.setattr(
        "licenselens.collectors.runtime_collect_endpoint._preview_client",
        _fail_preview,
    )
    fake = FakeGraphClient()
    fake.register_list(
        "/security/rules/detectionRules",
        paginated([{"displayName": "r1", "status": "enabled"}]),
    )
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
    env = collect_xdr_custom_detections_runtime(ctx, CollectionContext(envelopes={}))
    assert env.health is EvidenceHealth.OK
    assert env.metadata.source == "graph.security.rules.detectionRules"
    assert env.metadata.items_collected == 1


def test_collector_registered() -> None:
    registry = default_registry()
    assert "xdr_detections_collector" in {c.id for c in registry.collector_entries}
    assert "xdr_custom_detections" in {s.id for s in registry.data_source_entries}
