"""Typed evaluator registrations for identity_governance."""

from __future__ import annotations

from licenselens.engine.registration import RegistrationCatalog
from licenselens.evaluators.agent_lifecycle import evaluate_agent_lifecycle_policy_configured
from licenselens.evaluators.identity_governance import (
    evaluate_access_reviews_scope,
    evaluate_access_reviews_unused,
    evaluate_entitlement_access_packages,
    evaluate_security_defaults_on,
)
from licenselens.evaluators.lifecycle_workflows import evaluate_lifecycle_workflows_enabled
from licenselens.schema_contracts import EvaluationMode


def register_identity_governance(catalog: RegistrationCatalog) -> None:
    catalog.enter_module("licenselens.evaluators.bindings.identity_governance")
    try:
        catalog.add_evaluator(
            check_id="id-access-reviews-unused",
            evaluate=evaluate_access_reviews_unused,
            input_models=("access_review_definitions",),
            collector_id="graph_access_reviews",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="id-access-reviews-scope",
            evaluate=evaluate_access_reviews_scope,
            input_models=("access_review_definitions", "access_review_instances"),
            collector_id="graph_access_reviews",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="id-security-defaults-on",
            evaluate=evaluate_security_defaults_on,
            input_models=("security_defaults_policy", "ca_policies"),
            collector_id="graph_security_defaults",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="id-entitlement-access-packages",
            evaluate=evaluate_entitlement_access_packages,
            input_models=("access_packages",),
            collector_id="graph_entitlement_management",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="id-agent-lifecycle-policy-configured",
            evaluate=evaluate_agent_lifecycle_policy_configured,
            input_models=("agent_lifecycle_policies",),
            collector_id="graph_agent_lifecycle",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="id-lifecycle-workflows-enabled",
            evaluate=evaluate_lifecycle_workflows_enabled,
            input_models=("lifecycle_workflows",),
            collector_id="graph_lifecycle_workflows",
            evaluation_mode=EvaluationMode.DIRECT,
        )
    finally:
        catalog.exit_module("licenselens.evaluators.bindings.identity_governance")
