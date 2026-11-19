"""Typed evaluator registrations for endpoint_intune_policy."""

from __future__ import annotations

from licenselens.engine.registration import RegistrationCatalog
from licenselens.evaluators.endpoint_intune_policy import (
    evaluate_endpoint_mde_ai_agent_runtime_protection,
    evaluate_endpoint_mde_connector,
    evaluate_endpoint_security_baseline,
    evaluate_endpoint_security_policy_coverage,
    evaluate_intune_epm_policy_present,
)
from licenselens.schema_contracts import EvaluationMode


def register_endpoint_intune_policy(catalog: RegistrationCatalog) -> None:
    catalog.enter_module("licenselens.evaluators.bindings.endpoint_intune_policy")
    try:
        catalog.add_evaluator(
            check_id="endpoint-mde-connector",
            evaluate=evaluate_endpoint_mde_connector,
            input_models=("intune_bundle",),
            collector_id="intune_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="endpoint-security-baseline",
            evaluate=evaluate_endpoint_security_baseline,
            input_models=("intune_bundle",),
            collector_id="intune_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="endpoint-security-policy-coverage",
            evaluate=evaluate_endpoint_security_policy_coverage,
            input_models=("intune_bundle",),
            collector_id="intune_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="endpoint-epm-policy-present",
            evaluate=evaluate_intune_epm_policy_present,
            input_models=("intune_bundle",),
            collector_id="intune_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="endpoint-mde-ai-agent-runtime-protection",
            evaluate=evaluate_endpoint_mde_ai_agent_runtime_protection,
            input_models=("intune_bundle",),
            collector_id="intune_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
    finally:
        catalog.exit_module("licenselens.evaluators.bindings.endpoint_intune_policy")
