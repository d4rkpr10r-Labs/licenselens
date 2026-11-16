"""Typed evaluator registrations for Security Copilot checks."""

from __future__ import annotations

from licenselens.engine.registration import RegistrationCatalog
from licenselens.evaluators.security_copilot import evaluate_sec_copilot_workspace_provisioned
from licenselens.schema_contracts import EvaluationMode


def register_security_copilot(catalog: RegistrationCatalog) -> None:
    catalog.enter_module("licenselens.evaluators.bindings.security_copilot")
    try:
        catalog.add_evaluator(
            check_id="xdr-sec-copilot-workspace-provisioned",
            evaluate=evaluate_sec_copilot_workspace_provisioned,
            input_models=("security_copilot",),
            collector_id="security_copilot_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
    finally:
        catalog.exit_module("licenselens.evaluators.bindings.security_copilot")
