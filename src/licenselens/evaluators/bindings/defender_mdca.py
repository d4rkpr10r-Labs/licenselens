"""Typed evaluator registrations for Defender for Cloud Apps checks."""

from __future__ import annotations

from licenselens.engine.registration import RegistrationCatalog
from licenselens.evaluators.defender_mdca import evaluate_mdca_ca_session_control
from licenselens.schema_contracts import EvaluationMode


def register_defender_mdca(catalog: RegistrationCatalog) -> None:
    catalog.enter_module("licenselens.evaluators.bindings.defender_mdca")
    try:
        catalog.add_evaluator(
            check_id="id-mdca-ca-session-control",
            evaluate=evaluate_mdca_ca_session_control,
            input_models=("ca_policies",),
            collector_id="graph_ca",
            evaluation_mode=EvaluationMode.DIRECT,
        )
    finally:
        catalog.exit_module("licenselens.evaluators.bindings.defender_mdca")
