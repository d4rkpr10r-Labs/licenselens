"""Typed evaluator registrations for Global Secure Access checks."""

from __future__ import annotations

from licenselens.engine.registration import RegistrationCatalog
from licenselens.evaluators.gsa_network_access import (
    evaluate_gsa_internet_access_enabled,
    evaluate_gsa_private_access_enabled,
)
from licenselens.schema_contracts import EvaluationMode


def register_gsa_network_access(catalog: RegistrationCatalog) -> None:
    catalog.enter_module("licenselens.evaluators.bindings.gsa_network_access")
    try:
        catalog.add_evaluator(
            check_id="id-gsa-internet-access-enabled",
            evaluate=evaluate_gsa_internet_access_enabled,
            input_models=("gsa_network_access",),
            collector_id="gsa_network_access_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="id-gsa-private-access-enabled",
            evaluate=evaluate_gsa_private_access_enabled,
            input_models=("gsa_network_access",),
            collector_id="gsa_network_access_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
    finally:
        catalog.exit_module("licenselens.evaluators.bindings.gsa_network_access")
