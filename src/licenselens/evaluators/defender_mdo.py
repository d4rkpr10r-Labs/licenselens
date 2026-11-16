"""MDO Safe Links/Attachments evaluation (direct EXO + Secure Score proxy)."""

from __future__ import annotations

from typing import Any

from licenselens.evaluators.common import Evaluation, score_status
from licenselens.models import CheckDefinition, Confidence, FindingStatus


def evaluate_mdo_p2_policies(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """Assess MDO Safe Links/Attachments via direct EXO read, else Secure Score proxy."""
    del check
    if evidence.get("exchange_threat_usable"):
        return _evaluate_mdo_direct(evidence)
    return _evaluate_mdo_proxy(evidence)


def _evaluate_mdo_direct(evidence: dict[str, Any]) -> Evaluation:
    threat = evidence.get("exchange_threat_policies") or {}
    surfaces = threat.get("surfaces") if isinstance(threat, dict) else {}
    if not isinstance(surfaces, dict):
        surfaces = {}

    safe_links = _surface_items(surfaces, "safe_links")
    safe_attach = _surface_items(surfaces, "safe_attachments")
    preset = _surface_items(surfaces, "preset_security")

    enabled_links = [i for i in safe_links if i.get("enabled") is True]
    enabled_attach = [i for i in safe_attach if i.get("enabled") is True]
    blocking_attach = [i for i in enabled_attach if _safe_attach_blocks(i)]
    allow_only_attach = [i for i in enabled_attach if not _safe_attach_blocks(i)]
    enabled_preset = [
        i
        for i in preset
        if i.get("enabled") is True
        or str((i.get("properties") or {}).get("State") or "").lower() == "enabled"
    ]
    custom_links = [i for i in safe_links if str(i.get("kind") or "") == "custom"]
    org_wide_links = [i for i in enabled_links if _policy_is_org_wide(i)]
    org_wide_attach = [i for i in blocking_attach if _policy_is_org_wide(i)]
    org_wide_preset = [i for i in enabled_preset if _policy_is_org_wide(i)]
    has_default_or_preset = any(
        str(i.get("kind") or "") in {"default", "preset_standard", "preset_strict", "effective"}
        for i in org_wide_links + org_wide_attach + org_wide_preset
    )

    evidence_out = {
        "source": "powershell.exchange.exo_threat_policies",
        "proxy": False,
        "email_proxy_enabled": False,
        "exchange_direct": True,
        "safe_links_count": len(safe_links),
        "safe_links_enabled": len(enabled_links),
        "safe_links_org_wide": len(org_wide_links),
        "safe_attachments_count": len(safe_attach),
        "safe_attachments_enabled": len(enabled_attach),
        "safe_attachments_blocking": len(blocking_attach),
        "safe_attachments_org_wide_blocking": len(org_wide_attach),
        "safe_attachments_allow_only": len(allow_only_attach),
        "preset_enabled": len(enabled_preset),
        "preset_org_wide": len(org_wide_preset),
        "custom_safe_links": len(custom_links),
        "policies": {
            "safe_links": safe_links[:10],
            "safe_attachments": safe_attach[:10],
            "preset_security": preset[:10],
        },
        "note": (
            "Direct Exchange Online PowerShell read of Safe Links, Safe Attachments, "
            "and preset security policies (supersedes Secure Score proxy)."
        ),
    }
    meta = dict(
        confidence=Confidence.HIGH,
        data_sources=["Exchange Online PowerShell (exo_threat_policies)"],
        limitations=[],
    )

    if not enabled_links and not enabled_attach and not enabled_preset:
        return Evaluation(
            status=FindingStatus.GAP,
            summary=(
                "Direct Exchange read found no enabled Safe Links, Safe Attachments, "
                "or preset security policies despite Defender for Office licensing."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Stronger email protections appear off. Turn on Standard preset "
                "security policies (Safe Links and Safe Attachments) for all users."
            ),
            **meta,
        )

    if (
        org_wide_links
        and org_wide_attach
        and (org_wide_preset or has_default_or_preset)
        and not allow_only_attach
    ):
        summary = (
            f"Direct Exchange read: Safe Links ({len(org_wide_links)} org-wide), "
            f"Safe Attachments blocking ({len(org_wide_attach)} org-wide), "
            f"preset rules ({len(org_wide_preset)} org-wide); "
            f"{len(custom_links)} custom Safe Links policy(ies) also present."
        )
        return Evaluation(
            status=FindingStatus.OK,
            summary=summary,
            evidence=evidence_out,
            customer_summary=(
                "Safe Links and Safe Attachments look enabled org-wide with blocking "
                "attachment actions from a direct policy read."
            ),
            **meta,
        )

    return Evaluation(
        status=FindingStatus.PARTIAL,
        summary=(
            "Direct Exchange read shows incomplete MDO coverage: "
            f"Safe Links org-wide={len(org_wide_links)}, "
            f"Safe Attachments blocking org-wide={len(org_wide_attach)}, "
            f"preset org-wide={len(org_wide_preset)}, "
            f"allow-only Safe Attachments={len(allow_only_attach)}."
        ),
        evidence=evidence_out,
        customer_summary=(
            "Some stronger email protections are on, but coverage looks pilot-scoped, "
            "Allow-action Safe Attachments, or missing Standard/Strict presets. "
            "Review preset and custom policies in the portal."
        ),
        **meta,
    )


def _surface_items(surfaces: dict[str, Any], name: str) -> list[dict[str, Any]]:
    surface = surfaces.get(name) or {}
    if not isinstance(surface, dict):
        return []
    if str(surface.get("status") or "") != "ok":
        return []
    items = surface.get("items") or []
    return [i for i in items if isinstance(i, dict)]


_BLOCKING_SAFE_ATTACH_ACTIONS: frozenset[str] = frozenset(
    {
        "block",
        "dynamicdelivery",
        "replace",
    }
)


def _safe_attach_blocks(item: dict[str, Any]) -> bool:
    """True when Safe Attachments uses a blocking / Dynamic Delivery action."""
    props = item.get("properties") if isinstance(item.get("properties"), dict) else {}
    action = str(props.get("Action") or item.get("action") or "").strip().lower()
    if not action:
        # Missing Action on an enabled default/preset is treated as unresolved,
        # not as proof of blocking — caller still needs other signals for OK.
        return False
    if action in {"allow", "off", "disabled"}:
        return False
    return action in _BLOCKING_SAFE_ATTACH_ACTIONS


def _policy_is_org_wide(item: dict[str, Any]) -> bool:
    """Heuristic org-wide coverage from kind + EXO assignment fields."""
    kind = str(item.get("kind") or "").lower()
    if kind in {"default", "preset_standard", "preset_strict", "effective"}:
        return True
    assignments = item.get("assignments") or []
    if not isinstance(assignments, list):
        return False
    # Empty assignment lists on enabled custom policies are treated as scoped /
    # unknown — not org-wide — so pilots cannot look fully realized.
    if not assignments:
        return False
    normalized = {str(a).strip().lower() for a in assignments if a is not None}
    if not normalized:
        return False
    if normalized & {"all", "*", "allrecipients", "all users", "allusers"}:
        return True
    # Priority/State-only assignment captures from EXO are not recipient scope.
    non_meta = {
        value
        for value in normalized
        if value not in {"enabled", "disabled", "on", "off"} and not value.isdigit()
    }
    return not non_meta


def _evaluate_mdo_proxy(evidence: dict[str, Any]) -> Evaluation:
    from licenselens.collectors.secure_score import MDO_CONTROL_HINTS, summarize_controls

    controls = list(evidence.get("secure_score_controls") or [])
    summary = summarize_controls(controls, MDO_CONTROL_HINTS)
    ratio = summary.get("ratio")
    matched = int(summary.get("matched_count") or 0)

    evidence_out = {
        "source": "secureScore.controlScores",
        "proxy": True,
        "email_proxy_enabled": True,
        "matched_controls": matched,
        "score_ratio": ratio,
        "controls": summary.get("controls") or [],
        "note": (
            "Uses Microsoft Secure Score control signals as a proxy for "
            "Defender for Office 365 policy enforcement when direct policy "
            "APIs are unavailable."
        ),
    }
    proxy_meta = dict(
        confidence=Confidence.LOW,
        data_sources=["secureScore.controlScores (proxy)"],
        limitations=["Secure Score is a proxy — verify Safe Links/Attachments in the portal."],
    )

    if matched == 0:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                "No Defender for Office 365–related Secure Score controls were "
                "found. Unable to confirm Safe Links/Attachments enforcement."
            ),
            evidence=evidence_out,
            customer_summary=(
                "We could not automatically confirm whether extra email "
                "protections are turned on. Ask IT to verify Safe Links and "
                "Safe Attachments for all users."
            ),
            **proxy_meta,
        )

    status = score_status(float(ratio) if ratio is not None else None, matched=matched)
    if status == FindingStatus.OK:
        status = FindingStatus.PARTIAL
    pct = f"{float(ratio) * 100:.0f}%" if ratio is not None else "n/a"
    if status == FindingStatus.PARTIAL and ratio is not None and float(ratio) >= 0.85:
        return Evaluation(
            status=status,
            summary=(
                f"Secure Score shows strong MDO-related control completion "
                f"({matched} controls, ~{pct}) — treat as provisional until portal verify."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Score signals suggest stronger email protections are largely on, "
                "but this is not a direct policy read — confirm in the admin portal."
            ),
            **proxy_meta,
        )
    if status == FindingStatus.PARTIAL:
        return Evaluation(
            status=status,
            summary=(
                f"Secure Score shows partial MDO-related control completion "
                f"({matched} controls, ~{pct}). Safe Links/Attachments may be "
                "incomplete or not fully enforced."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Some stronger email protections appear configured, but not fully. "
                "Safe Links and Safe Attachments may still miss people or stay in "
                "test mode. Verify in the portal."
            ),
            **proxy_meta,
        )
    return Evaluation(
        status=status,
        summary=(
            f"Secure Score shows weak MDO-related control completion "
            f"({matched} controls, ~{pct}) despite Defender for Office licensing."
        ),
        evidence=evidence_out,
        customer_summary=(
            "You appear to pay for stronger email protection, but Microsoft's "
            "score signals suggest much of it is not turned on yet. Confirm in portal."
        ),
        **proxy_meta,
    )
