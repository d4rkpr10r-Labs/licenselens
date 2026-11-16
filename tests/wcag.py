"""Reusable WCAG 2.x contrast helpers for design-contract tests.

Pure, dependency-free functions: parse ``#rrggbb`` strings, compute relative
luminance per the WCAG 2.x formula, and return the contrast ratio between two
colors. Importable from anywhere in the test suite via ``tests.wcag``.
"""

from __future__ import annotations

import pytest

_HEX_RE = r"^#[0-9a-fA-F]{6}$"


def _parse_hex(color: str) -> tuple[int, int, int]:
    import re

    if not re.fullmatch(_HEX_RE, color):
        raise ValueError(f"expected #rrggbb hex color, got {color!r}")
    value = color[1:]
    return int(value[0:2], 16), int(value[2:4], 16), int(value[4:6], 16)


def relative_luminance(rgb: tuple[int, int, int]) -> float:
    """Relative luminance of an 8-bit RGB triple per WCAG 2.x (0.0..1.0)."""

    def channel(value: int) -> float:
        normalized = value / 255.0
        if normalized <= 0.03928:
            return normalized / 12.92
        return ((normalized + 0.055) / 1.055) ** 2.4

    r, g, b = rgb
    return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)


def contrast_ratio(fg: str, bg: str) -> float:
    """WCAG 2.x contrast ratio between two ``#rrggbb`` colors (1.0..21.0)."""
    fg_luminance = relative_luminance(_parse_hex(fg))
    bg_luminance = relative_luminance(_parse_hex(bg))
    lighter, darker = (
        (fg_luminance, bg_luminance)
        if fg_luminance >= bg_luminance
        else (bg_luminance, fg_luminance)
    )
    return (lighter + 0.05) / (darker + 0.05)


SEMANTIC_PRINT_COLORS = ("#ff737a", "#e2b84b", "#67c991", "#96938b")


def test_contrast_ratio_canonical_extremes() -> None:
    assert contrast_ratio("#000000", "#ffffff") == pytest.approx(21.0, abs=1e-9)
    assert contrast_ratio("#ffffff", "#000000") == pytest.approx(21.0, abs=1e-9)
    assert contrast_ratio("#ffffff", "#ffffff") == pytest.approx(1.0, abs=1e-9)


def test_contrast_ratio_rejects_malformed_input() -> None:
    for bad in ("", "#fff", "fff", "#12345", "#gggggg", "#1234567", "red"):
        with pytest.raises(ValueError, match="expected #rrggbb"):
            contrast_ratio(bad, "#ffffff")


def test_ledger_accent_on_canvas() -> None:
    assert contrast_ratio("#0B5F75", "#F3F5F8") >= 4.5


def test_ledger_focus_on_surface() -> None:
    assert contrast_ratio("#127A94", "#FFFFFF") >= 3.0


def test_print_accent_on_white() -> None:
    assert contrast_ratio("#0B5F75", "#ffffff") >= 4.5


def test_ledger_status_inks_meet_aa_on_white() -> None:
    """V3 Assessment Ledger status tokens are paper-safe (screen == print)."""
    for color in ("#B42318", "#B54708", "#087443", "#5B6B7C"):
        assert contrast_ratio(color, "#ffffff") >= 4.5, (
            f"ledger status {color} below 4.5:1 on white"
        )


def test_ledger_text_ramp_on_canvas() -> None:
    assert contrast_ratio("#15202B", "#F3F5F8") >= 4.5
    assert contrast_ratio("#3D4D5C", "#F3F5F8") >= 4.5
    assert contrast_ratio("#5E6E80", "#F3F5F8") >= 4.5
