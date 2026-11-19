#!/usr/bin/env python3
"""Capture production report dashboard+panel shots (Direction A). Not product code."""

from __future__ import annotations

import subprocess
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / "audit" / "2026-11" / "design" / "dashboard-shots"
REPORT_DIR = Path("/tmp/ll-demo-dashboard-prod")
REPORT = REPORT_DIR / "security-license-lens-report.html"

VIEWPORTS = {
    "1440": (1440, 1100),
    "1280": (1280, 1000),
    "390": (390, 844),
}


def ensure_demo_report() -> None:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    if REPORT.is_file():
        return
    subprocess.run(
        ["uv", "run", "licenselens", "demo", "-o", str(REPORT_DIR)],
        check=True,
        cwd=str(ROOT),
    )
    assert REPORT.is_file(), f"demo did not write {REPORT}"


def main() -> None:
    ensure_demo_report()
    uri = REPORT.resolve().as_uri()
    OUT.mkdir(parents=True, exist_ok=True)
    shots: list[str] = []
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        for vp_name, (w, h) in VIEWPORTS.items():
            context = browser.new_context(
                viewport={"width": w, "height": h},
                reduced_motion="reduce",
                color_scheme="dark",
            )
            page = context.new_page()
            page.goto(uri, wait_until="networkidle")
            page.wait_for_function(
                "() => document.documentElement.classList.contains('js-dashboard')"
            )
            page.wait_for_timeout(200)

            summary = OUT / f"prod-a-panel-{vp_name}-summary.png"
            page.screenshot(path=str(summary), full_page=False)
            shots.append(summary.name)

            page.locator('[data-panel="section-findings"]').first.click()
            page.wait_for_function(
                "() => { const p = document.getElementById('detail-panel');"
                " return p && !p.hidden && p.classList.contains('is-open'); }"
            )
            page.wait_for_timeout(120)
            open_shot = OUT / f"prod-a-panel-{vp_name}-panel-open.png"
            page.screenshot(path=str(open_shot), full_page=False)
            shots.append(open_shot.name)

            if vp_name == "1280":
                page.emulate_media(media="print")
                page.wait_for_timeout(100)
                print_shot = OUT / f"prod-a-panel-{vp_name}-print.png"
                page.screenshot(path=str(print_shot), full_page=True)
                shots.append(print_shot.name)

            context.close()
        browser.close()
    print(f"wrote {len(shots)} screenshots → {OUT}")
    for name in shots:
        print(f"  {name}")


if __name__ == "__main__":
    main()
