#!/usr/bin/env python3
"""Capture dashboard IA prototype shots. Not part of the product."""

from __future__ import annotations

from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[3]
DESIGN = ROOT / "audit" / "2026-11" / "design"
OUT = DESIGN / "dashboard-shots"

PAGES = {
    "a-panel": DESIGN / "dashboard-a-panel.html",
    "b-routes": DESIGN / "dashboard-b-routes.html",
}

VIEWPORTS = {
    "1440": (1440, 1100),
    "1280": (1280, 900),
    "390": (390, 844),
}


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        for slug, path in PAGES.items():
            uri = path.resolve().as_uri()
            for vp_name, (w, h) in VIEWPORTS.items():
                context = browser.new_context(
                    viewport={"width": w, "height": h},
                    color_scheme="dark",
                    reduced_motion="reduce",
                )
                page = context.new_page()
                page.goto(uri, wait_until="networkidle")
                page.wait_for_timeout(250)
                page.screenshot(
                    path=str(OUT / f"{slug}-{vp_name}-summary.png"),
                    full_page=False,
                )

                if slug == "a-panel":
                    page.locator('[data-panel="p1"]').click()
                    page.wait_for_timeout(280)
                    page.screenshot(
                        path=str(OUT / f"{slug}-{vp_name}-panel-open.png"),
                        full_page=False,
                    )
                    page.locator("#panel-close").click()
                    page.wait_for_timeout(200)
                else:
                    page.goto(uri + "#/priority/1", wait_until="networkidle")
                    page.wait_for_timeout(250)
                    page.screenshot(
                        path=str(OUT / f"{slug}-{vp_name}-priority.png"),
                        full_page=False,
                    )
                    page.goto(uri + "#/", wait_until="networkidle")

                if vp_name == "1280":
                    page.emulate_media(media="print")
                    page.wait_for_timeout(200)
                    page.screenshot(
                        path=str(OUT / f"{slug}-1280-print.png"),
                        full_page=True,
                    )
                    page.emulate_media(media="screen")

                context.close()
        browser.close()

    shots = sorted(OUT.glob("*.png"))
    print(f"wrote {len(shots)} screenshots → {OUT}")
    for p in shots:
        print(f"  {p.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
