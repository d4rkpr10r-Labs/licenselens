#!/usr/bin/env python3
"""Capture before-shots for Phase 3 design critique. Not part of the product."""

from __future__ import annotations

import threading
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

from licenselens.ui.pages import serve_wizard

ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / "audit" / "2026-11" / "design" / "before"
REPORT = Path("/tmp/ll-demo-before/security-license-lens-report.html")
WIZARD_OUT = Path("/tmp/ll-wizard-before")

VIEWPORTS = {
    "1440": (1440, 1100),
    "1280": (1280, 1000),
    "390": (390, 844),
}

SECTIONS = [
    ("hero", "#section-a"),
    ("priorities", "#section-c"),
    ("owned", "#section-b"),
    ("findings", "#section-findings"),
    ("evidence", "#section-detection-realization"),
]


def _shot(page, path: Path, *, full: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    page.screenshot(path=str(path), full_page=full)


def capture_report() -> None:
    uri = REPORT.resolve().as_uri()
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        for motion_name, reduced in (("motion-on", False), ("motion-off", True)):
            for vp_name, (w, h) in VIEWPORTS.items():
                context = browser.new_context(
                    viewport={"width": w, "height": h},
                    reduced_motion="reduce" if reduced else "no-preference",
                    color_scheme="dark",
                )
                page = context.new_page()
                page.goto(uri, wait_until="networkidle")
                page.wait_for_timeout(900 if not reduced else 200)

                _shot(
                    page,
                    OUT / f"report-{vp_name}-{motion_name}-viewport.png",
                    full=False,
                )
                _shot(
                    page,
                    OUT / f"report-{vp_name}-{motion_name}-full.png",
                    full=True,
                )

                # Expand disclosures for section detail shots (once per viewport/motion).
                page.evaluate(
                    "() => document.querySelectorAll('details').forEach(d => { d.open = true; })"
                )
                for slug, sel in SECTIONS:
                    loc = page.locator(sel)
                    if loc.count() == 0:
                        continue
                    loc.first.scroll_into_view_if_needed()
                    page.wait_for_timeout(150)
                    loc.first.screenshot(
                        path=str(OUT / f"report-{vp_name}-{motion_name}-{slug}.png")
                    )

                # Print preview (emulate media print) — capture once per viewport for motion-on.
                if not reduced:
                    page.emulate_media(media="print")
                    page.wait_for_timeout(200)
                    _shot(
                        page,
                        OUT / f"report-{vp_name}-print-preview.png",
                        full=True,
                    )
                    page.emulate_media(media="screen")

                context.close()
        browser.close()


def capture_wizard() -> None:
    WIZARD_OUT.mkdir(parents=True, exist_ok=True)
    server = serve_wizard("127.0.0.1", 0, WIZARD_OUT)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    base = f"http://127.0.0.1:{port}"
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            for vp_name, (w, h) in VIEWPORTS.items():
                context = browser.new_context(
                    viewport={"width": w, "height": h},
                    color_scheme="dark",
                )
                page = context.new_page()
                page.goto(f"{base}/", wait_until="networkidle")
                page.wait_for_timeout(200)
                _shot(page, OUT / f"wizard-{vp_name}-mode.png", full=True)

                # Kick the offline demo so scan + report pages are also visible.
                page.select_option("select[name=profile]", "core")
                page.click("button[type=submit]")
                page.wait_for_url("**/scan", timeout=10000)
                page.wait_for_timeout(400)
                _shot(page, OUT / f"wizard-{vp_name}-scan.png", full=True)

                # Wait for report availability.
                deadline = time.time() + 90
                while time.time() < deadline:
                    resp = page.request.get(f"{base}/report")
                    if resp.ok and b"Security License Lens" in resp.body():
                        break
                    time.sleep(0.4)
                page.goto(f"{base}/report", wait_until="networkidle")
                page.wait_for_timeout(600)
                _shot(page, OUT / f"wizard-{vp_name}-report-viewport.png", full=False)
                context.close()
            browser.close()
    finally:
        server.shutdown()
        server.server_close()


def main() -> None:
    assert REPORT.is_file(), f"missing demo report at {REPORT}"
    OUT.mkdir(parents=True, exist_ok=True)
    print(f"capturing report → {OUT}")
    capture_report()
    print("capturing wizard")
    capture_wizard()
    shots = sorted(OUT.glob("*.png"))
    print(f"wrote {len(shots)} screenshots")
    for p in shots:
        print(f"  {p.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
