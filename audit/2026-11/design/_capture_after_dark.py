#!/usr/bin/env python3
"""Capture after-dark shots for Exposure Console. Not part of the product."""

from __future__ import annotations

import subprocess
import threading
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

from licenselens.ui.pages import serve_wizard

ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / "audit" / "2026-11" / "design" / "after-dark"
REPORT_DIR = Path("/tmp/ll-demo-after-dark")
REPORT = REPORT_DIR / "security-license-lens-report.html"
WIZARD_OUT = Path("/tmp/ll-wizard-after-dark")

VIEWPORTS = {
    "1440": (1440, 1100),
    "1280": (1280, 1000),
    "390": (390, 844),
}

# Curated review set (matches after/ naming used for Ledger).
CURATED = {
    ("1440", "motion-on"): ("viewport", "hero", "priorities"),
    ("1440", "motion-off"): ("viewport", "hero", "priorities"),
    ("1280", "motion-on"): ("viewport", "hero", "priorities"),
    ("1280", "motion-off"): ("viewport", "hero"),
    ("390", "motion-on"): ("viewport", "hero", "priorities"),
    ("390", "motion-off"): ("viewport", "hero", "priorities"),
}

SECTIONS = {
    "hero": "#section-a",
    "priorities": "#section-c",
}


def _shot(page, path: Path, *, full: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    page.screenshot(path=str(path), full_page=full)


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


def capture_report() -> None:
    uri = REPORT.resolve().as_uri()
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        for motion_name, reduced in (("motion-on", False), ("motion-off", True)):
            for vp_name, (w, h) in VIEWPORTS.items():
                wanted = CURATED.get((vp_name, motion_name), ("viewport",))
                context = browser.new_context(
                    viewport={"width": w, "height": h},
                    reduced_motion="reduce" if reduced else "no-preference",
                    color_scheme="dark",
                )
                page = context.new_page()
                page.goto(uri, wait_until="networkidle")
                page.wait_for_timeout(900 if not reduced else 200)

                if "viewport" in wanted:
                    _shot(
                        page,
                        OUT / f"report-{vp_name}-{motion_name}-viewport.png",
                        full=False,
                    )

                page.evaluate(
                    "() => document.querySelectorAll('details').forEach(d => { d.open = true; })"
                )
                for slug in wanted:
                    if slug == "viewport":
                        continue
                    sel = SECTIONS.get(slug)
                    if not sel:
                        continue
                    loc = page.locator(sel)
                    if loc.count() == 0:
                        continue
                    loc.first.scroll_into_view_if_needed()
                    page.wait_for_timeout(150)
                    loc.first.screenshot(
                        path=str(OUT / f"report-{vp_name}-{motion_name}-{slug}.png")
                    )

                if vp_name == "1280" and not reduced:
                    page.emulate_media(media="print")
                    page.wait_for_timeout(200)
                    _shot(page, OUT / "report-1280-print-firstpage.png", full=False)
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
            context = browser.new_context(
                viewport={"width": 1440, "height": 1100},
                color_scheme="dark",
            )
            page = context.new_page()
            page.goto(f"{base}/", wait_until="networkidle")
            page.wait_for_timeout(200)
            _shot(page, OUT / "wizard-1440-mode.png", full=True)

            page.select_option("select[name=profile]", "core")
            page.click("button[type=submit]")
            page.wait_for_url("**/scan", timeout=10000)
            page.wait_for_timeout(400)
            _shot(page, OUT / "wizard-1440-scan.png", full=True)

            deadline = time.time() + 90
            while time.time() < deadline:
                resp = page.request.get(f"{base}/report")
                if resp.ok and b"Security License Lens" in resp.body():
                    break
                time.sleep(0.4)
            page.goto(f"{base}/report", wait_until="networkidle")
            page.wait_for_timeout(600)
            _shot(page, OUT / "wizard-1440-report-viewport.png", full=False)
            context.close()
            browser.close()
    finally:
        server.shutdown()
        server.server_close()


def main() -> None:
    ensure_demo_report()
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
