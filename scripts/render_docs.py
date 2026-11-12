#!/usr/bin/env python3
"""Render the documentation images (docs/architecture.png, docs/design.png).

Uses Playwright driving an installed Microsoft Edge or Google Chrome, so no browser download is needed:

  pip install -r requirements-docs.txt
  python scripts/render_docs.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import markdown
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

DESIGN_CSS = """
body { margin: 0; background: #fff; color: #16191f; font: 15px/1.55 "Segoe UI", Arial, sans-serif; }
main { width: 1240px; padding: 44px 56px 56px; }
h1 { font-size: 30px; margin: 0 0 18px; padding-bottom: 12px; border-bottom: 4px solid #ef6c00; }
h2 { font-size: 22px; margin: 34px 0 10px; padding-bottom: 6px; border-bottom: 1px solid #d5dbe1; color: #232f3e; }
h3 { font-size: 17px; margin: 22px 0 6px; color: #c62828; }
ul, ol { padding-left: 24px; margin: 6px 0; } li { margin: 3px 0; }
code { font-family: Consolas, monospace; font-size: 13px; background: #f3f5f7; padding: 1px 5px; border-radius: 4px; }
pre { background: #232f3e; color: #e8edf2; padding: 14px 18px; border-radius: 8px; font-size: 13px; line-height: 1.45; }
pre code { background: none; color: inherit; padding: 0; }
table { border-collapse: collapse; width: 100%; margin: 10px 0 14px; font-size: 13.5px; }
th { background: #232f3e; color: #fff; text-align: left; padding: 7px 10px; }
td { padding: 6px 10px; border-bottom: 1px solid #e3e7eb; vertical-align: top; }
tr:nth-child(even) td { background: #f8fafb; }
strong { color: #0d1117; }
.footer { margin-top: 30px; color: #6b7480; font-size: 12px; }
"""


def launch(p):
    for channel in ("msedge", "chrome"):
        try:
            return p.chromium.launch(channel=channel)
        except Exception:  # noqa: BLE001 - try the next installed browser
            continue
    return p.chromium.launch()  # falls back to a Playwright-managed Chromium


def main() -> int:
    md = (DOCS / "DESIGN.md").read_text(encoding="utf-8")
    body = markdown.markdown(md, extensions=["tables", "fenced_code", "sane_lists"])
    design_html = (
        f"<!doctype html><html><head><meta charset='utf-8'><style>{DESIGN_CSS}</style></head>"
        f"<body><main>{body}<div class='footer'>Rendered from docs/DESIGN.md</div></main></body></html>"
    )

    with sync_playwright() as p:
        browser = launch(p)

        page = browser.new_page(viewport={"width": 1900, "height": 1390}, device_scale_factor=1.5)
        page.goto((DOCS / "src" / "architecture.html").as_uri())
        page.wait_for_selector("body[data-ready='1']")
        page.locator("#canvas").screenshot(path=str(DOCS / "architecture.png"))
        print("wrote docs/architecture.png")

        page = browser.new_page(viewport={"width": 1240, "height": 1000}, device_scale_factor=1.5)
        page.set_content(design_html, wait_until="load")
        page.locator("main").screenshot(path=str(DOCS / "design.png"))
        print("wrote docs/design.png")

        browser.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
