#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
md2pdf_chrome.py — Convert Markdown → PDF using headless Chromium (Playwright).
No GTK/Pango needed (works great on Windows).
Usage:
  python md2pdf_chrome.py input.md -o output.pdf [--css theme.css] [--title "My Doc"]
"""

import argparse
from pathlib import Path
from datetime import datetime
import tempfile

import markdown as md
from pygments.formatters import HtmlFormatter

from playwright.sync_api import sync_playwright

BASE_CSS = r"""
@page { size: A4; margin: 22mm 18mm 20mm 18mm; }
html { font-size: 11pt; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Inter, "Helvetica Neue", Arial, "Noto Sans", "Liberation Sans", sans-serif;
  line-height: 1.5; color: #1a1a1a;
}
h1, h2, h3 { margin: 1.2em 0 .5em; font-weight: 700; }
h1 { font-size: 1.9rem; border-bottom: 2px solid #eee; padding-bottom: .3rem; }
h2 { font-size: 1.5rem; border-left: 4px solid #ddd; padding-left: .5rem; }
p { margin: .6em 0; }
ul, ol { margin: .6em 0 .6em 1.5em; }
a { color: #0366d6; text-decoration: none; }
a:hover { text-decoration: underline; }
img { max-width: 100%; }
table { border-collapse: collapse; margin: 1em 0; width: 100%; }
th, td { border: 1px solid #e5e5e5; padding: .5em .6em; vertical-align: top; }
pre { background: #f6f8fa; border: 1px solid #e5e5e5; padding: .8em; overflow: auto; border-radius: 6px; }
blockquote { margin: 1em 0; padding: .6em .8em; background: #fafafa; border-left: 4px solid #e0e0e0; color:#555; }
.page-break { break-before: page; }
"""

HTML_TPL = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>
{base_css}
{pyg_css}
</style>
{custom_css}
</head>
<body>
<header style="margin-bottom:10px;">
  <div style="font-size:12px;color:#666;">Generated: {gen}</div>
</header>
<main>
{content}
</main>
</body>
</html>"""

def build_html(md_text: str, title: str|None, custom_css_str: str|None) -> str:
    exts = [
        "extra", "codehilite", "toc", "sane_lists", "admonition", "smarty",
    ]
    conv = md.Markdown(extensions=exts, extension_configs={
        "codehilite": {"guess_lang": True, "noclasses": False}
    })
    body = conv.convert(md_text)

    # Tiêu đề: lấy <h1> đầu tiên nếu không ép --title
    import re
    doc_title = title
    if not doc_title:
        m = re.search(r"<h1[^>]*>(.*?)</h1>", body, flags=re.I|re.S)
        if m:
            doc_title = re.sub(r"<[^>]+>", "", m.group(1)).strip()
        else:
            doc_title = "Document"

    pyg_css = HtmlFormatter().get_style_defs(".codehilite")
    css_tag = f"<style>\n{custom_css_str}\n</style>" if custom_css_str else ""
    return HTML_TPL.format(
        title=doc_title,
        base_css=BASE_CSS,
        pyg_css=pyg_css,
        custom_css=css_tag,
        gen=datetime.now().strftime("%Y-%m-%d %H:%M"),
        content=body
    )

def main():
    ap = argparse.ArgumentParser(description="Export Markdown to PDF via headless Chromium (Playwright).")
    ap.add_argument("input", help="Input .md/.markdown")
    ap.add_argument("-o", "--output", help="Output .pdf (default: same name as input)")
    ap.add_argument("--css", help="Optional extra CSS file to embed", default=None)
    ap.add_argument("--title", help="Force document title", default=None)
    args = ap.parse_args()

    in_path = Path(args.input).resolve()
    if not in_path.exists() or in_path.suffix.lower() not in {".md", ".markdown"}:
        raise SystemExit("✖ Input must be an existing .md/.markdown file.")

    out_path = Path(args.output).resolve() if args.output else in_path.with_suffix(".pdf")
    extra_css = Path(args.css).read_text(encoding="utf-8") if args.css else None

    html = build_html(in_path.read_text(encoding="utf-8"), args.title, extra_css)

    # Lưu HTML tạm để Chromium render, base_url giúp ảnh relative hoạt động
    with tempfile.TemporaryDirectory() as tmp:
        html_path = Path(tmp, "doc.html")
        html_path.write_text(html, encoding="utf-8")

        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            page.goto(html_path.as_uri(), wait_until="load")
            page.pdf(
                path=str(out_path),
                format="A4",
                print_background=True,
                margin={"top": "18mm", "bottom": "18mm", "left": "14mm", "right": "14mm"},
            )
            browser.close()

    print(f"✓ Wrote PDF: {out_path}")

if __name__ == "__main__":
    main()
