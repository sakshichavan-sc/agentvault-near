#!/usr/bin/env python3
"""Inline redteam-report.json into web/index.html so the page works from file:// and GitHub Pages."""
import json, pathlib
root = pathlib.Path(__file__).resolve().parent.parent
data = json.loads((root / "redteam-report.json").read_text())
html = (root / "web" / "template.html").read_text().replace("/*DATA*/null", json.dumps(data))
(root / "web" / "index.html").write_text(html)
print("wrote web/index.html")
