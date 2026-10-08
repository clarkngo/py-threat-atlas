#!/usr/bin/env python3
"""Py-Threat-Atlas build tool.

    python tools/atlas.py refresh   # run every model, write dfd.svg, update README findings blocks
    python tools/atlas.py check     # fail if any README findings block is stale (CI)
    python tools/atlas.py site      # render the static site into _site/

Each system lives in systems/<tier>/<slug>/ with a model.py and README.md.
README.md contains a generated block between the markers below; everything
else in the README is hand-written analysis.
"""

import html
import json
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SYSTEMS = ROOT / "systems"
SITE = ROOT / "_site"
ASSETS = Path(__file__).resolve().parent / "site"
THREATLIB = ROOT / "threatlib" / "atlas_threats.json"

BEGIN = "<!-- atlas:findings:begin -->"
END = "<!-- atlas:findings:end -->"

TIERS = [
    ("traditional", "Traditional Apps", "Web, API and identity architectures: the baseline every later tier inherits."),
    ("cloud", "Cloud-Native Apps", "Serverless, containers and managed services: identity and configuration become the perimeter."),
    ("ai", "AI-Enabled Apps", "LLMs and ML models in the loop: untrusted text becomes an instruction channel."),
    ("agentic", "Agentic Apps", "Models that plan and act with tools: prompt injection becomes privileged action."),
]
# Reading order within each tier (simpler systems first); unlisted systems sort alphabetically after these.
ORDER = [
    "saas-oidc-login", "ecommerce-checkout", "mobile-banking-backend", "microservices-order-platform",
    "serverless-file-upload", "multi-tenant-eks-saas", "azure-iot-fleet", "gcp-data-lakehouse",
    "rag-support-chatbot", "ml-fraud-scoring", "enterprise-llm-gateway", "invoice-document-ai",
    "sre-incident-agent", "multi-agent-customer-ops",
]
STRIDE = [
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege",
]
SEVERITY_ORDER = {"Very High": 0, "High": 1, "Medium": 2, "Low": 3, "Very Low": 4}
STATUSES = ["open", "mitigated", "transferred", "accepted", "avoided"]


@dataclass
class System:
    tier: str
    slug: str
    path: Path
    title: str = ""
    summary: str = ""
    findings: list = field(default_factory=list)
    model: dict = field(default_factory=dict)
    svg: str = ""

    @property
    def rel(self):
        return f"{self.tier}/{self.slug}"


def load_threatlib():
    return {t["SID"]: t for t in json.loads(THREATLIB.read_text(encoding="utf8"))}


def discover():
    systems = []
    for tier, _, _ in TIERS:
        models = (SYSTEMS / tier).glob("*/model.py")
        rank = lambda m: (ORDER.index(m.parent.name) if m.parent.name in ORDER else len(ORDER), m.parent.name)
        for model in sorted(models, key=rank):
            systems.append(System(tier=tier, slug=model.parent.name, path=model.parent))
    return systems


EDGE = re.compile(r"^    (\w+) -> (\w+) \[\n(.*?)^    \]\n", re.M | re.S)


def merge_parallel_edges(dfd):
    """Draw all flows between one pair of nodes as a single edge.

    Graphviz can place the labels of parallel or opposing edges on top of each
    other; one arrow (two-headed if flows go both ways) with stacked labels
    ("(3) ...", "(13) ...") stays readable.
    """
    first, labels, directions = {}, {}, {}
    for m in EDGE.finditer(dfd):
        key = frozenset((m[1], m[2]))
        label = re.search(r'label = "(.*)";', m[3])
        labels.setdefault(key, []).append(label[1] if label else "")
        directions.setdefault(key, set()).add((m[1], m[2]))
        first.setdefault(key, m.start())

    def replace(m):
        key = frozenset((m[1], m[2]))
        if len(labels[key]) == 1:
            return m[0]
        if m.start() != first[key]:
            return ""  # folded into the first edge of this pair
        merged = "\\n".join(labels[key])
        edge = re.sub(r'label = ".*";', lambda _: f'label = "{merged}";', m[0], count=1)
        if len(directions[key]) == 2:
            edge = re.sub(r"dir = \w+;", "dir = both;", edge, count=1)
        return edge

    return EDGE.sub(replace, dfd)


def run_model(system, threatlib):
    model = system.path / "model.py"
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "tm.json"
        result = subprocess.run(
            [sys.executable, str(model), "--json", str(out)],
            cwd=system.path, capture_output=True, text=True,
        )
        if result.returncode != 0:
            sys.exit(f"{system.rel}: model failed\n{result.stderr}")
        data = json.loads(out.read_text(encoding="utf8"))

    dfd = subprocess.run(
        [sys.executable, str(model), "--dfd"], cwd=system.path, capture_output=True, text=True, check=True
    ).stdout
    # pytm's default top-to-bottom layout spreads boundaries horizontally and becomes
    # unreadable when scaled to page width; a left-to-right rank layout stacks them.
    dfd = dfd.replace("fontsize = 14;\n    ]", "fontsize = 14;\n        rankdir = LR;\n        ranksep = 1.1;\n    ]", 1)
    # Boundaries and Lambdas use HTML-like labels: pytm's "\n" wraps show literally there and a bare
    # "&" makes Graphviz fail, so convert the former to <br/> and escape the latter.
    def fix_html_label(m):
        text = re.sub(r"&(?!amp;|lt;|gt;|quot;|#)", "&amp;", m[2]).replace(chr(92) + "n", "<br/>")
        return f"<{m[1]}>{text}</{m[1]}>"

    dfd = re.sub(r"<(i|b)>(.*?)</\1>", fix_html_label, dfd, flags=re.S)
    dfd = merge_parallel_edges(dfd)
    svg = subprocess.run(["dot", "-Tsvg"], input=dfd, capture_output=True, text=True, check=True).stdout
    # Graphviz embeds its version in a comment; drop it so output is stable across machines.
    svg = re.sub(r"<!-- Generated by graphviz.*?-->\n", "", svg)

    findings = []
    for f in data["findings"]:
        threat = threatlib[f["threat_id"]]
        response = (f.get("response") or "").strip()
        status = response.split(":", 1)[0].strip().lower() if response else "open"
        if status not in STATUSES:
            sys.exit(f"{system.rel}: unknown response status in {response!r}")
        findings.append(
            {
                "threat_id": f["threat_id"],
                "threat": threat["description"],
                "target": f["target"],
                "severity": f["severity"],
                "stride": threat["stride"],
                "source": threat["source"],
                "status": status,
                "response": response.split(":", 1)[1].strip() if ":" in response else response,
                "mitigations": threat["mitigations"],
                "references": threat["references"],
            }
        )
    findings.sort(key=lambda f: (f["status"] != "open", SEVERITY_ORDER.get(f["severity"], 9), f["threat_id"], f["target"]))
    system.findings = findings
    system.model = data
    system.svg = svg
    return svg


def md_escape(text):
    return text.replace("|", "\\|").replace("\n", " ")


def findings_block(system):
    findings = system.findings
    open_findings = [f for f in findings if f["status"] == "open"]
    lines = [
        BEGIN,
        "<!-- Generated by tools/atlas.py refresh. Do not edit by hand. -->",
        "",
        "### pytm Findings Register",
        "",
        f"`pytm` evaluated **{len(system.model['elements'])} elements** and **{len(system.model['flows'])} dataflows** against "
        f"**{len(load_threatlib())} threat rules** and produced **{len(findings)} findings**: "
        f"**{len(open_findings)} open** and {len(findings) - len(open_findings)} with a recorded response "
        "(mitigated, transferred or accepted, set via `overrides` in `model.py`).",
        "",
        "| STRIDE | Open | Responded | Total |",
        "|---|---:|---:|---:|",
    ]
    for category in STRIDE:
        in_cat = [f for f in findings if f["stride"] == category]
        opened = sum(f["status"] == "open" for f in in_cat)
        lines.append(f"| {category} | {opened} | {len(in_cat) - opened} | {len(in_cat)} |")
    lines.append(f"| **Total** | **{len(open_findings)}** | **{len(findings) - len(open_findings)}** | **{len(findings)}** |")
    lines += ["", "#### Open findings", ""]
    if open_findings:
        lines += ["| Threat | Element | STRIDE | Severity |", "|---|---|---|---|"]
        for f in open_findings:
            lines.append(
                f"| `{f['threat_id']}` {md_escape(f['threat'])} | {md_escape(f['target'])} | {f['stride']} | {f['severity']} |"
            )
    else:
        lines.append("_No open findings._")
    responded = [f for f in findings if f["status"] != "open"]
    if responded:
        lines += [
            "",
            "<details>",
            f"<summary>Findings with a recorded response ({len(responded)})</summary>",
            "",
            "| Threat | Element | Severity | Status | Rationale |",
            "|---|---|---|---|---|",
        ]
        for f in responded:
            lines.append(
                f"| `{f['threat_id']}` {md_escape(f['threat'])} | {md_escape(f['target'])} | {f['severity']} "
                f"| {f['status'].title()} | {md_escape(f['response'])} |"
            )
        lines += ["", "</details>"]
    lines += ["", END]
    return "\n".join(lines)


def parse_readme(system):
    text = (system.path / "README.md").read_text(encoding="utf8")
    title = re.search(r"^# (.+)$", text, re.M)
    system.title = title.group(1).strip() if title else system.slug
    summary = re.search(r"^> (.+)$", text, re.M)
    system.summary = summary.group(1).strip() if summary else ""
    return text


def refresh(write=True):
    threatlib = load_threatlib()
    changed = []
    systems = discover()
    for system in systems:
        svg = run_model(system, threatlib)
        targets = {system.path / "dfd.svg": svg}
        readme = parse_readme(system)
        if BEGIN not in readme or END not in readme:
            sys.exit(f"{system.rel}/README.md is missing the {BEGIN} / {END} markers")
        start, end = readme.index(BEGIN), readme.index(END) + len(END)
        targets[system.path / "README.md"] = readme[:start] + findings_block(system) + readme[end:]
        for path, content in targets.items():
            if not path.exists() or path.read_text(encoding="utf8") != content:
                changed.append(path.relative_to(ROOT))
                if write:
                    path.write_text(content, encoding="utf8")
        opened = sum(f["status"] == "open" for f in system.findings)
        print(f"{system.rel}: {len(system.findings)} findings ({opened} open)")
    return systems, changed


# --- Static site ----------------------------------------------------------------


def render_markdown(text):
    from markdown_it import MarkdownIt

    md = MarkdownIt("commonmark", {"html": True, "linkify": False, "typographer": False}).enable("table")
    return md.render(text)


def page(title, body, depth, description=""):
    prefix = "../" * depth
    nav = "".join(
        f'<a href="{prefix}index.html#{tier}">{html.escape(name.split()[0])}</a>' for tier, name, _ in TIERS
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<meta name="description" content="{html.escape(description)}">
<link rel="stylesheet" href="{prefix}assets/style.css">
<link rel="icon" href="{prefix}assets/favicon.svg" type="image/svg+xml">
</head>
<body>
<header class="site-header">
  <a class="brand" href="{prefix}index.html"><img src="{prefix}assets/favicon.svg" alt="" width="22" height="22"> Py-Threat-Atlas</a>
  <nav>{nav}<a href="{prefix}threats.html">Threat library</a></nav>
</header>
<main>
{body}
</main>
<footer class="site-footer">
  Threat models as code with <a href="https://github.com/OWASP/pytm">OWASP pytm</a>.
  Findings are regenerated from each <code>model.py</code> on every build.
</footer>
</body>
</html>
"""


def severity_badge(severity):
    cls = severity.lower().replace(" ", "-")
    return f'<span class="sev sev-{cls}">{html.escape(severity)}</span>'


def stride_bar(findings):
    counts = Counter(f["stride"] for f in findings if f["status"] == "open")
    cells = "".join(
        f'<span title="{c}: {counts.get(c, 0)} open"><b>{c[0]}</b>{counts.get(c, 0)}</span>' for c in STRIDE
    )
    return f'<div class="stride-bar">{cells}</div>'


def build_system_page(system):
    readme = parse_readme(system)
    body_md = re.sub(r"^# .+\n", "", readme, count=1)
    body = render_markdown(body_md)
    body = re.sub(r'(<img src="dfd.svg"[^>]*>)', r'<a href="dfd.svg" title="Open full-size diagram">\1</a>', body)
    # Severity text in generated tables -> badges.
    for sev in SEVERITY_ORDER:
        body = body.replace(f"<td>{sev}</td>", f"<td>{severity_badge(sev)}</td>")
    opened = sum(f["status"] == "open" for f in system.findings)
    tier_name = next(name for tier, name, _ in TIERS if tier == system.tier)
    header = f"""
<article class="system">
<p class="crumbs"><a href="../../index.html#{system.tier}">{html.escape(tier_name)}</a></p>
<h1>{html.escape(system.title)}</h1>
<div class="meta">
  <span><b>{len(system.findings)}</b> findings</span>
  <span><b>{opened}</b> open</span>
  <span><b>{len(system.model['elements'])}</b> elements</span>
  <span><b>{len(system.model['flows'])}</b> dataflows</span>
  <a href="model.py">model.py</a>
  <a href="findings.json">findings.json</a>
</div>
{stride_bar(system.findings)}
"""
    return page(f"{system.title} | Py-Threat-Atlas", header + body + "</article>", 3, system.summary)


def build_index(systems):
    sections = []
    for tier, name, blurb in TIERS:
        cards = []
        for s in (s for s in systems if s.tier == tier):
            opened = [f for f in s.findings if f["status"] == "open"]
            top = min((f["severity"] for f in opened), key=lambda x: SEVERITY_ORDER.get(x, 9), default=None)
            atlas = sum(f["source"] == "atlas" for f in s.findings)
            atlas_note = f"<span>{atlas} from Atlas rules</span>" if atlas else ""
            top_note = f"<span>top open {severity_badge(top)}</span>" if top else ""
            cards.append(
                f"""<a class="card" href="systems/{s.rel}/index.html">
  <h3>{html.escape(s.title)}</h3>
  <p>{html.escape(s.summary)}</p>
  <div class="card-meta"><span>{len(s.findings)} findings</span><span>{len(opened)} open</span>{atlas_note}{top_note}</div>
  {stride_bar(s.findings)}
</a>"""
            )
        sections.append(
            f"""<section class="tier" id="{tier}">
  <div class="tier-head"><h2>{html.escape(name)}</h2><p>{html.escape(blurb)}</p></div>
  <div class="cards">{''.join(cards)}</div>
</section>"""
        )
    total = sum(len(s.findings) for s in systems)
    body = f"""
<section class="hero">
  <h1>Threat models as code, from web apps to autonomous agents.</h1>
  <p>Each system below is an executable <a href="https://github.com/OWASP/pytm">OWASP pytm</a> model with a data flow
  diagram, a STRIDE findings register produced by pytm, and a written mitigation strategy. The models go in four tiers;
  each tier keeps the threats of the one before it and adds new ones.</p>
  <div class="hero-stats"><span><b>{len(systems)}</b> systems</span><span><b>{len(load_threatlib())}</b> threat rules</span><span><b>{total}</b> findings</span></div>
  <p class="legend">STRIDE strip on each card: <b>S</b>poofing · <b>T</b>ampering · <b>R</b>epudiation ·
  <b>I</b>nformation disclosure · <b>D</b>enial of service · <b>E</b>levation of privilege (open findings).</p>
</section>
{''.join(sections)}
"""
    return page("Py-Threat-Atlas", body, 0, "Threat models as code with OWASP pytm across traditional, cloud, AI and agentic systems.")


def build_threats_page(threatlib):
    rows = []
    for t in sorted(threatlib.values(), key=lambda t: (t["source"] != "atlas", t["SID"])):
        targets = t["target"] if isinstance(t["target"], list) else [t["target"]]
        origin = "Atlas" if t["source"] == "atlas" else ("pytm (patched)" if t.get("patched") else "pytm")
        rows.append(
            f"<tr><td><code>{t['SID']}</code></td><td><b>{html.escape(t['description'])}</b>"
            f"<details><summary>Details</summary><p>{html.escape(t['details'])}</p>"
            f"<p><b>Mitigations:</b> {html.escape(t['mitigations'])}</p>"
            f"<p><b>Condition:</b> <code>{html.escape(t['condition'])}</code></p>"
            f"<p class='refs'>{html.escape(t['references'])}</p></details></td>"
            f"<td>{html.escape(', '.join(targets))}</td><td>{t['stride']}</td>"
            f"<td>{severity_badge(t['severity'])}</td><td>{origin}</td></tr>"
        )
    body = f"""
<article class="system">
<h1>Threat library</h1>
<p>The merged library used by every model: the {sum(t['source'] == 'pytm' for t in threatlib.values())} stock pytm
rules (CAPEC-derived) plus {sum(t['source'] == 'atlas' for t in threatlib.values())} Atlas extensions for cloud
(<code>CLD</code>), AI/LLM (<code>AI</code>) and agentic (<code>AGT</code>) systems. Each rule has a primary STRIDE category.
Extension rules read custom element attributes such as <code>isLLM</code>, <code>isAgent</code> and <code>isToolCall</code>
through <code>getattr</code>, so models that don't set them are unaffected.</p>
<div class="table-wrap"><table class="threats">
<thead><tr><th>ID</th><th>Threat</th><th>Targets</th><th>STRIDE</th><th>Severity</th><th>Origin</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table></div>
</article>"""
    return page("Threat library | Py-Threat-Atlas", body, 0, "Merged pytm + Atlas threat rules.")


def site():
    systems, changed = refresh(write=False)
    stale = [path for path in changed if path.suffix == ".md"]
    if stale:
        sys.exit("README findings blocks are stale; run `python tools/atlas.py refresh` first:\n  " + "\n  ".join(map(str, stale)))
    if SITE.exists():
        shutil.rmtree(SITE)
    shutil.copytree(ASSETS, SITE / "assets")
    for system in systems:
        out = SITE / "systems" / system.tier / system.slug
        out.mkdir(parents=True)
        (out / "index.html").write_text(build_system_page(system), encoding="utf8")
        (out / "dfd.svg").write_text(system.svg, encoding="utf8")  # freshly rendered, not the committed copy
        shutil.copy(system.path / "model.py", out / "model.py")
        (out / "findings.json").write_text(json.dumps(system.findings, indent=2), encoding="utf8")
    (SITE / "index.html").write_text(build_index(systems), encoding="utf8")
    (SITE / "threats.html").write_text(build_threats_page(load_threatlib()), encoding="utf8")
    (SITE / ".nojekyll").write_text("", encoding="utf8")
    print(f"Site written to {SITE.relative_to(ROOT)}/")


def main():
    command = sys.argv[1] if len(sys.argv) > 1 else "refresh"
    if command == "refresh":
        refresh()
    elif command == "check":
        _, changed = refresh(write=False)
        # dfd.svg output varies with the Graphviz version, so only README findings blocks are enforced.
        changed = [path for path in changed if path.suffix == ".md"]
        if changed:
            sys.exit("Stale generated files:\n  " + "\n  ".join(map(str, changed)))
        print("All generated files are up to date.")
    elif command == "site":
        site()
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
