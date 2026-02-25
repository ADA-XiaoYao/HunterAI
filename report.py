"""
HunterAI — Intelligent Report Generator
=========================================
Produces professional penetration test reports from session data.
LLM generates the executive summary automatically.
Exports: HTML (styled), JSON (machine-readable), Markdown.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from pathlib import Path

from hunterai.core.engine  import BaseModule
from hunterai.core.session import HunterSession
from hunterai.llm.router   import LLMRouter, TaskType

logger = logging.getLogger(__name__)

SEVERITY_COLOR = {
    "critical": "#b91c1c",
    "high":     "#ea580c",
    "medium":   "#d97706",
    "low":      "#16a34a",
    "info":     "#2563eb",
}
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class ReportModule(BaseModule):
    name     = "report"
    category = "report"

    def __init__(self, bus, session: HunterSession, llm: LLMRouter,
                 out_dir: str = "/tmp/hunterai_reports", lang: str = "en") -> None:
        super().__init__(bus, session)
        self.llm     = llm
        self.out_dir = Path(out_dir)
        self.lang    = lang

    async def execute(self) -> None:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        sid = self.session.session_id

        executive_summary = await self._generate_executive_summary()
        sorted_findings   = sorted(
            self.session.findings,
            key=lambda f: SEVERITY_RANK.get(f.get("severity", "info"), 4)
        )

        self._write_html(sorted_findings, executive_summary)
        self._write_json(sorted_findings, executive_summary)
        self._write_markdown(sorted_findings, executive_summary)

        self.log.info("Reports written to %s/%s.[html|json|md]", self.out_dir, sid)

    # ------------------------------------------------------------------
    # Executive summary (LLM-generated)
    # ------------------------------------------------------------------

    async def _generate_executive_summary(self) -> str:
        snap = self.session.snapshot()
        top  = sorted(
            self.session.confirmed or self.session.findings,
            key=lambda f: SEVERITY_RANK.get(f.get("severity", "info"), 4)
        )[:5]

        prompt = f"""Write a professional 3-paragraph penetration test executive summary for a management audience.

Target: {self.session.target}
Test duration: {snap['elapsed_s']}s
Finding counts: {json.dumps(snap['severity'])}
Top findings (up to 5):
{json.dumps([{{"title": f.get("title"), "severity": f.get("severity")}} for f in top], indent=2)}

Paragraph 1: Overall security posture assessment.
Paragraph 2: Most critical risks and potential business impact.
Paragraph 3: Prioritised remediation guidance.

Write in clear, professional English. Do not use technical jargon. Do not include specific exploit details."""

        try:
            resp = await self.llm.complete(
                task_type=TaskType.REPORT_WRITING,
                messages=[{"role": "user", "content": prompt}],
                system="You are a senior penetration tester writing an executive summary.",
                max_tokens=800,
            )
            return resp["content"]
        except Exception as e:
            self.log.warning("LLM executive summary failed: %s", e)
            s = snap["severity"]
            return (
                f"This penetration test of {self.session.target} identified "
                f"{len(self.session.findings)} security issues: "
                f"{s['critical']} critical, {s['high']} high, "
                f"{s['medium']} medium, {s['low']} low severity. "
                f"\n\nCritical and high severity findings pose immediate risk and require urgent attention. "
                f"Exploitation of these issues could lead to unauthorized data access, "
                f"system compromise, or service disruption. "
                f"\n\nWe recommend addressing critical findings within 24 hours, "
                f"high severity within 1 week, and medium severity within 30 days."
            )

    # ------------------------------------------------------------------
    # HTML
    # ------------------------------------------------------------------

    def _write_html(self, findings: list[dict], summary: str) -> None:
        snap = self.session.snapshot()
        sid  = self.session.session_id

        # Severity summary cards
        cards = "".join(
            f'<div class="card">'
            f'<div class="card-count" style="color:{SEVERITY_COLOR[s]}">'
            f'{snap["severity"].get(s, 0)}</div>'
            f'<div class="card-label">{s.upper()}</div></div>'
            for s in ("critical", "high", "medium", "low", "info")
        )

        # Finding rows
        finding_html = ""
        for i, f in enumerate(findings, 1):
            sev     = f.get("severity", "info")
            color   = SEVERITY_COLOR.get(sev, "#999")
            chain   = ' <span class="tag-chain">⛓ CHAIN</span>' if f.get("chain") else ""
            llm     = ' <span class="tag-llm">🤖 AI</span>'   if f.get("llm_assisted") else ""
            ev_li   = "".join(f"<li><code>{e}</code></li>" for e in f.get("evidence", []))
            ref_li  = "".join(f'<li><a href="{r}" target="_blank">{r}</a></li>'
                              for r in f.get("refs", []))
            cvss    = f.get("cvss")

            finding_html += f"""
<div class="finding" id="f{i}">
  <div class="finding-header">
    <span class="finding-num">{i:02d}</span>
    <span class="finding-title">{f.get("title", "")}{chain}{llm}</span>
    <span class="badge" style="background:{color}">{sev.upper()}</span>
    {f'<span class="badge badge-cvss">CVSS {cvss}</span>' if cvss else ""}
  </div>
  <div class="finding-body">
    <p><strong>Component:</strong> <code>{f.get("component", "")}</code></p>
    <p>{f.get("description", "")}</p>
    {"<p><strong>Evidence:</strong></p><ul>" + ev_li + "</ul>" if f.get("evidence") else ""}
    {"<p><strong>Remediation:</strong> " + f.get("fix","") + "</p>" if f.get("fix") else ""}
    {"<p><strong>References:</strong></p><ul>" + ref_li + "</ul>" if f.get("refs") else ""}
  </div>
</div>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>HunterAI Report — {self.session.target}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Syne:wght@400;700;800&display=swap" rel="stylesheet">
  <style>
    :root {{
      --bg: #0a0e17; --surface: #111827; --border: #1f2937;
      --accent: #f97316; --accent2: #3b82f6;
      --text: #f1f5f9; --muted: #94a3b8;
      --critical: #b91c1c; --high: #ea580c;
      --medium: #d97706; --low: #16a34a; --info: #2563eb;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: 'Syne', sans-serif;
      background: var(--bg); color: var(--text);
      padding: 2rem; min-height: 100vh;
    }}
    .watermark {{
      position: fixed; top: 50%; left: 50%;
      transform: translate(-50%, -50%) rotate(-35deg);
      font-size: 6rem; font-weight: 800;
      color: rgba(249,115,22,0.04); pointer-events: none;
      white-space: nowrap; z-index: 0;
    }}
    .wrapper {{ max-width: 1100px; margin: 0 auto; position: relative; z-index: 1; }}
    .top-bar {{
      background: linear-gradient(135deg, #f97316 0%, #ef4444 50%, #3b82f6 100%);
      height: 4px; border-radius: 2px; margin-bottom: 2.5rem;
    }}
    .logo {{ font-size: 1rem; font-weight: 700; letter-spacing: 0.2em;
              color: var(--accent); text-transform: uppercase; margin-bottom: .3rem; }}
    h1 {{ font-size: 2.4rem; font-weight: 800; line-height: 1.1;
           margin-bottom: .5rem; }}
    .subtitle {{ color: var(--muted); font-size: .9rem; margin-bottom: 2rem; }}
    .confidential {{
      display: inline-block; border: 1px solid var(--critical);
      color: var(--critical); padding: .2rem .8rem; font-size: .75rem;
      letter-spacing: .15em; text-transform: uppercase; margin-bottom: 2rem;
    }}
    .meta-grid {{
      display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 1rem; margin-bottom: 2.5rem;
    }}
    .meta-item {{
      background: var(--surface); border: 1px solid var(--border);
      padding: 1rem; border-radius: 6px;
    }}
    .meta-item .val {{ font-size: 1.3rem; font-weight: 700; color: var(--accent); }}
    .meta-item .lbl {{ font-size: .75rem; color: var(--muted); margin-top: .2rem; }}
    .cards {{ display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 2.5rem; }}
    .card {{
      background: var(--surface); border: 1px solid var(--border);
      padding: 1.2rem 2rem; border-radius: 6px; text-align: center; flex: 1; min-width: 90px;
    }}
    .card-count {{ font-size: 2.2rem; font-weight: 800; }}
    .card-label {{ font-size: .7rem; letter-spacing: .1em; color: var(--muted);
                    margin-top: .2rem; text-transform: uppercase; }}
    section {{ margin-bottom: 3rem; }}
    h2 {{ font-size: 1.3rem; font-weight: 700; margin-bottom: 1.2rem;
           padding-bottom: .5rem; border-bottom: 1px solid var(--border); }}
    .exec-summary {{
      background: var(--surface); border-left: 3px solid var(--accent);
      padding: 1.5rem; border-radius: 0 6px 6px 0;
      white-space: pre-line; line-height: 1.8; color: #cbd5e1;
    }}
    .finding {{
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 8px; margin-bottom: 1rem; overflow: hidden;
    }}
    .finding-header {{
      display: flex; align-items: center; gap: .75rem;
      padding: 1rem 1.2rem; border-bottom: 1px solid var(--border);
      flex-wrap: wrap;
    }}
    .finding-num {{
      font-family: 'JetBrains Mono', monospace;
      font-size: .75rem; color: var(--muted);
    }}
    .finding-title {{ flex: 1; font-weight: 700; font-size: .95rem; }}
    .badge {{
      padding: .2rem .6rem; border-radius: 4px; color: #fff;
      font-size: .7rem; font-weight: 700; letter-spacing: .05em;
      text-transform: uppercase; white-space: nowrap;
    }}
    .badge-cvss {{ background: #374151; }}
    .tag-chain {{ color: #a78bfa; font-size: .8rem; }}
    .tag-llm   {{ color: #34d399; font-size: .8rem; }}
    .finding-body {{ padding: 1.2rem; line-height: 1.7; }}
    .finding-body p {{ margin-bottom: .8rem; color: #cbd5e1; font-size: .9rem; }}
    .finding-body ul {{ padding-left: 1.2rem; margin: .5rem 0; }}
    .finding-body li {{ color: #94a3b8; font-size: .85rem; margin-bottom: .3rem; }}
    code {{
      font-family: 'JetBrains Mono', monospace;
      background: #1e293b; padding: .15rem .4rem;
      border-radius: 3px; font-size: .82rem; color: #7dd3fc;
    }}
    a {{ color: var(--accent2); }}
    footer {{
      margin-top: 3rem; padding-top: 1.5rem;
      border-top: 1px solid var(--border);
      text-align: center; font-size: .75rem; color: var(--muted);
    }}
  </style>
</head>
<body>
<div class="watermark">CONFIDENTIAL</div>
<div class="wrapper">
  <div class="top-bar"></div>
  <div class="logo">HunterAI v1.0 · AlfaNet Organization</div>
  <h1>Penetration Test Report</h1>
  <div class="subtitle">
    Target: <strong>{self.session.target}</strong> &nbsp;·&nbsp;
    Session: <code>{sid[:8]}</code> &nbsp;·&nbsp;
    {datetime.now().strftime("%Y-%m-%d %H:%M UTC")}
  </div>
  <div class="confidential">⚠ Confidential — Authorized Recipients Only</div>

  <div class="meta-grid">
    <div class="meta-item"><div class="val">{snap["elapsed_s"]}s</div><div class="lbl">Duration</div></div>
    <div class="meta-item"><div class="val">{snap["subdomains"]}</div><div class="lbl">Subdomains</div></div>
    <div class="meta-item"><div class="val">{snap["endpoints"]}</div><div class="lbl">Endpoints</div></div>
    <div class="meta-item"><div class="val">{snap["confirmed"]}</div><div class="lbl">Confirmed</div></div>
    <div class="meta-item"><div class="val">{", ".join(snap["technologies"][:3]) or "—"}</div><div class="lbl">Tech Stack</div></div>
  </div>

  <section>
    <h2>Findings Overview</h2>
    <div class="cards">{cards}</div>
  </section>

  <section>
    <h2>Executive Summary</h2>
    <div class="exec-summary">{summary}</div>
  </section>

  <section>
    <h2>Detailed Findings ({len(findings)})</h2>
    {finding_html or '<p style="color:var(--muted)">No findings recorded.</p>'}
  </section>

  <footer>
    Generated by HunterAI v1.0 · AlfaNet Organization · xiaoyao ·
    {datetime.now().strftime("%Y-%m-%d %H:%M")}
  </footer>
</div>
</body>
</html>"""

        (self.out_dir / f"{sid}.html").write_text(html, encoding="utf-8")

    # ------------------------------------------------------------------
    # JSON
    # ------------------------------------------------------------------

    def _write_json(self, findings: list[dict], summary: str) -> None:
        data = {
            "generator":         "HunterAI v1.0",
            "organization":      "AlfaNet",
            "author":            "xiaoyao",
            "session":           self.session.snapshot(),
            "executive_summary": summary,
            "findings":          findings,
            "confirmed":         self.session.confirmed,
            "credentials_found": len(self.session.credentials),
            "generated_at":      datetime.now().isoformat(),
        }
        sid = self.session.session_id
        (self.out_dir / f"{sid}.json").write_text(
            json.dumps(data, ensure_ascii=False, indent=2))

    # ------------------------------------------------------------------
    # Markdown
    # ------------------------------------------------------------------

    def _write_markdown(self, findings: list[dict], summary: str) -> None:
        snap = self.session.snapshot()
        sid  = self.session.session_id
        lines = [
            f"# HunterAI Penetration Test Report",
            f"\n> **CONFIDENTIAL** — AlfaNet Organization / xiaoyao\n",
            f"**Target:** `{self.session.target}`  ",
            f"**Date:** {datetime.now().strftime('%Y-%m-%d')}  ",
            f"**Session:** `{sid[:8]}`  ",
            f"**Profile:** {self.session.profile}\n",
            f"---\n## Executive Summary\n",
            summary,
            f"\n---\n## Findings Overview\n",
        ]
        for sev in ("critical", "high", "medium", "low", "info"):
            n = snap["severity"].get(sev, 0)
            if n:
                lines.append(f"- **{sev.upper()}**: {n}")

        lines.append(f"\n---\n## Detailed Findings\n")
        for i, f in enumerate(findings, 1):
            chain = " ⛓ CHAIN" if f.get("chain") else ""
            ai    = " 🤖 AI"   if f.get("llm_assisted") else ""
            cvss  = f" | CVSS {f['cvss']}" if f.get("cvss") else ""
            lines += [
                f"### {i}. {f.get('title','')}{chain}{ai}",
                f"**Severity:** {f.get('severity','').upper()}{cvss}  "
                f"| **Component:** `{f.get('component','')}`\n",
                f"{f.get('description', '')}\n",
            ]
            if f.get("evidence"):
                lines.append("**Evidence:**")
                for e in f["evidence"]:
                    lines.append(f"- `{e}`")
            if f.get("fix"):
                lines.append(f"\n**Remediation:** {f['fix']}")
            if f.get("refs"):
                lines.append("\n**References:**")
                for r in f["refs"]:
                    lines.append(f"- {r}")
            lines.append("\n---")

        (self.out_dir / f"{sid}.md").write_text("\n".join(lines), encoding="utf-8")
