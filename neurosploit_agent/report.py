"""
Report generation for NeuroSploit v3.3.0.

Produces a polished **HTML** report from a run's validated findings, plus a
**PDF** via the Typst engine when the `typst` binary is available (it is the
intended report engine; HTML is always emitted as a fallback/companion).

    from neurosploit_agent.report import generate
    paths = generate(target, findings, out_dir)   # -> {"html":..., "pdf":..., "typ":...}
"""

import datetime
import html
import os
import shutil
import subprocess
from typing import Dict, List, Optional

SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
SEV_COLOR = {"Critical": "#c0392b", "High": "#e67e22", "Medium": "#f1c40f",
             "Low": "#3498db", "Info": "#7f8c8d"}


def _sorted(findings: List[Dict]) -> List[Dict]:
    return sorted(findings, key=lambda f: SEV_ORDER.get(f.get("severity", "Info"), 9))


def _counts(findings: List[Dict]) -> Dict[str, int]:
    c = {}
    for f in findings:
        c[f.get("severity", "Info")] = c.get(f.get("severity", "Info"), 0) + 1
    return c


def typst_available() -> bool:
    return shutil.which("typst") is not None


# --------------------------------------------------------------------------- HTML
def render_html(target: str, findings: List[Dict], when: str) -> str:
    counts = _counts(findings)
    chips = "".join(
        f'<span class="chip" style="background:{SEV_COLOR.get(s,"#777")}">{s}: {n}</span>'
        for s, n in sorted(counts.items(), key=lambda kv: SEV_ORDER.get(kv[0], 9))
    ) or '<span class="chip" style="background:#27ae60">No validated findings</span>'
    rows = []
    for i, f in enumerate(_sorted(findings), 1):
        sev = f.get("severity", "Info")
        rows.append(f"""
        <section class="finding">
          <h3><span class="sev" style="background:{SEV_COLOR.get(sev,'#777')}">{html.escape(sev)}</span>
              {i}. {html.escape(str(f.get('title','Untitled')))}</h3>
          <table class="kv">
            <tr><th>Agent</th><td>{html.escape(str(f.get('agent','')))}</td>
                <th>CWE</th><td>{html.escape(str(f.get('cwe','')))}</td></tr>
            <tr><th>CVSS</th><td>{html.escape(str(f.get('cvss','')))}</td>
                <th>Confidence</th><td>{html.escape(str(f.get('confidence','')))}</td></tr>
            <tr><th>Endpoint</th><td colspan="3">{html.escape(str(f.get('endpoint','')))}</td></tr>
          </table>
          <h4>Payload</h4><pre>{html.escape(str(f.get('payload','')))}</pre>
          <h4>Evidence</h4><pre>{html.escape(str(f.get('evidence','')))}</pre>
          <h4>Impact</h4><p>{html.escape(str(f.get('impact','')))}</p>
          <h4>Remediation</h4><p>{html.escape(str(f.get('remediation','')))}</p>
        </section>""")
    body = "\n".join(rows) or "<p><em>No validated findings were produced for this engagement.</em></p>"
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>NeuroSploit Report — {html.escape(target)}</title>
<style>
 body{{font:14px/1.6 -apple-system,Segoe UI,Roboto,sans-serif;color:#1a1a1a;max-width:860px;margin:40px auto;padding:0 24px}}
 h1{{margin:0;font-size:26px}} .meta{{color:#666;margin:4px 0 18px}}
 .chips{{margin:14px 0 28px}} .chip{{color:#fff;border-radius:999px;padding:4px 12px;margin-right:8px;font-size:13px;font-weight:600}}
 .finding{{border:1px solid #e3e3e3;border-radius:12px;padding:18px 20px;margin:18px 0}}
 .finding h3{{margin:0 0 12px;font-size:17px}} .sev{{color:#fff;border-radius:6px;padding:2px 8px;font-size:12px;margin-right:8px}}
 table.kv{{border-collapse:collapse;width:100%;margin:8px 0}} .kv th{{text-align:left;color:#666;font-weight:600;width:90px;padding:3px 8px}}
 .kv td{{padding:3px 8px}} pre{{background:#0f1117;color:#dfe6f3;padding:12px;border-radius:8px;overflow:auto;font-size:12.5px}}
 h4{{margin:14px 0 4px;font-size:13px;text-transform:uppercase;letter-spacing:.5px;color:#8b5cf6}}
 .brand{{color:#8b5cf6;font-weight:800}} footer{{color:#999;font-size:12px;margin-top:30px;border-top:1px solid #eee;padding-top:12px}}
</style></head><body>
<h1><span class="brand">NeuroSploit</span> Penetration Test Report</h1>
<div class="meta">Target: <b>{html.escape(target)}</b> · Generated {html.escape(when)} · v3.3.0 Autonomous MD-Agent Engine</div>
<div class="chips">{chips}</div>
<h2>Findings ({len(findings)})</h2>
{body}
<footer>Authorized testing only. All findings were independently validated and false-positive-filtered before inclusion.</footer>
</body></html>"""


# --------------------------------------------------------------------------- Typst
def render_typst(target: str, findings: List[Dict], when: str) -> str:
    def s(v):
        """Safely embed arbitrary text as a Typst string literal (// is inert)."""
        return '"' + str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ") + '"'

    counts = _counts(findings)
    summary = ", ".join(f"{k}: {n}" for k, n in sorted(counts.items(), key=lambda kv: SEV_ORDER.get(kv[0], 9))) or "No validated findings"
    parts = [f'''#set page(margin: 2cm, numbering: "1")
#set text(size: 10pt)
#let sevcolor = (Critical: rgb("#c0392b"), High: rgb("#e67e22"), Medium: rgb("#f1c40f"), Low: rgb("#3498db"), Info: rgb("#7f8c8d"))
#let sev(label) = box(fill: sevcolor.at(label, default: rgb("#7f8c8d")), inset: 3pt, radius: 3pt, text(fill: white, weight: "bold", label))
#align(center)[#text(20pt, weight: "bold")[#text(fill: rgb("#8b5cf6"))[NeuroSploit] Penetration Test Report]]
#align(center)[Target: #strong(target) #h(6pt) Generated {s(when)} #h(6pt) v3.3.0]
#line(length: 100%, stroke: 0.5pt + gray)
#strong[Summary:] {s(summary)}
#v(6pt)
== Findings ({len(findings)})
'''.replace("#strong(target)", f"#strong({s(target)})")]
    for i, f in enumerate(_sorted(findings), 1):
        parts.append(f'''
#block(breakable: false, stroke: 0.5pt + rgb("#dddddd"), radius: 6pt, inset: 10pt, width: 100%)[
  #sev({s(f.get('severity','Info'))}) #h(4pt) #strong[{i}. ] #strong({s(f.get('title','Untitled'))})
  #v(4pt)
  Agent: {s(f.get('agent',''))} #h(6pt) CWE: {s(f.get('cwe',''))} #h(6pt) CVSS: {s(f.get('cvss',''))}
  #v(2pt) Endpoint: #raw({s(f.get('endpoint',''))})
  #v(4pt) #strong[Payload] #linebreak() #raw({s(f.get('payload',''))})
  #v(2pt) #strong[Evidence] #linebreak() #raw({s(f.get('evidence',''))})
  #v(2pt) #strong[Impact:] {s(f.get('impact',''))}
  #v(2pt) #strong[Remediation:] {s(f.get('remediation',''))}
]''')
    if not findings:
        parts.append("\n#emph[No validated findings were produced for this engagement.]\n")
    return "\n".join(parts)


# --------------------------------------------------------------------------- API
def generate(target: str, findings: List[Dict], out_dir: str,
             when: Optional[str] = None) -> Dict[str, str]:
    os.makedirs(out_dir, exist_ok=True)
    when = when or datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    out: Dict[str, str] = {}

    html_path = os.path.join(out_dir, "report.html")
    open(html_path, "w").write(render_html(target, findings, when))
    out["html"] = html_path

    typ_path = os.path.join(out_dir, "report.typ")
    open(typ_path, "w").write(render_typst(target, findings, when))
    out["typ"] = typ_path

    if typst_available():
        pdf_path = os.path.join(out_dir, "report.pdf")
        try:
            r = subprocess.run(["typst", "compile", typ_path, pdf_path],
                               capture_output=True, text=True, timeout=120)
            if r.returncode == 0 and os.path.exists(pdf_path):
                out["pdf"] = pdf_path
            else:
                out["pdf_error"] = (r.stderr or "typst failed").strip()[:400]
        except Exception as e:
            out["pdf_error"] = str(e)
    else:
        out["pdf_error"] = "typst binary not found"
    return out
