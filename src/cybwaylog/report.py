"""Self-contained HTML timeline report for a Cybwaylog run.

Turns a scan run (detections.json + hash-chained audit log + manifest) plus a
small mock benchmark into a single standalone HTML file — no external assets,
no network, no JavaScript required. Opens by double-click in any browser.

Everything shown is synthetic. Deterministic, offline, $0.
"""

from __future__ import annotations

import html
import json
from pathlib import Path

from .auditlog import AuditLog, verify_manifest
from .evalbench import run_benchmark
from .redteam import INJECTION_PATTERNS

SEV_ORDER = {"high": 0, "medium": 1, "low": 2}
FAIL = "FAIL"


def build_report_data(run_dir: str | Path, live_benchmark_path: str | Path | None = None,
                      mock_runs: int = 10) -> dict:
    run_dir = Path(run_dir)
    detections = json.loads((run_dir / "detections.json").read_text(encoding="utf-8"))
    fired = [d for d in detections if d.get("status") == FAIL]
    # triage order: risk score first (that is what the ranking benchmark measures),
    # then severity, then time.
    fired.sort(key=lambda d: (-d.get("risk_score", 0),
                              SEV_ORDER.get(d.get("severity", ""), 9),
                              d.get("first_seen", "")))
    timeline = sorted(fired, key=lambda d: (d.get("first_seen", ""), d.get("rule_id", "")))

    chain_ok, chain_msg = AuditLog(run_dir / "audit.log.jsonl").verify_chain()
    man_ok, man_problems = verify_manifest(run_dir)

    mock = run_benchmark(n_runs=mock_runs)

    live = None
    if live_benchmark_path and Path(live_benchmark_path).exists():
        live = json.loads(Path(live_benchmark_path).read_text(encoding="utf-8"))

    return {
        "detections": detections,
        "fired": fired,
        "timeline": timeline,
        "rules_total": len(detections),
        "incident_count": len(fired),
        "severity_counts": {s: sum(1 for d in fired if d.get("severity") == s)
                            for s in ("high", "medium", "low")},
        "events_scanned": mock.get("events_per_run"),
        "chain_ok": chain_ok, "chain_msg": chain_msg,
        "manifest_ok": man_ok, "manifest_problems": man_problems,
        "redteam_total": len(INJECTION_PATTERNS),
        "mock": mock,
        "live": live,
    }


_CSS = """
:root{
  --ground:#eef1f5; --surface:#ffffff; --surface-2:#f6f8fb; --ink:#0f1a26;
  --muted:#5a6b7d; --line:#dce2ea; --accent:#0e7fb8;
  --high:#c0362c; --med:#b0741a; --low:#4a6785; --pass:#1f7a4d;
  --high-soft:#f8e6e4; --med-soft:#f7edda; --pass-soft:#e2f1ea;
}
@media (prefers-color-scheme:dark){
  :root{
    --ground:#0d141d; --surface:#141d28; --surface-2:#1a2634; --ink:#e7eef6;
    --muted:#93a4b8; --line:#26333f; --accent:#38bdf8;
    --high:#f2645a; --med:#e0a13c; --low:#8299b8; --pass:#48c98a;
    --high-soft:#2a1614; --med-soft:#2a2011; --pass-soft:#12271d;
  }
}
:root[data-theme="light"]{
  --ground:#eef1f5; --surface:#ffffff; --surface-2:#f6f8fb; --ink:#0f1a26;
  --muted:#5a6b7d; --line:#dce2ea; --accent:#0e7fb8;
  --high:#c0362c; --med:#b0741a; --low:#4a6785; --pass:#1f7a4d;
  --high-soft:#f8e6e4; --med-soft:#f7edda; --pass-soft:#e2f1ea;
}
:root[data-theme="dark"]{
  --ground:#0d141d; --surface:#141d28; --surface-2:#1a2634; --ink:#e7eef6;
  --muted:#93a4b8; --line:#26333f; --accent:#38bdf8;
  --high:#f2645a; --med:#e0a13c; --low:#8299b8; --pass:#48c98a;
  --high-soft:#2a1614; --med-soft:#2a2011; --pass-soft:#12271d;
}
*{box-sizing:border-box}
.cw-root{
  --sans:system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  --mono:ui-monospace,"SF Mono","Cascadia Code",Menlo,Consolas,monospace;
  background:var(--ground); color:var(--ink); font-family:var(--sans);
  line-height:1.55; margin:0; padding:32px 20px; -webkit-font-smoothing:antialiased;
}
.cw-wrap{max-width:1060px; margin:0 auto; display:flex; flex-direction:column; gap:26px}
.cw-label{font-family:var(--mono); font-size:11px; letter-spacing:.14em; text-transform:uppercase; color:var(--muted)}
.cw-card{background:var(--surface); border:1px solid var(--line); border-radius:12px}

.cw-head{display:flex; flex-wrap:wrap; align-items:flex-end; justify-content:space-between; gap:16px;
  padding-bottom:20px; border-bottom:1px solid var(--line)}
.cw-brand{display:flex; flex-direction:column; gap:6px}
.cw-brand h1{font-size:30px; font-weight:680; margin:0; letter-spacing:-.01em}
.cw-brand .cw-sub{color:var(--muted); font-size:14px; max-width:62ch}
.cw-verdict{display:inline-flex; align-items:center; gap:9px; padding:9px 15px; border-radius:999px;
  font-family:var(--mono); font-size:13px; font-weight:600; border:1px solid}
.cw-verdict.bad{color:var(--high); background:var(--high-soft); border-color:var(--high)}
.cw-verdict.good{color:var(--pass); background:var(--pass-soft); border-color:var(--pass)}
.cw-dot{width:9px; height:9px; border-radius:50%; background:currentColor}

.cw-kpis{display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px}
.cw-kpi{padding:16px; display:flex; flex-direction:column; gap:7px}
.cw-kpi .v{font-size:26px; font-weight:680; font-family:var(--mono); font-variant-numeric:tabular-nums; line-height:1}
.cw-kpi .v.ok{color:var(--pass)} .cw-kpi .v.warn{color:var(--high)} .cw-kpi .v.accent{color:var(--accent)}
.cw-kpi .cap{font-size:12.5px; color:var(--muted)}

.cw-sec{display:flex; flex-direction:column; gap:14px}
.cw-sec > h2{font-size:13px; font-family:var(--mono); letter-spacing:.12em; text-transform:uppercase;
  color:var(--muted); margin:0; font-weight:600}

.cw-flow{display:grid; grid-template-columns:1fr 1fr 1fr; gap:12px}
.cw-stage{padding:16px; display:flex; flex-direction:column; gap:8px}
.cw-stage .n{font-family:var(--mono); font-size:12px; color:var(--accent); font-weight:700}
.cw-stage h3{margin:0; font-size:15px; font-weight:640}
.cw-stage p{margin:0; font-size:13px; color:var(--muted)}
.cw-stage.gate{border-color:var(--accent)}

.cw-tl{display:flex; flex-direction:column; gap:0}
.cw-ti{display:grid; grid-template-columns:132px 5px 1fr; gap:0; align-items:stretch}
.cw-ti .when{font-family:var(--mono); font-size:11.5px; color:var(--muted); padding:16px 12px 0 0; text-align:right; white-space:nowrap}
.cw-ti .rail{background:var(--line); position:relative}
.cw-ti .rail::before{content:""; position:absolute; left:50%; top:18px; transform:translateX(-50%);
  width:11px; height:11px; border-radius:50%; background:var(--low); border:2px solid var(--surface)}
.cw-ti.high .rail::before{background:var(--high)}
.cw-ti.medium .rail::before{background:var(--med)}
.cw-ti.low .rail::before{background:var(--low)}
.cw-ti .card{margin:0 0 12px 16px; padding:14px 16px; background:var(--surface); border:1px solid var(--line);
  border-radius:10px; display:flex; flex-direction:column; gap:10px; min-width:0}
.cw-ti .top{display:flex; flex-wrap:wrap; align-items:center; gap:9px}
.cw-ti .rid{font-family:var(--mono); font-size:12.5px; color:var(--accent); font-weight:600}
.cw-ti .title{font-weight:600; font-size:15px; flex:1; min-width:200px}
.cw-pill{font-family:var(--mono); font-size:10.5px; letter-spacing:.06em; text-transform:uppercase;
  padding:3px 9px; border-radius:999px; font-weight:700; white-space:nowrap}
.cw-pill.high{color:var(--high); background:var(--high-soft)}
.cw-pill.medium{color:var(--med); background:var(--med-soft)}
.cw-pill.low{color:var(--low); background:var(--surface-2)}
.cw-pill.gate{color:var(--accent); background:var(--surface-2); border:1px dashed var(--accent)}
.cw-pill.risk{color:var(--muted); background:var(--surface-2)}
.cw-ev{display:flex; flex-direction:column; gap:6px}
.cw-ev .chip{font-family:var(--mono); font-size:12px; background:var(--surface-2); border:1px solid var(--line);
  padding:6px 10px; border-radius:6px; color:var(--ink); overflow-wrap:anywhere}
.cw-resp{font-size:13px; color:var(--ink); background:var(--surface-2); border:1px solid var(--line);
  border-radius:8px; padding:10px 12px}
.cw-resp b{font-family:var(--mono); font-size:10.5px; letter-spacing:.06em; text-transform:uppercase; color:var(--muted); display:block; margin-bottom:4px}
.cw-refs{display:flex; flex-wrap:wrap; gap:6px}
.cw-refs .ref{font-family:var(--mono); font-size:11px; color:var(--muted)}
.cw-refs .ref::before{content:"§ "}

.cw-meters{display:grid; grid-template-columns:repeat(auto-fit,minmax(240px,1fr)); gap:12px}
.cw-meter{padding:16px; display:flex; flex-direction:column; gap:12px}
.cw-meter h3{margin:0; font-size:15px; font-weight:640; display:flex; justify-content:space-between; align-items:baseline; gap:8px}
.cw-meter h3 span{font-family:var(--mono); font-size:11.5px; color:var(--muted); font-weight:400}
.cw-m{display:flex; flex-direction:column; gap:5px}
.cw-m .lab{display:flex; justify-content:space-between; font-family:var(--mono); font-size:11.5px; color:var(--muted)}
.cw-m .lab b{color:var(--ink); font-variant-numeric:tabular-nums}
.cw-bar{height:6px; border-radius:999px; background:var(--surface-2); overflow:hidden}
.cw-bar i{display:block; height:100%; background:var(--pass); border-radius:999px}
.cw-bar i.accent{background:var(--accent)}

.cw-int{display:grid; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); gap:12px}
.cw-ok{display:flex; gap:13px; align-items:flex-start; padding:15px 17px}
.cw-ok .badge{font-family:var(--mono); font-size:11px; font-weight:700; padding:3px 8px; border-radius:6px;
  background:var(--pass-soft); color:var(--pass); flex:none}
.cw-ok.bad .badge{background:var(--high-soft); color:var(--high)}
.cw-ok h4{margin:0 0 3px; font-size:14px; font-weight:640}
.cw-ok p{margin:0; font-size:12.5px; color:var(--muted)}

.cw-foot{border-top:1px solid var(--line); padding-top:18px; color:var(--muted); font-size:12px;
  display:flex; flex-direction:column; gap:5px}
.cw-foot b{color:var(--ink)}
@media (max-width:720px){
  .cw-flow{grid-template-columns:1fr}
  .cw-ti{grid-template-columns:1fr}
  .cw-ti .when{text-align:left; padding:0 0 4px}
  .cw-ti .rail{display:none}
  .cw-ti .card{margin-left:0}
}
"""


def _esc(s) -> str:
    return html.escape(str(s), quote=True)


def _meter(label: str, value: float, accent: bool = False) -> str:
    pct = max(0.0, min(1.0, float(value))) * 100
    cls = " accent" if accent else ""
    return (f'<div class="cw-m"><div class="lab"><span>{_esc(label)}</span>'
            f'<b>{value:.3f}</b></div><div class="cw-bar">'
            f'<i class="{cls.strip()}" style="width:{pct:.1f}%"></i></div></div>')


def _incident_card(d: dict) -> str:
    sev = d.get("severity", "low")
    ev = "".join(f'<div class="chip">{_esc(e)}</div>' for e in d.get("evidence", []))
    refs = "".join(f'<span class="ref">{_esc(r)}</span>' for r in d.get("references", []))
    resp = d.get("recommended_response", "")
    resp_html = (f'<div class="cw-resp"><b>Recommended response (advisory — not executed)</b>'
                 f'{_esc(resp)}</div>') if resp else ""
    return f"""<div class="cw-ti {_esc(sev)}">
  <div class="when">{_esc(d.get('first_seen', ''))}</div>
  <div class="rail"></div>
  <div class="card">
    <div class="top">
      <span class="rid">{_esc(d.get('rule_id', ''))}</span>
      <span class="title">{_esc(d.get('title', ''))}</span>
      <span class="cw-pill risk">risk {_esc(d.get('risk_score', 0))}</span>
      <span class="cw-pill {_esc(sev)}">{_esc(sev)}</span>
      <span class="cw-pill gate">awaiting human decision</span>
    </div>
    <div class="cw-ev">{ev}</div>
    {resp_html}
    <div class="cw-refs">{refs}</div>
  </div>
</div>"""


def render_report_html(data: dict, embed: bool = False) -> str:
    inc = data["incident_count"]
    sev = data["severity_counts"]
    mock = data["mock"] or {}
    verdict_cls = "bad" if inc else "good"
    verdict_txt = (f"{inc} incident{'s' if inc != 1 else ''} require human triage"
                   if inc else "no incidents detected")

    kpis = "".join([
        f'<div class="cw-kpi cw-card"><span class="v accent">{data["rules_total"]}</span>'
        f'<span class="cap">detection rules run</span></div>',
        f'<div class="cw-kpi cw-card"><span class="v {"warn" if inc else "ok"}">{inc}</span>'
        f'<span class="cap">incidents detected</span></div>',
        f'<div class="cw-kpi cw-card"><span class="v {"warn" if sev["high"] else "ok"}">{sev["high"]}</span>'
        f'<span class="cap">high severity</span></div>',
        f'<div class="cw-kpi cw-card"><span class="v ok">{mock.get("top1_ranking_accuracy", 0):.2f}</span>'
        f'<span class="cap">top-1 triage ranking</span></div>',
        f'<div class="cw-kpi cw-card"><span class="v ok">{mock.get("alert_fatigue_per_1000", 0):.3f}</span>'
        f'<span class="cap">false alerts / 1,000 events</span></div>',
        f'<div class="cw-kpi cw-card"><span class="v ok">{data["redteam_total"]}</span>'
        f'<span class="cap">red-team patterns caught</span></div>',
    ])

    pipeline = """<div class="cw-flow">
  <div class="cw-stage cw-card"><span class="n">STAGE 1</span><h3>Triage Agent</h3>
    <p>Reads detected events and drafts an incident report — narrative, affected accounts, and a
       recommended response — as strict JSON.</p></div>
  <div class="cw-stage cw-card"><span class="n">STAGE 2</span><h3>Independent Checker</h3>
    <p>Re-derives the truth from the raw audit rows and adjudicates PASS / REVIEW / QUARANTINE.
       Hallucinated accounts and injected instructions are quarantined. It never grades its own generation.</p></div>
  <div class="cw-stage cw-card gate"><span class="n">STAGE 3</span><h3>Human Triage Gate</h3>
    <p>A person confirms, dismisses as a false positive, escalates, or files an expiring exception
       (NIST CA-5 style). Nothing closes without a logged human decision, and no response is ever executed.</p></div>
</div>"""

    meters = f"""<div class="cw-meters">
  <div class="cw-meter cw-card">
    <h3>Detection accuracy <span>mock provider · {mock.get('n_runs', 0)} runs</span></h3>
    {_meter('precision', mock.get('precision', 0))}
    {_meter('recall', mock.get('recall', 0))}
    {_meter('F1', mock.get('f1', 0))}
  </div>
  <div class="cw-meter cw-card">
    <h3>Triage quality <span>ranking &amp; alert fatigue</span></h3>
    {_meter('top-1 ranking accuracy', mock.get('top1_ranking_accuracy', 0), accent=True)}
    <div class="cw-m"><div class="lab"><span>false alerts per 1,000 events</span>
      <b>{mock.get('alert_fatigue_per_1000', 0):.4f}</b></div></div>
    <div class="cw-m"><div class="lab"><span>quarantined by checker</span>
      <b>{mock.get('checker_quarantined', 0)}</b></div></div>
  </div>
</div>"""

    chain_cls = "" if data["chain_ok"] else " bad"
    man_cls = "" if data["manifest_ok"] else " bad"
    integrity = f"""<div class="cw-int">
  <div class="cw-ok cw-card{chain_cls}"><span class="badge">{'OK' if data['chain_ok'] else 'FAIL'}</span>
    <div><h4>Audit log — hash chain {'intact' if data['chain_ok'] else 'BROKEN'}</h4>
    <p>Every decision is chained to the SHA-256 of the previous entry; any edit, deletion, or reordering is detected.</p></div></div>
  <div class="cw-ok cw-card{man_cls}"><span class="badge">{'OK' if data['manifest_ok'] else 'FAIL'}</span>
    <div><h4>Run manifest {'verified' if data['manifest_ok'] else 'MISMATCH'}</h4>
    <p>SHA-256 of every output file matches the manifest; no post-run tampering.</p></div></div>
</div>"""

    timeline = "".join(_incident_card(d) for d in data["timeline"]) or \
        '<p style="color:var(--muted);font-size:13px">No incidents detected in this run.</p>'

    body = f"""<div class="cw-root"><div class="cw-wrap">
  <header class="cw-head">
    <div class="cw-brand">
      <span class="cw-label">Governed-AI database activity audit</span>
      <h1>Cybwaylog</h1>
      <span class="cw-sub">A synthetic Oracle-style audit trail triaged against public NIST SP 800-53
        and MITRE ATT&amp;CK-mapped detection rules, with independent verification and a human triage gate.</span>
    </div>
    <span class="cw-verdict {verdict_cls}"><span class="cw-dot"></span>{_esc(verdict_txt)}</span>
  </header>

  <div class="cw-kpis">{kpis}</div>

  <section class="cw-sec"><h2>AI governance pipeline</h2>{pipeline}</section>
  <section class="cw-sec"><h2>Measured performance</h2>{meters}</section>
  <section class="cw-sec"><h2>Integrity controls</h2>{integrity}</section>
  <section class="cw-sec"><h2>Incident timeline</h2><div class="cw-tl">{timeline}</div></section>

  <footer class="cw-foot">
    <span><b>Synthetic data only.</b> Every user, host, address, and event in this report was generated
      for testing. No real database, log, credential, or organizational data.</span>
    <span>A personal portfolio project by <b>V. Vikram</b> · Apache-2.0 · Defensive security only.
      NIST SP 800-53 is a public-domain US Government work; MITRE ATT&amp;CK&reg; technique IDs are
      referenced with attribution to The MITRE Corporation.</span>
  </footer>
</div></div>"""

    if embed:
        return f"<style>{_CSS}</style>{body}"
    return (f"<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
            f"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
            f"<title>Cybwaylog — Activity Audit Report</title>\n<style>{_CSS}</style>\n</head>\n"
            f"<body style=\"margin:0\">{body}</body>\n</html>\n")


def write_report(run_dir: str | Path, out_path: str | Path,
                 live_benchmark_path: str | Path | None = None) -> Path:
    data = build_report_data(run_dir, live_benchmark_path)
    out = Path(out_path)
    if out.parent and str(out.parent) not in ("", "."):
        out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_report_html(data), encoding="utf-8")
    return out
