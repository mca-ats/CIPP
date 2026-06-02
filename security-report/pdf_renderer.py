"""
Branded PDF renderer for the ATS Client Health / QBR report.

build_html() is a pure HTML/CSS builder (no native deps) styled with the ATS
brand language: terminal/neon-orange wordmark on near-black cover, clean light
content pages, monospace section labels. render_qbr_pdf() rasterizes it to PDF
via WeasyPrint.

macOS note: WeasyPrint's native libs (pango/cairo via Homebrew) are resolved by
the dynamic loader, which reads DYLD_FALLBACK_LIBRARY_PATH at dlopen time. We set
it before importing weasyprint so the import succeeds regardless of how the
process was launched.
"""

from __future__ import annotations

import html as _html
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from qbr_models import QbrData, score_trend
from qbr_narrative import QbrNarrative

# --- brand tokens (from ats-design/logo + brand voice) -------------------
ORANGE = "#FF7B00"
ORANGE_HI = "#FFB000"
INK = "#15130F"
COVER_BG = "#0A0A0A"
PAPER = "#FAFAF7"
MUTED = "#6B665C"
HAIRLINE = "#E6E1D6"
STATUS = {"good": "#16834A", "warn": "#B7791F", "bad": "#C2410C", "info": "#6B665C"}
SEV = {
    "critical": ("#FFFFFF", "#B91C1C"),
    "high": ("#FFFFFF", "#C2410C"),
    "medium": ("#1A1A1A", "#FCD34D"),
    "low": ("#FFFFFF", "#16834A"),
    "info": ("#FFFFFF", "#2563EB"),
}


def _e(s: Any) -> str:
    return _html.escape(str(s))


def _metric_value(m: Any) -> str:
    # Word units ("devices", "SKUs") get a separating space; "%" and unitless stay tight.
    sep = "" if m.unit in ("", "%") else "&nbsp;"
    return f"{_e(m.value)}{sep}{_e(m.unit)}" if m.unit else _e(m.value)


def _metric_rows(q: QbrData) -> str:
    """Clean label→value list (replaces the KPI card grid)."""
    rows = ""
    for m in q.kpis:
        color = STATUS.get(m.status, MUTED)
        rows += (
            f'<div class="mrow">'
            f'<span class="mlabel">{_e(m.label)}</span>'
            f'<span class="mval" style="color:{color}">'
            f'<span class="mdot" style="background:{color}"></span>{_metric_value(m)}</span>'
            f'</div>'
        )
    return rows


def _sev_badge(sev: str) -> str:
    fg, bg = SEV.get(sev, SEV["info"])
    return f'<span class="badge" style="color:{fg};background:{bg}">{_e(sev.upper())}</span>'


def _score_trend_block(q: QbrData) -> str:
    t = score_trend(q.score_history)
    if t["latest_pct"] is None:
        # Never silently omit the flagship metric — show an explicit placeholder.
        return f"""
      <div class="score">
        <div class="score-head">
          <span class="score-label">Microsoft Secure Score</span>
          <span class="score-now" style="font-size:13pt;color:{MUTED}">Data unavailable this period</span>
        </div>
      </div>"""
    bars = ""
    pts = sorted(q.score_history, key=lambda p: p.date)
    for p in pts:
        pct = p.pct or 0
        bars += (
            f'<div class="bar-col"><div class="bar" style="height:{max(6, pct)}%"></div>'
            f'<div class="bar-lbl">{_e(p.date[5:])}</div></div>'
        )
    delta_html = ""
    if t["delta"] is not None and t["direction"] != "flat":
        sign = "+" if t["delta"] > 0 else ""
        arrow = "▲" if t["direction"] == "up" else "▼"
        dc = STATUS["good"] if t["direction"] == "up" else STATUS["bad"]
        delta_html = f'<span class="trend-delta" style="color:{dc}">{arrow} {sign}{t["delta"]} pts QoQ</span>'
    return f"""
      <div class="score">
        <div class="score-head">
          <span class="score-label">Microsoft Secure Score</span>
          <span class="score-now">{t['latest_pct']}% {delta_html}</span>
        </div>
        <div class="bars">{bars}</div>
      </div>"""


def _findings_rows(q: QbrData) -> str:
    sec = q.security
    findings = list(getattr(sec, "findings", []) or []) if sec is not None else []
    if not findings:
        return '<tr><td colspan="3" class="clean">No outstanding findings.</td></tr>'
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    rows = ""
    for f in sorted(findings, key=lambda x: order.get(_sev_str(x), 9)):
        items = _finding_items(f)
        items_html = ""
        if items:
            lis = "".join(f'<div class="fitem">{_e(i)}</div>' for i in items)
            items_html = f'<div class="fitems">{lis}</div>'
        rows += (
            f'<tr><td>{_sev_badge(_sev_str(f))}</td>'
            f'<td><strong>{_e(f.title)}</strong><br><span class="muted">{_e(f.category)}</span>'
            f'{items_html}</td>'
            f'<td>{_e(f.recommendation)}</td></tr>'
        )
    return rows


def _sev_str(f: Any) -> str:
    s = getattr(f, "severity", "info")
    return s.value if hasattr(s, "value") else str(s)


# Detail keys (in priority order) whose list value names the affected items —
# the mailboxes/users/admins/etc. behind a finding, listed under it in the appendix.
_ITEM_KEYS = ["forwarding", "users", "global_admins", "devices", "accounts"]


def _finding_items(f: Any) -> list[str]:
    """The affected items (mailboxes, users, …) behind a finding, if any."""
    d = getattr(f, "details", {}) or {}

    def _is_str_list(v: Any) -> bool:
        return isinstance(v, list) and bool(v) and all(isinstance(x, str) for x in v)

    for k in _ITEM_KEYS:
        if _is_str_list(d.get(k)):
            return d[k]
    for v in d.values():           # fallback: any list-of-strings detail
        if _is_str_list(v):
            return v
    return []


_COMPLIANCE_BADGE = {
    "compliant": ("#FFFFFF", "#16834A"),
    "noncompliant": ("#FFFFFF", "#B91C1C"),
    "ingraceperiod": ("#1A1A1A", "#FCD34D"),
}
_COMPLIANCE_LABEL = {"ingraceperiod": "in grace"}


def _compliance_badge(state: str) -> str:
    fg, bg = _COMPLIANCE_BADGE.get(state, ("#FFFFFF", "#6B665C"))
    label = _COMPLIANCE_LABEL.get(state, state or "unknown")
    return f'<span class="badge" style="color:{fg};background:{bg}">{_e(label.upper())}</span>'


_STATUS_BADGE = {"active": ("#FFFFFF", "#16834A"), "disabled": ("#FFFFFF", "#B91C1C")}


def _status_badge(status: str) -> str:
    s = (status or "").lower()
    if s.startswith("inactive"):
        fg, bg = ("#1A1A1A", "#FCD34D")
    else:
        fg, bg = _STATUS_BADGE.get(s, ("#FFFFFF", "#6B665C"))
    return f'<span class="badge" style="color:{fg};background:{bg}">{_e(status)}</span>'


def _licensed_user_rows(q: QbrData) -> str:
    users = q.licensed_users or []
    if not users:
        return (f'<tr><td colspan="4" style="text-align:center;padding:4mm;color:{MUTED}">'
                f'No paid-SKU users found.</td></tr>')
    rows = ""
    for u in users:
        rows += (
            f'<tr><td><strong>{_e(u.name)}</strong></td>'
            f'<td>{_e(u.upn)}</td>'
            f'<td>{_e(", ".join(u.licenses))}</td>'
            f'<td>{_status_badge(u.status)}</td></tr>'
        )
    return rows


def _device_rows(q: QbrData) -> str:
    devices = q.devices or []
    if not devices:
        return (f'<tr><td colspan="6" style="text-align:center;padding:4mm;color:{MUTED}">'
                f'No managed devices enrolled.</td></tr>')
    rows = ""
    for d in devices:
        rows += (
            f'<tr><td><strong>{_e(d.name)}</strong></td>'
            f'<td>{_e(d.os)}</td>'
            f'<td>{_e(d.owner)}</td>'
            f'<td>{_compliance_badge(d.compliance)}</td>'
            f'<td>{_e(d.last_sync)}</td>'
            f'<td>{_e(d.user)}</td></tr>'
        )
    return rows


def build_html(q: QbrData, n: QbrNarrative) -> str:
    """Build the full branded report HTML. Pure — no native deps."""
    generated = q.generated_at or datetime.now(timezone.utc).isoformat()
    try:
        gdate = datetime.fromisoformat(generated).strftime("%B %-d, %Y")
    except (ValueError, TypeError):
        gdate = generated[:10]

    metric_rows = _metric_rows(q)
    wins = "".join(f"<li>{_e(w)}</li>" for w in n.wins) or "<li>No notable changes this quarter.</li>"
    risks = "".join(
        f'<div class="risk"><div class="risk-top">{_sev_badge(r.severity)}'
        f'<span class="risk-title">{_e(r.title)}</span></div>'
        f'<div class="risk-impact">{_e(r.business_impact)}</div></div>'
        for r in n.risks
    ) or '<div class="risk none">No active risks identified.</div>'
    errors = getattr(q, "errors", None) or []
    banner = (
        f'<div class="degraded">&#9888; Data incomplete this period — some sources '
        f'were unavailable, so figures below may understate reality: '
        f'{_e(", ".join(errors))}</div>' if errors else ""
    )
    device_rows = _device_rows(q)
    device_count = len(q.devices or [])
    licensed_user_rows = _licensed_user_rows(q)
    licensed_count = len(q.licensed_users or [])
    recs = "".join(f"<li>{_e(r)}</li>" for r in n.recommendations)
    priorities = "".join(
        f'<li><span class="num">{i + 1:02d}</span>{_e(p)}</li>'
        for i, p in enumerate(n.next_quarter_priorities)
    )

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>
  @page {{ size: Letter; margin: 0; }}
  @page content {{
    margin: 22mm 18mm 20mm 18mm;
    @bottom-center {{ content: "Abate Technology Services  ·  Confidential  ·  {_e(q.tenant_name)}";
      font-family: ui-monospace, Menlo, monospace; font-size: 7.5pt; color: {MUTED}; }}
    @bottom-right {{ content: "Page " counter(page); font-family: ui-monospace, Menlo, monospace;
      font-size: 7.5pt; color: {MUTED}; }}
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, 'Segoe UI', Helvetica, Arial, sans-serif; color: {INK};
    font-size: 10.5pt; line-height: 1.5; -webkit-print-color-adjust: exact; }}
  .mono {{ font-family: ui-monospace, 'SF Mono', Menlo, monospace; }}

  /* COVER */
  .cover {{ page: cover; background: {COVER_BG}; color: #F0F0F0; height: 279mm; width: 100%;
    padding: 30mm 22mm; position: relative;
    background-image:
      linear-gradient(rgba(255,255,255,.03) 1px, transparent 1px),
      linear-gradient(90deg, rgba(255,255,255,.03) 1px, transparent 1px);
    background-size: 14mm 14mm; }}
  .wordmark {{ font-family: ui-monospace, 'SF Mono', Menlo, monospace; font-size: 30pt;
    font-weight: 700; letter-spacing: 1px; }}
  .wordmark .p {{ color: {ORANGE}; }} .wordmark .c {{ color: #F0F0F0; }}
  .wordmark .u {{ color: {ORANGE}; }}
  .cover-rule {{ width: 64px; height: 4px; margin: 26mm 0 8mm 0;
    background: linear-gradient(90deg, {ORANGE}, {ORANGE_HI}); border-radius: 2px; }}
  .cover-kicker {{ font-family: ui-monospace, Menlo, monospace; font-size: 9pt; letter-spacing: 3px;
    text-transform: uppercase; color: {ORANGE_HI}; }}
  .cover-title {{ font-size: 40pt; font-weight: 800; line-height: 1.05; margin: 6mm 0 4mm 0; }}
  .cover-client {{ font-size: 18pt; color: #C9C5BD; }}
  .cover-meta {{ position: absolute; bottom: 30mm; left: 22mm; font-family: ui-monospace, Menlo, monospace;
    font-size: 9.5pt; color: #9A958C; }}
  .cover-meta b {{ color: #F0F0F0; font-weight: 600; }}
  .cover-domain {{ position: absolute; bottom: 30mm; right: 22mm; font-family: ui-monospace, Menlo, monospace;
    font-size: 9.5pt; color: {ORANGE}; }}

  /* CONTENT */
  .content {{ page: content; background: {PAPER}; }}
  .sec {{ margin-bottom: 9mm; }}
  .sec-label {{ font-family: ui-monospace, Menlo, monospace; font-size: 8.5pt; letter-spacing: 2.5px;
    text-transform: uppercase; color: {ORANGE}; display: flex; align-items: center; gap: 8px;
    margin-bottom: 4mm; }}
  .sec-label::before {{ content: "▸"; color: {ORANGE}; }}
  .sec-label::after {{ content: ""; flex: 1; height: 1px; background: {HAIRLINE}; }}
  .lede {{ font-size: 12pt; line-height: 1.55; color: {INK}; }}
  .degraded {{ background: #FEF3C7; border: 1px solid #F59E0B; border-radius: 6px;
    padding: 3mm 4mm; margin-bottom: 6mm; color: #92400E; font-size: 9.5pt; font-weight: 600; }}

  /* Clean metric list (label -> value), not cards. */
  .metrics {{ border-top: 1px solid {HAIRLINE}; }}
  .mrow {{ display: flex; justify-content: space-between; align-items: baseline;
    padding: 2.4mm 1mm; border-bottom: 1px solid {HAIRLINE}; }}
  .mlabel {{ font-family: ui-monospace, Menlo, monospace; font-size: 9pt; letter-spacing: .5px;
    text-transform: uppercase; color: {MUTED}; }}
  .mval {{ font-size: 13pt; font-weight: 700; white-space: nowrap; }}
  .mdot {{ display: inline-block; width: 7px; height: 7px; border-radius: 50%;
    margin-right: 7px; vertical-align: middle; }}

  .score {{ border: 1px solid {HAIRLINE}; border-radius: 8px; padding: 5mm; background: #FFFFFF;
    margin-bottom: 5mm; }}
  .score-head {{ display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 4mm; }}
  .score-label {{ font-family: ui-monospace, Menlo, monospace; font-size: 9pt; letter-spacing: 1px;
    text-transform: uppercase; color: {MUTED}; }}
  .score-now {{ font-size: 22pt; font-weight: 800; color: {INK}; }}
  .trend-delta {{ font-size: 10pt; font-weight: 700; margin-left: 6px; }}
  .bars {{ display: flex; align-items: flex-end; gap: 8px; height: 28mm; }}
  .bar-col {{ flex: 0 0 auto; width: 14mm; display: flex; flex-direction: column;
    align-items: center; justify-content: flex-end; height: 100%; }}
  .bar {{ width: 9mm; background: linear-gradient(180deg, {ORANGE_HI}, {ORANGE}); border-radius: 3px 3px 0 0; }}
  .bar-lbl {{ font-family: ui-monospace, Menlo, monospace; font-size: 7pt; color: {MUTED}; margin-top: 2mm; }}

  ul.wins {{ list-style: none; }}
  ul.wins li {{ padding: 2mm 0 2mm 7mm; position: relative; border-bottom: 1px solid {HAIRLINE}; }}
  ul.wins li::before {{ content: "✓"; position: absolute; left: 0; color: {STATUS['good']}; font-weight: 800; }}

  .risk {{ border-left: 3px solid {ORANGE}; background: #FFFFFF; border: 1px solid {HAIRLINE};
    border-left: 3px solid {ORANGE}; border-radius: 6px; padding: 3.5mm 4mm; margin-bottom: 3mm; }}
  .risk.none {{ border-left-color: {STATUS['good']}; color: {MUTED}; }}
  .risk-top {{ display: flex; align-items: center; gap: 8px; }}
  .risk-title {{ font-weight: 700; font-size: 11pt; }}
  .risk-impact {{ color: {MUTED}; margin-top: 1.5mm; font-size: 10pt; }}

  .badge {{ font-family: ui-monospace, Menlo, monospace; font-size: 7pt; font-weight: 700;
    letter-spacing: .5px; padding: 2px 7px; border-radius: 4px; }}

  ol.recs {{ padding-left: 6mm; }} ol.recs li {{ margin-bottom: 2mm; }}
  ul.prio {{ list-style: none; }}
  ul.prio li {{ display: flex; align-items: baseline; gap: 4mm; padding: 2.5mm 0;
    border-bottom: 1px solid {HAIRLINE}; font-size: 11pt; }}
  ul.prio .num {{ font-family: ui-monospace, Menlo, monospace; font-weight: 800; color: {ORANGE};
    font-size: 12pt; }}

  table.findings {{ width: 100%; border-collapse: collapse; font-size: 9.5pt; }}
  table.findings th {{ font-family: ui-monospace, Menlo, monospace; font-size: 7.5pt; letter-spacing: 1px;
    text-transform: uppercase; color: {MUTED}; text-align: left; padding: 2mm; border-bottom: 2px solid {HAIRLINE}; }}
  table.findings td {{ padding: 2.5mm 2mm; border-bottom: 1px solid {HAIRLINE}; vertical-align: top; }}
  .muted {{ color: {MUTED}; font-size: 8.5pt; }}
  .clean {{ color: {STATUS['good']}; text-align: center; padding: 4mm; }}
  /* Affected items (mailboxes/users/…) listed under a finding. */
  .fitems {{ margin-top: 2mm; }}
  .fitem {{ font-family: ui-monospace, Menlo, monospace; font-size: 8pt; color: {INK};
    padding: 0.6mm 0; }}
  .appendix {{ break-before: page; }}
</style></head>
<body>

  <section class="cover">
    <div class="wordmark"><span class="p">&gt;</span> <span class="c">ATS</span><span class="u">_</span></div>
    <div class="cover-rule"></div>
    <div class="cover-kicker">Client Health Report</div>
    <div class="cover-title">Quarterly<br>Business Review</div>
    <div class="cover-client">{_e(q.tenant_name)}</div>
    <div class="cover-meta">PERIOD <b>{_e(q.period)}</b><br>PREPARED <b>{_e(gdate)}</b></div>
    <div class="cover-domain">{_e(q.default_domain)}</div>
  </section>

  <section class="content">
    {banner}
    <div class="sec">
      <div class="sec-label">Executive Summary</div>
      <p class="lede">{_e(n.exec_summary)}</p>
    </div>

    <div class="sec">
      <div class="sec-label">Health Scorecard</div>
      {_score_trend_block(q)}
      <div class="metrics">{metric_rows}</div>
    </div>

    <div class="sec">
      <div class="sec-label">Wins This Quarter</div>
      <ul class="wins">{wins}</ul>
    </div>

    <div class="sec">
      <div class="sec-label">Risks &amp; Exposure</div>
      {risks}
    </div>

    <div class="sec">
      <div class="sec-label">Recommendations</div>
      <ol class="recs">{recs}</ol>
    </div>

    <div class="sec">
      <div class="sec-label">Next-Quarter Priorities</div>
      <ul class="prio">{priorities}</ul>
    </div>

    <div class="sec appendix">
      <div class="sec-label">Appendix · Security Findings</div>
      <table class="findings">
        <thead><tr><th>Severity</th><th>Finding</th><th>Recommended Action</th></tr></thead>
        <tbody>{_findings_rows(q)}</tbody>
      </table>
    </div>

    <div class="sec appendix">
      <div class="sec-label">Appendix · Device Inventory ({device_count})</div>
      <table class="findings devices">
        <thead><tr><th>Device</th><th>OS</th><th>Owner</th><th>Compliance</th><th>Last Sync</th><th>User</th></tr></thead>
        <tbody>{device_rows}</tbody>
      </table>
    </div>

    <div class="sec appendix">
      <div class="sec-label">Appendix · Licensed Users — Paid SKUs ({licensed_count})</div>
      <table class="findings users">
        <thead><tr><th>User</th><th>Email</th><th>Paid License(s)</th><th>Status</th></tr></thead>
        <tbody>{licensed_user_rows}</tbody>
      </table>
    </div>
  </section>

</body></html>"""


def render_qbr_pdf(q: QbrData, n: QbrNarrative, out_path: str | Path) -> Path:
    """Render the QBR to a branded PDF at out_path. Returns the Path."""
    # Ensure WeasyPrint's native libs (pango/cairo) are discoverable. On macOS the
    # loader reads DYLD_FALLBACK_LIBRARY_PATH; on Linux pango must be installed
    # system-wide (no shim needed). Candidates cover Apple-Silicon + Intel Homebrew
    # and an explicit override.
    candidates = [os.environ.get("WEASYPRINT_LIB_DIR"), "/opt/homebrew/lib", "/usr/local/lib"]
    for lib in candidates:
        if lib and os.path.isdir(lib):
            cur = os.environ.get("DYLD_FALLBACK_LIBRARY_PATH", "")
            if lib not in cur.split(":"):
                os.environ["DYLD_FALLBACK_LIBRARY_PATH"] = f"{lib}:{cur}" if cur else lib

    from weasyprint import HTML  # imported here so build_html() needs no native deps

    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    HTML(string=build_html(q, n)).write_pdf(str(out_path))
    return out_path
