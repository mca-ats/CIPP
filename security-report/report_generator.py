"""
Report generator — takes collected security data and produces formatted reports
for Obsidian (markdown), email (HTML), and Notion.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from collectors import Finding, Severity, TenantSecuritySummary


def _severity_emoji(sev: Severity) -> str:
    return {
        Severity.CRITICAL: "🔴",
        Severity.HIGH: "🟠",
        Severity.MEDIUM: "🟡",
        Severity.LOW: "🟢",
        Severity.INFO: "🔵",
    }.get(sev, "⚪")


def _severity_badge_html(sev: Severity) -> str:
    colors = {
        Severity.CRITICAL: ("#dc2626", "#fef2f2"),
        Severity.HIGH: ("#ea580c", "#fff7ed"),
        Severity.MEDIUM: ("#ca8a04", "#fefce8"),
        Severity.LOW: ("#16a34a", "#f0fdf4"),
        Severity.INFO: ("#2563eb", "#eff6ff"),
    }
    fg, bg = colors.get(sev, ("#6b7280", "#f9fafb"))
    return f'<span style="background:{bg};color:{fg};padding:2px 8px;border-radius:4px;font-weight:600;font-size:12px">{sev.value.upper()}</span>'


# ---------------------------------------------------------------------------
# Summary statistics
# ---------------------------------------------------------------------------
def _compute_stats(summaries: list[TenantSecuritySummary]) -> dict[str, Any]:
    all_findings = [f for s in summaries for f in s.findings]
    return {
        "tenant_count": len(summaries),
        "total_findings": len(all_findings),
        "critical": sum(1 for f in all_findings if f.severity == Severity.CRITICAL),
        "high": sum(1 for f in all_findings if f.severity == Severity.HIGH),
        "medium": sum(1 for f in all_findings if f.severity == Severity.MEDIUM),
        "low": sum(1 for f in all_findings if f.severity == Severity.LOW),
        "by_category": _group_count(all_findings, lambda f: f.category),
        "tenants_with_criticals": [s.tenant_name for s in summaries if s.critical_count > 0],
        "avg_score_pct": _avg([s.score_pct for s in summaries if s.score_pct is not None]),
        "errors": sum(len(s.errors) for s in summaries),
    }


def _group_count(items: list, key_fn) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        k = key_fn(item)
        counts[k] = counts.get(k, 0) + 1
    return dict(sorted(counts.items(), key=lambda x: -x[1]))


def _avg(values: list[float]) -> float | None:
    vals = [v for v in values if v is not None]
    return round(sum(vals) / len(vals), 1) if vals else None


# ---------------------------------------------------------------------------
# Obsidian Markdown Report
# ---------------------------------------------------------------------------
def generate_obsidian_report(summaries: list[TenantSecuritySummary], run_time: datetime) -> str:
    stats = _compute_stats(summaries)
    date_str = run_time.strftime("%Y-%m-%d")
    time_str = run_time.strftime("%H:%M UTC")

    lines: list[str] = []
    lines.append(f"# Security Posture Report — {date_str}")
    lines.append(f"")
    lines.append(f"> Generated {date_str} at {time_str} | {stats['tenant_count']} tenants analyzed")
    lines.append(f"")

    # Executive summary
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"| Metric | Value |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Tenants Scanned | {stats['tenant_count']} |")
    lines.append(f"| Total Findings | {stats['total_findings']} |")
    lines.append(f"| 🔴 Critical | {stats['critical']} |")
    lines.append(f"| 🟠 High | {stats['high']} |")
    lines.append(f"| 🟡 Medium | {stats['medium']} |")
    lines.append(f"| 🟢 Low | {stats['low']} |")
    if stats['avg_score_pct'] is not None:
        lines.append(f"| Avg Secure Score | {stats['avg_score_pct']}% |")
    lines.append("")

    if stats['tenants_with_criticals']:
        lines.append("### ⚠️ Tenants with Critical Findings")
        lines.append("")
        for t in stats['tenants_with_criticals']:
            lines.append(f"- **{t}**")
        lines.append("")

    # Findings by category
    lines.append("## Findings by Category")
    lines.append("")
    for cat, count in stats['by_category'].items():
        lines.append(f"- **{cat}**: {count} findings")
    lines.append("")

    # Priority action items (critical + high)
    priority_findings = sorted(
        [f for s in summaries for f in s.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)],
        key=lambda f: (0 if f.severity == Severity.CRITICAL else 1, f.tenant),
    )

    if priority_findings:
        lines.append("## Priority Action Items")
        lines.append("")
        for f in priority_findings:
            lines.append(f"- [ ] {_severity_emoji(f.severity)} **{f.tenant}** — {f.title}")
            lines.append(f"  - {f.recommendation}")
        lines.append("")

    # Per-tenant details
    lines.append("## Tenant Details")
    lines.append("")

    for s in sorted(summaries, key=lambda x: -(x.critical_count * 100 + x.high_count)):
        score_str = f" | Secure Score: {s.score_pct}%" if s.score_pct is not None else ""
        finding_str = f"{len(s.findings)} findings"
        if s.critical_count:
            finding_str += f" ({s.critical_count} critical)"

        lines.append(f"### {s.tenant_name}")
        lines.append(f"*{s.default_domain}{score_str} | {finding_str}*")
        lines.append("")

        if not s.findings:
            lines.append("✅ No issues found")
            lines.append("")
            continue

        for f in sorted(s.findings, key=lambda x: list(Severity).index(x.severity)):
            lines.append(f"- {_severity_emoji(f.severity)} **{f.title}**")
            lines.append(f"  - {f.description}")
            lines.append(f"  - 💡 {f.recommendation}")
        lines.append("")

        if s.errors:
            lines.append(f"⚠️ Collection errors: {', '.join(s.errors)}")
            lines.append("")

    # Footer
    lines.append("---")
    lines.append(f"*Report generated by CIPP Security Reporter | {date_str} {time_str}*")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Email HTML Report
# ---------------------------------------------------------------------------
def generate_email_html(summaries: list[TenantSecuritySummary], run_time: datetime) -> tuple[str, str]:
    """Returns (subject, html_body)."""
    stats = _compute_stats(summaries)
    date_str = run_time.strftime("%Y-%m-%d")

    subject = f"Security Posture Report — {date_str} | {stats['critical']} critical, {stats['high']} high findings"

    priority_findings = [
        f for s in summaries for f in s.findings
        if f.severity in (Severity.CRITICAL, Severity.HIGH)
    ]

    findings_rows = ""
    for f in sorted(priority_findings, key=lambda x: (0 if x.severity == Severity.CRITICAL else 1, x.tenant)):
        findings_rows += f"""
        <tr>
            <td style="padding:8px;border-bottom:1px solid #e5e7eb">{_severity_badge_html(f.severity)}</td>
            <td style="padding:8px;border-bottom:1px solid #e5e7eb"><strong>{f.tenant}</strong></td>
            <td style="padding:8px;border-bottom:1px solid #e5e7eb">{f.title}</td>
            <td style="padding:8px;border-bottom:1px solid #e5e7eb">{f.recommendation}</td>
        </tr>"""

    tenant_scores = ""
    for s in sorted(summaries, key=lambda x: x.score_pct or 0):
        score_str = f"{s.score_pct}%" if s.score_pct is not None else "N/A"
        count_str = f"{s.critical_count}C / {s.high_count}H / {len(s.findings)}T"
        color = "#dc2626" if s.critical_count else "#ea580c" if s.high_count else "#16a34a"
        tenant_scores += f"""
        <tr>
            <td style="padding:6px 8px;border-bottom:1px solid #e5e7eb">{s.tenant_name}</td>
            <td style="padding:6px 8px;border-bottom:1px solid #e5e7eb">{score_str}</td>
            <td style="padding:6px 8px;border-bottom:1px solid #e5e7eb;color:{color}">{count_str}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;max-width:800px;margin:0 auto;padding:20px;color:#1f2937">

<div style="background:linear-gradient(135deg,#1e3a5f,#2563eb);color:white;padding:24px 32px;border-radius:12px;margin-bottom:24px">
    <h1 style="margin:0 0 8px 0;font-size:24px">Security Posture Report</h1>
    <p style="margin:0;opacity:0.9">{date_str} | {stats['tenant_count']} tenants analyzed</p>
</div>

<div style="display:flex;gap:16px;margin-bottom:24px;flex-wrap:wrap">
    <div style="flex:1;min-width:120px;background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:16px;text-align:center">
        <div style="font-size:32px;font-weight:700;color:#dc2626">{stats['critical']}</div>
        <div style="font-size:13px;color:#991b1b">Critical</div>
    </div>
    <div style="flex:1;min-width:120px;background:#fff7ed;border:1px solid #fed7aa;border-radius:8px;padding:16px;text-align:center">
        <div style="font-size:32px;font-weight:700;color:#ea580c">{stats['high']}</div>
        <div style="font-size:13px;color:#9a3412">High</div>
    </div>
    <div style="flex:1;min-width:120px;background:#fefce8;border:1px solid #fde68a;border-radius:8px;padding:16px;text-align:center">
        <div style="font-size:32px;font-weight:700;color:#ca8a04">{stats['medium']}</div>
        <div style="font-size:13px;color:#854d0e">Medium</div>
    </div>
    <div style="flex:1;min-width:120px;background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;padding:16px;text-align:center">
        <div style="font-size:32px;font-weight:700;color:#16a34a">{stats['low']}</div>
        <div style="font-size:13px;color:#166534">Low</div>
    </div>
</div>

{"<h2 style='margin-top:32px;color:#1e3a5f'>Priority Actions</h2>" + '''
<table style="width:100%;border-collapse:collapse;margin-bottom:24px">
<thead><tr style="background:#f9fafb">
    <th style="padding:8px;text-align:left;border-bottom:2px solid #e5e7eb">Severity</th>
    <th style="padding:8px;text-align:left;border-bottom:2px solid #e5e7eb">Tenant</th>
    <th style="padding:8px;text-align:left;border-bottom:2px solid #e5e7eb">Finding</th>
    <th style="padding:8px;text-align:left;border-bottom:2px solid #e5e7eb">Recommendation</th>
</tr></thead>
<tbody>''' + findings_rows + "</tbody></table>" if priority_findings else "<p style='color:#16a34a;font-weight:600'>✅ No critical or high findings across all tenants.</p>"}

<h2 style="margin-top:32px;color:#1e3a5f">Tenant Overview</h2>
<table style="width:100%;border-collapse:collapse">
<thead><tr style="background:#f9fafb">
    <th style="padding:8px;text-align:left;border-bottom:2px solid #e5e7eb">Tenant</th>
    <th style="padding:8px;text-align:left;border-bottom:2px solid #e5e7eb">Secure Score</th>
    <th style="padding:8px;text-align:left;border-bottom:2px solid #e5e7eb">Findings (C/H/Total)</th>
</tr></thead>
<tbody>{tenant_scores}</tbody>
</table>

<div style="margin-top:32px;padding-top:16px;border-top:1px solid #e5e7eb;color:#6b7280;font-size:12px">
    Generated by CIPP Security Reporter | Abate Technology Services
</div>

</body>
</html>"""

    return subject, html


# ---------------------------------------------------------------------------
# Notion blocks (structured content for Notion API)
# ---------------------------------------------------------------------------
def generate_notion_blocks(summaries: list[TenantSecuritySummary], run_time: datetime) -> dict[str, Any]:
    """Returns a dict with 'title', 'properties', and 'children' blocks for Notion."""
    stats = _compute_stats(summaries)
    date_str = run_time.strftime("%Y-%m-%d")

    title = f"Security Report — {date_str}"

    properties = {
        "Date": date_str,
        "Tenants": stats["tenant_count"],
        "Critical": stats["critical"],
        "High": stats["high"],
        "Total Findings": stats["total_findings"],
    }
    if stats["avg_score_pct"] is not None:
        properties["Avg Secure Score"] = f"{stats['avg_score_pct']}%"

    # Build simplified text content for Notion
    content_lines = [
        f"# Security Posture Report — {date_str}",
        f"",
        f"**{stats['tenant_count']}** tenants | **{stats['total_findings']}** findings | "
        f"**{stats['critical']}** critical | **{stats['high']}** high",
        f"",
    ]

    priority_findings = [
        f for s in summaries for f in s.findings
        if f.severity in (Severity.CRITICAL, Severity.HIGH)
    ]
    if priority_findings:
        content_lines.append("## Priority Actions")
        content_lines.append("")
        for f in sorted(priority_findings, key=lambda x: (0 if x.severity == Severity.CRITICAL else 1)):
            content_lines.append(f"- {_severity_emoji(f.severity)} **{f.tenant}**: {f.title} → {f.recommendation}")
        content_lines.append("")

    for s in sorted(summaries, key=lambda x: -(x.critical_count * 100 + x.high_count)):
        score_str = f" ({s.score_pct}%)" if s.score_pct is not None else ""
        content_lines.append(f"### {s.tenant_name}{score_str}")
        if not s.findings:
            content_lines.append("✅ Clean")
        else:
            for f in s.findings:
                content_lines.append(f"- {_severity_emoji(f.severity)} {f.title}")
        content_lines.append("")

    return {
        "title": title,
        "properties": properties,
        "content": "\n".join(content_lines),
    }


# ---------------------------------------------------------------------------
# JSON export (for archival / programmatic use)
# ---------------------------------------------------------------------------
def generate_json_report(summaries: list[TenantSecuritySummary], run_time: datetime) -> str:
    stats = _compute_stats(summaries)

    report = {
        "generated_at": run_time.isoformat(),
        "stats": stats,
        "tenants": [
            {
                "name": s.tenant_name,
                "tenant_id": s.tenant_id,
                "domain": s.default_domain,
                "secure_score": s.secure_score,
                "secure_score_max": s.secure_score_max,
                "score_pct": s.score_pct,
                "findings": [
                    {
                        "category": f.category,
                        "title": f.title,
                        "severity": f.severity.value,
                        "description": f.description,
                        "recommendation": f.recommendation,
                    }
                    for f in s.findings
                ],
                "errors": s.errors,
            }
            for s in summaries
        ],
    }

    return json.dumps(report, indent=2, ensure_ascii=False)
