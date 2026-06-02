"""
QBR narrative layer — turns structured KPIs + findings into a value-framed,
client-ready narrative.

Two backends:
  - generate_narrative() calls Claude (structured output) when an API key is
    available, encoding the ATS brand voice + QBR section contract.
  - fallback_narrative() is a deterministic, key-free rules engine that produces
    the same QbrNarrative shape. It runs when no ANTHROPIC_API_KEY is set, so the
    end-to-end pipeline always yields a populated report. The AI path is a quality
    upgrade, not a hard dependency.

The layout downstream (pdf_renderer) consumes QbrNarrative either way — prose is
the only thing that varies between backends; the structure is identical and tested.
"""

from __future__ import annotations

import os
from typing import Any

from pydantic import BaseModel, Field

from qbr_models import QbrData, score_trend

MODEL = "claude-opus-4-8"


# --- structured contract (shared by both backends) -----------------------

class Risk(BaseModel):
    title: str
    severity: str = Field(description="critical | high | medium | low")
    business_impact: str


class QbrNarrative(BaseModel):
    exec_summary: str
    wins: list[str] = Field(default_factory=list)
    risks: list[Risk] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    next_quarter_priorities: list[str] = Field(default_factory=list)


# --- prompt construction (pure, testable) --------------------------------

def build_system_prompt() -> str:
    """Stable system prompt: brand voice + QBR section contract. Cacheable."""
    return (
        "You are the analyst voice of Abate Technology Services (ATS), a managed "
        "IT services practice serving Connecticut nonprofits. You are writing the "
        "narrative for a quarterly Client Health / QBR report.\n\n"
        "VOICE (non-negotiable):\n"
        "- Direct, confident, factual. State posture plainly. No hedging.\n"
        "- NO marketing speak, no hype, no salesy filler. This is a no-BS working "
        "document for a client's admin/finance audience. Every sentence earns its place.\n"
        "- Frame value honestly: name real wins, name real risks, never inflate.\n\n"
        "QBR SECTION CONTRACT — return exactly these sections:\n"
        "- exec_summary: 2-4 sentences. Overall posture for the period, grounded in the numbers.\n"
        "- wins: concrete things going well this quarter (improving Secure Score, full MFA "
        "coverage, no license waste, etc.).\n"
        "- risks: each with a title, a severity (critical|high|medium|low), and a one-line "
        "business_impact stated in plain terms (what it means for the client, not jargon).\n"
        "- recommendations: specific, actionable next steps.\n"
        "- next_quarter_priorities: the 3-5 things to tackle next quarter, highest-impact first."
    )


def build_data_block(q: QbrData) -> str:
    """Per-tenant data block (the volatile part of the prompt)."""
    lines: list[str] = []
    lines.append(f"Client: {q.tenant_name} ({q.default_domain})")
    lines.append(f"Period: {q.period}")

    trend = score_trend(q.score_history)
    if trend["latest_pct"] is not None:
        s = f"Secure Score: {trend['latest_pct']}%"
        if trend["delta"] is not None:
            arrow = {"up": "up", "down": "down", "flat": "flat"}[trend["direction"]]
            s += f" ({arrow} {abs(trend['delta'])} pts vs prior quarter)"
        lines.append(s)

    lines.append("")
    lines.append("Health KPIs:")
    for m in q.kpis:
        unit = m.unit if m.unit else ""
        lines.append(f"  - {m.label}: {m.value}{unit} [{m.status}]")

    sec = q.security
    if sec is not None and getattr(sec, "findings", None):
        lines.append("")
        lines.append("Findings:")
        for f in sec.findings:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            lines.append(f"  - [{sev}] {f.title} — {f.description} (Rec: {f.recommendation})")

    return "\n".join(lines)


# --- deterministic fallback (no API key required) ------------------------

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# KPI key prefix -> coverage domain; finding category -> the same domain. Used to
# suppress a KPI-derived risk when a security finding already covers that domain
# (so one noncompliant device isn't counted as three separate risks).
_DOMAIN_BY_PREFIX = {"device_": "device", "mfa_": "identity",
                     "identity_": "identity", "license_": "license"}
_FINDING_DOMAIN = {
    "Device Compliance": "device", "Endpoint Protection": "device",
    "MFA": "identity", "Identity Hygiene": "identity",
    "Conditional Access": "identity", "Admin Roles": "identity",
}


def _fmt(value: Any, unit: str) -> str:
    """Value + unit with a space for word-units, tight for % and unitless."""
    return f"{value}{unit}" if unit in ("", "%") else f"{value} {unit}"


def _kpi_domain(key: str) -> str:
    for p, d in _DOMAIN_BY_PREFIX.items():
        if key.startswith(p):
            return d
    return key


def _kpi_impact(m: Any) -> str:
    """Concrete, metric-specific impact line — no filler, no 'red zone' cliche."""
    d = m.detail or {}
    if m.key == "license_utilization":
        return (f"Only {m.value}% of paid licenses are in use; "
                f"{d.get('available', 'several')} paid seats are unassigned.")
    if m.key == "license_available":
        return f"{m.value} paid seats are purchased but sitting unassigned."
    if m.key == "mfa_coverage_pct":
        return f"Only {m.value}% of enabled users have registered for MFA."
    if m.key == "mfa_admins_uncovered":
        return f"{m.value} administrator account(s) can sign in without MFA."
    if m.key == "device_compliance_pct":
        return f"Only {m.value}% of evaluated devices meet compliance policy."
    if m.key == "device_noncompliant":
        return f"{m.value} managed device(s) are out of compliance policy."
    return f"{m.label} is at {_fmt(m.value, m.unit)}, below the healthy threshold."


def fallback_narrative(q: QbrData) -> QbrNarrative:
    """Rules-based narrative. Deterministic; used when Claude is unavailable."""
    trend = score_trend(q.score_history)
    findings = _findings(q)

    # --- risks: findings first, then KPI risks not already covered by a finding ---
    risks: list[Risk] = []
    for f in sorted(findings, key=lambda x: _SEV_ORDER.get(_sev(x), 9)):
        if _sev(f) in ("critical", "high", "medium"):
            risks.append(Risk(title=f.title, severity=_sev(f), business_impact=f.description))
    covered = {_FINDING_DOMAIN.get(f.category) for f in findings}
    covered.discard(None)
    for m in q.kpis:
        if m.status == "bad" and _kpi_domain(m.key) not in covered:
            risks.append(Risk(
                title=f"{m.label} below target ({_fmt(m.value, m.unit)})",
                severity="high",
                business_impact=_kpi_impact(m),
            ))

    # --- exec summary: reflect the FULL deduped risk tally ---
    parts = [f"This Client Health review covers {q.tenant_name} for {q.period}."]
    if trend["latest_pct"] is not None:
        if trend["delta"] is not None and trend["direction"] != "flat":
            verb = "improved to" if trend["direction"] == "up" else "declined to"
            parts.append(
                f"Microsoft Secure Score {verb} {trend['latest_pct']}% "
                f"({'+' if trend['delta'] > 0 else ''}{trend['delta']} points versus last quarter)."
            )
        else:
            parts.append(f"Microsoft Secure Score stands at {trend['latest_pct']}%.")
    counts = {s: sum(1 for r in risks if r.severity == s) for s in ("critical", "high", "medium", "low")}
    tally = [f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low") if counts[s]]
    total = sum(counts.values())
    if tally:
        noun = "item" if total == 1 else "items"
        verb = "needs" if total == 1 else "need"
        parts.append(f"{', '.join(tally)} {noun} {verb} attention this quarter.")
    else:
        parts.append("No material risks were identified this quarter.")
    exec_summary = " ".join(parts)

    # --- wins (good KPIs + improving score + clean posture) ---
    crit = [f for f in findings if _sev(f) == "critical"]
    wins: list[str] = []
    if trend["delta"] is not None and trend["direction"] == "up":
        wins.append(f"Secure Score improved {trend['delta']} points quarter-over-quarter.")
    for m in q.kpis:
        if m.status == "good":
            wins.append(f"{m.label} at {_fmt(m.value, m.unit)}.")
    if not crit and findings:
        wins.append("No critical findings — core security posture is holding.")
    if not wins:
        wins.append("Environment is stable with no major regressions this quarter.")

    # --- recommendations ---
    recommendations: list[str] = []
    seen: set[str] = set()
    for f in findings:
        if _sev(f) in ("critical", "high", "medium") and f.recommendation not in seen:
            recommendations.append(f.recommendation)
            seen.add(f.recommendation)
    if not recommendations:
        recommendations.append("Maintain current controls and continue monthly posture review.")

    # --- next-quarter priorities (top risks first) ---
    priorities = [r.title for r in risks[:5]]
    if not priorities:
        priorities.append("Sustain current posture; revisit Secure Score targets next quarter.")

    return QbrNarrative(
        exec_summary=exec_summary,
        wins=wins,
        risks=risks,
        recommendations=recommendations,
        next_quarter_priorities=priorities,
    )


def _findings(q: QbrData) -> list[Any]:
    sec = q.security
    return list(getattr(sec, "findings", []) or []) if sec is not None else []


def _sev(f: Any) -> str:
    s = getattr(f, "severity", "info")
    return s.value if hasattr(s, "value") else str(s)


# --- live Claude backend -------------------------------------------------

def generate_narrative(q: QbrData, client: Any | None = None) -> QbrNarrative:
    """Generate the narrative via Claude when a key is available, else fallback.

    Falls back deterministically on: no API key, missing SDK, or any API error —
    so the pipeline never hard-fails on the narrative step.
    """
    if client is None and not os.environ.get("ANTHROPIC_API_KEY"):
        return fallback_narrative(q)

    try:
        import anthropic
    except ImportError:
        return fallback_narrative(q)

    try:
        client = client or anthropic.Anthropic()
        resp = client.messages.parse(
            model=MODEL,
            max_tokens=4000,
            thinking={"type": "adaptive"},
            system=[{
                "type": "text",
                "text": build_system_prompt(),
                "cache_control": {"type": "ephemeral"},
            }],
            messages=[{"role": "user", "content": build_data_block(q)}],
            output_format=QbrNarrative,
        )
        parsed = getattr(resp, "parsed_output", None)
        if isinstance(parsed, QbrNarrative):
            return parsed
        return fallback_narrative(q)
    except Exception:
        return fallback_narrative(q)
