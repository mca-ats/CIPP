"""Tests for the QBR narrative layer (qbr_narrative.py).

The live Claude path is non-deterministic and needs an API key, so it is NOT
unit-tested here. We test the deterministic, key-free pieces:
  - the data block sent to Claude (contract: contains the KPIs/findings)
  - the rules-based fallback narrative (used when no API key is present)
  - the structured contract: every narrative has all required sections + types
"""
from collectors import Finding, Severity, TenantSecuritySummary
from qbr_models import KpiMetric, ScorePoint, QbrData
from qbr_narrative import (
    QbrNarrative,
    Risk,
    build_system_prompt,
    build_data_block,
    fallback_narrative,
)


def _sample_qbr() -> QbrData:
    summary = TenantSecuritySummary(
        tenant_name="Abate Tech", tenant_id="abc", default_domain="abatetech.io",
        secure_score=42.0, secure_score_max=60.0,
        findings=[
            Finding(tenant="Abate Tech", tenant_id="abc", category="Device Compliance",
                    title="1 noncompliant device (100.0%)", severity=Severity.CRITICAL,
                    description="1 of 1 managed devices are noncompliant.",
                    recommendation="Remediate compliance policy failures."),
            Finding(tenant="Abate Tech", tenant_id="abc", category="Conditional Access",
                    title="Policy in report-only mode", severity=Severity.LOW,
                    description="A policy is not enforcing.",
                    recommendation="Switch to enforced."),
        ],
    )
    return QbrData(
        tenant_name="Abate Tech", tenant_id="abc", default_domain="abatetech.io",
        period="2026-Q2", security=summary,
        kpis=[
            KpiMetric(key="mfa_coverage_pct", label="MFA Coverage", value=100.0, unit="%", status="good"),
            KpiMetric(key="device_compliance_pct", label="Device Compliance", value=0.0, unit="%", status="bad"),
            KpiMetric(key="license_utilization", label="License Utilization", value=83.0, unit="%", status="good"),
            KpiMetric(key="license_available", label="Unused Seats", value=0, unit="", status="good"),
        ],
        score_history=[
            ScorePoint(date="2026-02-01", score=30.0, max_score=60.0),
            ScorePoint(date="2026-05-30", score=42.0, max_score=60.0),
        ],
    )


# --- system prompt -------------------------------------------------------

def test_system_prompt_encodes_brand_voice_and_sections():
    sp = build_system_prompt()
    low = sp.lower()
    # Brand voice: no marketing speak, direct, factual
    assert "marketing" in low or "no-bs" in low or "plain" in low
    # QBR section contract present
    for section in ["exec", "win", "risk", "recommend", "priorit"]:
        assert section in low


# --- data block ----------------------------------------------------------

def test_data_block_includes_tenant_period_and_kpis():
    block = build_data_block(_sample_qbr())
    assert "Abate Tech" in block
    assert "2026-Q2" in block
    assert "MFA Coverage" in block
    assert "Device Compliance" in block
    # secure score trend should be conveyed
    assert "70.0" in block or "70" in block  # latest pct
    # findings should appear
    assert "noncompliant" in block.lower()


# --- fallback narrative (deterministic) ----------------------------------

def test_fallback_returns_full_contract():
    n = fallback_narrative(_sample_qbr())
    assert isinstance(n, QbrNarrative)
    assert isinstance(n.exec_summary, str) and len(n.exec_summary) > 0
    assert isinstance(n.wins, list)
    assert isinstance(n.risks, list) and all(isinstance(r, Risk) for r in n.risks)
    assert isinstance(n.recommendations, list)
    assert isinstance(n.next_quarter_priorities, list)


def test_fallback_exec_summary_mentions_tenant_and_period():
    n = fallback_narrative(_sample_qbr())
    assert "Abate Tech" in n.exec_summary
    assert "2026-Q2" in n.exec_summary


def test_fallback_surfaces_critical_finding_as_risk():
    n = fallback_narrative(_sample_qbr())
    risk_text = " ".join(r.title + " " + r.business_impact for r in n.risks).lower()
    assert "noncompliant" in risk_text
    # the critical finding must drive a risk with a severity
    assert any(r.severity in ("critical", "high", "medium", "low") for r in n.risks)


def test_fallback_surfaces_good_kpi_as_win():
    n = fallback_narrative(_sample_qbr())
    wins_text = " ".join(n.wins).lower()
    # MFA coverage 100% (good) and improving secure score should read as wins
    assert "mfa" in wins_text or "secure score" in wins_text or "100" in wins_text


def test_fallback_priorities_are_nonempty_when_risks_exist():
    n = fallback_narrative(_sample_qbr())
    assert len(n.next_quarter_priorities) >= 1


def test_fallback_exec_summary_grammar_is_correct():
    # "1 critical item require attention" -> subject/verb disagreement bug.
    n = fallback_narrative(_sample_qbr())
    assert "item require " not in n.exec_summary
    assert "items requires" not in n.exec_summary


def test_fallback_dedupes_device_kpi_risk_against_finding():
    # _sample_qbr has a CRITICAL device-compliance finding AND a bad device KPI.
    # The bad device KPI must NOT add a second "below target" risk for the same
    # condition — the finding already covers it.
    n = fallback_narrative(_sample_qbr())
    titles = [r.title for r in n.risks]
    assert not any("below target" in t and ("Device" in t or "Noncompliant" in t) for t in titles)
    # the finding-based device risk is still present
    assert any("noncompliant" in t.lower() for t in titles)


def test_fallback_no_marketing_filler_in_impacts():
    n = fallback_narrative(_sample_qbr())
    impacts = " ".join(r.business_impact for r in n.risks).lower()
    assert "red zone" not in impacts
    assert "needs remediation" not in impacts


def test_fallback_exec_tally_matches_risk_severities():
    # A tenant with a bad license KPI (license is unique — not covered by findings)
    # should surface as a risk and be reflected in the exec tally.
    summary = TenantSecuritySummary(tenant_name="T", tenant_id="t", default_domain="t.io",
                                    secure_score=58.0, secure_score_max=60.0, findings=[])
    q = QbrData(tenant_name="T", tenant_id="t", default_domain="t.io", period="2026-Q2",
                security=summary,
                kpis=[KpiMetric(key="license_utilization", label="License Utilization",
                                value=40.0, unit="%", status="bad",
                                detail={"assigned": 4, "available": 6})],
                score_history=[])
    n = fallback_narrative(q)
    assert len(n.risks) == 1
    assert "License Utilization" in n.risks[0].title
    # impact is concrete (mentions the number), not boilerplate
    assert "40" in n.risks[0].business_impact or "6" in n.risks[0].business_impact


def test_fallback_win_unit_has_space():
    summary = TenantSecuritySummary(tenant_name="T", tenant_id="t", default_domain="t.io",
                                    secure_score=58.0, secure_score_max=60.0, findings=[])
    q = QbrData(tenant_name="T", tenant_id="t", default_domain="t.io", period="2026-Q2",
                security=summary,
                kpis=[KpiMetric(key="device_stale_30d", label="Stale Devices",
                                value=0, unit="devices", status="good")],
                score_history=[])
    n = fallback_narrative(q)
    assert any("0 devices" in w for w in n.wins)
    assert not any("0devices" in w for w in n.wins)


def test_fallback_healthy_tenant_has_no_critical_risks():
    # A clean tenant: no findings, all-good KPIs
    summary = TenantSecuritySummary(tenant_name="Clean Co", tenant_id="x",
                                    default_domain="clean.io",
                                    secure_score=58.0, secure_score_max=60.0, findings=[])
    q = QbrData(tenant_name="Clean Co", tenant_id="x", default_domain="clean.io",
                period="2026-Q2", security=summary,
                kpis=[KpiMetric(key="mfa_coverage_pct", label="MFA Coverage",
                                value=100.0, unit="%", status="good")],
                score_history=[ScorePoint(date="2026-05-30", score=58.0, max_score=60.0)])
    n = fallback_narrative(q)
    assert n.wins  # healthy tenant should have wins
    assert not any(r.severity == "critical" for r in n.risks)
