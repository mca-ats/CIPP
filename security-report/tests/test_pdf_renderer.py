"""Tests for the branded PDF renderer (pdf_renderer.py).

- build_html() is pure and fast: assert the report HTML carries all the content.
- render_qbr_pdf() is a smoke test: it must emit a non-empty, valid PDF.
"""
from collectors import Finding, Severity, TenantSecuritySummary
from qbr_models import KpiMetric, ScorePoint, QbrData, DeviceRecord, LicensedUser
from qbr_narrative import QbrNarrative, Risk
from pdf_renderer import build_html, render_qbr_pdf


def _qbr() -> QbrData:
    summary = TenantSecuritySummary(
        tenant_name="Abate Tech", tenant_id="abc", default_domain="abatetech.io",
        secure_score=42.0, secure_score_max=60.0,
        findings=[Finding(tenant="Abate Tech", tenant_id="abc", category="Device Compliance",
                          title="1 noncompliant device", severity=Severity.CRITICAL,
                          description="1 of 1 devices noncompliant.",
                          recommendation="Remediate compliance.")],
    )
    return QbrData(
        tenant_name="Abate Tech", tenant_id="abc", default_domain="abatetech.io",
        period="2026-Q2", security=summary,
        kpis=[KpiMetric(key="mfa_coverage_pct", label="MFA Coverage", value=100.0, unit="%", status="good"),
              KpiMetric(key="device_compliance_pct", label="Device Compliance", value=0.0, unit="%", status="bad")],
        score_history=[ScorePoint(date="2026-02-01", score=30.0, max_score=60.0),
                       ScorePoint(date="2026-05-30", score=42.0, max_score=60.0)],
        generated_at="2026-05-30T21:00:00+00:00",
    )


def _narrative() -> QbrNarrative:
    return QbrNarrative(
        exec_summary="Posture improved this quarter for Abate Tech.",
        wins=["MFA Coverage at 100%.", "Secure Score improved 20 points."],
        risks=[Risk(title="1 noncompliant device", severity="critical",
                    business_impact="Device is out of policy and may be exposed.")],
        recommendations=["Remediate the noncompliant device."],
        next_quarter_priorities=["Bring all devices into compliance."],
    )


# --- build_html (pure) ---------------------------------------------------

def test_html_contains_cover_identity():
    html = build_html(_qbr(), _narrative())
    assert "Abate Tech" in html
    assert "2026-Q2" in html
    assert "abatetech.io" in html


def test_html_contains_all_sections():
    html = build_html(_qbr(), _narrative()).lower()
    assert "exec" in html  # executive summary heading
    assert "win" in html
    assert "risk" in html
    assert "recommend" in html or "priorit" in html


def test_html_renders_narrative_content():
    html = build_html(_qbr(), _narrative())
    assert "Posture improved this quarter" in html
    assert "MFA Coverage at 100%." in html
    assert "noncompliant device" in html
    assert "Bring all devices into compliance." in html


def test_html_includes_kpi_scorecard_values():
    html = build_html(_qbr(), _narrative())
    assert "MFA Coverage" in html
    assert "100.0" in html or "100" in html
    assert "Device Compliance" in html


def test_html_includes_secure_score_trend():
    html = build_html(_qbr(), _narrative())
    assert "70.0" in html or "70" in html  # latest pct
    assert "Secure Score" in html


def test_html_kpi_card_word_unit_has_space():
    q = _qbr()
    q.kpis.append(KpiMetric(key="device_stale_30d", label="Stale Devices",
                            value=0, unit="devices", status="good"))
    html = build_html(q, _narrative())
    # word units get a separating &nbsp; before the unit; % stays tight.
    assert "&nbsp;devices" in html
    assert "&nbsp;%" not in html


def test_html_applies_brand_color():
    html = build_html(_qbr(), _narrative())
    # ATS orange accent must appear in the styling
    assert "FF" in html.upper() and ("#FF" in html.upper())


# --- render_qbr_pdf (smoke) ----------------------------------------------

def test_html_secure_score_never_silently_absent():
    # When score history is empty, the scorecard must show an explicit
    # "data unavailable" note rather than silently dropping the flagship metric.
    q = _qbr()
    q.score_history = []
    q.security.secure_score = None
    q.security.secure_score_max = None
    html = build_html(q, _narrative())
    assert "Secure Score" in html
    assert "unavailable" in html.lower()


def test_html_device_inventory_lists_devices():
    q = _qbr()
    q.devices = [DeviceRecord(name="CPC-oddjo", os="Windows 10.0.26200", owner="company",
                              compliance="noncompliant", last_sync="2026-05-30", user="Odd Job")]
    html = build_html(q, _narrative())
    assert "Device Inventory" in html
    assert "CPC-oddjo" in html
    assert "Windows 10.0.26200" in html
    assert "Odd Job" in html
    assert "2026-05-30" in html


def test_html_device_inventory_empty_state():
    q = _qbr()
    q.devices = []
    html = build_html(q, _narrative())
    assert "Device Inventory" in html
    assert "No managed devices enrolled" in html


def test_html_licensed_users_appendix():
    q = _qbr()
    q.licensed_users = [
        LicensedUser(name="Alice Active", upn="alice@x.io", licenses=["Business Premium"], status="Active"),
        LicensedUser(name="Gone User", upn="gone@x.io", licenses=["Business Premium"], status="Disabled"),
    ]
    html = build_html(q, _narrative())
    assert "Licensed Users" in html
    assert "Alice Active" in html
    assert "alice@x.io" in html
    assert "Business Premium" in html
    assert "Disabled" in html          # offboarding flag surfaced


def test_html_licensed_users_empty_state():
    q = _qbr()
    q.licensed_users = []
    html = build_html(q, _narrative())
    assert "Licensed Users" in html
    assert "No paid-SKU users found" in html


def test_html_finding_lists_affected_items():
    # A finding carrying a list of affected items (mailboxes/users) must surface them.
    q = _qbr()
    q.security.findings = [
        Finding(tenant="Abate Tech", tenant_id="abc", category="Mail Security",
                title="3 mailboxes with forwarding enabled", severity=Severity.HIGH,
                description="exfil risk", recommendation="Audit forwarding.",
                details={"forwarding": ["alice@x.io → ext@gmail.com",
                                        "bob@x.io → ext2@gmail.com",
                                        "carol@x.io → ext3@gmail.com"]}),
        Finding(tenant="Abate Tech", tenant_id="abc", category="MFA",
                title="2 users without MFA registered", severity=Severity.MEDIUM,
                description="x", recommendation="Require MFA.",
                details={"users": ["dave@x.io", "erin@x.io"]}),
    ]
    html = build_html(q, _narrative())
    for item in ["alice@x.io → ext@gmail.com", "carol@x.io → ext3@gmail.com",
                 "dave@x.io", "erin@x.io"]:
        assert item in html


def test_html_metrics_rendered_as_list_not_cards():
    html = build_html(_qbr(), _narrative())
    # new clean list structure, not the old card grid
    assert 'class="metrics"' in html
    assert 'class="mrow"' in html
    assert 'class="kpis"' not in html      # card grid removed
    # values still present
    assert "MFA Coverage" in html and "100" in html


def test_html_shows_degraded_banner_when_errors():
    q = _qbr()
    q.errors = ["KPI fetch failed: ListMFAUsers"]
    html = build_html(q, _narrative())
    assert "incomplete" in html.lower()       # visible degraded marker
    q2 = _qbr()
    q2.errors = []
    assert "incomplete" not in build_html(q2, _narrative()).lower()


def test_render_produces_valid_pdf(tmp_path):
    out = tmp_path / "qbr.pdf"
    result = render_qbr_pdf(_qbr(), _narrative(), out)
    assert result == out
    assert out.exists()
    data = out.read_bytes()
    assert data[:5] == b"%PDF-"        # valid PDF magic bytes
    assert len(data) > 2000            # non-trivial content
