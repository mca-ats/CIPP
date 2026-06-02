"""Tests for the QBR aggregator (kpi_collectors.assemble_qbr_data).

The live fetch path (collect_qbr_data) does CIPP I/O and is verified end-to-end,
not here. We test the pure assembly: given raw CIPP responses + a security
summary, assemble_qbr_data must produce a complete QbrData with all KPI families,
the right period, and a persisted score trend.
"""
from datetime import datetime, timezone

from collectors import TenantSecuritySummary
from qbr_models import QbrData
from kpi_collectors import assemble_qbr_data


def _raw():
    return {
        "licenses": [
            {"License": "Microsoft 365 Business Premium", "CountUsed": "8", "CountAvailable": 2,
             "TotalLicenses": "10", "availableUnits": 2,
             "TermInfo": [{"DaysUntilRenew": 200}],
             "AssignedUsers": [{"displayName": "Alice", "userPrincipalName": "a@x.io"},
                               {"displayName": "Bob", "userPrincipalName": "b@x.io"}]},
        ],
        "devices": [
            {"deviceName": "PC1", "complianceState": "compliant",
             "lastSyncDateTime": "2026-05-30T13:08:31Z"},
            {"deviceName": "PC2", "complianceState": "noncompliant",
             "lastSyncDateTime": "2026-05-30T13:08:31Z"},
        ],
        "mfa_users": [
            {"UPN": "a@x.io", "AccountEnabled": True, "MFARegistration": True, "IsAdmin": False, "UserType": "Member"},
            {"UPN": "b@x.io", "AccountEnabled": True, "MFARegistration": True, "IsAdmin": True, "UserType": "Member"},
        ],
        "inactive": [
            {"userPrincipalName": "old@x.io", "numberOfAssignedLicenses": 1, "daysSinceLastSignIn": 400.0},
        ],
    }


def _summary():
    return TenantSecuritySummary(
        tenant_name="Abate Tech", tenant_id="tid-123", default_domain="abatetech.io",
        secure_score=42.0, secure_score_max=60.0, findings=[],
    )


def test_assemble_returns_qbr_data_with_identity_fields(tmp_path):
    q = assemble_qbr_data(
        summary=_summary(), raw=_raw(),
        run_time=datetime(2026, 5, 30, tzinfo=timezone.utc),
        history_path=tmp_path / "hist.json",
    )
    assert isinstance(q, QbrData)
    assert q.tenant_name == "Abate Tech"
    assert q.tenant_id == "tid-123"
    assert q.default_domain == "abatetech.io"
    assert q.period == "2026-Q2"
    assert q.security is _summary().__class__ or q.security is not None
    assert q.generated_at  # stamped


def test_assemble_includes_all_kpi_families(tmp_path):
    q = assemble_qbr_data(
        summary=_summary(), raw=_raw(),
        run_time=datetime(2026, 5, 30, tzinfo=timezone.utc),
        history_path=tmp_path / "hist.json",
    )
    keys = {m.key for m in q.kpis}
    # license family
    assert "license_utilization" in keys
    # compliance family
    assert "device_compliance_pct" in keys
    # identity family
    assert "mfa_coverage_pct" in keys


def test_assemble_persists_and_returns_score_trend(tmp_path):
    hist = tmp_path / "hist.json"
    q = assemble_qbr_data(
        summary=_summary(), raw=_raw(),
        run_time=datetime(2026, 5, 30, tzinfo=timezone.utc),
        history_path=hist,
    )
    assert hist.exists()                       # score persisted
    assert len(q.score_history) == 1
    assert q.score_history[0].pct == 70.0      # 42/60


def test_assemble_score_trend_grows_across_runs(tmp_path):
    hist = tmp_path / "hist.json"
    assemble_qbr_data(summary=_summary(), raw=_raw(),
                      run_time=datetime(2026, 2, 1, tzinfo=timezone.utc), history_path=hist)
    q2 = assemble_qbr_data(summary=_summary(), raw=_raw(),
                           run_time=datetime(2026, 5, 30, tzinfo=timezone.utc), history_path=hist)
    assert len(q2.score_history) == 2          # two distinct run dates accumulate


def test_assemble_excludes_secure_score_control_findings(tmp_path):
    # collect_secure_score emits a Finding per control gap (~147 for a real tenant);
    # those would flood the QBR appendix. The score is shown as a KPI/trend instead,
    # so per-control "Secure Score" findings must be dropped from the QBR finding set.
    from collectors import Finding, Severity
    summary = _summary()
    summary.findings = [
        Finding(tenant="Abate Tech", tenant_id="tid-123", category="Secure Score",
                title="Secure Score gap: MFA", severity=Severity.MEDIUM,
                description="d", recommendation="r"),
        Finding(tenant="Abate Tech", tenant_id="tid-123", category="Device Compliance",
                title="1 noncompliant device", severity=Severity.CRITICAL,
                description="d", recommendation="r"),
    ]
    q = assemble_qbr_data(summary=summary, raw=_raw(),
                          run_time=datetime(2026, 5, 30, tzinfo=timezone.utc),
                          history_path=tmp_path / "h.json")
    cats = {f.category for f in q.security.findings}
    assert "Secure Score" not in cats
    assert "Device Compliance" in cats
    # the score VALUE is still preserved for the trend
    assert q.score_history and q.score_history[0].pct == 70.0


def test_assemble_populates_device_inventory(tmp_path):
    q = assemble_qbr_data(
        summary=_summary(), raw=_raw(),
        run_time=datetime(2026, 5, 30, tzinfo=timezone.utc),
        history_path=tmp_path / "hist.json",
    )
    assert len(q.devices) == 2                         # PC1 + PC2 from _raw()
    assert q.devices[0].compliance == "noncompliant"   # problems sorted first


def test_assemble_populates_licensed_users_and_metric(tmp_path):
    q = assemble_qbr_data(
        summary=_summary(), raw=_raw(),
        run_time=datetime(2026, 5, 30, tzinfo=timezone.utc),
        history_path=tmp_path / "hist.json",
    )
    # two paid-SKU users from AssignedUsers, alphabetical
    assert [u.name for u in q.licensed_users] == ["Alice", "Bob"]
    # and the scorecard count KPI is present
    assert any(m.key == "licensed_users" and m.value == 2 for m in q.kpis)


def test_licensed_inactive_kpi_reconciles_with_roster(tmp_path):
    # stale@x -> Inactive (60d); gone@x -> Disabled (not counted as Inactive).
    # The KPI count must equal the roster's Inactive-flagged count, not 2.
    raw = {
        "licenses": [{"License": "Microsoft 365 E5", "CountUsed": "2", "CountAvailable": 0,
                      "TotalLicenses": "2",
                      "AssignedUsers": [{"displayName": "Stale", "userPrincipalName": "stale@x"},
                                        {"displayName": "Gone", "userPrincipalName": "gone@x"}]}],
        "devices": [],
        "mfa_users": [{"UPN": "stale@x", "AccountEnabled": True},
                      {"UPN": "gone@x", "AccountEnabled": False}],
        "inactive": [{"userPrincipalName": "stale@x", "daysSinceLastSignIn": 60.0,
                      "numberOfAssignedLicenses": 1, "accountEnabled": True},
                     {"userPrincipalName": "gone@x", "daysSinceLastSignIn": 60.0,
                      "numberOfAssignedLicenses": 1, "accountEnabled": False}],
    }
    q = assemble_qbr_data(summary=_summary(), raw=raw,
                          run_time=datetime(2026, 5, 30, tzinfo=timezone.utc),
                          history_path=tmp_path / "h.json")
    roster_inactive = sum(1 for u in q.licensed_users if u.status.startswith("Inactive"))
    kpi = next(m for m in q.kpis if m.key == "identity_licensed_inactive")
    assert roster_inactive == 1               # only stale@x; gone@x is Disabled
    assert kpi.value == roster_inactive


def test_assemble_tolerates_empty_raw(tmp_path):
    q = assemble_qbr_data(
        summary=_summary(), raw={"licenses": [], "devices": [], "mfa_users": [], "inactive": []},
        run_time=datetime(2026, 5, 30, tzinfo=timezone.utc),
        history_path=tmp_path / "hist.json",
    )
    assert isinstance(q, QbrData)
    assert q.kpis  # still emits info/zero metrics, never empty
