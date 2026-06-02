"""Regression tests for issues surfaced by the adversarial review against real
abatetech.io data. Each test pins a specific real-world data shape the original
collectors mishandled.
"""
import datetime

from kpi.licenses import collect_license_kpis
from kpi.identity import collect_identity_kpis
from kpi.compliance import collect_compliance_kpis
from kpi.score_trend import collect_score_trend


def _kpi(metrics, key):
    return next(m for m in metrics if m.key == key)


# --- licenses ------------------------------------------------------------

def test_free_dev_sku_excluded_from_waste_and_utilization():
    # Power Apps for Developer ships 9999 free seats — must NOT count as waste,
    # and must not poison utilization. One real paid SKU is fully used.
    skus = [
        {"License": "Microsoft 365 E5", "CountUsed": "4", "CountAvailable": 0, "TotalLicenses": "4"},
        {"License": "Microsoft Power Apps for Developer", "CountUsed": "1",
         "CountAvailable": 9999, "TotalLicenses": "10000"},
    ]
    m = collect_license_kpis(skus)
    assert _kpi(m, "license_available").value == 0           # dev seats not waste
    assert _kpi(m, "license_available").status == "good"
    assert _kpi(m, "license_utilization").value == 100.0     # 4/4 paid, dev excluded
    assert _kpi(m, "license_utilization").status == "good"


def test_negative_available_sentinel_clamped_and_suspended_excluded():
    # Windows 365 suspended SKU: CountAvailable -1, TotalLicenses "0".
    skus = [
        {"License": "Microsoft 365 E5", "CountUsed": "3", "CountAvailable": 1, "TotalLicenses": "4"},
        {"License": "Windows 365 Enterprise", "CountUsed": "0", "CountAvailable": -1,
         "TotalLicenses": "0", "TermInfo": [{"Status": "Suspended"}]},
    ]
    m = collect_license_kpis(skus)
    # only the real SKU's 1 unused seat counts; the -1 sentinel is dropped, not summed
    assert _kpi(m, "license_available").value == 1


def test_renewals_excludes_garbage_negative_days():
    skus = [
        {"License": "Microsoft 365 E5", "CountUsed": "4", "CountAvailable": 0, "TotalLicenses": "4",
         "TermInfo": [{"DaysUntilRenew": 26}]},                       # real, <=90
        {"License": "Power Apps Developer", "CountUsed": "1", "CountAvailable": 9999,
         "TotalLicenses": "10000", "TermInfo": [{"DaysUntilRenew": -739765}]},  # garbage
        {"License": "Annual SKU", "CountUsed": "2", "CountAvailable": 0, "TotalLicenses": "2",
         "TermInfo": [{"DaysUntilRenew": 313}]},                      # >90
    ]
    m = collect_license_kpis(skus)
    assert _kpi(m, "license_renewals_90d").value == 1                 # only the 26-day one


def test_renewals_handles_single_dict_terminfo():
    # CIPP often flattens a single-element TermInfo array to a bare object.
    skus = [{"License": "E5", "CountUsed": "1", "CountAvailable": 0, "TotalLicenses": "1",
             "TermInfo": {"DaysUntilRenew": 30}}]
    m = collect_license_kpis(skus)
    assert _kpi(m, "license_renewals_90d").value == 1


# --- identity ------------------------------------------------------------

def test_identity_tolerates_non_dict_elements():
    # CIPP can return error strings/None mixed into a list — must not crash the QBR.
    m = collect_identity_kpis(["oops", None, 42, {"UPN": "a@x", "AccountEnabled": True,
                                                  "MFARegistration": True}],
                              ["bad", None])
    assert _kpi(m, "mfa_coverage_pct").value == 100.0   # the one valid enabled user is covered


def test_identity_licensed_inactive_enforces_30_day_threshold():
    inactive = [
        {"userPrincipalName": "old@x", "numberOfAssignedLicenses": 1, "daysSinceLastSignIn": 400.0},
        {"userPrincipalName": "midold@x", "numberOfAssignedLicenses": 1, "daysSinceLastSignIn": 40.0},
        {"userPrincipalName": "recent@x", "numberOfAssignedLicenses": 1, "daysSinceLastSignIn": 20.0},
    ]
    m = collect_identity_kpis([], inactive)
    # 400 and 40 days count (>= 30); the 20-day account does not
    assert _kpi(m, "identity_licensed_inactive").value == 2


# --- compliance ----------------------------------------------------------

def test_compliance_credits_in_grace_period_like_intune():
    devices = (
        [{"deviceName": f"c{i}", "complianceState": "compliant"} for i in range(8)]
        + [{"deviceName": "g", "complianceState": "inGracePeriod"}]
        + [{"deviceName": "n", "complianceState": "noncompliant"}]
    )
    m = collect_compliance_kpis(devices)
    assert _kpi(m, "device_compliant").value == 9            # 8 + grace
    assert _kpi(m, "device_noncompliant").value == 1
    assert _kpi(m, "device_compliance_pct").value == 90.0    # matches Intune, not 80
    assert _kpi(m, "device_compliance_pct").status == "good"


def test_compliance_excludes_non_evaluated_from_denominator():
    devices = (
        [{"deviceName": f"c{i}", "complianceState": "compliant"} for i in range(8)]
        + [{"deviceName": "u", "complianceState": "unknown"}]
        + [{"deviceName": "n", "complianceState": "noncompliant"}]
    )
    m = collect_compliance_kpis(devices)
    assert _kpi(m, "device_total").value == 10
    # unknown excluded from % denominator: 8 / (8+1) = 88.9
    assert _kpi(m, "device_compliance_pct").value == 88.9


# --- score_trend ---------------------------------------------------------

def test_score_trend_upsert_dedupes_non_str_run_date(tmp_path):
    p = tmp_path / "h.json"
    d = datetime.date(2026, 5, 30)
    collect_score_trend("t1", 10.0, 20.0, d, p)
    pts = collect_score_trend("t1", 15.0, 20.0, d, p)   # same date, non-str
    assert len(pts) == 1                                 # replaced, not appended
    assert pts[0].score == 15.0
