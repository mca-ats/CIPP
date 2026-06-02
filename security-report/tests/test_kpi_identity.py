"""Tests for the identity KPI collector (kpi/identity.py).

Pure-function transform from CIPP /api/ListMFAUsers and
/api/ListInactiveAccounts payloads into QBR KpiMetric scorecard rows.
Inline dict literals stand in for the real API responses — no mocking.
"""
import pytest

from qbr_models import KpiMetric
from kpi.identity import collect_identity_kpis


def _by_key(metrics: list[KpiMetric]) -> dict[str, KpiMetric]:
    return {m.key: m for m in metrics}


# --- shape ---------------------------------------------------------------

def test_returns_the_four_expected_keys():
    metrics = collect_identity_kpis([], [])
    keys = {m.key for m in metrics}
    assert keys == {
        "mfa_coverage_pct",
        "mfa_admins_uncovered",
        "identity_guests",
        "identity_licensed_inactive",
    }
    assert all(isinstance(m, KpiMetric) for m in metrics)


# --- empty / robustness --------------------------------------------------

def test_empty_inputs_do_not_crash_and_are_zero_info():
    m = _by_key(collect_identity_kpis([], []))
    # No enabled users -> coverage denom 0 -> 0.0 / info, never a divide error.
    assert m["mfa_coverage_pct"].value == 0.0
    assert m["mfa_coverage_pct"].status == "info"
    assert m["mfa_coverage_pct"].unit == "%"
    # Zero of everything else.
    assert m["mfa_admins_uncovered"].value == 0
    assert m["mfa_admins_uncovered"].status == "good"
    assert m["identity_guests"].value == 0
    assert m["identity_guests"].status == "info"
    assert m["identity_licensed_inactive"].value == 0
    assert m["identity_licensed_inactive"].status == "good"


# --- mfa_coverage_pct ----------------------------------------------------

def test_full_mfa_coverage_is_100_good():
    users = [
        {"UPN": "a@x.com", "AccountEnabled": True, "MFARegistration": True,
         "IsAdmin": False, "UserType": "Member"},
        {"UPN": "b@x.com", "AccountEnabled": True, "MFARegistration": True,
         "IsAdmin": False, "UserType": "Member"},
    ]
    m = _by_key(collect_identity_kpis(users, []))
    assert m["mfa_coverage_pct"].value == 100.0
    assert m["mfa_coverage_pct"].status == "good"


def test_partial_coverage_six_of_eight_is_75_bad():
    users = []
    for i in range(6):  # registered
        users.append({"UPN": f"r{i}@x.com", "AccountEnabled": True,
                      "MFARegistration": True, "IsAdmin": False,
                      "UserType": "Member"})
    for i in range(2):  # not registered (one None, one False)
        users.append({"UPN": f"n{i}@x.com", "AccountEnabled": True,
                      "MFARegistration": None if i == 0 else False,
                      "IsAdmin": False, "UserType": "Member"})
    m = _by_key(collect_identity_kpis(users, []))
    assert m["mfa_coverage_pct"].value == 75.0  # 6/8
    assert m["mfa_coverage_pct"].status == "bad"


def test_coverage_warn_band_85_pct():
    # 17 of 20 registered = 85% -> warn
    users = []
    for i in range(17):
        users.append({"UPN": f"r{i}@x.com", "AccountEnabled": True,
                      "MFARegistration": True, "IsAdmin": False,
                      "UserType": "Member"})
    for i in range(3):
        users.append({"UPN": f"n{i}@x.com", "AccountEnabled": True,
                      "MFARegistration": False, "IsAdmin": False,
                      "UserType": "Member"})
    m = _by_key(collect_identity_kpis(users, []))
    assert m["mfa_coverage_pct"].value == 85.0
    assert m["mfa_coverage_pct"].status == "warn"


def test_disabled_accounts_excluded_from_coverage_denominator():
    # Only one enabled user, registered -> 100%. Disabled+unregistered ignored.
    users = [
        {"UPN": "a@x.com", "AccountEnabled": True, "MFARegistration": True,
         "IsAdmin": False, "UserType": "Member"},
        {"UPN": "z@x.com", "AccountEnabled": False, "MFARegistration": None,
         "IsAdmin": False, "UserType": "Member"},
    ]
    m = _by_key(collect_identity_kpis(users, []))
    assert m["mfa_coverage_pct"].value == 100.0
    assert m["mfa_coverage_pct"].status == "good"


def test_string_booleans_are_coerced():
    # Some CIPP fields arrive as strings — must coerce defensively.
    users = [
        {"UPN": "a@x.com", "AccountEnabled": "true", "MFARegistration": "true",
         "IsAdmin": "false", "UserType": "Member"},
        {"UPN": "b@x.com", "AccountEnabled": "true", "MFARegistration": "false",
         "IsAdmin": "false", "UserType": "Member"},
    ]
    m = _by_key(collect_identity_kpis(users, []))
    assert m["mfa_coverage_pct"].value == 50.0  # 1 of 2
    assert m["mfa_coverage_pct"].status == "bad"


# --- mfa_admins_uncovered ------------------------------------------------

def test_admin_without_mfa_is_bad_and_sampled():
    users = [
        {"UPN": "admin@x.com", "AccountEnabled": True, "MFARegistration": False,
         "IsAdmin": True, "UserType": "Member"},
        {"UPN": "ok@x.com", "AccountEnabled": True, "MFARegistration": True,
         "IsAdmin": True, "UserType": "Member"},
    ]
    m = _by_key(collect_identity_kpis(users, []))
    assert m["mfa_admins_uncovered"].value == 1
    assert m["mfa_admins_uncovered"].status == "bad"
    assert "admin@x.com" in m["mfa_admins_uncovered"].detail.get("sample", [])
    assert "ok@x.com" not in m["mfa_admins_uncovered"].detail.get("sample", [])


def test_admin_with_null_mfa_counts_as_uncovered():
    users = [
        {"UPN": "admin@x.com", "AccountEnabled": True, "MFARegistration": None,
         "IsAdmin": True, "UserType": "Member"},
    ]
    m = _by_key(collect_identity_kpis(users, []))
    assert m["mfa_admins_uncovered"].value == 1
    assert m["mfa_admins_uncovered"].status == "bad"


def test_disabled_admin_without_mfa_not_counted():
    users = [
        {"UPN": "admin@x.com", "AccountEnabled": False, "MFARegistration": False,
         "IsAdmin": True, "UserType": "Member"},
    ]
    m = _by_key(collect_identity_kpis(users, []))
    assert m["mfa_admins_uncovered"].value == 0
    assert m["mfa_admins_uncovered"].status == "good"


def test_all_admins_covered_is_good():
    users = [
        {"UPN": "admin@x.com", "AccountEnabled": True, "MFARegistration": True,
         "IsAdmin": True, "UserType": "Member"},
    ]
    m = _by_key(collect_identity_kpis(users, []))
    assert m["mfa_admins_uncovered"].value == 0
    assert m["mfa_admins_uncovered"].status == "good"


# --- identity_guests -----------------------------------------------------

def test_guest_accounts_counted_info():
    users = [
        {"UPN": "g@x.com", "AccountEnabled": True, "MFARegistration": True,
         "IsAdmin": False, "UserType": "Guest"},
        {"UPN": "m@x.com", "AccountEnabled": True, "MFARegistration": True,
         "IsAdmin": False, "UserType": "Member"},
    ]
    m = _by_key(collect_identity_kpis(users, []))
    assert m["identity_guests"].value == 1
    assert m["identity_guests"].status == "info"
    assert m["identity_guests"].unit == "guests"


# --- identity_licensed_inactive ------------------------------------------

def test_licensed_inactive_counts_only_licensed():
    inactive = [
        {"userPrincipalName": "lic@x.com", "numberOfAssignedLicenses": 2,
         "daysSinceLastSignIn": 1505.0, "userType": "Member"},
        {"userPrincipalName": "unlic@x.com", "numberOfAssignedLicenses": 0,
         "daysSinceLastSignIn": 900.0, "userType": "Member"},
    ]
    m = _by_key(collect_identity_kpis([], inactive))
    assert m["identity_licensed_inactive"].value == 1  # only the licensed one
    # 0 -> good, 1-2 -> warn, >=3 -> bad. One licensed-inactive falls in warn.
    assert m["identity_licensed_inactive"].status == "warn"
    samples = m["identity_licensed_inactive"].detail.get("sample", [])
    upns = [s.get("upn") for s in samples]
    assert "lic@x.com" in upns
    assert "unlic@x.com" not in upns
    # days carried in sample
    lic_sample = next(s for s in samples if s.get("upn") == "lic@x.com")
    assert lic_sample.get("days") == 1505.0


def test_licensed_inactive_three_or_more_is_bad():
    inactive = [
        {"userPrincipalName": f"u{i}@x.com", "numberOfAssignedLicenses": 1,
         "daysSinceLastSignIn": 200.0, "userType": "Member"}
        for i in range(3)
    ]
    m = _by_key(collect_identity_kpis([], inactive))
    assert m["identity_licensed_inactive"].value == 3
    assert m["identity_licensed_inactive"].status == "bad"


def test_licensed_inactive_string_license_count_coerced():
    inactive = [
        {"userPrincipalName": "lic@x.com", "numberOfAssignedLicenses": "2",
         "daysSinceLastSignIn": "1505.0", "userType": "Member"},
    ]
    m = _by_key(collect_identity_kpis([], inactive))
    assert m["identity_licensed_inactive"].value == 1
    assert m["identity_licensed_inactive"].status == "warn"
