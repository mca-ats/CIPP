"""Tests for the licensed-users collector (kpi/licensed_users.py).

Lists users who hold a PAID productivity SKU (Business Premium / F3 / E3 / E5 /
etc.) — not free licenses — with a status flag so an exec can spot paid seats
held by users who are disabled or long-inactive (an offboarding gap + wasted spend).
"""
from qbr_models import LicensedUser, KpiMetric
from kpi.licensed_users import is_paid_sku, collect_licensed_users, licensed_users_metric


# --- paid SKU matcher ----------------------------------------------------

def test_paid_seats_match():
    for name in ["Microsoft 365 Business Premium", "Microsoft 365 F3",
                 "Microsoft 365 E5", "Office 365 E3", "Microsoft 365 E5 (no Teams)",
                 "Microsoft 365 E3 EEA (no Teams)",
                 "Microsoft 365 Business Standard", "Microsoft 365 Business Basic"]:
        assert is_paid_sku(name), name


def test_free_and_addon_skus_do_not_match():
    # Free SKUs, paid add-ons (E5 Security/Compliance/etc.), and EMS are NOT seats.
    for name in ["Microsoft Power Apps for Developer", "Microsoft Power Automate Free",
                 "Windows 365 Enterprise 8 vCPU, 32 GB, 256 GB", "Microsoft 365 Business Voice",
                 "Microsoft Teams Exploratory", "Microsoft 365 Apps for Business",
                 "Microsoft 365 E5 Security", "Microsoft 365 E5 Compliance",
                 "Microsoft 365 E5 Information Protection and Governance",
                 "Microsoft 365 E5 eDiscovery and Audit", "Microsoft 365 E3 Extra Features",
                 "Enterprise Mobility + Security E3", "Enterprise Mobility + Security E5", ""]:
        assert not is_paid_sku(name), name


# --- collector -----------------------------------------------------------

def _sku(name, users):
    return {"License": name, "AssignedUsers": [
        {"displayName": dn, "userPrincipalName": upn} for dn, upn in users]}


def test_lists_only_paid_sku_users():
    licenses = [
        _sku("Microsoft 365 Business Premium", [("Bob Smith", "bob@x.io")]),
        _sku("Microsoft Power Apps for Developer", [("Dev Account", "dev@x.io")]),  # free -> excluded
    ]
    rows = collect_licensed_users(licenses, [], [])
    assert [r.upn for r in rows] == ["bob@x.io"]
    assert rows[0].licenses == ["Business Premium"]   # display prefix stripped


def test_alphabetical_by_name():
    licenses = [_sku("Microsoft 365 E5", [("Zoe", "z@x.io"), ("Anna", "a@x.io"), ("mike", "m@x.io")])]
    rows = collect_licensed_users(licenses, [], [])
    assert [r.name for r in rows] == ["Anna", "mike", "Zoe"]   # case-insensitive sort


def test_user_with_multiple_paid_skus_deduped():
    licenses = [
        _sku("Microsoft 365 E3", [("Bob Smith", "bob@x.io")]),
        _sku("Microsoft 365 E5", [("Bob Smith", "bob@x.io")]),
    ]
    rows = collect_licensed_users(licenses, [], [])
    assert len(rows) == 1
    assert rows[0].licenses == ["E3", "E5"]


def test_status_disabled_and_inactive_flagged():
    licenses = [_sku("Microsoft 365 Business Premium", [
        ("Active User", "act@x.io"), ("Gone User", "gone@x.io"), ("Stale User", "stale@x.io")])]
    mfa = [{"UPN": "act@x.io", "AccountEnabled": True},
           {"UPN": "gone@x.io", "AccountEnabled": False},
           {"UPN": "stale@x.io", "AccountEnabled": True}]
    inactive = [{"userPrincipalName": "stale@x.io", "daysSinceLastSignIn": 240.0}]
    rows = {r.upn: r for r in collect_licensed_users(licenses, mfa, inactive)}
    assert rows["act@x.io"].status == "Active"
    assert rows["gone@x.io"].status == "Disabled"
    assert rows["stale@x.io"].status == "Inactive 240d"


def test_missing_accountenabled_key_is_not_disabled():
    # A user present in MFA but with no AccountEnabled key must NOT be flagged Disabled.
    licenses = [_sku("Microsoft 365 E5", [("Bob", "bob@x.io")])]
    mfa = [{"UPN": "bob@x.io"}]  # AccountEnabled absent
    rows = collect_licensed_users(licenses, mfa, [])
    assert rows[0].status == "Active"


def test_inactive_threshold_is_30_days():
    # Offboarding flag fires at >= 30 days; a more-recent sign-in stays Active.
    licenses = [_sku("Microsoft 365 E5", [("Recent", "r@x.io"), ("Stale", "s@x.io")])]
    inactive = [{"userPrincipalName": "r@x.io", "daysSinceLastSignIn": 20.0},
                {"userPrincipalName": "s@x.io", "daysSinceLastSignIn": 40.0}]
    rows = {r.upn: r for r in collect_licensed_users(licenses, [], inactive)}
    assert rows["r@x.io"].status == "Active"
    assert rows["s@x.io"].status == "Inactive 40d"


def test_non_dict_and_empty_inputs_tolerated():
    assert collect_licensed_users([], [], []) == []
    assert collect_licensed_users(None, None, None) == []
    licenses = ["junk", None, _sku("Microsoft 365 F3", [("Ok", "ok@x.io")])]
    rows = collect_licensed_users(licenses, ["bad", None], [None, "x"])
    assert [r.upn for r in rows] == ["ok@x.io"]


# --- KPI metric ----------------------------------------------------------

def test_licensed_users_metric_counts_and_flags():
    users = [
        LicensedUser(name="A", upn="a", licenses=["E5"], status="Active"),
        LicensedUser(name="B", upn="b", licenses=["E5"], status="Disabled"),
        LicensedUser(name="C", upn="c", licenses=["E5"], status="Inactive 200d"),
    ]
    m = licensed_users_metric(users)
    assert isinstance(m, KpiMetric)
    assert m.key == "licensed_users"
    assert m.value == 3
    assert m.detail["flagged"] == 2   # disabled + inactive = offboarding candidates
    assert m.status == "warn"         # flagged paid seats -> warn


def test_licensed_users_metric_no_flags_is_info_not_a_win():
    # A bare healthy count must be "info" (not "good") so it never becomes a Win.
    users = [LicensedUser(name="A", upn="a", licenses=["E5"], status="Active")]
    assert licensed_users_metric(users).status == "info"
    assert licensed_users_metric([]).status == "info"
