"""Tests for the real sign-in-activity inactivity source (true 30-day roster)."""
from datetime import datetime, timezone

from kpi.signin_activity import signin_to_inactive_accounts, NEVER_SIGNED_IN_DAYS

NOW = datetime(2026, 5, 30, tzinfo=timezone.utc)


def _user(upn, last_success=None, last_interactive=None, licenses=1, enabled=True):
    sia = {}
    if last_success:
        sia["lastSuccessfulSignInDateTime"] = last_success
    if last_interactive:
        sia["lastSignInDateTime"] = last_interactive
    return {
        "userPrincipalName": upn,
        "signInActivity": sia,
        "assignedLicenses": [{"skuId": "x"}] * licenses,
        "accountEnabled": enabled,
    }


def test_computes_days_since_last_successful_signin():
    rows = signin_to_inactive_accounts([_user("a@x", last_success="2026-04-20T00:00:00Z")], NOW)
    assert rows[0]["userPrincipalName"] == "a@x"
    assert rows[0]["daysSinceLastSignIn"] == 40.0   # 2026-04-20 -> 2026-05-30


def test_recent_signin_is_low_days():
    rows = signin_to_inactive_accounts([_user("a@x", last_success="2026-05-28T00:00:00Z")], NOW)
    assert rows[0]["daysSinceLastSignIn"] == 2.0


def test_never_signed_in_gets_sentinel():
    rows = signin_to_inactive_accounts([_user("a@x", last_success=None, last_interactive=None)], NOW)
    assert rows[0]["daysSinceLastSignIn"] == float(NEVER_SIGNED_IN_DAYS)


def test_prefers_most_recent_of_the_timestamps():
    # non-interactive more recent than interactive -> use the more recent
    u = _user("a@x", last_interactive="2026-02-01T00:00:00Z")
    u["signInActivity"]["lastNonInteractiveSignInDateTime"] = "2026-05-29T00:00:00Z"
    rows = signin_to_inactive_accounts([u], NOW)
    assert rows[0]["daysSinceLastSignIn"] == 1.0


def test_passes_through_licenses_and_enabled():
    rows = signin_to_inactive_accounts(
        [_user("a@x", last_success="2026-01-01T00:00:00Z", licenses=2, enabled=False)], NOW)
    assert rows[0]["numberOfAssignedLicenses"] == 2
    assert rows[0]["accountEnabled"] is False


def test_emits_every_user_so_downstream_filters_apply():
    rows = signin_to_inactive_accounts([
        _user("active@x", last_success="2026-05-29T00:00:00Z"),   # 1 day
        _user("stale@x", last_success="2026-03-01T00:00:00Z"),    # ~90 days
    ], NOW)
    days = {r["userPrincipalName"]: r["daysSinceLastSignIn"] for r in rows}
    assert days["active@x"] < 30 and days["stale@x"] >= 30


def test_new_hire_never_signed_in_uses_creation_date_not_sentinel():
    # Created 5 days ago, no sign-in yet -> 5 days (NOT flagged as long-inactive).
    u = {"userPrincipalName": "newhire@x", "signInActivity": {},
         "createdDateTime": "2026-05-25T00:00:00Z", "assignedLicenses": [{"skuId": "x"}]}
    rows = signin_to_inactive_accounts([u], NOW)
    assert rows[0]["daysSinceLastSignIn"] == 5.0


def test_long_provisioned_never_used_seat_is_flagged():
    # Created 300 days ago, never signed in -> 300 days (flagged).
    u = {"userPrincipalName": "ghost@x", "signInActivity": {},
         "createdDateTime": "2025-08-03T00:00:00Z", "assignedLicenses": [{"skuId": "x"}]}
    rows = signin_to_inactive_accounts([u], NOW)
    assert rows[0]["daysSinceLastSignIn"] >= 290


def test_naive_now_does_not_crash():
    naive = datetime(2026, 5, 30)  # no tzinfo
    rows = signin_to_inactive_accounts([_user("a@x", last_success="2026-04-30T00:00:00Z")], naive)
    assert rows[0]["daysSinceLastSignIn"] == 30.0


def test_tolerates_junk_and_empty():
    assert signin_to_inactive_accounts(None, NOW) == []
    assert signin_to_inactive_accounts(["junk", None, {}], NOW) == []  # no UPN -> skipped
