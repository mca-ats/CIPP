"""Real per-user sign-in activity -> inactivity, for a TRUE 30-day roster.

CIPP's /api/ListInactiveAccounts only returns accounts already inactive ~180+
days, so a 30-day threshold can't see 30-179 day inactivity. Instead we pull
Graph signInActivity per user (via /api/ListGraphRequest Endpoint=users,
$select=...,signInActivity,...) and compute days since last *successful* sign-in
(interactive OR non-interactive).

signin_to_inactive_accounts() reshapes that into the same record shape the
existing identity / licensed-users collectors already consume
({userPrincipalName, daysSinceLastSignIn, numberOfAssignedLicenses,
accountEnabled}), so they get accurate data without any signature change.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

NEVER_SIGNED_IN_DAYS = 99999  # sentinel for accounts with no sign-in on record


def _parse_dt(value: Any) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _last_signin(sia: dict) -> datetime | None:
    """Most recent of the successful / interactive / non-interactive timestamps."""
    if not isinstance(sia, dict):
        return None
    candidates = [
        _parse_dt(sia.get("lastSuccessfulSignInDateTime")),
        _parse_dt(sia.get("lastSignInDateTime")),
        _parse_dt(sia.get("lastNonInteractiveSignInDateTime")),
    ]
    found = [c for c in candidates if c is not None]
    return max(found) if found else None


def signin_to_inactive_accounts(graph_users: list[dict] | None,
                                now: datetime) -> list[dict]:
    """Reshape Graph users (+ signInActivity) into inactive-account records.

    Each user's ``daysSinceLastSignIn`` is days since their last successful
    sign-in. For never-signed-in accounts we fall back to days since
    ``createdDateTime`` — so a brand-new licensed hire shows a small number (not
    flagged), while a long-provisioned but unused seat shows a large one (flagged).
    Only accounts with neither timestamp get the NEVER_SIGNED_IN_DAYS sentinel.
    Downstream collectors apply the >= 30d and licensed filters.
    """
    if now.tzinfo is None:                       # never crash on a naive caller
        now = now.replace(tzinfo=timezone.utc)

    out: list[dict] = []
    for u in graph_users or []:
        if not isinstance(u, dict):
            continue
        upn = u.get("userPrincipalName") or u.get("UserPrincipalName")
        if not upn:
            continue
        last = _last_signin(u.get("signInActivity") or {})
        if last is None:
            last = _parse_dt(u.get("createdDateTime"))   # new-hire / sign-in-lag guard
        days = NEVER_SIGNED_IN_DAYS if last is None else max(0, (now - last).days)
        out.append({
            "userPrincipalName": upn,
            "daysSinceLastSignIn": float(days),
            "numberOfAssignedLicenses": len(u.get("assignedLicenses") or []),
            "accountEnabled": u.get("accountEnabled", True),
        })
    return out
