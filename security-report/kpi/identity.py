"""Identity KPIs for the QBR scorecard.

Pure transform from two CIPP endpoints into value-framed KpiMetrics:

  * /api/ListMFAUsers        -> MFA coverage, admins without MFA, guest count
  * /api/ListInactiveAccounts -> licensed-but-inactive accounts

No httpx / no I/O — callers pass the already-fetched JSON lists. Degrades
gracefully on empty input and coerces CIPP's string-typed booleans/numbers.
"""
from __future__ import annotations

from typing import Any

from qbr_models import KpiMetric

_SAMPLE_LIMIT = 5
INACTIVE_DAYS = 30  # window for "licensed inactive" flagging


def _truthy(value: Any) -> bool:
    """Coerce a CIPP field to bool. Handles real bools, None, and strings
    like "true"/"false"/"1"/"0" that some endpoints emit instead of JSON bools.
    """
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "yes", "y"}
    return bool(value)


def _to_float(value: Any) -> float:
    """Coerce a possibly-string numeric field to float; 0.0 on failure."""
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return 0.0
    return 0.0


def collect_identity_kpis(
    mfa_users: list[dict],
    inactive_accounts: list[dict],
) -> list[KpiMetric]:
    # CIPP list endpoints can return error strings / None mixed in — keep only
    # dict rows so a malformed element degrades gracefully instead of crashing.
    mfa_users = [u for u in (mfa_users or []) if isinstance(u, dict)]
    inactive_accounts = [a for a in (inactive_accounts or []) if isinstance(a, dict)]

    # --- MFA coverage over enabled users ---------------------------------
    enabled = [u for u in mfa_users if _truthy(u.get("AccountEnabled"))]
    enabled_count = len(enabled)
    registered_count = sum(
        1 for u in enabled if _truthy(u.get("MFARegistration"))
    )

    if enabled_count:
        coverage = round(registered_count / enabled_count * 100, 1)
        if coverage >= 95:
            coverage_status = "good"
        elif coverage >= 80:
            coverage_status = "warn"
        else:
            coverage_status = "bad"
    else:
        coverage = 0.0
        coverage_status = "info"

    coverage_metric = KpiMetric(
        key="mfa_coverage_pct",
        label="MFA Coverage",
        value=coverage,
        unit="%",
        status=coverage_status,
        detail={"registered": registered_count, "enabled": enabled_count},
    )

    # --- Admins without MFA (enabled only) -------------------------------
    uncovered_admins = [
        u for u in enabled
        if _truthy(u.get("IsAdmin")) and not _truthy(u.get("MFARegistration"))
    ]
    admin_sample = [
        u.get("UPN") for u in uncovered_admins[:_SAMPLE_LIMIT] if u.get("UPN")
    ]
    admins_metric = KpiMetric(
        key="mfa_admins_uncovered",
        label="Admins Without MFA",
        value=len(uncovered_admins),
        unit="admins",
        status="good" if not uncovered_admins else "bad",
        detail={"sample": admin_sample},
    )

    # --- Guest accounts --------------------------------------------------
    guest_count = sum(
        1 for u in mfa_users
        if str(u.get("UserType", "")).strip().lower() == "guest"
    )
    guests_metric = KpiMetric(
        key="identity_guests",
        label="Guest Accounts",
        value=guest_count,
        unit="guests",
        status="info",
        detail={},
    )

    # --- Licensed but inactive ------------------------------------------
    # Enforce the inactivity window locally rather than trusting CIPP's server-side
    # filter, so the metric matches its "(30d+)" label regardless of endpoint params.
    licensed_inactive = [
        a for a in inactive_accounts
        if _to_float(a.get("numberOfAssignedLicenses")) > 0
        and _to_float(a.get("daysSinceLastSignIn")) >= INACTIVE_DAYS
    ]
    inactive_sample = [
        {
            "upn": a.get("userPrincipalName"),
            "days": _to_float(a.get("daysSinceLastSignIn")),
        }
        for a in licensed_inactive[:_SAMPLE_LIMIT]
    ]
    n_inactive = len(licensed_inactive)
    if n_inactive == 0:
        inactive_status = "good"
    elif n_inactive <= 2:
        inactive_status = "warn"
    else:
        inactive_status = "bad"
    inactive_metric = KpiMetric(
        key="identity_licensed_inactive",
        label="Licensed Inactive (30d+)",
        value=n_inactive,
        unit="accounts",
        status=inactive_status,
        detail={"sample": inactive_sample},
    )

    return [coverage_metric, admins_metric, guests_metric, inactive_metric]
