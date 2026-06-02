"""Licensed-users collector for the QBR.

Lists users who hold a PAID productivity SKU — Business Premium / Standard /
Basic, F1 / F3, E1 / E3 / E5 — so an executive can review who is paying for a
seat. Free SKUs (Power Apps Developer, Power Automate Free, Teams Exploratory…)
and paid add-ons (Windows 365, Business Voice…) are intentionally excluded: a
user who only holds a free license is not a real billable seat.

Each user is tagged with a status (Active / Disabled / Inactive Nd) by joining
ListLicenses' AssignedUsers to the MFA + inactive-account data. A disabled or
long-inactive user still holding a paid seat is an offboarding gap + wasted spend.

EDIT THE ALLOWLIST below if a client uses a paid SKU not covered here.
"""
from __future__ import annotations

import re
from typing import Any

from qbr_models import LicensedUser, KpiMetric

# Paid productivity suites only. Matched against the CIPP license display name.
# "business premium|standard|basic" + the enterprise/frontline suite codes E1/E3/E5/F1/F3.
PAID_SKU_RE = re.compile(r"business (premium|standard|basic)|\b(e1|e3|e5|f1|f3)\b", re.I)
# An E/F token also appears in paid ADD-ONs and EMS, which are NOT seats. Reject any
# name carrying an add-on qualifier (e.g. "Microsoft 365 E5 Security", "EMS E5") so the
# billable-seat count isn't inflated. EDIT this list if a new add-on slips through.
ADDON_SKU_RE = re.compile(
    r"enterprise mobility|security|compliance|ediscovery|audit|"
    r"information protection|insider risk|governance|extra features|threat", re.I)
# Inactivity window for flagging a paid seat as an offboarding candidate.
INACTIVE_DAYS = 30


def is_paid_sku(name: str | None) -> bool:
    n = name or ""
    return bool(PAID_SKU_RE.search(n)) and not ADDON_SKU_RE.search(n)


def _short_sku(name: str) -> str:
    """'Microsoft 365 Business Premium' -> 'Business Premium'."""
    for prefix in ("Microsoft 365 ", "Office 365 ", "Microsoft ", "Office "):
        if name.startswith(prefix):
            return name[len(prefix):]
    return name


def _truthy(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v != 0
    if isinstance(v, str):
        return v.strip().lower() in ("true", "1", "yes")
    return False


def _to_float(v: Any) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def collect_licensed_users(
    licenses: list[dict] | None,
    mfa_users: list[dict] | None,
    inactive_accounts: list[dict] | None,
) -> list[LicensedUser]:
    licenses = [s for s in (licenses or []) if isinstance(s, dict)]
    mfa_users = [u for u in (mfa_users or []) if isinstance(u, dict)]
    inactive_accounts = [a for a in (inactive_accounts or []) if isinstance(a, dict)]

    # Status lookups keyed by lowercased UPN. Only record an explicit enabled flag
    # when present, so a user missing the field defaults to enabled (not "Disabled").
    # Seed from the sign-in source's accountEnabled (authoritative, present for every
    # user), then let ListMFAUsers override where it has the field.
    enabled = {}
    inactive_days = {}
    for a in inactive_accounts:
        upn = a.get("userPrincipalName")
        if not upn:
            continue
        key = str(upn).lower()
        inactive_days[key] = _to_float(a.get("daysSinceLastSignIn"))
        ae = a.get("accountEnabled")
        if ae is not None:
            enabled[key] = _truthy(ae)
    for u in mfa_users:
        upn = u.get("UPN") or u.get("userPrincipalName")
        ae = u.get("AccountEnabled")
        if upn and ae is not None:
            enabled[str(upn).lower()] = _truthy(ae)

    # Collect paid-SKU users (dedupe by UPN; gather all their paid SKUs).
    users: dict[str, dict] = {}
    for sku in licenses:
        name = sku.get("License") or sku.get("skuPartNumber") or ""
        if not is_paid_sku(name):
            continue
        short = _short_sku(str(name))
        for au in sku.get("AssignedUsers") or []:
            if not isinstance(au, dict):
                continue
            upn = au.get("userPrincipalName") or au.get("UserPrincipalName")
            if not upn:
                continue
            key = str(upn).lower()
            rec = users.setdefault(key, {
                "name": au.get("displayName") or str(upn),
                "upn": str(upn),
                "skus": set(),
            })
            rec["skus"].add(short)

    records: list[LicensedUser] = []
    for key, u in users.items():
        is_enabled = enabled.get(key, True)   # default enabled if unknown
        days = inactive_days.get(key)
        if is_enabled is False:
            status = "Disabled"
        elif days is not None and days >= INACTIVE_DAYS:
            # Flag offboarding candidates: paid seats unused for 30+ days. The
            # 99999 sentinel (from signin_activity) means no sign-in on record.
            status = "Inactive (never)" if days >= 9000 else f"Inactive {int(days)}d"
        else:
            status = "Active"
        records.append(LicensedUser(
            name=u["name"], upn=u["upn"],
            licenses=sorted(u["skus"]), status=status,
        ))

    records.sort(key=lambda r: r.name.lower())
    return records


def licensed_users_metric(users: list[LicensedUser]) -> KpiMetric:
    """Scorecard KPI: count of paid-seat users, flagging disabled/inactive ones."""
    total = len(users)
    flagged = sum(1 for u in users if u.status != "Active")
    # "info" unless there are flagged (disabled/inactive) seats — a bare healthy
    # headcount is inventory, not a "win", so it must not read as a good-status KPI.
    status = "warn" if flagged else "info"
    return KpiMetric(
        key="licensed_users",
        label="Licensed Users",
        value=total,
        unit="users",
        status=status,
        detail={"active": total - flagged, "flagged": flagged},
    )
