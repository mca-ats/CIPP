"""License KPIs for the QBR / Client Health scorecard.

Pure transformation of the raw list returned by CIPP ``/api/ListLicenses``
into value-framed :class:`~qbr_models.KpiMetric` rows. No I/O, no httpx.

CIPP quirk: several numeric fields (``CountUsed``, ``TotalLicenses``, and
sometimes ``CountAvailable``) arrive as STRINGS. We coerce defensively and
never raise on malformed / missing input — an empty tenant yields a sane
"info"/zeroed metric set rather than an exception.
"""
from __future__ import annotations

from typing import Any

from qbr_models import KpiMetric

RENEWAL_WINDOW_DAYS = 90
# CIPP returns free/unlimited dev & trial pools with absurd seat counts (e.g.
# "Power Apps for Developer" = 10000 free seats). Treat these as not-purchased
# capacity so they don't poison waste/utilization. Markers + a seat sentinel.
FREE_SKU_MARKERS = ("developer", "trial", "viral", "(free)", " free")
FREE_SEAT_SENTINEL = 1000


def _to_int(value: Any) -> int:
    """Coerce a possibly-string, possibly-None numeric to int; 0 on failure."""
    if value is None:
        return 0
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def _terms(sku: dict) -> list[dict]:
    """SKU's TermInfo as a list of dicts. CIPP often flattens a single-element
    array to a bare object — normalize both shapes."""
    t = sku.get("TermInfo") or []
    if isinstance(t, dict):
        t = [t]
    return [x for x in t if isinstance(x, dict)]


def _is_paid_pool(sku: dict, name: str, avail: int, total: int) -> bool:
    """True if this SKU is real purchased capacity (counts toward waste/util).

    Excludes free/dev/trial SKUs, suspended terms, zero/negative capacity, and
    pools with a free-seat sentinel count.
    """
    n = name.lower()
    if any(mk in n for mk in FREE_SKU_MARKERS):
        return False
    if total <= 0:                      # suspended / zero-capacity sentinel
        return False
    if avail >= FREE_SEAT_SENTINEL:     # unlimited/free seat pool
        return False
    if any(str(t.get("Status", "")).lower() == "suspended" for t in _terms(sku)):
        return False
    return True


def _min_days_until_renew(sku: dict) -> int | None:
    """Smallest in-window DaysUntilRenew across a SKU's TermInfo, else None.

    Only 0..RENEWAL_WINDOW_DAYS counts — negative sentinels (e.g. -739765 for
    non-NCE/'Term unknown' SKUs) are not real imminent renewals.
    """
    days = []
    for term in _terms(sku):
        d = term.get("DaysUntilRenew")
        if d is None:
            continue
        try:
            di = int(float(d))
        except (TypeError, ValueError):
            continue
        if 0 <= di <= RENEWAL_WINDOW_DAYS:
            days.append(di)
    return min(days) if days else None


def collect_license_kpis(licenses: list[dict]) -> list[KpiMetric]:
    """Transform raw CIPP license SKUs into QBR scorecard metrics."""
    licenses = licenses or []

    sku_count = len(licenses)
    assigned = 0          # total assigned across all SKUs (informational)
    paid_used = 0         # assigned within real paid pools (utilization basis)
    available = 0         # unused seats in real paid pools (waste)
    waste: list[dict] = []
    renewals: list[dict] = []

    for sku in licenses:
        if not isinstance(sku, dict):
            continue
        name = sku.get("License") or sku.get("skuPartNumber") or "Unknown SKU"

        used = _to_int(sku.get("CountUsed"))
        avail = max(0, _to_int(sku.get("CountAvailable")))  # clamp -1 sentinel
        total = _to_int(sku.get("TotalLicenses"))
        assigned += used

        if not _is_paid_pool(sku, name, avail, total):
            continue  # free/dev/trial/suspended: excluded from waste, util, renewals

        paid_used += used
        available += avail
        if avail > 0:
            waste.append({"license": name, "available": avail})

        days = _min_days_until_renew(sku)
        if days is not None:
            renewals.append({"license": name, "days": days})

    # --- unused (available) seats: paid waste ---------------------------
    if available == 0:
        avail_status = "good"
    elif available < 5:
        avail_status = "warn"
    else:
        avail_status = "bad"

    # --- utilization (over real paid pools only) ------------------------
    denom = paid_used + available
    if denom == 0:
        util_value = 0.0
        util_status = "info"
    else:
        util_value = round(paid_used / denom * 100, 1)
        if util_value >= 80:
            util_status = "good"
        elif util_value >= 50:
            util_status = "warn"
        else:
            util_status = "bad"

    # --- renewals -------------------------------------------------------
    renewal_count = len(renewals)
    renewal_status = "good" if renewal_count == 0 else "info"

    return [
        KpiMetric(
            key="license_sku_count",
            label="License SKUs",
            value=sku_count,
            status="info",
        ),
        KpiMetric(
            key="license_assigned",
            label="Assigned Licenses",
            value=assigned,
            status="info",
        ),
        KpiMetric(
            key="license_available",
            label="Unused (Available) Seats",
            value=available,
            status=avail_status,
            detail={"waste": waste},
        ),
        KpiMetric(
            key="license_utilization",
            label="License Utilization",
            value=util_value,
            unit="%",
            status=util_status,
            detail={"assigned": paid_used, "available": available, "basis": "paid SKUs only"},
        ),
        KpiMetric(
            key="license_renewals_90d",
            label="Renewals < 90 days",
            value=renewal_count,
            unit="SKUs",
            status=renewal_status,
            detail={"renewals": renewals},
        ),
    ]
