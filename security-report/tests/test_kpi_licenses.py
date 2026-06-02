"""Tests for the license KPI collector (kpi/licenses.py).

Input is the raw list returned by CIPP /api/ListLicenses. The collector must:
  - coerce STRING numerics (CountUsed/TotalLicenses arrive as strings),
  - flag paid waste (unused available seats),
  - compute utilization with a safe zero-denominator path,
  - count near-term renewals,
  - degrade gracefully on an empty list (never raise).
"""
import pytest

from qbr_models import KpiMetric
from kpi.licenses import collect_license_kpis


# --- helpers -------------------------------------------------------------

def _by_key(metrics):
    return {m.key: m for m in metrics}


def _term(days):
    return [{"DaysUntilRenew": days, "NextLifecycle": "2027-04-09T00:00:00Z",
             "IsTrial": False, "Status": "Enabled"}]


# --- sample inputs -------------------------------------------------------

HEALTHY = [
    {
        "License": "Microsoft 365 Business Premium",
        "CountUsed": "10",
        "CountAvailable": 0,
        "TotalLicenses": "10",
        "skuPartNumber": "SPB",
        "availableUnits": 0,
        "TermInfo": _term(313),
    },
]

WASTE = [
    {
        "License": "Microsoft 365 Business Premium",
        "CountUsed": "5",
        "CountAvailable": 7,        # 7 unused paid seats -> bad
        "TotalLicenses": "12",
        "skuPartNumber": "SPB",
        "availableUnits": 7,
        "TermInfo": _term(313),
    },
]

RENEWALS = [
    {
        "License": "Exchange Online Plan 1",
        "CountUsed": "3",
        "CountAvailable": 0,
        "TotalLicenses": "3",
        "skuPartNumber": "EXO1",
        "availableUnits": 0,
        "TermInfo": _term(30),       # near-term renewal
    },
    {
        "License": "Microsoft 365 Business Premium",
        "CountUsed": "1",
        "CountAvailable": 0,
        "TotalLicenses": "1",
        "skuPartNumber": "SPB",
        "availableUnits": 0,
        "TermInfo": _term(313),      # far-out renewal
    },
]


# --- shape ---------------------------------------------------------------

def test_returns_all_expected_keys():
    keys = {m.key for m in collect_license_kpis(HEALTHY)}
    assert keys == {
        "license_sku_count",
        "license_assigned",
        "license_available",
        "license_utilization",
        "license_renewals_90d",
    }


def test_all_items_are_kpimetric():
    for m in collect_license_kpis(HEALTHY):
        assert isinstance(m, KpiMetric)


# --- healthy tenant (full utilization, no waste) -------------------------

def test_healthy_tenant_full_utilization_no_waste():
    m = _by_key(collect_license_kpis(HEALTHY))
    assert m["license_sku_count"].value == 1
    assert m["license_sku_count"].status == "info"
    assert m["license_assigned"].value == 10
    assert m["license_available"].value == 0
    assert m["license_available"].status == "good"      # 0 unused
    assert m["license_utilization"].value == 100.0
    assert m["license_utilization"].unit == "%"
    assert m["license_utilization"].status == "good"    # >= 80
    assert m["license_renewals_90d"].value == 0
    assert m["license_renewals_90d"].unit == "SKUs"


# --- waste tenant (available >= 5 -> bad) --------------------------------

def test_waste_available_five_or_more_is_bad():
    m = _by_key(collect_license_kpis(WASTE))
    assert m["license_available"].value == 7
    assert m["license_available"].status == "bad"
    # waste detail lists offending SKU
    waste_list = m["license_available"].detail.get("waste")
    assert waste_list == [{"license": "Microsoft 365 Business Premium",
                           "available": 7}]


def test_waste_one_to_four_is_warn():
    data = [{
        "License": "SKU A", "CountUsed": "2", "CountAvailable": 3,
        "TotalLicenses": "5", "TermInfo": _term(200),
    }]
    m = _by_key(collect_license_kpis(data))
    assert m["license_available"].value == 3
    assert m["license_available"].status == "warn"


# --- utilization status bands -------------------------------------------

def test_utilization_below_50_is_bad():
    data = [{
        "License": "SKU A", "CountUsed": "2", "CountAvailable": 8,
        "TotalLicenses": "10", "TermInfo": _term(200),
    }]
    m = _by_key(collect_license_kpis(data))
    assert m["license_utilization"].value == 20.0   # 2/(2+8)
    assert m["license_utilization"].status == "bad"


def test_utilization_50_to_79_is_warn():
    data = [{
        "License": "SKU A", "CountUsed": "6", "CountAvailable": 4,
        "TotalLicenses": "10", "TermInfo": _term(200),
    }]
    m = _by_key(collect_license_kpis(data))
    assert m["license_utilization"].value == 60.0   # 6/(6+4)
    assert m["license_utilization"].status == "warn"


# --- string coercion -----------------------------------------------------

def test_string_numerics_are_coerced():
    data = [{
        "License": "SKU A",
        "CountUsed": "3",          # STRING
        "CountAvailable": "0",     # STRING too (defensive)
        "TotalLicenses": "3",      # STRING
        "TermInfo": _term(200),
    }]
    m = _by_key(collect_license_kpis(data))
    assert m["license_assigned"].value == 3
    assert isinstance(m["license_assigned"].value, int)
    assert m["license_available"].value == 0


# --- renewals ------------------------------------------------------------

def test_renewals_counts_only_within_90_days():
    m = _by_key(collect_license_kpis(RENEWALS))
    assert m["license_renewals_90d"].value == 1      # only the 30-day SKU
    renewals = m["license_renewals_90d"].detail.get("renewals")
    assert renewals == [{"license": "Exchange Online Plan 1", "days": 30}]


def test_renewals_zero_is_good_status():
    m = _by_key(collect_license_kpis(HEALTHY))
    assert m["license_renewals_90d"].value == 0
    assert m["license_renewals_90d"].status == "good"


def test_renewals_handles_missing_or_none_daysuntilrenew():
    data = [
        {"License": "No term", "CountUsed": "1", "CountAvailable": 0,
         "TotalLicenses": "1"},                                  # no TermInfo
        {"License": "Null days", "CountUsed": "1", "CountAvailable": 0,
         "TotalLicenses": "1",
         "TermInfo": [{"DaysUntilRenew": None}]},                # None days
        {"License": "Due soon", "CountUsed": "1", "CountAvailable": 0,
         "TotalLicenses": "1", "TermInfo": _term(15)},
    ]
    m = _by_key(collect_license_kpis(data))
    assert m["license_renewals_90d"].value == 1


# --- empty list (graceful degradation) -----------------------------------

def test_empty_list_does_not_raise_and_returns_sane_defaults():
    metrics = collect_license_kpis([])
    m = _by_key(metrics)
    assert m["license_sku_count"].value == 0
    assert m["license_assigned"].value == 0
    assert m["license_available"].value == 0
    assert m["license_available"].status == "good"   # 0 waste
    assert m["license_utilization"].value == 0.0
    assert m["license_utilization"].status == "info"  # zero denominator
    assert m["license_renewals_90d"].value == 0
    assert m["license_renewals_90d"].status == "good"


def test_zero_denominator_utilization_is_info():
    data = [{
        "License": "Empty SKU", "CountUsed": "0", "CountAvailable": 0,
        "TotalLicenses": "0", "TermInfo": _term(200),
    }]
    m = _by_key(collect_license_kpis(data))
    assert m["license_utilization"].value == 0.0
    assert m["license_utilization"].status == "info"
