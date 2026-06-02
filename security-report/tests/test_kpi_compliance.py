"""Tests for the device-compliance KPI collector (kpi/compliance.py).

Pure function: input is the raw list of device dicts from CIPP
/api/ListDevices, output is a list[KpiMetric]. No httpx, no mocking.

Staleness is the only time-dependent dimension. To keep the suite stable we
anchor on two extremes:
  * a far-past constant ("2020-01-01T00:00:00Z") is ALWAYS older than 30 days,
    so it is always stale regardless of when the test runs.
  * a "fresh" sync is computed relative to *now* inside the test (now - 1 day),
    so it is always within the 30-day window.
"""
from datetime import datetime, timedelta, timezone

from qbr_models import KpiMetric
from kpi.compliance import collect_compliance_kpis


# --- helpers -------------------------------------------------------------

STALE_SYNC = "2020-01-01T00:00:00Z"  # always > 30 days old
ZERO_SYNC = "0001-01-01T00:00:00Z"   # Graph "never synced" sentinel


def _fresh_sync() -> str:
    """An ISO sync timestamp guaranteed to be within the 30-day window."""
    return (datetime.now(timezone.utc) - timedelta(days=1)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _by_key(metrics: list[KpiMetric]) -> dict[str, KpiMetric]:
    return {m.key: m for m in metrics}


def _device(name, compliance="compliant", sync=None, owner="company"):
    return {
        "deviceName": name,
        "complianceState": compliance,
        "operatingSystem": "Windows",
        "lastSyncDateTime": sync if sync is not None else _fresh_sync(),
        "managedDeviceOwnerType": owner,
    }


# --- shape / contract ----------------------------------------------------

EXPECTED_KEYS = {
    "device_total",
    "device_compliant",
    "device_noncompliant",
    "device_compliance_pct",
    "device_stale_30d",
}


def test_returns_all_expected_metric_keys():
    metrics = collect_compliance_kpis([_device("PC-1")])
    assert {m.key for m in metrics} == EXPECTED_KEYS
    assert all(isinstance(m, KpiMetric) for m in metrics)


def test_metric_labels_and_units():
    m = _by_key(collect_compliance_kpis([_device("PC-1")]))
    assert m["device_total"].label == "Managed Devices"
    assert m["device_compliant"].label == "Compliant Devices"
    assert m["device_noncompliant"].label == "Noncompliant Devices"
    assert m["device_compliance_pct"].label == "Device Compliance"
    assert m["device_compliance_pct"].unit == "%"
    assert m["device_stale_30d"].label == "Stale Devices (30d+)"
    assert m["device_stale_30d"].unit == "devices"


# --- all compliant -------------------------------------------------------

def test_all_compliant_gives_100_pct_good():
    devices = [_device(f"PC-{i}", compliance="compliant") for i in range(5)]
    m = _by_key(collect_compliance_kpis(devices))

    assert m["device_total"].value == 5
    assert m["device_total"].status == "info"
    assert m["device_compliant"].value == 5
    assert m["device_compliant"].status == "info"
    assert m["device_noncompliant"].value == 0
    assert m["device_noncompliant"].status == "good"  # 0 noncompliant
    assert m["device_compliance_pct"].value == 100.0
    assert m["device_compliance_pct"].status == "good"  # >= 90


# --- mixed (1 of 13 noncompliant) ---------------------------------------

def test_mixed_one_noncompliant_of_thirteen():
    devices = [_device(f"PC-{i}", compliance="compliant") for i in range(12)]
    devices.append(_device("PC-BAD", compliance="noncompliant"))
    m = _by_key(collect_compliance_kpis(devices))

    assert m["device_total"].value == 13
    assert m["device_compliant"].value == 12
    assert m["device_noncompliant"].value == 1
    assert m["device_noncompliant"].status == "bad"  # > 0 -> bad
    # 12/13 = 92.307... -> 92.3, >= 90 so good
    assert m["device_compliance_pct"].value == 92.3
    assert m["device_compliance_pct"].status == "good"
    # noncompliant detail samples the bad device name
    assert "PC-BAD" in m["device_noncompliant"].detail.get("sample", [])


def test_unknown_compliance_state_counts_as_neither():
    devices = [
        _device("PC-1", compliance="compliant"),
        _device("PC-2", compliance="unknown"),
    ]
    m = _by_key(collect_compliance_kpis(devices))
    assert m["device_total"].value == 2
    assert m["device_compliant"].value == 1
    assert m["device_noncompliant"].value == 0
    # "unknown" is non-evaluated: excluded from the % denominator (Intune-aligned),
    # so 1 compliant / 1 evaluated = 100%. It still appears in device_total.
    assert m["device_compliance_pct"].value == 100.0
    assert m["device_compliance_pct"].status == "good"


# --- compliance pct thresholds ------------------------------------------

def test_compliance_pct_warn_band():
    # 8 compliant of 10 = 80% -> warn (70 - 89.9)
    devices = [_device(f"OK-{i}", compliance="compliant") for i in range(8)]
    devices += [_device(f"BAD-{i}", compliance="noncompliant") for i in range(2)]
    m = _by_key(collect_compliance_kpis(devices))
    assert m["device_compliance_pct"].value == 80.0
    assert m["device_compliance_pct"].status == "warn"


def test_compliance_pct_bad_band():
    # 6 compliant of 10 = 60% -> bad (< 70)
    devices = [_device(f"OK-{i}", compliance="compliant") for i in range(6)]
    devices += [_device(f"BAD-{i}", compliance="noncompliant") for i in range(4)]
    m = _by_key(collect_compliance_kpis(devices))
    assert m["device_compliance_pct"].value == 60.0
    assert m["device_compliance_pct"].status == "bad"


# --- empty list (graceful) ----------------------------------------------

def test_empty_list_does_not_crash_and_is_info():
    metrics = collect_compliance_kpis([])
    m = _by_key(metrics)
    assert {x.key for x in metrics} == EXPECTED_KEYS
    assert m["device_total"].value == 0
    assert m["device_total"].status == "info"
    assert m["device_compliant"].value == 0
    # 0 noncompliant -> good
    assert m["device_noncompliant"].value == 0
    assert m["device_noncompliant"].status == "good"
    # total 0 -> pct value 0.0, status info (special-cased)
    assert m["device_compliance_pct"].value == 0.0
    assert m["device_compliance_pct"].status == "info"
    # 0 stale -> good
    assert m["device_stale_30d"].value == 0
    assert m["device_stale_30d"].status == "good"


# --- staleness -----------------------------------------------------------

def test_stale_device_vs_fresh_device():
    devices = [
        _device("FRESH", sync=_fresh_sync()),
        _device("STALE", sync=STALE_SYNC),  # 2020 -> always stale
    ]
    m = _by_key(collect_compliance_kpis(devices))
    assert m["device_stale_30d"].value == 1
    assert "STALE" in m["device_stale_30d"].detail.get("sample", [])
    assert "FRESH" not in m["device_stale_30d"].detail.get("sample", [])


def test_stale_status_thresholds():
    # 0 stale -> good
    fresh = [_device(f"F-{i}", sync=_fresh_sync()) for i in range(3)]
    assert _by_key(collect_compliance_kpis(fresh))["device_stale_30d"].status == "good"

    # 1 stale -> warn
    one = fresh + [_device("S-1", sync=STALE_SYNC)]
    assert _by_key(collect_compliance_kpis(one))["device_stale_30d"].status == "warn"

    # 2 stale -> warn
    two = fresh + [_device("S-1", sync=STALE_SYNC), _device("S-2", sync=STALE_SYNC)]
    assert _by_key(collect_compliance_kpis(two))["device_stale_30d"].status == "warn"

    # 3 stale -> bad
    three = fresh + [_device(f"S-{i}", sync=STALE_SYNC) for i in range(3)]
    assert _by_key(collect_compliance_kpis(three))["device_stale_30d"].status == "bad"


def test_zero_sentinel_and_empty_dates_are_not_stale():
    devices = [
        _device("NEVER", sync=ZERO_SYNC),      # 0001-01-01 sentinel
        _device("EMPTY", sync=""),             # empty string
        _device("MISSING_KEY"),                # fresh fallback via helper
    ]
    # build one with the key entirely absent
    no_key = {"deviceName": "NOKEY", "complianceState": "compliant"}
    devices.append(no_key)
    m = _by_key(collect_compliance_kpis(devices))
    # None of the sentinel/empty/missing should be counted as stale
    assert m["device_stale_30d"].value == 0
    assert m["device_stale_30d"].status == "good"


def test_unparseable_date_does_not_raise():
    devices = [_device("WEIRD", sync="not-a-date")]
    m = _by_key(collect_compliance_kpis(devices))
    assert m["device_stale_30d"].value == 0


# --- defensive type coercion --------------------------------------------

def test_string_typed_fields_are_handled():
    # CIPP sometimes serialises fields oddly; complianceState should still
    # match by value, and a None compliance must not crash.
    devices = [
        {"deviceName": "PC-1", "complianceState": "compliant",
         "lastSyncDateTime": STALE_SYNC, "managedDeviceOwnerType": "company"},
        {"deviceName": "PC-2", "complianceState": None,
         "lastSyncDateTime": None},
    ]
    m = _by_key(collect_compliance_kpis(devices))
    assert m["device_total"].value == 2
    assert m["device_compliant"].value == 1
    assert m["device_noncompliant"].value == 0
    assert m["device_stale_30d"].value == 1  # PC-1 stale, PC-2 None sync skipped


def test_compliance_state_is_case_insensitive():
    devices = [
        _device("PC-1", compliance="Compliant"),
        _device("PC-2", compliance="NONCOMPLIANT"),
    ]
    m = _by_key(collect_compliance_kpis(devices))
    assert m["device_compliant"].value == 1
    assert m["device_noncompliant"].value == 1
