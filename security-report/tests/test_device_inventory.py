"""Tests for the device inventory collector (kpi/device_inventory.py).

Pure transform of raw CIPP ListDevices dicts into DeviceRecord rows for the
QBR's device-inventory appendix.
"""
from qbr_models import DeviceRecord
from kpi.device_inventory import collect_device_inventory


def _dev(**kw):
    base = {
        "deviceName": "PC-1", "operatingSystem": "Windows", "osVersion": "10.0.26200",
        "managedDeviceOwnerType": "company", "complianceState": "compliant",
        "lastSyncDateTime": "2026-05-30T13:08:31Z", "userDisplayName": "Odd Job",
    }
    base.update(kw)
    return base


def test_maps_core_fields():
    [d] = collect_device_inventory([_dev()])
    assert isinstance(d, DeviceRecord)
    assert d.name == "PC-1"
    assert d.os == "Windows 10.0.26200"
    assert d.owner == "company"
    assert d.compliance == "compliant"
    assert d.last_sync == "2026-05-30"
    assert d.user == "Odd Job"


def test_user_falls_back_to_upn_then_email():
    d = collect_device_inventory([_dev(userDisplayName="", userPrincipalName="a@x.io")])[0]
    assert d.user == "a@x.io"
    d2 = collect_device_inventory([_dev(userDisplayName="", userPrincipalName="", emailAddress="b@x.io")])[0]
    assert d2.user == "b@x.io"


def test_sentinel_last_sync_becomes_empty():
    d = collect_device_inventory([_dev(lastSyncDateTime="0001-01-01T00:00:00Z")])[0]
    assert d.last_sync == ""


def test_missing_fields_degrade_gracefully():
    d = collect_device_inventory([{"deviceName": "Bare"}])[0]
    assert d.name == "Bare"
    assert d.os == ""          # no OS info
    assert d.compliance == ""  # unknown
    assert d.last_sync == ""


def test_noncompliant_devices_sorted_first():
    devs = [
        _dev(deviceName="A-compliant", complianceState="compliant"),
        _dev(deviceName="Z-noncompliant", complianceState="noncompliant"),
        _dev(deviceName="B-grace", complianceState="inGracePeriod"),
    ]
    rows = collect_device_inventory(devs)
    assert rows[0].name == "Z-noncompliant"   # problems surface first


def test_non_dict_elements_skipped():
    rows = collect_device_inventory(["oops", None, _dev()])
    assert len(rows) == 1
    assert rows[0].name == "PC-1"


def test_empty_list_returns_empty():
    assert collect_device_inventory([]) == []
    assert collect_device_inventory(None) == []


def test_device_total_reconciles_with_inventory_on_junk_input():
    # The scorecard "Managed Devices" count and the inventory row count must agree
    # for the SAME raw list, even when CIPP returns non-dict junk elements.
    from kpi.compliance import collect_compliance_kpis
    devices = [_dev(deviceName="A"), "junk", None, _dev(deviceName="B")]
    total = next(m.value for m in collect_compliance_kpis(devices) if m.key == "device_total")
    assert total == len(collect_device_inventory(devices)) == 2
