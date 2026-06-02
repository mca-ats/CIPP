"""Device inventory for the QBR appendix.

Pure transformation of the raw CIPP ``/api/ListDevices`` list into
:class:`~qbr_models.DeviceRecord` rows — name, OS/version, owner, compliance,
last sync, and user. Degrades gracefully on missing fields / non-dict elements;
sorts noncompliant devices first so problems surface at the top.
"""
from __future__ import annotations

from typing import Any

from qbr_models import DeviceRecord

# Graph's "never synced" sentinel.
_SYNC_SENTINEL_PREFIX = "0001-01-01"
# Compliance ordering for the table: problems first.
_COMPLIANCE_ORDER = {"noncompliant": 0, "ingraceperiod": 1, "compliant": 2}


def _date_only(value: Any) -> str:
    """ISO datetime -> 'YYYY-MM-DD'; '' for empty / the 0001 sentinel / garbage."""
    if not value or not isinstance(value, str):
        return ""
    if value.startswith(_SYNC_SENTINEL_PREFIX):
        return ""
    return value[:10]


def _user(d: dict) -> str:
    for key in ("userDisplayName", "userPrincipalName", "emailAddress"):
        v = d.get(key)
        if v:
            return str(v)
    return ""


def collect_device_inventory(devices: list[dict] | None) -> list[DeviceRecord]:
    rows: list[DeviceRecord] = []
    for d in devices or []:
        if not isinstance(d, dict):
            continue
        os_name = str(d.get("operatingSystem") or "").strip()
        os_ver = str(d.get("osVersion") or "").strip()
        rows.append(DeviceRecord(
            name=str(d.get("deviceName") or "(unnamed)"),
            os=f"{os_name} {os_ver}".strip(),
            owner=str(d.get("managedDeviceOwnerType") or d.get("ownerType") or "").strip(),
            compliance=str(d.get("complianceState") or "").strip().lower(),
            last_sync=_date_only(d.get("lastSyncDateTime")),
            user=_user(d),
        ))

    rows.sort(key=lambda r: (_COMPLIANCE_ORDER.get(r.compliance, 3), r.name.lower()))
    return rows
