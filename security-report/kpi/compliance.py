"""Device-compliance KPIs for the QBR / Client Health scorecard.

Pure transformation: takes the raw list of device dicts from CIPP
``/api/ListDevices`` and emits value-framed ``KpiMetric`` objects (counts,
compliance %, staleness). Stdlib-only — no httpx, no CIPP coupling.

Degrades gracefully: an empty list yields a sensible zero/info metric set and
never raises. CIPP numeric/date fields that arrive as strings, ``None``, or the
Graph "never synced" sentinel (``0001-01-01T00:00:00Z``) are handled
defensively.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from qbr_models import KpiMetric

# How long since last sync before a device is "stale".
STALE_AFTER = timedelta(days=30)
# Cap how many names we attach as detail samples.
SAMPLE_LIMIT = 10


def _norm_state(device: dict) -> str:
    """Lower-cased, whitespace-trimmed complianceState ("" if absent/None)."""
    raw = device.get("complianceState")
    if raw is None:
        return ""
    return str(raw).strip().lower()


def _parse_sync(value: Any) -> datetime | None:
    """Parse a CIPP lastSyncDateTime into an aware UTC datetime, or None.

    Returns None for empty/missing values, the ``0001-01-01`` sentinel, and
    anything unparseable. A naive parsed datetime is assumed to be UTC.
    """
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    # Graph "never synced" sentinel.
    if text.startswith("0001-01-01"):
        return None
    # Tolerate a trailing 'Z' (UTC) which fromisoformat rejects pre-3.11.
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except (ValueError, TypeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def collect_compliance_kpis(devices: list[dict]) -> list[KpiMetric]:
    """Build the device-compliance KPI set from raw CIPP device dicts."""
    # Count only dict rows so device_total reconciles with the device-inventory
    # appendix (which skips non-dict junk) — no contradictory counts in one PDF.
    devices = [d for d in (devices or []) if isinstance(d, dict)]
    total = len(devices)

    compliant = 0
    noncompliant_names: list[str] = []
    stale_names: list[str] = []

    now = datetime.now(timezone.utc)
    cutoff = now - STALE_AFTER

    for d in devices:
        if not isinstance(d, dict):
            continue
        state = _norm_state(d)
        name = d.get("deviceName") or "(unnamed)"

        # Intune counts inGracePeriod as compliant; non-evaluated states
        # (unknown/notApplicable/conflict/error/"") are excluded from the % below.
        if state in ("compliant", "ingraceperiod"):
            compliant += 1
        elif state == "noncompliant":
            noncompliant_names.append(str(name))

        synced = _parse_sync(d.get("lastSyncDateTime"))
        if synced is not None and synced < cutoff:
            stale_names.append(str(name))

    noncompliant = len(noncompliant_names)
    stale = len(stale_names)

    # Compliance percentage over EVALUATED devices only (reconciles with Intune;
    # unknown/notApplicable don't deflate the number).
    evaluated = compliant + noncompliant
    if evaluated > 0:
        pct = round(compliant / evaluated * 100, 1)
        if pct >= 90:
            pct_status = "good"
        elif pct >= 70:
            pct_status = "warn"
        else:
            pct_status = "bad"
    else:
        pct = 0.0
        pct_status = "info"

    return [
        KpiMetric(
            key="device_total",
            label="Managed Devices",
            value=total,
            status="info",
        ),
        KpiMetric(
            key="device_compliant",
            label="Compliant Devices",
            value=compliant,
            status="info",
        ),
        KpiMetric(
            key="device_noncompliant",
            label="Noncompliant Devices",
            value=noncompliant,
            status="good" if noncompliant == 0 else "bad",
            detail={"sample": noncompliant_names[:SAMPLE_LIMIT]},
        ),
        KpiMetric(
            key="device_compliance_pct",
            label="Device Compliance",
            value=pct,
            unit="%",
            status=pct_status,
        ),
        KpiMetric(
            key="device_stale_30d",
            label="Stale Devices (30d+)",
            value=stale,
            unit="devices",
            status="good" if stale == 0 else ("warn" if stale <= 2 else "bad"),
            detail={"sample": stale_names[:SAMPLE_LIMIT]},
        ),
    ]
