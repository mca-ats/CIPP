"""
Shared data model for the QBR / Client Health report.

The existing security pipeline (collectors.py) produces ``Finding`` objects —
problem-framed, emitted only when something is wrong. A QBR additionally needs
*metrics*: value-framed numbers that appear even when posture is healthy
("12 of 13 devices compliant, 92%"). ``KpiMetric`` is that shape.

This module is intentionally dependency-free (stdlib only) so the parallel
KPI collectors can import it without coupling to httpx/CIPP.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

# Scorecard status for a KPI — drives colour in the PDF. Not a security severity.
KpiStatus = Literal["good", "warn", "bad", "info"]


@dataclass
class KpiMetric:
    """A single value-framed metric for the QBR scorecard."""
    key: str                       # stable id, e.g. "license_utilization"
    label: str                     # human label, e.g. "License Utilization"
    value: Any                     # number or short string
    unit: str = ""                 # "%", "users", "devices", "" for strings
    status: KpiStatus = "info"     # good | warn | bad | info
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass
class DeviceRecord:
    """One managed device, for the QBR device-inventory appendix."""
    name: str
    os: str = ""            # "Windows 10.0.26200"
    owner: str = ""         # "company" | "personal" | ""
    compliance: str = ""    # normalized lower state: compliant/noncompliant/ingraceperiod/...
    last_sync: str = ""     # "YYYY-MM-DD" or "" when unknown/sentinel
    user: str = ""          # display name, UPN, or email


@dataclass
class LicensedUser:
    """A user holding a paid productivity SKU, for the QBR licensed-users appendix."""
    name: str
    upn: str
    licenses: list[str] = field(default_factory=list)  # short SKU names, sorted
    status: str = "Active"                              # Active | Disabled | Inactive Nd


@dataclass
class ScorePoint:
    """One historical Secure Score reading."""
    date: str                      # ISO date "YYYY-MM-DD"
    score: float
    max_score: float

    @property
    def pct(self) -> float | None:
        if self.max_score:
            return round(self.score / self.max_score * 100, 1)
        return None


@dataclass
class QbrData:
    """Everything the narrative + renderer need for one tenant, one period."""
    tenant_name: str
    tenant_id: str
    default_domain: str
    period: str                                  # "2026-Q2"
    security: Any = None                          # TenantSecuritySummary (from collectors)
    kpis: list[KpiMetric] = field(default_factory=list)
    score_history: list[ScorePoint] = field(default_factory=list)
    devices: list[DeviceRecord] = field(default_factory=list)
    licensed_users: list[LicensedUser] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)   # collection failures (degraded run)
    generated_at: str = ""


def quarter_label(dt: datetime) -> str:
    """Map a datetime to a calendar-quarter label, e.g. 2026-Q2."""
    q = (dt.month - 1) // 3 + 1
    return f"{dt.year}-Q{q}"


def score_trend(history: list[ScorePoint]) -> dict[str, Any]:
    """Summarise a Secure Score history into latest/previous/delta/direction.

    Sorts chronologically by date first, so callers may pass points in any
    order. ``delta`` and ``previous_pct`` are None when there is < 2 points.
    """
    ordered = sorted(history, key=lambda p: p.date)

    if not ordered:
        return {"latest_pct": None, "previous_pct": None,
                "delta": None, "direction": "flat"}

    latest_pct = ordered[-1].pct

    if len(ordered) < 2:
        return {"latest_pct": latest_pct, "previous_pct": None,
                "delta": None, "direction": "flat"}

    previous_pct = ordered[-2].pct

    if latest_pct is None or previous_pct is None:
        return {"latest_pct": latest_pct, "previous_pct": previous_pct,
                "delta": None, "direction": "flat"}

    delta = round(latest_pct - previous_pct, 1)
    direction = "up" if delta > 0 else "down" if delta < 0 else "flat"
    return {"latest_pct": latest_pct, "previous_pct": previous_pct,
            "delta": delta, "direction": direction}
