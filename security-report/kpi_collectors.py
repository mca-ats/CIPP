"""
QBR aggregator — orchestrates security + KPI collection into one QbrData.

Two entry points:
  - assemble_qbr_data(): PURE assembly (raw CIPP dicts + a security summary ->
    QbrData). Persists/loads the Secure Score trend. Unit-tested with fixtures.
  - collect_qbr_data(): thin live wrapper — fetches the raw CIPP responses via
    the existing _safe_call pattern, runs the existing security sweep, then
    delegates to assemble_qbr_data(). Verified end-to-end against the lab tenant.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cipp_client import CippClient
from collectors import collect_tenant_security, _safe_call, TenantSecuritySummary
from qbr_models import QbrData, quarter_label
from kpi.licenses import collect_license_kpis
from kpi.compliance import collect_compliance_kpis
from kpi.identity import collect_identity_kpis
from kpi.score_trend import collect_score_trend
from kpi.device_inventory import collect_device_inventory
from kpi.licensed_users import collect_licensed_users, licensed_users_metric
from kpi.signin_activity import signin_to_inactive_accounts

DEFAULT_HISTORY_PATH = Path(__file__).resolve().parent / "reports" / "qbr" / "score_history.json"


def assemble_qbr_data(
    summary: TenantSecuritySummary,
    raw: dict[str, list],
    run_time: datetime,
    history_path: str | Path,
) -> QbrData:
    """Combine a security summary + raw CIPP KPI responses into a QbrData.

    ``raw`` keys: ``licenses``, ``devices``, ``mfa_users``, ``inactive`` (each a list).
    """
    run_date = run_time.strftime("%Y-%m-%d")

    # Drop QBR-redundant findings from the security sweep:
    #  - "Secure Score" per-control gaps (~147) would flood the appendix; the
    #    score is shown as a KPI + trend instead.
    #  - the ~180-day-floored "licensed inactive" finding, now superseded by the
    #    accurate 30-day Licensed Inactive KPI + the Licensed Users roster.
    if summary is not None and getattr(summary, "findings", None):
        summary.findings = [
            f for f in summary.findings
            if f.category != "Secure Score"
            and "licensed inactive" not in (f.title or "").lower()
        ]

    licensed_users = collect_licensed_users(
        raw.get("licenses") or [], raw.get("mfa_users") or [], raw.get("inactive") or [])

    kpis = []
    kpis += collect_license_kpis(raw.get("licenses") or [])
    kpis += collect_compliance_kpis(raw.get("devices") or [])
    kpis += collect_identity_kpis(raw.get("mfa_users") or [], raw.get("inactive") or [])
    kpis.append(licensed_users_metric(licensed_users))

    # Reconcile the "Licensed Inactive" KPI with the roster — they must show the same
    # number. The roster is the source of truth (paid seats, enabled, 30d+); recompute
    # the KPI from it so the scorecard count == the Inactive-flagged roster rows.
    roster_inactive = sum(1 for u in licensed_users if u.status.startswith("Inactive"))
    for m in kpis:
        if m.key == "identity_licensed_inactive":
            m.value = roster_inactive
            m.status = "good" if roster_inactive == 0 else "warn" if roster_inactive <= 2 else "bad"
            m.detail = {"basis": "paid-seat roster, enabled, 30d+"}

    score_history = collect_score_trend(
        tenant_id=summary.tenant_id,
        current_score=summary.secure_score,
        max_score=summary.secure_score_max,
        run_date=run_date,
        history_path=history_path,
    )

    return QbrData(
        tenant_name=summary.tenant_name,
        tenant_id=summary.tenant_id,
        default_domain=summary.default_domain,
        period=quarter_label(run_time),
        security=summary,
        kpis=kpis,
        score_history=score_history,
        devices=collect_device_inventory(raw.get("devices") or []),
        licensed_users=licensed_users,
        errors=list(getattr(summary, "errors", []) or []),
        generated_at=run_time.isoformat(),
    )


def _fetch_kpi_raw(client: CippClient, tenant_id: str,
                   run_time: datetime) -> tuple[dict[str, list], list[str]]:
    """Fetch raw CIPP responses the KPI collectors need. Returns (raw, errors),
    where errors names the endpoints that FAILED (None) — distinct from a
    legitimately empty ([]) result — so a degraded run can be flagged."""
    errors: list[str] = []

    def as_list(v: Any) -> list:
        return v if isinstance(v, list) else []

    def results(v: Any) -> list:
        if isinstance(v, dict):
            return as_list(v.get("Results") or v.get("value"))
        return as_list(v)

    def fetch(name: str, path: str, params: dict) -> Any:
        v = _safe_call(client, path, params)
        if v is None:                       # exception was swallowed by _safe_call
            errors.append(name)
        return v

    # True per-user inactivity from Graph signInActivity (any threshold), built
    # into the inactive-account shape the collectors expect. Fall back to CIPP's
    # ~180-day-floored ListInactiveAccounts if the Graph call is unavailable.
    signin = results(fetch("signInActivity (users)", "/api/ListGraphRequest", {
        "TenantFilter": tenant_id, "Endpoint": "users",
        "$select": "displayName,userPrincipalName,accountEnabled,signInActivity,assignedLicenses,createdDateTime",
        "$top": "999",
    }))
    if signin:
        inactive = signin_to_inactive_accounts(signin, run_time)
    else:
        inactive = as_list(fetch("ListInactiveAccounts", "/api/ListInactiveAccounts", {"tenantFilter": tenant_id}))

    raw = {
        "licenses": as_list(fetch("ListLicenses", "/api/ListLicenses", {"TenantFilter": tenant_id})),
        "devices": as_list(fetch("ListDevices", "/api/ListDevices", {"TenantFilter": tenant_id})),
        "mfa_users": as_list(fetch("ListMFAUsers", "/api/ListMFAUsers", {"TenantFilter": tenant_id})),
        "inactive": inactive,
    }
    return raw, errors


def collect_qbr_data(
    client: CippClient,
    tenant: dict[str, Any],
    run_time: datetime | None = None,
    history_path: str | Path = DEFAULT_HISTORY_PATH,
) -> QbrData:
    """Live path: security sweep + KPI fetch + assembly for one tenant."""
    run_time = run_time or datetime.now(timezone.utc)
    summary = collect_tenant_security(client, tenant)
    raw, fetch_errors = _fetch_kpi_raw(client, summary.tenant_id, run_time)
    qbr = assemble_qbr_data(summary, raw, run_time, history_path)
    qbr.errors = list(qbr.errors) + [f"KPI fetch failed: {e}" for e in fetch_errors]
    return qbr
