"""
Security data collectors — each function pulls a specific security domain
from the CIPP API using its native endpoints (not raw Graph passthrough).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

from cipp_client import CippClient, CippError

log = logging.getLogger(__name__)


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    tenant: str
    tenant_id: str
    category: str
    title: str
    severity: Severity
    description: str
    recommendation: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class TenantSecuritySummary:
    tenant_name: str
    tenant_id: str
    default_domain: str
    secure_score: float | None = None
    secure_score_max: float | None = None
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def score_pct(self) -> float | None:
        if self.secure_score is not None and self.secure_score_max:
            return round(self.secure_score / self.secure_score_max * 100, 1)
        return None

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)


def _safe_call(client: CippClient, path: str, params: dict | None = None) -> Any:
    """Call CIPP API with error handling — returns None on failure."""
    try:
        return client.get(path, params=params)
    except CippError as e:
        log.warning("API call failed: %s — %s", path, e)
        return None
    except Exception as e:
        log.warning("Unexpected error on %s: %s", path, e)
        return None


# ---------------------------------------------------------------------------
# 1. Secure Score (via CIPP's cached secure score data)
# ---------------------------------------------------------------------------
def collect_secure_score(client: CippClient, tenant_id: str, tenant_name: str) -> tuple[float | None, float | None, list[Finding]]:
    """Fetch Secure Score via CIPP's native secure score endpoints."""
    findings: list[Finding] = []

    # CIPP caches secure score data — try the dedicated endpoint first
    data = _safe_call(client, "/api/ListGraphRequest", params={
        "TenantFilter": tenant_id,
        "Endpoint": "security/secureScores",
        "$top": "1",
    })

    current_score = None
    max_score = None

    if data and isinstance(data, list) and len(data) > 0:
        latest = data[0] if isinstance(data[0], dict) else {}
        current_score = latest.get("currentScore")
        max_score = latest.get("maxScore")

        control_scores = latest.get("controlScores", [])
        for ctrl in control_scores:
            if not isinstance(ctrl, dict):
                continue
            score = ctrl.get("score", 0)
            max_s = ctrl.get("maxScore", 0) or ctrl.get("scoreInPercentage", 0)
            name = ctrl.get("controlName", "Unknown")
            desc = ctrl.get("description", "")

            if max_s and score < max_s:
                gap = max_s - score
                sev = Severity.HIGH if gap >= 5 else Severity.MEDIUM if gap >= 2 else Severity.LOW
                findings.append(Finding(
                    tenant=tenant_name, tenant_id=tenant_id,
                    category="Secure Score",
                    title=f"Secure Score gap: {name}",
                    severity=sev,
                    description=f"{desc} (Score: {score}/{max_s})",
                    recommendation=f"Address '{name}' to gain up to {gap} points",
                    details=ctrl,
                ))

    return current_score, max_score, findings


# ---------------------------------------------------------------------------
# 2. Conditional Access & MFA (via /api/ListConditionalAccessPolicies
#    and /api/ListMFAUsers)
# ---------------------------------------------------------------------------

def _parse_cipp_ca_policy(p: dict) -> dict:
    """
    CIPP flattens CA policy data into top-level string fields.
    This parses both the flattened format and falls back to the rawjson
    for details like authenticationStrength.

    Flattened fields from CIPP:
      - builtInControls: "block" or "mfa" or "" (comma-separated string)
      - clientAppTypes: "exchangeActiveSync,other" (comma-separated string)
      - includeRoles: "Global Administrator\\nSecurity Administrator\\n" (newline-separated)
      - includeUsers: "All\\n" (newline-separated)
      - grantControlsOperator: "OR"
    """
    import json as _json

    # Parse flattened string fields into lists
    def _split_field(val: str | None) -> list[str]:
        if not val or not isinstance(val, str):
            return []
        # CIPP uses both commas and newlines as delimiters depending on the field
        items = []
        for part in val.replace("\n", ",").split(","):
            part = part.strip()
            if part:
                items.append(part)
        return items

    client_app_types = _split_field(p.get("clientAppTypes"))
    built_in_controls = _split_field(p.get("builtInControls"))
    include_roles = _split_field(p.get("includeRoles"))
    include_users = _split_field(p.get("includeUsers"))
    grant_operator = p.get("grantControlsOperator", "")

    # Check rawjson for authenticationStrength (newer MFA enforcement method)
    has_auth_strength_mfa = False
    raw = p.get("rawjson")
    if raw and isinstance(raw, str):
        try:
            raw_obj = _json.loads(raw)
            grant_controls = raw_obj.get("grantControls", {}) or {}
            auth_strength = grant_controls.get("authenticationStrength")
            if isinstance(auth_strength, dict):
                req = auth_strength.get("requirementsSatisfied", "")
                if "mfa" in req.lower():
                    has_auth_strength_mfa = True
        except (_json.JSONDecodeError, AttributeError):
            pass

    return {
        "clientAppTypes": client_app_types,
        "builtInControls": built_in_controls,
        "includeRoles": include_roles,
        "includeUsers": include_users,
        "grantOperator": grant_operator,
        "has_auth_strength_mfa": has_auth_strength_mfa,
        "requires_mfa": "mfa" in built_in_controls or has_auth_strength_mfa,
        "blocks": "block" in built_in_controls,
    }


def collect_conditional_access(client: CippClient, tenant_id: str, tenant_name: str) -> list[Finding]:
    findings: list[Finding] = []

    # --- CA Policies ---
    raw_response = _safe_call(client, "/api/ListConditionalAccessPolicies", params={"TenantFilter": tenant_id})

    # CIPP may return {Results: [...]} or just [...]
    policies: list[dict] = []
    if isinstance(raw_response, list):
        policies = raw_response
    elif isinstance(raw_response, dict):
        policies = raw_response.get("Results", []) or raw_response.get("value", []) or []

    if not isinstance(policies, list):
        policies = []

    enabled_policies = [p for p in policies if isinstance(p, dict) and p.get("state") == "enabled"]
    report_only = [p for p in policies if isinstance(p, dict) and p.get("state") == "enabledForReportingButNotEnforced"]

    if len(enabled_policies) == 0:
        findings.append(Finding(
            tenant=tenant_name, tenant_id=tenant_id,
            category="Conditional Access",
            title="No enabled Conditional Access policies",
            severity=Severity.CRITICAL,
            description="This tenant has zero enabled Conditional Access policies.",
            recommendation="Deploy baseline CA policies: require MFA for all users, block legacy auth, require compliant devices for admin access.",
        ))

    has_legacy_block = False
    has_mfa_policy = False
    has_admin_mfa = False

    for p in enabled_policies:
        parsed = _parse_cipp_ca_policy(p)

        # Legacy auth block: policy targets exchangeActiveSync/other and blocks
        if any(t in parsed["clientAppTypes"] for t in ["exchangeActiveSync", "other"]):
            if parsed["blocks"]:
                has_legacy_block = True

        # MFA enforcement: via builtInControls or authenticationStrength
        if parsed["requires_mfa"]:
            has_mfa_policy = True
            # Admin-specific MFA: policy targets specific admin roles
            if parsed["includeRoles"]:
                has_admin_mfa = True

    if not has_legacy_block:
        findings.append(Finding(
            tenant=tenant_name, tenant_id=tenant_id,
            category="Conditional Access",
            title="Legacy authentication not blocked",
            severity=Severity.HIGH,
            description="No CA policy blocks legacy authentication protocols (Exchange ActiveSync, POP3, IMAP, etc.).",
            recommendation="Create a CA policy to block legacy authentication for all users.",
        ))

    if not has_mfa_policy:
        findings.append(Finding(
            tenant=tenant_name, tenant_id=tenant_id,
            category="Conditional Access",
            title="No MFA enforcement policy",
            severity=Severity.CRITICAL,
            description="No Conditional Access policy requires multi-factor authentication.",
            recommendation="Deploy a CA policy requiring MFA for all users, at minimum for admin roles.",
        ))

    if not has_admin_mfa and len(enabled_policies) > 0 and has_mfa_policy:
        findings.append(Finding(
            tenant=tenant_name, tenant_id=tenant_id,
            category="Conditional Access",
            title="No dedicated admin MFA policy",
            severity=Severity.MEDIUM,
            description="No CA policy specifically targets admin roles with MFA requirements. MFA may still be enforced via a broader policy.",
            recommendation="Consider a dedicated CA policy for admin roles with stricter controls (phishing-resistant MFA, compliant device).",
        ))

    for p in report_only:
        findings.append(Finding(
            tenant=tenant_name, tenant_id=tenant_id,
            category="Conditional Access",
            title=f"Policy in report-only mode: {p.get('displayName', 'Unknown')}",
            severity=Severity.LOW,
            description=f"Policy '{p.get('displayName')}' is in report-only mode and not enforcing controls.",
            recommendation="Review the policy's report-only insights and consider switching to enforced.",
            details={"policyId": p.get("id"), "policyName": p.get("displayName")},
        ))

    # --- MFA Coverage via /api/ListMFAUsers ---
    mfa_users = _safe_call(client, "/api/ListMFAUsers", params={"TenantFilter": tenant_id})
    if isinstance(mfa_users, list) and len(mfa_users) > 0:
        no_mfa = [u for u in mfa_users if isinstance(u, dict)
                  and not u.get("MFARegistration") and u.get("AccountEnabled", True)]
        if no_mfa:
            pct = round(len(no_mfa) / len(mfa_users) * 100, 1)
            sev = Severity.CRITICAL if pct > 30 else Severity.HIGH if pct > 10 else Severity.MEDIUM
            sample = [u.get("UPN", "Unknown") for u in no_mfa[:5]]
            findings.append(Finding(
                tenant=tenant_name, tenant_id=tenant_id,
                category="MFA",
                title=f"{len(no_mfa)} users without MFA registered ({pct}%)",
                severity=sev,
                description=f"{len(no_mfa)} of {len(mfa_users)} enabled users have not registered for MFA.",
                recommendation="Require MFA registration for all users via CA policy or security defaults.",
                details={"count": len(no_mfa), "total": len(mfa_users), "sample": sample},
            ))

    return findings


# ---------------------------------------------------------------------------
# 3. Admin Role Analysis (via /api/ListRoles)
# ---------------------------------------------------------------------------
def collect_admin_roles(client: CippClient, tenant_id: str, tenant_name: str) -> list[Finding]:
    findings: list[Finding] = []

    roles = _safe_call(client, "/api/ListRoles", params={"tenantFilter": tenant_id})
    if not isinstance(roles, list):
        return findings

    total_admins = set()
    global_admins = []

    for role in roles:
        if not isinstance(role, dict):
            continue
        role_name = role.get("DisplayName", "") or role.get("displayName", "")
        members = role.get("Members", []) or role.get("members", []) or []

        for m in members:
            if isinstance(m, dict):
                upn = m.get("userPrincipalName", "") or m.get("displayName", "")
                total_admins.add(upn)
                if role_name == "Global Administrator":
                    global_admins.append(upn)

    if len(global_admins) > 5:
        findings.append(Finding(
            tenant=tenant_name, tenant_id=tenant_id,
            category="Admin Roles",
            title=f"Excessive Global Administrators ({len(global_admins)})",
            severity=Severity.HIGH,
            description=f"There are {len(global_admins)} Global Administrators. Microsoft recommends no more than 5.",
            recommendation="Review and reduce GA count. Use least-privilege roles instead.",
            details={"global_admins": global_admins},
        ))
    elif len(global_admins) > 2:
        findings.append(Finding(
            tenant=tenant_name, tenant_id=tenant_id,
            category="Admin Roles",
            title=f"{len(global_admins)} Global Administrators",
            severity=Severity.MEDIUM,
            description=f"There are {len(global_admins)} Global Administrators. Consider reducing to 2-4.",
            recommendation="Audit whether all GAs need that level of access. Use scoped admin roles where possible.",
            details={"global_admins": global_admins},
        ))

    if len(global_admins) == 1:
        findings.append(Finding(
            tenant=tenant_name, tenant_id=tenant_id,
            category="Admin Roles",
            title="Only 1 Global Administrator — no break-glass account",
            severity=Severity.HIGH,
            description="Only one GA exists. If that account is compromised or locked out, there is no recovery path.",
            recommendation="Create a dedicated break-glass account with GA role, strong password, and no MFA (stored securely offline).",
        ))

    return findings


# ---------------------------------------------------------------------------
# 4. Mailbox Security (via /api/ListTransportRules, /api/ListMailboxes)
# ---------------------------------------------------------------------------
def collect_mailbox_security(client: CippClient, tenant_id: str, tenant_name: str) -> list[Finding]:
    findings: list[Finding] = []

    # Transport rules
    transport_rules = _safe_call(client, "/api/ListTransportRules", params={"TenantFilter": tenant_id})
    if isinstance(transport_rules, list):
        for rule in transport_rules:
            if not isinstance(rule, dict):
                continue
            actions = []
            if rule.get("RedirectMessageTo"):
                actions.append("redirect")
            if rule.get("BlindCopyTo"):
                actions.append("BCC")
            if rule.get("CopyTo"):
                actions.append("CC copy")

            if actions:
                findings.append(Finding(
                    tenant=tenant_name, tenant_id=tenant_id,
                    category="Mail Security",
                    title=f"Transport rule with external routing: {rule.get('Name', 'Unknown')}",
                    severity=Severity.MEDIUM,
                    description=f"Transport rule '{rule.get('Name')}' performs: {', '.join(actions)}. This could be used for data exfiltration.",
                    recommendation="Audit this rule to confirm it is legitimate and required.",
                    details={"rule_name": rule.get("Name"), "state": rule.get("State"), "actions": actions},
                ))

    # Mailbox forwarding
    mailboxes = _safe_call(client, "/api/ListMailboxes", params={"TenantFilter": tenant_id})
    forwarding_details: list[str] = []
    if isinstance(mailboxes, list):
        for mb in mailboxes:
            if not isinstance(mb, dict):
                continue
            fwd = mb.get("ForwardingSmtpAddress") or mb.get("ForwardingAddress")
            if fwd:
                upn = mb.get("UPN") or mb.get("UserPrincipalName") or mb.get("displayName", "Unknown")
                forwarding_details.append(f"{upn} → {fwd}")

    if forwarding_details:
        count = len(forwarding_details)
        findings.append(Finding(
            tenant=tenant_name, tenant_id=tenant_id,
            category="Mail Security",
            title=f"{count} mailbox(es) with forwarding enabled",
            severity=Severity.HIGH if count > 3 else Severity.MEDIUM,
            description=f"{count} mailboxes have external forwarding configured. This is a common attack vector.",
            recommendation="Audit all mailbox forwarding rules. Consider disabling external forwarding via transport rule.",
            details={"forwarding": forwarding_details[:20]},
        ))

    return findings


# ---------------------------------------------------------------------------
# 5. Device Compliance (via /api/ListDevices)
# ---------------------------------------------------------------------------
def collect_device_compliance(client: CippClient, tenant_id: str, tenant_name: str) -> list[Finding]:
    findings: list[Finding] = []

    devices = _safe_call(client, "/api/ListDevices", params={"TenantFilter": tenant_id})
    if not isinstance(devices, list):
        return findings

    if len(devices) == 0:
        findings.append(Finding(
            tenant=tenant_name, tenant_id=tenant_id,
            category="Device Compliance",
            title="No managed devices enrolled",
            severity=Severity.MEDIUM,
            description="No devices are enrolled in Intune for this tenant.",
            recommendation="Evaluate if device management should be deployed for this tenant.",
        ))
        return findings

    noncompliant = [d for d in devices if isinstance(d, dict) and d.get("complianceState") == "noncompliant"]

    if noncompliant:
        pct = round(len(noncompliant) / len(devices) * 100, 1)
        sev = Severity.CRITICAL if pct > 30 else Severity.HIGH if pct > 10 else Severity.MEDIUM
        findings.append(Finding(
            tenant=tenant_name, tenant_id=tenant_id,
            category="Device Compliance",
            title=f"{len(noncompliant)} noncompliant devices ({pct}%)",
            severity=sev,
            description=f"{len(noncompliant)} of {len(devices)} managed devices are noncompliant.",
            recommendation="Review noncompliant devices and remediate compliance policy failures.",
            details={"noncompliant_count": len(noncompliant), "total": len(devices), "pct": pct},
        ))

    # Stale devices
    now = datetime.now(timezone.utc)
    stale = []
    for d in devices:
        if not isinstance(d, dict):
            continue
        last_sync = d.get("lastSyncDateTime")
        if last_sync:
            try:
                sync_dt = datetime.fromisoformat(last_sync.replace("Z", "+00:00"))
                if (now - sync_dt) > timedelta(days=30):
                    stale.append(d.get("deviceName", "Unknown"))
            except (ValueError, TypeError):
                pass

    if stale:
        findings.append(Finding(
            tenant=tenant_name, tenant_id=tenant_id,
            category="Device Compliance",
            title=f"{len(stale)} stale devices (no sync in 30+ days)",
            severity=Severity.MEDIUM,
            description=f"{len(stale)} devices haven't synced in over 30 days and may be abandoned.",
            recommendation="Review stale devices and retire or wipe those no longer in use.",
            details={"stale_devices": stale[:20]},
        ))

    return findings


# ---------------------------------------------------------------------------
# 6. Standards Compliance & Configuration Drift
# ---------------------------------------------------------------------------
def collect_standards_drift(client: CippClient, tenant_id: str, tenant_name: str) -> list[Finding]:
    """Check CIPP Standards compliance and configuration drift."""
    findings: list[Finding] = []

    drift = _safe_call(client, "/api/ListTenantDrift", params={"TenantFilter": tenant_id})
    if isinstance(drift, list):
        for item in drift:
            if not isinstance(item, dict):
                continue
            standard_name = item.get("standardName") or item.get("Standard") or "Unknown"
            status = item.get("status") or item.get("State") or ""
            drift_detected = status.lower() in ("failed", "drifted", "noncompliant", "false")

            if drift_detected:
                findings.append(Finding(
                    tenant=tenant_name, tenant_id=tenant_id,
                    category="Standards Compliance",
                    title=f"Configuration drift: {standard_name}",
                    severity=Severity.HIGH,
                    description=f"Tenant has drifted from the applied standard '{standard_name}' (status: {status}).",
                    recommendation=f"Re-apply the '{standard_name}' standard via CIPP or investigate why the configuration changed.",
                    details=item,
                ))

    standards = _safe_call(client, "/api/ListStandards", params={"TenantFilter": tenant_id})
    if isinstance(standards, list) and len(standards) == 0:
        findings.append(Finding(
            tenant=tenant_name, tenant_id=tenant_id,
            category="Standards Compliance",
            title="No CIPP standards applied",
            severity=Severity.MEDIUM,
            description="This tenant has no CIPP standards applied. Security baselines are not being enforced.",
            recommendation="Review and apply appropriate CIPP security standards for this tenant.",
        ))

    return findings


# ---------------------------------------------------------------------------
# 7. Inactive Accounts & Legacy Auth (via /api/ListInactiveAccounts,
#    /api/ListBasicAuth)
# ---------------------------------------------------------------------------
def collect_identity_hygiene(client: CippClient, tenant_id: str, tenant_name: str) -> list[Finding]:
    """Check for inactive accounts and legacy auth usage using CIPP's native endpoints."""
    findings: list[Finding] = []

    # Inactive accounts (no sign-in in 180 days)
    inactive = _safe_call(client, "/api/ListInactiveAccounts", params={"tenantFilter": tenant_id})
    if isinstance(inactive, list) and len(inactive) > 0:
        licensed_inactive = [u for u in inactive if isinstance(u, dict)
                            and (u.get("numberOfAssignedLicenses", 0) or 0) > 0]
        if licensed_inactive:
            sample = [u.get("userPrincipalName", "Unknown") for u in licensed_inactive[:5]]
            findings.append(Finding(
                tenant=tenant_name, tenant_id=tenant_id,
                category="Identity Hygiene",
                title=f"{len(licensed_inactive)} licensed inactive accounts (180+ days)",
                severity=Severity.HIGH if len(licensed_inactive) > 5 else Severity.MEDIUM,
                description=f"{len(licensed_inactive)} licensed users haven't signed in for 180+ days. These are wasted licenses and potential security risks.",
                recommendation="Disable or remove licenses from inactive accounts. Review for possible shared/service accounts.",
                details={"count": len(licensed_inactive), "sample": sample},
            ))

        unlicensed_inactive = [u for u in inactive if isinstance(u, dict)
                               and (u.get("numberOfAssignedLicenses", 0) or 0) == 0
                               and u.get("accountEnabled", True)]
        if len(unlicensed_inactive) > 10:
            findings.append(Finding(
                tenant=tenant_name, tenant_id=tenant_id,
                category="Identity Hygiene",
                title=f"{len(unlicensed_inactive)} enabled accounts with no licenses and no sign-in",
                severity=Severity.LOW,
                description=f"{len(unlicensed_inactive)} enabled accounts have no licenses and haven't signed in recently.",
                recommendation="Review and disable stale accounts to reduce attack surface.",
            ))

    # Legacy/basic auth usage
    basic_auth = _safe_call(client, "/api/ListBasicAuth", params={"tenantFilter": tenant_id})
    if isinstance(basic_auth, list) and len(basic_auth) > 0:
        users_using_basic = set()
        protocols: set[str] = set()
        for entry in basic_auth:
            if isinstance(entry, dict):
                users_using_basic.add(entry.get("userPrincipalName", "Unknown"))
                protocols.add(entry.get("clientAppUsed", "Unknown"))

        if users_using_basic:
            findings.append(Finding(
                tenant=tenant_name, tenant_id=tenant_id,
                category="Identity Hygiene",
                title=f"{len(users_using_basic)} user(s) using legacy/basic authentication",
                severity=Severity.HIGH,
                description=f"{len(users_using_basic)} users authenticated via legacy protocols ({', '.join(sorted(protocols))}). Basic auth bypasses MFA.",
                recommendation="Block legacy auth via Conditional Access policy and migrate users to modern authentication.",
                details={"users": sorted(users_using_basic)[:10], "protocols": sorted(protocols)},
            ))

    return findings


# ---------------------------------------------------------------------------
# 8. Security Alerts (via /api/ExecAlertsList)
# ---------------------------------------------------------------------------
def collect_security_alerts(client: CippClient, tenant_id: str, tenant_name: str) -> list[Finding]:
    """Check for active security alerts via CIPP's alerts endpoint."""
    findings: list[Finding] = []

    alerts = _safe_call(client, "/api/ExecAlertsList", params={"TenantFilter": tenant_id})
    if not alerts:
        return findings

    # ExecAlertsList may return alerts in different structures
    alert_list = []
    if isinstance(alerts, list):
        alert_list = alerts
    elif isinstance(alerts, dict):
        alert_list = alerts.get("MSResults", []) or alerts.get("value", []) or []

    active_alerts = [a for a in alert_list if isinstance(a, dict)
                     and a.get("Status", "").lower() not in ("resolved", "dismissed")]

    high_sev_alerts = [a for a in active_alerts
                       if a.get("Severity", "").lower() in ("high", "critical")]
    med_sev_alerts = [a for a in active_alerts
                      if a.get("Severity", "").lower() == "medium"]

    if high_sev_alerts:
        titles = [a.get("Title", "Unknown") for a in high_sev_alerts[:5]]
        findings.append(Finding(
            tenant=tenant_name, tenant_id=tenant_id,
            category="Security Alerts",
            title=f"{len(high_sev_alerts)} high/critical security alert(s)",
            severity=Severity.CRITICAL,
            description=f"Active high-severity alerts: {'; '.join(titles)}",
            recommendation="Investigate and resolve these security alerts immediately.",
            details={"alerts": [{"title": a.get("Title"), "category": a.get("Category"), "severity": a.get("Severity")} for a in high_sev_alerts[:10]]},
        ))

    if med_sev_alerts:
        findings.append(Finding(
            tenant=tenant_name, tenant_id=tenant_id,
            category="Security Alerts",
            title=f"{len(med_sev_alerts)} medium security alert(s)",
            severity=Severity.MEDIUM,
            description=f"{len(med_sev_alerts)} unresolved medium-severity security alerts.",
            recommendation="Review and triage medium-severity alerts.",
        ))

    return findings


# ---------------------------------------------------------------------------
# 9. Defender State (via /api/ListDefenderState)
# ---------------------------------------------------------------------------
def collect_defender_state(client: CippClient, tenant_id: str, tenant_name: str) -> list[Finding]:
    """Check Windows Defender protection status across managed devices."""
    findings: list[Finding] = []

    defender = _safe_call(client, "/api/ListDefenderState", params={"TenantFilter": tenant_id})
    if not isinstance(defender, list) or len(defender) == 0:
        return findings

    unprotected = []
    outdated_sigs = []
    for d in defender:
        if not isinstance(d, dict):
            continue
        protection = d.get("windowsProtectionState", {}) or {}
        device_name = d.get("deviceName", "Unknown")

        if protection.get("realTimeProtectionEnabled") is False:
            unprotected.append(device_name)

        # Check signature staleness
        sig_date = protection.get("lastQuickScanSignatureVersion")
        if not sig_date:
            sig_date = protection.get("signatureLastUpdateDateTime")

    if unprotected:
        findings.append(Finding(
            tenant=tenant_name, tenant_id=tenant_id,
            category="Endpoint Protection",
            title=f"{len(unprotected)} device(s) with Defender real-time protection disabled",
            severity=Severity.CRITICAL,
            description=f"Devices without real-time protection: {', '.join(unprotected[:10])}",
            recommendation="Enable Defender real-time protection on these devices immediately.",
            details={"devices": unprotected[:20]},
        ))

    return findings


# ---------------------------------------------------------------------------
# Orchestrator: collect all data for a single tenant
# ---------------------------------------------------------------------------
def collect_tenant_security(client: CippClient, tenant: dict[str, Any]) -> TenantSecuritySummary:
    tenant_name = tenant.get("displayName") or tenant.get("defaultDomainName") or "Unknown"
    tenant_id = tenant.get("customerId") or tenant.get("tenantId", "")
    default_domain = tenant.get("defaultDomainName", "")

    summary = TenantSecuritySummary(
        tenant_name=tenant_name,
        tenant_id=tenant_id,
        default_domain=default_domain,
    )

    log.info("Collecting security data for %s (%s)", tenant_name, default_domain)

    collectors = [
        ("Secure Score", lambda: _collect_secure_score_wrapper(client, tenant_id, tenant_name, summary)),
        ("Conditional Access & MFA", lambda: collect_conditional_access(client, tenant_id, tenant_name)),
        ("Admin Roles", lambda: collect_admin_roles(client, tenant_id, tenant_name)),
        ("Mail Security", lambda: collect_mailbox_security(client, tenant_id, tenant_name)),
        ("Device Compliance", lambda: collect_device_compliance(client, tenant_id, tenant_name)),
        ("Standards Compliance", lambda: collect_standards_drift(client, tenant_id, tenant_name)),
        ("Identity Hygiene", lambda: collect_identity_hygiene(client, tenant_id, tenant_name)),
        ("Security Alerts", lambda: collect_security_alerts(client, tenant_id, tenant_name)),
        ("Defender State", lambda: collect_defender_state(client, tenant_id, tenant_name)),
    ]

    for name, collector in collectors:
        try:
            result = collector()
            if isinstance(result, list):
                summary.findings.extend(result)
        except Exception as e:
            summary.errors.append(f"{name}: {e}")
            log.error("%s collection failed for %s: %s", name, tenant_name, e)

    log.info("  %s: %d findings (%d critical, %d high)",
             tenant_name, len(summary.findings), summary.critical_count, summary.high_count)

    return summary


def _collect_secure_score_wrapper(client: CippClient, tenant_id: str, tenant_name: str, summary: TenantSecuritySummary) -> list[Finding]:
    score, max_score, findings = collect_secure_score(client, tenant_id, tenant_name)
    summary.secure_score = score
    summary.secure_score_max = max_score
    return findings
