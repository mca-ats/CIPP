#!/usr/bin/env python3
"""
Daily CIPP Security Posture Report
===================================
Main entrypoint — collects security data from all tenants via the CIPP API,
generates a multi-format report, and delivers it to Obsidian, email, and Notion.

Usage:
    python run_report.py                    # Full run, all tenants
    python run_report.py --tenant-filter X  # Single tenant by name/domain
    python run_report.py --dry-run          # Collect data but don't deliver
    python run_report.py --obsidian-only    # Only write to Obsidian
"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

# Ensure the script directory is on the path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from cipp_client import CippClient, CippError
from collectors import collect_tenant_security, TenantSecuritySummary
from report_generator import (
    generate_obsidian_report,
    generate_email_html,
    generate_notion_blocks,
    generate_json_report,
)
from delivery import deliver_all

log = logging.getLogger("security-report")


def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def run(
    tenant_filter: str | None = None,
    dry_run: bool = False,
    obsidian_only: bool = False,
    vault_path: str | None = None,
    env_path: str | None = None,
) -> dict:
    run_time = datetime.now(timezone.utc)
    log.info("Starting security posture report at %s", run_time.isoformat())

    # Connect to CIPP
    env = Path(env_path) if env_path else None
    client = CippClient.from_env(env) if env else CippClient.from_env()

    with client:
        # Get tenants
        log.info("Fetching tenant list...")
        tenants = client.list_tenants()
        log.info("Found %d tenants", len(tenants))

        # Apply filter if specified
        if tenant_filter:
            filtered = [
                t for t in tenants
                if tenant_filter.lower() in (t.get("displayName", "") or "").lower()
                or tenant_filter.lower() in (t.get("defaultDomainName", "") or "").lower()
            ]
            log.info("Filter '%s' matched %d of %d tenants", tenant_filter, len(filtered), len(tenants))
            tenants = filtered

        if not tenants:
            log.warning("No tenants to analyze!")
            return {"status": "no_tenants"}

        # Collect security data for each tenant
        summaries: list[TenantSecuritySummary] = []
        for tenant in tenants:
            name = tenant.get("displayName") or tenant.get("defaultDomainName", "Unknown")
            try:
                summary = collect_tenant_security(client, tenant)
                summaries.append(summary)
            except Exception as e:
                log.error("Failed to collect data for %s: %s", name, e)
                # Create a minimal summary with the error
                summaries.append(TenantSecuritySummary(
                    tenant_name=name,
                    tenant_id=tenant.get("customerId", ""),
                    default_domain=tenant.get("defaultDomainName", ""),
                    errors=[str(e)],
                ))

    # Generate reports
    log.info("Generating reports...")
    obsidian_md = generate_obsidian_report(summaries, run_time)
    email_subject, email_html = generate_email_html(summaries, run_time)
    notion_data = generate_notion_blocks(summaries, run_time)
    json_report = generate_json_report(summaries, run_time)

    if dry_run:
        log.info("Dry run — printing Obsidian report to stdout")
        print(obsidian_md)
        return {"status": "dry_run", "tenants": len(summaries)}

    # Deliver
    if obsidian_only:
        from delivery import deliver_to_obsidian
        path = deliver_to_obsidian(obsidian_md, run_time, vault_path)
        log.info("Report written to %s", path)
        return {"status": "ok", "obsidian": str(path)}

    results = deliver_all(
        obsidian_md=obsidian_md,
        email_subject=email_subject,
        email_html=email_html,
        notion_data=notion_data,
        json_report=json_report,
        run_time=run_time,
        vault_path=vault_path,
    )

    # Summary
    total_findings = sum(len(s.findings) for s in summaries)
    critical = sum(s.critical_count for s in summaries)
    high = sum(s.high_count for s in summaries)
    log.info("Report complete: %d tenants, %d findings (%d critical, %d high)",
             len(summaries), total_findings, critical, high)

    return {"status": "ok", "tenants": len(summaries), "findings": total_findings, "delivery": results}


def main():
    parser = argparse.ArgumentParser(description="CIPP Daily Security Posture Report")
    parser.add_argument("--tenant-filter", help="Filter tenants by name or domain")
    parser.add_argument("--dry-run", action="store_true", help="Collect and print, don't deliver")
    parser.add_argument("--obsidian-only", action="store_true", help="Only write Obsidian markdown")
    parser.add_argument("--vault-path", help="Override Obsidian vault path")
    parser.add_argument("--env", help="Path to .env file (default: ../cipp-local/.env)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")
    args = parser.parse_args()

    setup_logging(args.verbose)

    try:
        result = run(
            tenant_filter=args.tenant_filter,
            dry_run=args.dry_run,
            obsidian_only=args.obsidian_only,
            vault_path=args.vault_path,
            env_path=args.env,
        )
        log.info("Result: %s", result)
        return 0
    except CippError as e:
        log.error("CIPP error: %s", e)
        return 1
    except Exception as e:
        log.error("Unexpected error: %s", e, exc_info=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
