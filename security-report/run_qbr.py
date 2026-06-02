#!/usr/bin/env python3
"""
ATS Client Health / QBR Report Generator
========================================
Single-tenant pipeline: CIPP collection -> Claude narrative -> branded PDF.

    python run_qbr.py --tenant abatetech.io
    python run_qbr.py --tenant abatetech.io --out /abs/path/reports

Writes <out>/<domain>/<YYYY-QN>.pdf. Uses the deterministic narrative fallback
when ANTHROPIC_API_KEY is unset (the AI narrative is a quality upgrade, not a
hard dependency).

Exit codes: 0 ok · 1 CIPP error · 2 unexpected · 3 report rendered but some data
was incomplete (degraded — a scheduler should quarantine rather than ship).
"""

from __future__ import annotations

import argparse
import logging
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cipp_client import CippClient, CippError
from kpi_collectors import collect_qbr_data, DEFAULT_HISTORY_PATH
from qbr_narrative import generate_narrative
from pdf_renderer import render_qbr_pdf

log = logging.getLogger("qbr")
DEFAULT_OUT_DIR = Path(__file__).resolve().parent / "reports" / "qbr"


def setup_logging(verbose: bool = False) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9.-]+", "-", s.lower()).strip("-") or "tenant"


def run(tenant_filter: str, out_dir: str | Path = DEFAULT_OUT_DIR,
        env_path: str | None = None,
        history_path: str | Path = DEFAULT_HISTORY_PATH) -> tuple[Path, list[str]]:
    """Returns (pdf_path, errors). A non-empty errors list means the report
    rendered but some data was incomplete (degraded run)."""
    run_time = datetime.now(timezone.utc)
    out_dir = Path(out_dir).resolve()   # absolute so scheduled (cwd=/) runs don't scatter
    client = CippClient.from_env(Path(env_path)) if env_path else CippClient.from_env()

    with client:
        log.info("Fetching tenant list...")
        tenants = client.list_tenants()
        matches = [
            t for t in tenants
            if tenant_filter.lower() in (t.get("displayName", "") or "").lower()
            or tenant_filter.lower() in (t.get("defaultDomainName", "") or "").lower()
        ]
        if not matches:
            raise CippError(f"No tenant matched '{tenant_filter}' (of {len(tenants)} tenants)")
        if len(matches) > 1:
            names = ", ".join(t.get("defaultDomainName", "?") for t in matches)
            raise CippError(f"'{tenant_filter}' matched {len(matches)} tenants ({names}); be more specific")

        tenant = matches[0]
        log.info("Collecting QBR data for %s...", tenant.get("displayName"))
        qbr = collect_qbr_data(client, tenant, run_time=run_time, history_path=history_path)

    log.info("Generating narrative (%d KPIs, %d findings)...",
             len(qbr.kpis), len(getattr(qbr.security, "findings", []) or []))
    narrative = generate_narrative(qbr)

    out_path = out_dir / _slug(qbr.default_domain or qbr.tenant_name) / f"{qbr.period}.pdf"
    log.info("Rendering branded PDF -> %s", out_path)
    render_qbr_pdf(qbr, narrative, out_path)
    log.info("Done: %s (%d bytes)", out_path, out_path.stat().st_size)
    if qbr.errors:
        log.error("DEGRADED RUN — %d data domain(s) incomplete: %s",
                  len(qbr.errors), "; ".join(qbr.errors))
    return out_path, qbr.errors


def main() -> int:
    parser = argparse.ArgumentParser(description="ATS Client Health / QBR Report Generator")
    parser.add_argument("--tenant", required=True, help="Tenant name or domain (e.g. abatetech.io)")
    parser.add_argument("--out", default=str(DEFAULT_OUT_DIR),
                        help="Output directory (absolute recommended for scheduled runs)")
    parser.add_argument("--env", help="Path to .env (default: co-located, then ../.env)")
    parser.add_argument("--history", default=str(DEFAULT_HISTORY_PATH), help="Secure Score history JSON path")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    setup_logging(args.verbose)
    try:
        path, errors = run(args.tenant, args.out, args.env, args.history)
        print(path)
        # Exit 3 = report rendered but incomplete, so a scheduler can quarantine it
        # rather than ship a degraded client report as if it were clean.
        return 3 if errors else 0
    except CippError as e:
        log.error("CIPP error: %s", e)
        return 1
    except Exception as e:
        log.error("Unexpected error: %s", e, exc_info=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
