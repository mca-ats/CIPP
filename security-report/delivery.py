"""
Delivery integrations — send the report to Obsidian, email, and Notion.
"""

from __future__ import annotations

import json
import logging
import os
import smtplib
import ssl
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 1. Obsidian — write markdown to daily notes
# ---------------------------------------------------------------------------
def deliver_to_obsidian(
    markdown: str,
    run_time: datetime,
    vault_path: str | None = None,
) -> Path:
    """
    Write the security report to the Obsidian vault.
    Default location: ~/Developer/devdocs (Michael's vault)
    Falls back to the ats workspace if vault isn't found.
    """
    date_str = run_time.strftime("%Y-%m-%d")

    # Try the devdocs vault first, then ats workspace
    candidates = [
        Path(vault_path) if vault_path else None,
        Path.home() / "Developer" / "devdocs" / "Security Reports",
        Path.home() / "Developer" / "devdocs" / "CIPP",
    ]

    output_dir = None
    for candidate in candidates:
        if candidate and candidate.parent.exists():
            output_dir = candidate
            break

    if output_dir is None:
        # Fallback: write next to the script
        output_dir = Path(__file__).parent / "reports"

    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / f"security-report-{date_str}.md"
    output_file.write_text(markdown, encoding="utf-8")
    log.info("Obsidian report written to %s", output_file)
    return output_file


# ---------------------------------------------------------------------------
# 2. Email — send via SMTP
# ---------------------------------------------------------------------------
def deliver_via_email(
    subject: str,
    html_body: str,
    to_address: str | None = None,
    from_address: str | None = None,
    smtp_host: str | None = None,
    smtp_port: int | None = None,
    smtp_user: str | None = None,
    smtp_password: str | None = None,
) -> bool:
    """
    Send the HTML report via email.
    Reads SMTP config from environment variables if not provided:
        SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, SMTP_FROM, REPORT_EMAIL_TO
    """
    to_addr = to_address or os.environ.get("REPORT_EMAIL_TO", "michael@abatetechnology.com")
    from_addr = from_address or os.environ.get("SMTP_FROM", to_addr)
    host = smtp_host or os.environ.get("SMTP_HOST")
    port = smtp_port or int(os.environ.get("SMTP_PORT", "587"))
    user = smtp_user or os.environ.get("SMTP_USER")
    password = smtp_password or os.environ.get("SMTP_PASSWORD")

    if not host:
        log.warning("Email delivery skipped — SMTP_HOST not configured. "
                     "Set SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD in .env")
        return False

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = to_addr

    # Plain text fallback
    plain_text = f"Security Posture Report\n\nView the full HTML report in your email client.\n"
    msg.attach(MIMEText(plain_text, "plain"))
    msg.attach(MIMEText(html_body, "html"))

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(host, port) as server:
            server.ehlo()
            server.starttls(context=context)
            if user and password:
                server.login(user, password)
            server.sendmail(from_addr, [to_addr], msg.as_string())
        log.info("Email sent to %s", to_addr)
        return True
    except Exception as e:
        log.error("Email delivery failed: %s", e)
        return False


# ---------------------------------------------------------------------------
# 3. Notion — post via Notion MCP or API
# ---------------------------------------------------------------------------
def deliver_to_notion(
    notion_data: dict[str, Any],
    database_id: str | None = None,
) -> bool:
    """
    Prepare Notion delivery payload.
    When run via Cowork scheduled task, the Notion MCP connector handles the actual posting.
    This function writes a .notion-payload.json that the scheduled task script can pick up.
    """
    db_id = database_id or os.environ.get("NOTION_SECURITY_DB_ID")

    payload = {
        "title": notion_data["title"],
        "properties": notion_data["properties"],
        "content": notion_data["content"],
        "database_id": db_id,
    }

    # Write payload for the Cowork task to pick up
    payload_path = Path(__file__).parent / ".notion-payload.json"
    payload_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    log.info("Notion payload written to %s", payload_path)

    if not db_id:
        log.warning("Notion delivery pending — set NOTION_SECURITY_DB_ID to enable automatic posting")
        return False

    return True


# ---------------------------------------------------------------------------
# Orchestrator: deliver to all channels
# ---------------------------------------------------------------------------
def deliver_all(
    obsidian_md: str,
    email_subject: str,
    email_html: str,
    notion_data: dict[str, Any],
    json_report: str,
    run_time: datetime,
    vault_path: str | None = None,
) -> dict[str, Any]:
    """Deliver the report to all configured channels. Returns status dict."""
    results: dict[str, Any] = {}

    # Always save JSON archive
    archive_dir = Path(__file__).parent / "reports"
    archive_dir.mkdir(exist_ok=True)
    date_str = run_time.strftime("%Y-%m-%d")
    json_path = archive_dir / f"security-report-{date_str}.json"
    json_path.write_text(json_report, encoding="utf-8")
    results["json_archive"] = str(json_path)

    # Obsidian
    try:
        obs_path = deliver_to_obsidian(obsidian_md, run_time, vault_path)
        results["obsidian"] = {"status": "ok", "path": str(obs_path)}
    except Exception as e:
        results["obsidian"] = {"status": "error", "error": str(e)}
        log.error("Obsidian delivery failed: %s", e)

    # Email
    try:
        email_ok = deliver_via_email(email_subject, email_html)
        results["email"] = {"status": "ok" if email_ok else "skipped"}
    except Exception as e:
        results["email"] = {"status": "error", "error": str(e)}
        log.error("Email delivery failed: %s", e)

    # Notion
    try:
        notion_ok = deliver_to_notion(notion_data)
        results["notion"] = {"status": "ok" if notion_ok else "pending_config"}
    except Exception as e:
        results["notion"] = {"status": "error", "error": str(e)}
        log.error("Notion delivery failed: %s", e)

    return results
