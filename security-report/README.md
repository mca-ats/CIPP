# CIPP Client Health / QBR Report Generator

Turns a Microsoft 365 tenant's [CIPP](https://cipp.app) data into a branded, client-ready
Quarterly Business Review PDF: **CIPP API → KPIs → narrative → branded PDF**.

```
CIPP API ─► collectors + KPI transforms ─► QbrData ─► narrative ─► branded PDF
```

Each report covers Secure Score (with quarter-over-quarter trend), license utilization & waste,
device compliance, MFA/identity hygiene, a **paid-seat roster with offboarding flags**, a device
inventory, and a security-findings appendix where every finding lists the mailboxes/users behind it.

## Quick start

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# macOS only, once (WeasyPrint native dep):  brew install pango

cp .env.example .env        # then fill in your CIPP API credentials
python run_qbr.py --tenant <domain-or-name>
# -> reports/qbr/<domain>/<YYYY-QN>.pdf
```

## Configuration

All credentials come from `.env` (gitignored) — see `.env.example`. The CLI reads nothing
interactively, so it is safe to run unattended/scheduled.

## Narrative backends

- **AI** (default when `ANTHROPIC_API_KEY` is set): Claude writes the narrative as structured JSON
  in the ATS brand voice.
- **Deterministic fallback** (no key): a rules engine produces the same report shape. The pipeline
  always yields a complete report either way.

## Layout

```
run_qbr.py            CLI entrypoint
cipp_client.py        CIPP OAuth client (retry + long timeout)
collectors.py         security sweep (findings + Secure Score) + shared model
kpi_collectors.py     aggregator (live fetch + assembly -> QbrData)
qbr_models.py         shared dataclasses (KpiMetric, DeviceRecord, LicensedUser, QbrData, …)
qbr_narrative.py      dual-backend narrative
pdf_renderer.py       HTML/CSS -> PDF (WeasyPrint, ATS identity)
kpi/                  pure KPI transforms (licenses, compliance, identity, devices,
                      licensed_users, signin_activity, score_trend)
tests/                pytest suite (TDD)
```

## Testing

```bash
pytest -q        # 150+ tests
```

## Security

- Secrets only via `.env` (gitignored); no hardcoded credentials.
- Generated `reports/` (client PII) and `*.xlsx` are gitignored — never committed.
- `signInActivity` (for the 30-day inactive roster) requires AAD P1 + the audit-log permission on
  the CIPP app registration.

Full architecture + design notes: see the dev-docs note *CIPP Client Health / QBR Report Generator*.
