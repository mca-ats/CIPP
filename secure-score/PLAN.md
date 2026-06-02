# Secure Score Remediation App — Implementation Plan

## Context

**Why now.** `~/.claude/memory/projects.md` records a deliberately-deferred project: *"Secure Score remediation = SEPARATE planned workflow. DO NOT start without Michael's explicit say-so (2026-05-30)."* This is that say-so. The QBR generator (`cipp-local/security-report/`) already **reads** every tenant's Secure Score and tracks per-tenant history; this project is its **write sibling** — it turns the gap into an ordered, justified remediation plan and (in later phases) applies the fixes via CIPP.

**The problem it solves.** Across ATS's tenants, raising Secure Score today means manually walking ~147 controls per tenant in the portal, deciding what's safe to change, and doing it by hand. This app automates the *analysis and planning* (v1) and later the *safe, staged execution* — turning a repeated manual chore into a reviewable, auditable, goal-driven workflow.

**The mandate (decided).** Score is the **measure** of posture, never the **target**. The app only does *genuine remediation* — actually changing tenant settings via CIPP's Standards engine. It will **never** game the number by marking controls `ignored`/`thirdParty`/`reviewed` (CIPP's `Invoke-CIPPStandardSecureScoreRemediation` / `ExecUpdateSecureScore`). For a client base holding DV, PHI, and CPA-financial data, a clean dashboard over an unchanged posture is a liability, not a win.

**Decisions locked (user-confirmed):**
1. **Genuine remediation only** — no score-gaming.
2. **Hybrid agentic** — an AI *planner* triages + justifies + sequences; a deterministic, unit-tested core does the math and (later) executes; an AI *verifier* confirms results (later phase). Humans approve between plan and execute.
3. **v1 = report + plan only** — computes the plan, writes the artifact, changes **nothing** in any tenant. Graduate to apply later, mirroring the QBR's lab→partner→client staged discipline.
4. **Location** — a new package **inside `cipp-local/`, beside `security-report/`**, reusing its read primitives via shared import. Write path isolated in its own package so a report run can never trigger a change.

---

## Architecture

### Package home & name
`/Users/mca/Developer/ats/cipp-local/secure-score/` (sibling of `security-report/`). Name mirrors the user's intent and parallels `security-report` (read) ↔ `secure-score` (write/remediate). *(The empty `~/Developer/ats/secure-score` dir created earlier is orphaned by decision #4 — remove it or leave it; the real work lives in `cipp-local`.)*

### File tree (modules deliberately small + single-purpose for the agent-team build)
```
cipp-local/
├── security-report/                 # EXISTING — unchanged; imported FROM
└── secure-score/
    ├── README.md
    ├── requirements.txt              # httpx, pydantic, anthropic, pytest (no weasyprint in v1)
    ├── .env.example                  # same vars; points at ../.env like the sibling
    ├── standards.json                # PINNED copy of CIPP-API/Config/standards.json (149 entries)
    ├── tenants.yaml                  # tenant tier registry: lab / partner / client
    │
    ├── score_source.py               # data in: reuse CippClient + collect_secure_score;
    │                                  #   add secureScoreControlProfiles fetch; → list[ControlGap]
    ├── catalog.py                     # control→Standard mapping, risk tier, gain, rationale (THE BRAIN)
    ├── plan_models.py                # ControlGap, RemediationItem, RemediationPlan (+ Pydantic AI I/O)
    ├── prioritize.py                 # PURE deterministic core: build candidates + order (3 bands)
    ├── planner.py                    # AI layer (Claude structured output) + deterministic fallback
    ├── plan_writer.py                # plan.json (source of truth) + path resolution
    ├── plan_markdown.py              # human-readable Markdown rendering
    ├── audit.py                      # append-only remediation_log.jsonl (hash-chained)
    ├── run_remediation.py            # CLI — structural clone of run_qbr.py
    └── tests/
        ├── conftest.py               # sys.path bootstrap for THIS pkg + ../security-report
        ├── fixtures/secure_scores.json
        ├── stubs.py                  # StubCippClient, StubCatalog, StubAnthropic
        └── test_*.py                 # one per module (see Testing)
```

### Cross-package reuse strategy — `sys.path` insert (not a refactor)
The codebase already uses flat top-level imports + `sys.path.insert` (`run_qbr.py:27`, `tests/conftest.py`). Mirror it: both `run_remediation.py` and `tests/conftest.py` insert the sibling `security-report/` dir on `sys.path`, then `from cipp_client import CippClient` etc. **Reused, never duplicated:** `CippClient`/`CippError`/`from_env`/`.get`/`.list_tenants` (`cipp_client.py`); `collect_secure_score`, `Finding`, `Severity` (`collectors.py`); the break-glass/Global-Admin detection in `collectors.py` (~lines 345-360); `quarter_label` (`qbr_models.py`). **Defer** extracting a shared `cippcommon` package until the apply phase justifies touching the QBR's ~148 tests.

### The control catalog (`catalog.py`) — the load-bearing piece
A version-controlled module of frozen dataclasses, **validated at import + in CI**. Each entry maps ONE Secure Score control to: `control_id`, `coverage` (standard / multi / manual_only / defender_only / unmapped), `standard_names` (tuple — real controls like "block legacy auth" need `DisableBasicAuthSMTP` *plus* a CA template), `action_type`, `standard_params`, `risk_tier` (safe / low / disruptive / high_blast), `prerequisites` (free-text gates, e.g. "break-glass account excluded"), `depends_on` (control IDs → topological sort), `requires_license`, `rationale`, `caveats`, `verify_hint`, `last_reviewed`, `catalog_status`.

- **Join to `standards.json`, don't re-parse PowerShell.** The pinned 149-entry catalog supplies each standard's `impact`, `tag` (CIS/NIST IDs), `addedComponent` (params), `executiveText`. Verified present with exactly these keys.
- **Hard rules enforced by `tests/test_catalog.py`:** every `standard_name` resolves in the pinned `standards.json`; no entry ever maps to `SecureScoreRemediation` (the forbidden score-gaming standard — assert explicitly); `requires_license` matches the standard's capability check; `depends_on` forms a DAG; enums valid. This catches the "standard became a stub" failure class (e.g. `SSPR` is now a dead stub in CIP­P).
- **v1 scope ≈ 25 high-value, cleanly-mappable controls** (Identity: block legacy auth, MFA all-users, MFA admins, admin-consent-for-apps, app-consent-request-workflow, Security Defaults [no-CA tenants], auth-methods migration, banned-password list; Apps/MDO: Unified Audit Log, mailbox auditing, Safe Links, Safe Attachments, anti-phishing, Safe Docs, spam/malware filter, block auto-forwarding, outbound-spam alert; Data/SP: external-sharing capability, disable SP legacy auth, block infected download; Governance: Customer Lockbox).
- **The long tail is never silently dropped.** `scid_*` → `defender_only` (auto-detected by prefix; surfaced as a manual Defender-portal task with the profile `actionUrl`). Real-but-unmapped → `manual`/`unmapped` with a loud "NEEDS MANUAL REVIEW" banner and logged for the next catalog review. The plan reports an explicit **automatable-coverage %** (`mapped / total-gap-controls`) so coverage is honest.
- **Maintenance:** quarterly drift report diffing live `standards.json` and live `secureScoreControlProfiles` against the catalog → triage list; `last_reviewed`/`catalog_status` discipline; a disappeared standard degrades its entries to `manual` rather than emitting a broken remediation.

### Data models (`plan_models.py`)
Two layers (matching the module's split): stdlib dataclasses for internal flow, Pydantic at the AI boundary.
- `ControlGap` — derived from `collect_secure_score`'s `Finding.details` (the raw control dict): `control_name`, `description`, `current`, `max_score`, `raw`; `.gap` property.
- `RemediationItem` — `control_name`, `mapped_standard`, `risk_tier`, `projected_gain` (clamped ≤ gap), `current`, `max_score`, `rationale`, `status` (planned/needs_review/blocked/manual), `judgment_call`, `catalog_notes`; plus apply-time intent fields (`mechanism`, `mode`, `ca_state`, `preconditions`, `rollback`) **emitted in v1 even though unused**, so the apply phase consumes the artifact rather than re-deriving it.
- `RemediationPlan` — tenant meta, `period` (`quarter_label`), `current_score`/`max_score`/`target_score`, ordered `items`, `exec_summary`, `errors`; properties `current_pct` (mirrors `TenantSecuritySummary.score_pct` so both apps show identical numbers), `total_projected_gain`, `projected_score`.

### Prioritization (`prioritize.py`, pure + heavily tested)
`projected_gain = maxScore − currentScore` (handle the `scoreInPercentage`-only case). Multiplicative priority so one bad factor can't be out-voted: `recoverable × risk_weight × effort_weight × coverage_weight × license_ok × prereqs_met`. **Render in three ordered bands**, not one flat list (pure score-sort would wrongly surface high-blast MFA first):
- **Band A — Quick wins:** safe/low + standard-mapped + license OK.
- **Band B — Scheduled change:** disruptive / high_blast, each carrying its prerequisites checklist + a forced "report-only first" note.
- **Band C — Manual / blocked:** manual_only, defender_only, unmapped, license-blocked — with `actionUrl` + remediation text, no false automation promise.
Ordering is deterministic + stable (tie-break: effort, then `depends_on` topo order). The AI never reorders or invents numbers.

### The planner (`planner.py`) — clone of `qbr_narrative.py`
Deterministic core builds + orders candidates; AI is a quality layer that writes per-item rationale + an exec narrative and flags judgment calls; deterministic fallback when no `ANTHROPIC_API_KEY`. Mirror the verified call shape: `client.messages.parse(model="claude-opus-4-8", thinking={"type":"adaptive"}, system=[{…cache_control: ephemeral}], output_format=PlanReview)` → `resp.parsed_output`, wrapped in try/except → `fallback_plan`. AI output contract:
```python
class ItemReview(BaseModel):
    control_name: str   # echo, to match back to the deterministic candidate
    rationale: str
    judgment_call: bool
class PlanReview(BaseModel):
    exec_summary: str
    item_reviews: list[ItemReview]
```
The AI **annotates** the deterministic list (matched by `control_name`); unmatched items keep fallback rationale; ordering + gain math stay verifiable.

### Safety architecture (designed in v1, enforced when apply lands)
- **Blast-radius taxonomy** seeded from standards' `impact` (CIPP: 93 Low / 50 Medium / 22 High). Two danger classes get hard gates: **identity/lockout** (MFA via CA, Security Defaults, auth-method removal) and **protocol/integration breakage** (block legacy/basic auth, mail-flow, admin-surface). Each names mandatory preconditions: proven **break-glass exclusion** (reuse `collectors.py` GA detection — if unconfirmed, item is *blocked*, not warned), **report-only CA first** (`enabledForReportingButNotEnforced` is a first-class state in CIPP's `New-CIPPCAPolicy`), exclusion groups, a recorded comms window, and a **live-usage probe** (legacy-auth sign-ins / per-mailbox SMTP-auth must be zero before blocking).
- **Lifecycle state machine** (per control per tenant): `PLANNED → APPROVED → PRE_CHECK → APPLIED_REPORT → APPLIED_ENFORCE → VERIFIED` (with `FAILED → ROLLED_BACK`). **v1 builds up to PLANNED + the artifact.** Each transition maps to a concrete CIPP mechanism: PRE_CHECK/drift = `Invoke-ListStandardsCompare` reading the `CippStandardsReports` table (`CurrentValue`/`ExpectedValue`); apply = `Invoke-ExecStandardsRun` in `remediate` mode; CA report-only soak = `New-CIPPCAPolicy` state; verify = re-fetch `security/secureScores` + drift re-read + a **health check** (sign-in failure spike on error codes 50076/50079/53003; break-glass reachable; no newly-blocked *live* legacy auth).
- **Approval gate = `plan.json`** the human edits/signs; `plan_hash` (sha256 over item content) makes it tamper-evident — the apply phase refuses if the hash no longer matches.
- **Idempotency** in depth: CIPP standards already short-circuit when `StateIsCorrect`; our engine re-runs report mode immediately before apply (drops vanished-drift items); an applied-ledger keyed by deterministic `item_id` (`tenant_domain::standard`) prevents double-apply.
- **Audit (`audit.py`)** — ATS-owned, independent of CIPP's `CippLogs`: append-only `remediation_log.jsonl`, hash-chained (`prev_hash`), recording proposed/approved/applied/verified/rolled-back events with before/after scores, actor, preconditions evidence, and a `cipp_log_correlation` stub to join CIPP's row. Reuse `score_trend.py`'s defensive-JSON ethos; reuse `score_history.json` for the before/after series.
- **Rollout guardrails as code** (`tenants.yaml` + checks): tier registry (lab=abatetech.io,novumdives.com / partner=abatetechnology.com / client=…); enforce-mode refused against `client` tier without an explicit flag + dual approval; promotion-order check (no enforce at tier N until a VERIFIED debrief exists at tier N−1); hard cap on changes/run; mandatory dry-run before first enforce; global kill switch (**ON for v1** — every run is plan-only regardless).

### Artifacts & CLI
- **Outputs:** `plan.json` (source of truth, consumed by the apply phase) + `plan.md` (human view). **PDF deferred** — v1 is internal-facing for Michael; Markdown diffs cleanly run-over-run and avoids the WeasyPrint/pango dependency. Renderer is a swappable module so a branded `plan_pdf.py` (reusing `pdf_renderer`'s ATS tokens) is a one-file add when this goes client-facing. Path mirrors the QBR: `secure-score/reports/remediation/<slug-domain>/<YYYY-QN>/plan.{json,md}` (under gitignored `reports/`).
- **CLI (`run_remediation.py`)** — clone `run_qbr.py`: `python run_remediation.py --tenant <domain> [--target 80] [--max-risk safe|low|disruptive|high_blast] [--format json|md|both] [--out …] [--env …] [--verbose]`. Tenant resolution = `list_tenants()` + substring match with the **multi-match error** from `run_qbr.run`. Exit codes 0 (clean) / 1 (CippError) / 2 (unexpected) / 3 (degraded — wrote plan but some controls unmapped or score unavailable). Factor the body into `run_one(resolved_tenant, …)` so v2 multi-tenant fan-out (`--all`/`--tenant-glob`) needs no signature change. **`--target` + `--max-risk` are the "set goals" knobs** the planner works toward within the risk ceiling.

---

## "Agent teams and workflows" — both senses, explicitly

**Runtime (the app's own agents).** The hybrid model *is* a small agent team working toward a set goal (target score, capped at a risk tier): the **Planner agent** (Claude structured output) triages/justifies/sequences in v1; the **Verifier agent** confirms control movement + tenant health in the apply phase. Deterministic core sits between them as the safe executor.

**Dev-time (how we build it).** Reuse the existing build patterns: `.qbr_build_kpi_workflow.js` (Workflow `meta`+phases, TDD mandate, one module+test per parallel agent, file-scoped to avoid collisions) to build the modules, and `.qbr_review_workflow.js` (independent adversarial reviewers returning structured JSON — data-correctness / code-bugs / safety) to review before merge. The `.claude/skills/*/SKILL.md` playbooks (msp-dash) are the convention for any reusable sub-pattern. Because v1 writes nothing to tenants, the build + tests are fully safe to run.

---

## Phase roadmap

- **Phase 0 — Scaffolding & reuse seam.** Package skeleton, `sys.path` bootstrap, pinned `standards.json`, `.env.example`, `score_source.py` reusing `collect_secure_score` + adding the `secureScoreControlProfiles` fetch. Tests green against the lab `secure_scores.json` fixture.
- **Phase 1 — v1 deliverable (report+plan).** `catalog.py` (≈25 controls + validation test), `plan_models.py`, `prioritize.py` (3-band ordering), `planner.py` (AI + fallback), `audit.py` (PROPOSED record), `plan_writer.py`/`plan_markdown.py`, `run_remediation.py`. Run against lab tenants → debrief.
- **Phase 2 — Apply (gated).** Wire APPROVED→APPLIED_ENFORCE via `Invoke-ExecStandardsRun`, CA report-only soak, plan-hash verification, idempotency ledger. Safe controls only; lab tier; kill switch flips per-control.
- **Phase 3 — Verify + rollback + fan-out.** Verifier agent (drift re-read + score + health check), rollback execution, multi-tenant `--all`, promotion-order enforcement, partner→client graduation.

*Out of scope (permanently): marking controls `ignored`/`thirdParty`/`reviewed` to move the number. Defender `scid_*` controls remain manual.*

---

## Verification (how to test v1 end-to-end)

1. **Unit tests (primary gate):** `cd cipp-local/secure-score && python -m pytest`. Heaviest coverage on the pure surface — `test_catalog` (every standard resolves; none maps to `SecureScoreRemediation`; DAG valid), `test_prioritize` (band ordering stable; `--max-risk` filtering; gain clamped to gap; unmapped→manual), `test_plan_models` (score math; plan.json round-trip), `test_planner` (fallback fills every item; `StubAnthropic` grafts prose by `control_name`; any AI exception falls back), `test_score_source` (parses both `Results`-dict and bare-list shapes), `test_plan_writer`/`test_plan_markdown`, `test_audit` (hash chain). Target ≥90% on the deterministic modules; live Claude branch not unit-tested (matches `security-report` stance). All offline via stubs — **no live CIPP/tenant calls**.
2. **Live read against a lab tenant (safe — no writes):** `python run_remediation.py --tenant abatetech.io --max-risk safe --format both`. Confirm: `plan.json` + `plan.md` written under `reports/remediation/abatetech.io/<period>/`; the Secure Score numbers match the latest QBR run for the same tenant; Band A/B/C populated; automatable-coverage % shown; every gap control present (none silently dropped); a PROPOSED record appended to `remediation_log.jsonl`. Repeat for `novumdives.com`.
3. **AI vs fallback parity:** run once with `ANTHROPIC_API_KEY` unset (deterministic narrative) and once set (Claude narrative); confirm identical item set + ordering + gain math, only prose differs.
4. **Negative/degraded path:** point at a tenant filter matching 2+ tenants → exit 1 with the multi-match error; inject an unmapped control via fixture → exit 3 + "NEEDS MANUAL REVIEW" in the plan.
5. **Debrief gate:** review the lab plans with Michael before building Phase 2 (mirrors the QBR's lab→partner→client discipline).

---

## Critical files

**Reuse (import, do not modify):**
- `cipp-local/security-report/cipp_client.py` — `CippClient.from_env/.get/.list_tenants`
- `cipp-local/security-report/collectors.py` — `collect_secure_score` (the seam, lines 79-125), `Finding`, `Severity`, break-glass/GA detection (~345-360)
- `cipp-local/security-report/qbr_narrative.py` — Claude `messages.parse(output_format=…)` + fallback pattern (lines 238-272)
- `cipp-local/security-report/run_qbr.py` — CLI/tenant-resolution/exit-code/slug pattern
- `cipp-local/security-report/kpi/score_trend.py` — defensive-JSON persistence to mirror for audit
- `CIPP-API/Config/standards.json` — pin a copy as the catalog join target (149 entries, verified)

**Create (the new package):** `secure-score/score_source.py`, `catalog.py`, `plan_models.py`, `prioritize.py`, `planner.py`, `plan_writer.py`, `plan_markdown.py`, `audit.py`, `run_remediation.py`, `standards.json`, `tenants.yaml`, `tests/*`.
