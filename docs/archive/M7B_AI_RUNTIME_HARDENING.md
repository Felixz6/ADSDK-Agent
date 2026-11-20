# M7B AI Runtime Hardening — Phase A

## Scope and evidence

Phase A hardens the local AI planning path without contacting a model, device, ADB, Frida, or mitmproxy. The planner accepts constrained JSON, validates the schema/tool whitelist/DAG, makes one structured repair attempt at most, and records a deterministic fallback when validation fails.

The runtime diagnostic artifact records only stable codes, bounded JSON paths, booleans, strategy provenance, report provenance, token/round counters, and validation outcomes. It excludes prompts, model bodies, reasoning content, credentials, cookies, authorization values, and device serials.

## Implemented

- Canonical `PlanValidationIssue` model shared by validator and persisted diagnostics.
- Safe parser, schema/whitelist/DAG validation, one-repair contract, and deterministic plan fallback.
- Requested/effective strategy provenance plus normalization facts.
- Evidence-validator and report-source provenance.
- FullAnalysisSession now runs the read-only freshness comparison and runtime semantic validator on the execution path; fatal change results still flow through cleanup.
- TaskDetail and Reports diagnostics show plan source, validation error/path, repair/fallback, strategy normalization, report source, and evidence-validator status. Older tasks render missing values as `—`.

## Automated evidence

- `pip check`: passed.
- Focused M7B backend tests: 225 passed.
- Full backend suite: 699 passed (one upstream Starlette deprecation warning).
- Frontend typecheck and focused card tests: passed during Phase A recovery.

## Current limits

No real DeepSeek call, device, MuMu, ADB, Frida, mitmproxy, proxy mutation, or dynamic full-analysis run was performed in Phase A. Device acceptance belongs exclusively to the next read-only Phase B preflight.
