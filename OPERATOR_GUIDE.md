# GuardRail operator guide

GuardRail is for local, owned, or explicitly authorized chatbot assessment.
Do not use it to bypass CAPTCHA, rotate proxies, perform destructive actions,
or test third-party systems without written permission.

## Evidence workflow

1. Confirm authorization and run browser preflight when testing a website.
2. Treat capture, transport, model, or judge degradation as incomplete coverage.
3. Review pending findings using the exact typed evidence and provenance.
4. Reproduce high-impact hypotheses with inert markers before confirmation.
5. Record reviewer rationale; reject false positives instead of deleting them.
6. Apply authorization, permission, output-validation, secret-handling, and
   human-confirmation controls in addition to prompt hardening.

Persisted transcript excerpts are bounded and redact detected credentials, PII,
and email addresses. Evidence hashes preserve correlation without storing the
original secret value.

## Agentic learning controls

- Knowledge is isolated by `project_id` and active `run_id`.
- Hypotheses require compatible attack family or mechanism and target fingerprint.
- Heuristic, low-confidence, and capture-rejected discoveries are quarantined.
- Fan-out is capped by `hypothesis_fanout_limit` and never exceeds three
  dedicated confirmation lanes.
- Confirmation lanes use one turn and only consume remaining global run budget.
- Baseline attack coverage finishes before dedicated confirmation scheduling.

## Retention and deletion

Set project retention with `PATCH /projects/{id}` and apply it with
`POST /projects/{id}/retention/apply`. Deleting project data removes durable and
in-memory runs, hypotheses, findings, and reviews. The default `local` project
cannot be deleted, but its data can be cleared explicitly.

## Defensible comparisons

Use `GET /runs/compare` after mitigation and rerun. A comparison is defensible
only when `comparable` is true. Mismatched attack corpus, coverage profile,
capture method, project, or judge versions are returned as explicit reasons;
do not present such a delta as verified risk reduction.

Run `make calibrate-judge` before a release. The release gate requires at least
0.85 macro-F1 and 0.95 recall for confirmed critical golden cases.
