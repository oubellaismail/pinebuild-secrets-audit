# Secrets and CI audit

The fictional PineBuild team exported two small repository snapshots during a credential rotation. They want an audit that distinguishes dangerous use from harmless test/documentation markers and can be rerun after changes. Build an offline auditor and a short prioritized remediation queue.

## Inputs and setup

- [Audit policy and schema](inputs/policy.md).
- Snapshot one: [inventory](inputs/snapshot-one/inventory.json), [CI data](inputs/snapshot-one/ci.json), [app environment](inputs/snapshot-one/app/env.txt), [test fixture](inputs/snapshot-one/tests/mock.txt), [rotation note](inputs/snapshot-one/docs/rotation.txt), [build report](inputs/snapshot-one/build/report.txt).
- Snapshot two: [inventory](inputs/snapshot-two/inventory.json), [CI data](inputs/snapshot-two/ci.json), [app environment](inputs/snapshot-two/app/env.txt), [test fixture](inputs/snapshot-two/tests/mock.txt), [rotation note](inputs/snapshot-two/docs/rotation.txt), [build report](inputs/snapshot-two/build/report.txt).

These are **deliberately unsafe training configurations represented as data**, not executable CI workflows. Every token is a nonfunctional DEMO marker; even “active” means active only in the fictional inventory. No real credentials or services exist. Do not try tokens against any service. Baseline skills: inspect text/JSON, apply simple rules, write a small file-processing script. Python 3.10+ standard library is sufficient; no install or account required. From exported `candidate/` confirm `python3 --version`. JSON paths and token state are authoritative; do not look up actual CI provider behavior.

## Core work and acceptance

1. Build a reusable offline auditor that accepts a snapshot directory and outputs a machine-readable finding list plus a readable summary. Implement S1–S5 in policy, keeping CI references separate from token text matches. Scan only the supplied content paths; inventory is classification metadata, not leaked content.
2. Run unchanged rules on both snapshots. Include evidence for at least two benign decisions as well as risks. Each finding has rule ID, workflow ID or file path/line, redacted evidence, rationale and suggested next action. Do not print full DEMO values in your submission's audit output; redaction should preserve token_id for traceability.
3. Add at least four runnable checks: active text detection, test/revoked suppression, exact permission/trigger policy, and artifact wildcard expansion or secret/untrusted intersection. They must assert decisions, not only file existence. Record a validation/refinement.
4. Prioritize the top two remediation actions with realistic ordering, and explain the change between snapshots. Do not implement a real CI pipeline or rotate any real secret.

Acceptance: one documented command per snapshot produces reproducible results; another reviewer can audit new same-schema content without modifying source. Exact paths, line references and rule IDs make results actionable; the second snapshot exposes assumptions that “rotation fixed everything.” No external secret scanner required. Optional stretch: safely demonstrate a third synthetic mutation; not required for full marks.

## Submission, AI and timing

Submit an archive or repository containing runnable artifacts, source/evidence references, captured verification output and a concise walkthrough (up to five minutes recording **or equivalent accessible text**). Include exact commands and tool versions. Add a short decision/work log recording prioritization, one obstacle and response, one validation/refinement, limits and next step. Add an AI-use note with one accepted, corrected or rejected output and how you checked it; if no AI was used, say so. Never fabricate an AI failure.

No AI tool is provided: you may use any AI tool you already have. AI is allowed and encouraged for coding, drafting, research, automation and critique. Verify AI output. Tool choice is not graded; free/offline tools are supported, no purchases or personal account access are needed. Synthetic fixtures are the authoritative universe; outside research is optional and cannot affect marks.

Your 24 hours start when you click **Start** on the link in your invitation email; the exercise zip becomes available at that moment. Send your submission back within 24 hours of clicking Start. You are not expected to work for the full 24 hours: organize your own working time and breaks within the window. There are no surprise messages or overnight availability requirements, and hours worked are not scored. The clock tests bounded execution, follow-through and verification, not willingness to sacrifice sleep. Do only this assigned exercise. Full marks are possible on core alone: usable result **40**, accuracy/verification **25**, prioritization **20**, communication/handoff **15**. No AI-detector, writing-volume or prose-polish scoring. Work is an exercise submission, not a company deliverable: no external targets, outreach, production actions or public deployment.
