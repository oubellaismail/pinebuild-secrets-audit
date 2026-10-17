# Decision and work log

Dates: 2026-10-16 to 2026-10-17.

## Order of work

0. Before any code, made sure I understood the problem: had the AI explain each rule S1–S5 with the risks shown in the snapshots, each `ci.json` field (meaning, risk, best practice), and what "untrusted code" means. Chose to build step by step so I could review each step before the next.
1. Read the README, the policy and both snapshots. Worked out the expected findings by hand before writing code, so there was an independent answer to check the auditor against.
2. Built `audit.py` incrementally: loading → S1 text scan → S2–S5 CI checks → JSON and summary output. Ran both snapshots after each step and compared with the hand results.
3. Wrote decision tests, then a mutation check to prove the tests can fail.
4. Wrote the remediation queue and docs from the captured output.
5. Reviewed the implementation: walked through the S1 functions and their tests, and `main()`, line by line, and confirmed how the mutation check works (temporary copies only).
6. Asked the AI to grade the work against the rubric. The probing this triggered found real problems (dotfiles skipped, blank token values, string flags passing S2/S4, tracebacks on broken JSON), each fixed with tests in its own commit. Review of the code is ongoing.

## Key decisions

- **Unknown token states are treated as sensitive.** The policy names three states. Only `revoked_in_fixture` and `test_only` are explicitly harmless, so any other state fails closed rather than silently passing.
- **Schema validation before any rule.** Malformed input (invalid JSON, non-boolean flags, unknown `trigger`/`permissions`, missing fields, duplicate ids) stops the audit with every problem listed and exit code 2. A partial audit of broken input could look clean when it is not.
- **Defensive rule code stays fail-closed.** Even after validation, S3 only passes `read-only` and the exact `release-write` exception, and flags are compared with `is True` / `is False`.
- **Dotfiles are scanned.** Only OS metadata (`.DS_Store`, `Thumbs.db`) is skipped; `app/.env`-style files are exactly where real secrets end up.
- **Blank inventory values are not matched** (an empty string is "in" every line) and are reported as inventory warnings instead.
- **Next actions say rotate first, then clean up**, because deleting a leaked value does not un-expose it.
- **Unknown `secret_refs` are reported separately** as unresolved configuration evidence and never count as active, as the policy requires.
- **S5 matches only supplied files.** Patterns are expanded against the files actually present, using `fnmatchcase` so results do not depend on the OS's case rules. S5 does not depend on token state.
- **Benign decisions are first-class output**, with the same evidence fields as findings, so a reviewer can see what was suppressed and why.
- **Sensitive paths are a CLI option** with the policy's paths as the default, so new same-schema content can be audited without editing the source.

## Prioritization

Capacity is one immediate workflow change and one scheduled repo cleanup. For snapshot two, the highest risk is the live `release-rotated` value in `docs/rotation.txt:2` (rotate first, then the cleanup lane removes the copy), and the second is `pr-build`'s `app/*` artifact pattern (workflow lane, done now because it is a one-line change). Full reasoning: [REMEDIATION.md](REMEDIATION.md).

## Obstacle and response

The first version of the mutation check was a shell loop that cleaned up with `rm -rf $SP/$1`. The Claude Code safety check refused to run it, because if a variable were empty the path could expand to `/`. Response: rewrote it as [tests/mutation_check.py](tests/mutation_check.py), which uses `tempfile.TemporaryDirectory()`. Each copy is created and removed automatically, so no `rm` is needed at all.

## Validation and refinement

- **Validation (mutation check).** All tests passed on their first run, which on its own does not prove they test anything. The mutation check plants bugs, one at a time, in temp copies of `audit.py`: S3 ignoring `runs_untrusted_code`, S1 flagging every state, S5 without wildcards, S2 counting revoked refs, redaction disabled, and (added later) CI schema validation skipped. All six are caught ([output/mutation_check.txt](output/mutation_check.txt)).
- **Validation (hand results).** The auditor output for both snapshots matches the findings worked out by hand from the raw files before coding.
- **Validation (redaction and reproducibility).** `grep -c DEMO_` over every output file returns 0. Two consecutive runs produce byte-identical JSON.
- **Refinement.** The first summary printed Python list syntax in messages (`Remove ['release-active'] from ...`). Changed to plain comma-joined text.
- **Refinement (self-review, 2026-10-17).** Probing the finished auditor with inputs the tests never used found two gaps: an active token in `app/.env` produced **0 findings** (the scanner skipped every dotfile, not just `.DS_Store`), and a blank inventory value matched every line with garbled evidence. Both were fixed, and the rotation advice was reordered to rotate first. Four new tests cover this; all four **fail on the previous commit and pass now**. Suite: 23 tests, mutation check still 5/5 caught.
- **Refinement (code quality, second pass, 2026-10-17).** Fixed the remaining issues from a code review: (1) the output safety net raised a bare `RuntimeError` (traceback, exit 1, which the docs reserve for findings); it now prints a clear error, writes nothing and exits 2, covered by a new test that fails on the previous commit; (2) unresolved refs, inventory warnings and the report are now typed dataclasses like the findings; (3) the single `Record` with optional fields became `TextRecord` and `CiRecord`, so a text record cannot be built without a path and line; (4) S1 sorts token values once per scan instead of once per match. Same proof as before: all outputs byte-identical to the baseline, 30 tests pass on Python 3.14 and 3.12, mutation check 6/6.
- **Refinement (code quality, 2026-10-17).** Behaviour-preserving refactor after a code review: section headers; removed the unused `ACTIVE_STATE` constant; `trigger`/`permissions` values come from named constants instead of repeated strings; findings are a typed `Record` dataclass instead of hand-built dicts; type hints made specific; each workflow's refs resolved once; the output safety net uses the already-loaded inventory instead of re-reading it; explanation text moved into per-rule record builders so each check is only its logic; consistent field access after validation. Proof that behaviour did not change: before/after byte comparison of both supplied reports (JSON, summary, stdout) and of two edge-case snapshots (schema errors, warnings, unresolved refs, all rules, exit codes), all identical; 29 tests pass on Python 3.14 and 3.12; mutation check 6/6.
- **Refinement (input validation, 2026-10-17).** A second probe found that `"runs_untrusted_code": "true"` (a string) with an active secret produced **no S2**: `is True` made S3 fail closed but let S2/S4 fail open, contradicting this log's earlier "strict booleans" claim. Broken JSON also crashed with a traceback and exit 1, which the docs reserve for "findings exist". Added schema validation with clear errors and exit 2. Six new tests; all six **fail on the previous commit and pass now**. Suite: 29 tests, mutation check 6/6 caught.
- **Refinement.** Added `assert_no_token_values`, a final check that refuses to write any output containing a full inventory value, as a safety net beyond per-line redaction.

## Limits

- Detection is **exact string matching** against inventory values. A token that is split across lines, encoded (base64, URL-encoded) or partially pasted is not detected, and a secret that is not in the inventory cannot be found.
- Files are read as UTF-8 text with replacement for undecodable bytes. Binary files are not handled specially.
- OS metadata files (`.DS_Store`, `Thumbs.db`) are skipped; every other file, including dotfiles, is scanned.
- `fnmatch` `*` also matches `/`, so `app/*` matches nested files. That matches the policy's "whole relative-path matching", but it is broader than shell globbing.
- The CI model is the simplified assessment schema. No real provider behavior is modelled, and git history is not inspected.

## Next step

Add a third synthetic snapshot (the optional stretch), for example one with an unknown `secret_ref`, a nested `app/config/env.txt` and a non-default sensitive path, to demonstrate auditing new content end to end with no source changes.
