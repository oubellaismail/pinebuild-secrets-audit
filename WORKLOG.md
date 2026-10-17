# Decision and work log

Date: 2026-10-16.

## Order of work

1. Read the README, the policy and both snapshots. Worked out the expected findings by hand before writing code, so there was an independent answer to check the auditor against.
2. Built `audit.py` incrementally: loading → S1 text scan → S2–S5 CI checks → JSON and summary output. Ran both snapshots after each step and compared with the hand results.
3. Wrote decision tests, then a mutation check to prove the tests can fail.
4. Wrote the remediation queue and docs from the captured output.

## Key decisions

- **Unknown token states are treated as sensitive.** The policy names three states. Only `revoked_in_fixture` and `test_only` are explicitly harmless, so any other state fails closed rather than silently passing.
- **Strict booleans.** Flags are checked with `is True` / `is False`, so a malformed value such as `"yes"` cannot satisfy the S3 `release-write` exception.
- **Unknown permissions fail S3.** Only `read-only` and the defined `release-write` exception pass.
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

- **Validation (mutation check).** All tests passed on their first run, which on its own does not prove they test anything. The mutation check plants five bugs, one at a time, in temp copies of `audit.py`: S3 ignoring `runs_untrusted_code`, S1 flagging every state, S5 without wildcards, S2 counting revoked refs, redaction disabled. All five were caught ([output/mutation_check.txt](output/mutation_check.txt)).
- **Validation (hand results).** The auditor output for both snapshots matches the findings worked out by hand from the raw files before coding.
- **Validation (redaction and reproducibility).** `grep -c DEMO_` over every output file returns 0. Two consecutive runs produce byte-identical JSON.
- **Refinement.** The first summary printed Python list syntax in messages (`Remove ['release-active'] from ...`). Changed to plain comma-joined text.
- **Refinement (self-review, 2026-10-17).** Probing the finished auditor with inputs the tests never used found two gaps: an active token in `app/.env` produced **0 findings** (the scanner skipped every dotfile, not just `.DS_Store`), and a blank inventory value matched every line with garbled evidence. Both were fixed, and the rotation advice was reordered to rotate first. Four new tests cover this; all four **fail on the previous commit and pass now**. Suite: 23 tests, mutation check still 5/5 caught.
- **Refinement.** Added `assert_no_token_values`, a final check that refuses to write any output containing a full inventory value, as a safety net beyond per-line redaction.

## Limits

- Detection is **exact string matching** against inventory values. A token that is split across lines, encoded (base64, URL-encoded) or partially pasted is not detected, and a secret that is not in the inventory cannot be found.
- Files are read as UTF-8 text with replacement for undecodable bytes. Binary files are not handled specially.
- OS metadata files (`.DS_Store`, `Thumbs.db`) are skipped; every other file, including dotfiles, is scanned.
- `fnmatch` `*` also matches `/`, so `app/*` matches nested files. That matches the policy's "whole relative-path matching", but it is broader than shell globbing.
- The CI model is the simplified assessment schema. No real provider behavior is modelled, and git history is not inspected.

## Next step

Add a third synthetic snapshot (the optional stretch), for example one with an unknown `secret_ref`, a nested `app/config/env.txt` and a non-default sensitive path, to demonstrate auditing new content end to end with no source changes.
