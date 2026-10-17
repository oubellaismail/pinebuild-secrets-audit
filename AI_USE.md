# AI-use note

**Tool:** Claude Code (Claude Opus 5.5) in the Claude desktop app.

**How it was used:** explaining the policy rules and the CI schema; drafting `audit.py` step by step, with each step run and checked before the next; drafting the tests, the mutation check and these docs.

**How output was checked:**

- The expected findings for both snapshots were worked out by hand from the raw files before any code was written. Each step's output was compared against that.
- Every output file was grepped for `DEMO_` (0 matches).
- Reruns were compared byte for byte.
- The tests themselves were checked with a mutation check (below).

## Example: AI output not accepted as-is

The AI-written test suite passed all 19 tests on its first run. A suite that has never failed could be asserting nothing useful, so the result was not accepted at face value. A mutation check ([tests/mutation_check.py](tests/mutation_check.py)) planted five specific bugs in copies of the auditor, and the tests failed on every one ([output/mutation_check.txt](output/mutation_check.txt)). Only then was the suite accepted.

## Example: AI-introduced gap found and fixed

The AI-written scanner skipped every file whose name starts with `.`, intended to avoid `.DS_Store`. When asked to grade the finished work, the AI probed it with new inputs and found that this also skipped `app/.env`, so an active token there gave 0 findings. It was fixed to skip only OS metadata files, and a regression test was added. The new test was checked by running it against the previous commit (fails) and the fixed code (passes).

## Example: corrected output

The first summary format printed raw Python lists inside messages, for example `Remove ['release-active'] from 'pr-build'`. This was spotted while reviewing the run output and changed to plain text.
