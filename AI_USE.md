# AI-use note

**Tool:** Claude Code (Claude Opus 5.5) in the Claude desktop app.

**How it was used:** explaining the policy rules and the CI schema; drafting `audit.py` step by step, with each step run and checked before the next; drafting the tests, the mutation check and these docs.

**How output was checked:**

- The expected findings for both snapshots were worked out by hand from the raw files before any code was written. Each step's output was compared against that.
- Every output file was grepped for `DEMO_` (0 matches).
- Reruns were compared byte for byte.
- The tests themselves were checked with a mutation check (below).

## My role: understanding and reviewing the code

I did not accept the code as a black box.

- **Before implementation**, I had the AI explain the policy rules S1–S5 and the risk behind each one using the snapshot examples, every field of `ci.json` with its risk and best practice, and what "untrusted code" means, until I understood the problem I was solving.
- **During implementation**, I chose to build step by step instead of in one go, so I could review and run each step (loading, S1, S2–S5, output, tests) before approving the next.
- **After implementation**, I went through the code line by line with the AI: the S1 functions (`is_sensitive`, `list_content_files`, `values_longest_first`, `redact`, `scan_text`) with their unit tests, and `main()`. I also asked what the mutation check does until it was clear that it only modifies temporary copies, never `audit.py`.
- **Finding problems**: I asked the AI to grade the finished work against the rubric. That request is what led to probing with new inputs, which found the `app/.env` gap, the blank-value bug and the fail-open boolean flags (examples below). I asked for each one to be fixed with tests.
- **Ongoing**: I am still reading the code to understand it fully and look for further problems.

## Example: AI output not accepted as-is

The AI-written test suite passed all 19 tests on its first run. A suite that has never failed could be asserting nothing useful, so the result was not accepted at face value. A mutation check ([tests/mutation_check.py](tests/mutation_check.py)) planted five specific bugs in copies of the auditor, and the tests failed on every one ([output/mutation_check.txt](output/mutation_check.txt)). Only then was the suite accepted.

## Example: AI-introduced gap found and fixed

The AI-written scanner skipped every file whose name starts with `.`, intended to avoid `.DS_Store`. When I asked the AI to grade the finished work, it probed it with new inputs and found that this also skipped `app/.env`, so an active token there gave 0 findings. It was fixed to skip only OS metadata files, and a regression test was added. The new test was checked by running it against the previous commit (fails) and the fixed code (passes).

## Example: AI claim that turned out wrong

The AI-written work log stated that strict boolean checks (`is True`) meant a malformed flag could not pass. That was only true for S3. After the first fixes, I asked for a new grade; probing with `"runs_untrusted_code": "true"` then showed S2 silently passing. The claim was corrected and input validation was added; the new tests were checked to fail on the previous commit and pass on the fix.

## Example: corrected output

The first summary format printed raw Python lists inside messages, for example `Remove ['release-active'] from 'pr-build'`. This was spotted while reviewing the run output and changed to plain text.
