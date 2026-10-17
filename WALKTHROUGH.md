# Walkthrough: PineBuild secrets and CI auditor

Text walkthrough (in place of a recording), about five minutes to read.

## 1. What it is

`audit.py` is an offline auditor. It reads one snapshot directory and applies the policy rules S1–S5 from [inputs/policy.md](inputs/policy.md). It writes:

- a **machine-readable JSON report** (findings, benign decisions, unresolved refs, inventory warnings), and
- a **readable summary** on stdout and optionally to a file.

It uses the Python standard library only. It never contacts a network and never prints a full token value: evidence shows `[REDACTED:<token_id>]`.

## 2. Tool versions used

- Python 3.14.6 (any Python 3.10+ should work; only standard library modules are used)
- macOS 26.5.2
- No packages to install, no accounts.

```bash
python3 --version
```

## 3. Commands (run from `candidate/`)

One command per snapshot:

```bash
python3 audit.py inputs/snapshot-one --json output/snapshot-one.json --summary output/snapshot-one.txt
```
```bash
python3 audit.py inputs/snapshot-two --json output/snapshot-two.json --summary output/snapshot-two.txt
```

Tests (30 decision checks):

```bash
python3 -m unittest discover -s tests -v
```

Mutation check (plants 6 bugs in temp copies of `audit.py` and confirms the tests catch each one):

```bash
python3 tests/mutation_check.py .
```

Options:

| Option | Effect |
|---|---|
| `--json FILE` | Write the JSON report |
| `--summary FILE` | Also write the summary text to a file |
| `--sensitive-path PATH` | Override the S5 sensitive files (repeatable). Default: `app/env.txt`, `docs/rotation.txt` |
| `--fail-on-findings` | Exit with status 1 if any finding exists (default exit is 0) |

Output is reproducible: no timestamps, stable ordering. Rerunning produces byte-identical JSON.

Exit codes:

| Code | Meaning |
|---|---|
| `0` | Audit ran (findings, if any, are in the report) |
| `1` | Audit ran and found something, only with `--fail-on-findings` |
| `2` | Could not audit: bad usage, missing `inventory.json`/`ci.json`, input that does not match the schema, or the output safety net found a full token value (nothing is written) |

**Input validation.** Before any rule runs, both JSON files are checked against the policy schema: valid JSON; `trigger` is `pull_request` or `tag`; `permissions` is `read-only`, `release-write` or `write-all`; `runs_untrusted_code` and `log_environment` are real booleans; `secret_refs` and `artifact_paths` are lists of strings; token entries have string `token_id`/`value`/`state` and unique ids. Every problem in both files is listed in one run, and no report is written. Messages never include token values. This prevents a malformed flag such as `"true"` (a string) from silently passing S2/S4.

## 4. How it decides

| Rule | Input | Logic |
|---|---|---|
| S1 | Text of every file under `app/`, `tests/`, `docs/`, `build/`, including dotfiles such as `app/.env` (only OS metadata like `.DS_Store` is skipped) | Exact match of each inventory value, line by line, longest value first. Active (or unknown) state → finding. `revoked_in_fixture` / `test_only` → benign decision. Filename is never an exemption. `inventory.json` is not scanned. An inventory entry with a blank value is not matched (it would match every line) and is reported under **inventory warnings**. |
| S2 | `ci.json` | `runs_untrusted_code is True` and at least one `secret_ref` resolves to an active token |
| S3 | `ci.json` | `read-only` OK; `release-write` OK only with `trigger=tag` and `runs_untrusted_code is False`; everything else (including `write-all`) fails |
| S4 | `ci.json` | `log_environment is True` and at least one active `secret_ref` |
| S5 | `ci.json` + supplied file list | Each `artifact_paths` pattern is expanded with `fnmatchcase` against the supplied content files; a match on a sensitive path is a finding, regardless of token state |

Text findings (`kind: "text"`, `path` + `line`) are kept separate from CI findings (`kind: "ci"`, `workflow_id`). A `secret_ref` that is not in the inventory is listed under **unresolved refs**; it is never assumed to be a credential.

## 5. Results

| | Findings | Benign decisions |
|---|---|---|
| Snapshot one | S1 `app/env.txt:2`; S2, S3, S4, S5 on `workflow:pr-build` | S1 `tests/mock.txt:2` (test_only), S1 `docs/rotation.txt:1` (revoked), `release` workflow's `release-write` and secret use |
| Snapshot two | S1 `docs/rotation.txt:2` (new active `release-rotated`); S5 on `workflow:pr-build` (`app/*` → `app/env.txt`) | S1 `app/env.txt:2` and `docs/rotation.txt:1` (old value, now revoked), S1 `tests/mock.txt:2`, `release` workflow |

Full output: [output/](output/). Remediation priorities and the snapshot comparison: [REMEDIATION.md](REMEDIATION.md).

The short version: rotation fixed the CI hardening (S2, S3, S4), but the new token was copied into the rotation note, and the artifact wildcard still publishes the env file.

## 6. Auditing new content

Point the script at any directory with the same schema (`inventory.json`, `ci.json`, and content under the four directories). No source changes are needed. If the sensitive files differ, pass them with `--sensitive-path`.

## 7. File map

| Path | Purpose |
|---|---|
| [audit.py](audit.py) | The auditor, one file in labelled sections: constants → typed records (`TextRecord`, `CiRecord`, `UnresolvedRef`, `InventoryWarning`, `Report`) → loading & schema validation → matching & redaction → record builders (explanation text per rule) → S1 scan → S2–S5 checks → report → command line |
| [tests/test_audit.py](tests/test_audit.py) | 30 decision tests |
| [tests/mutation_check.py](tests/mutation_check.py) | Confirms the tests catch planted bugs |
| [output/](output/) | Captured reports, test output, mutation output |
| [REMEDIATION.md](REMEDIATION.md) | Top-two actions and snapshot comparison |
| [WORKLOG.md](WORKLOG.md) | Decisions, obstacle, validation, limits, next step |
| [AI_USE.md](AI_USE.md) | AI-use note |
