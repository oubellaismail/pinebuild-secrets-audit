# Remediation queue and snapshot comparison

Source: [output/snapshot-one.txt](output/snapshot-one.txt), [output/snapshot-two.txt](output/snapshot-two.txt), produced by `audit.py` with unchanged rules. Token values are shown only as `token_id`.

Capacity (from policy): the team can **change one workflow immediately** and **schedule one repository cleanup**. These are two separate lanes, so the queue picks the single most valuable item for each and orders them by risk.

## Current state (snapshot two): top two actions

| Rank | Lane | Action | Closes | Why this rank |
|---|---|---|---|---|
| **1** | Rotate now, then scheduled repo cleanup (first slot) | **First** rotate `release-rotated` in the secret store and point `release` at the new value (stored only there). **Then**, in the cleanup slot, delete the "temporary troubleshooting copy" at `docs/rotation.txt:2` and purge it from history. | S1 `docs/rotation.txt:2` | This is the **only active credential currently exposed**, and it is the release secret used by a `release-write` workflow. Anyone who can read the repo has it. Deleting the line does not un-expose it (history, clones, forks), so containment comes first: once rotated, the leaked value is dead and the cleanup is no longer racing an attacker. |
| **2** | Immediate workflow change | In `pr-build`, replace `artifact_paths: ["app/*", ...]` with the explicit `["build/report.txt"]`. | S5 `workflow:pr-build` | `app/*` still expands to `app/env.txt`. Today that file holds a revoked value, so nothing live is published, but the next real value written there would be published by a job anyone can trigger with a pull request. It is ranked below #1 because it is a leak *path*, not a live leak, but it is done **today** because the workflow lane is free and the change is one line. |

**Assumption:** rotating a secret is a secret-store operation, not a workflow change or a repository cleanup, so it is not limited by the two capacity lanes. If the team cannot rotate immediately either, rank 1 still comes first and rotation happens at the cleanup slot, before the file edit.

The two actions use different lanes, so doing #2 now does not delay #1. After both, a rerun of the auditor on the changed snapshot should report 0 findings (the old revoked value in `app/env.txt:2` stays a benign decision; removing it is optional hygiene).

## Historical state (snapshot one): what the queue would have been

| Rank | Lane | Action | Closes |
|---|---|---|---|
| **1** | Immediate workflow change | Lock down `pr-build`: `secret_refs: []`, `permissions: read-only`, `log_environment: false`, `artifact_paths: ["build/report.txt"]`. | S2, S3, S4, S5 on `workflow:pr-build` |
| **2** | Rotate now, then scheduled repo cleanup | Rotate `release-active` first, then remove `RELEASE_TOKEN` from `app/env.txt:2` and history. | S1 `app/env.txt:2` |

Here the workflow comes first: one change closes four rules on a job that runs untrusted pull-request code with the active release secret, `write-all`, environment logging and publication of the file containing that secret. These are unsafe configurations; the data does not show that anyone exploited them.

## What changed between snapshots

| Rule | Snapshot one | Snapshot two | Change |
|---|---|---|---|
| S1 | `app/env.txt:2` holds active `release-active` | `app/env.txt:2` still holds the same value, now **revoked** (benign). `docs/rotation.txt:2` holds the **new active** `release-rotated` | Old exposure retired by revocation, **new exposure introduced** by the rotation note |
| S2 | `pr-build` untrusted + active secret | `pr-build` has no secrets | Fixed |
| S3 | `pr-build` `write-all` | `pr-build` `read-only` | Fixed |
| S4 | `pr-build` logs env with active secret | Logging off | Fixed |
| S5 | `pr-build` publishes `app/env.txt` | `pr-build` publishes `app/*`, which still matches `app/env.txt` | **Not fixed**: an exact path was replaced by a wildcard that matches the same file |
| `release` | Allowed (tag, trusted, `release-write`) | Allowed, now uses `release-rotated` | Unchanged and compliant |

Findings: 5 → 2.

### Assumptions the second snapshot disproves

"Rotation fixed everything" rests on three assumptions, and the audit shows each one is wrong:

1. **"Revoking the old token removes the exposure."** It removes the *old* exposure only. The new value was pasted into `docs/rotation.txt`, a documentation file, and filename is not an exemption (S1).
2. **"We removed `app/env.txt` from the artifacts."** The exact path was replaced by `app/*`, which expands to the same file (S5).
3. **"`app/env.txt` is safe now."** It holds a revoked value today, so it is not a current credential exposure. But the file is still the place where the release token lives, and it is still published, so S5 protects the *next* value.

What rotation did achieve: the CI hardening of `pr-build` (S2, S3, S4) is real and verified by the rerun.
