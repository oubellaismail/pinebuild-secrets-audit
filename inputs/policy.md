# Fictional PineBuild audit policy

All CI config is a simplified assessment schema, **not** runnable GitHub/GitLab syntax. No provider knowledge needed.

Each snapshot has `inventory.json` (metadata), `ci.json` (configuration), and content files under app/, tests/, docs/, build/. Only those four content directories are text-scanned. Inventory values classify exact token matches; matching token values in inventory itself is not a finding. CI secret_refs name token_id, not token text. Treat unknown refs as unresolved configuration evidence, never invent credentials; supplied refs are known.

Token states: active_in_fixture requires handling as sensitive; revoked_in_fixture and test_only do not represent current credential exposure. Test/documentation filename alone is **not** an exemption for an active token. All DEMO strings are nonfunctional training markers.

Rules:
- S1: Any active token value in scanned content is plaintext exposure, regardless of filename. Give path, line and token_id, redact value.
- S2: runs_untrusted_code=true with any active secret_ref is unsafe secret availability. Trigger alone does not prove exploitation.
- S3: permissions must be read-only unless trigger=tag **and** runs_untrusted_code=false, where release-write is permitted. write-all is never permitted.
- S4: log_environment=true with any active secret_ref is unsafe logging exposure; the flag models full environment logging.
- S5: Any artifact_paths pattern matching a configured sensitive file is unsafe publication. The configured sensitive paths are `app/env.txt` and `docs/rotation.txt` in both snapshots. This protects future credentials too, even if a current token is revoked. Patterns use Python fnmatch-style whole relative-path matching, so `app/*` matches `app/env.txt`. Match only supplied content file paths, no network expansion.

workflow_id uniquely names each workflow; trigger is pull_request or tag; permissions are read-only/release-write/write-all; flags are booleans; secret_refs and artifact_paths are arrays of strings. One workflow may violate several rules: report separately or aggregate with all rule IDs and evidence. A matching active token is sufficient for S1 even if no workflow uses it. Do not label revoked docs/test markers “critical secrets” or claim an actual attacker exploited the CI data.

Fictional team can immediately change one workflow and schedule one repository cleanup. Use these capacity limits to prioritize. Avoid logging full token values; token_id and path/line are enough for evidence.
