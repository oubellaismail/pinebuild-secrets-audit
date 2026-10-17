#!/usr/bin/env python3
"""Offline secrets and CI auditor for the fictional PineBuild snapshots.

Usage:
    python3 audit.py <snapshot-dir>

Python 3.10+ standard library only. Reads files, never contacts a network.
"""

import argparse
import json
import sys
from fnmatch import fnmatchcase
from pathlib import Path

# The four content directories the policy allows us to text-scan.
SCANNED_DIRS = ("app", "tests", "docs", "build")

# OS metadata files that are never content. Other dotfiles (e.g. app/.env)
# are scanned: they are a common place for real secrets.
SKIPPED_FILENAMES = (".DS_Store", "Thumbs.db")

# S5 sensitive files from the policy; override with --sensitive-path.
DEFAULT_SENSITIVE_PATHS = ("app/env.txt", "docs/rotation.txt")

# Token states. Only these two are known to be harmless; anything else
# (active_in_fixture, or an unknown future state) is handled as sensitive.
ACTIVE_STATE = "active_in_fixture"
NON_SENSITIVE_STATES = ("revoked_in_fixture", "test_only")


def is_sensitive(state: str) -> bool:
    return state not in NON_SENSITIVE_STATES


# Allowed CI values from the policy. Anything else is a schema error, so a
# malformed flag such as "true" (a string) cannot silently pass S2/S4.
TRIGGERS = ("pull_request", "tag")
PERMISSIONS = ("read-only", "release-write", "write-all")
BOOLEAN_FIELDS = ("runs_untrusted_code", "log_environment")
STRING_LIST_FIELDS = ("secret_refs", "artifact_paths")


class SchemaError(Exception):
    """Input does not match the assessment schema; carries every problem found."""

    def __init__(self, errors: list):
        self.errors = errors
        super().__init__("; ".join(errors))


def read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SchemaError([f"{path.name}: invalid JSON ({exc.msg} at line {exc.lineno}, column {exc.colno})"])
    except UnicodeDecodeError:
        raise SchemaError([f"{path.name}: not valid UTF-8 text"])


def validate_inventory(data) -> list:
    """Return schema errors for inventory.json. Messages never include token values."""
    if not isinstance(data, dict) or not isinstance(data.get("tokens"), list):
        return ["inventory.json: expected an object with a 'tokens' list"]
    errors, seen = [], set()
    for i, entry in enumerate(data["tokens"]):
        where = f"inventory.json: tokens[{i}]"
        if not isinstance(entry, dict):
            errors.append(f"{where} must be an object")
            continue
        token_id = entry.get("token_id")
        if not isinstance(token_id, str) or not token_id:
            errors.append(f"{where}.token_id must be a non-empty string")
        elif token_id in seen:
            errors.append(f"{where}.token_id '{token_id}' is duplicated")
        else:
            seen.add(token_id)
        for field in ("value", "state"):
            if not isinstance(entry.get(field), str):
                errors.append(f"{where}.{field} must be a string")
    return errors


def validate_ci(data) -> list:
    """Return schema errors for ci.json."""
    if not isinstance(data, dict) or not isinstance(data.get("workflows"), list):
        return ["ci.json: expected an object with a 'workflows' list"]
    errors, seen = [], set()
    for i, wf in enumerate(data["workflows"]):
        if not isinstance(wf, dict):
            errors.append(f"ci.json: workflows[{i}] must be an object")
            continue
        wf_id = wf.get("workflow_id")
        if not isinstance(wf_id, str) or not wf_id:
            errors.append(f"ci.json: workflows[{i}].workflow_id must be a non-empty string")
            wf_id = f"workflows[{i}]"
        elif wf_id in seen:
            errors.append(f"ci.json: workflow_id '{wf_id}' is duplicated")
        seen.add(wf_id)
        where = f"ci.json: workflow '{wf_id}'"
        if wf.get("trigger") not in TRIGGERS:
            errors.append(f"{where}: trigger must be one of {', '.join(TRIGGERS)}")
        if wf.get("permissions") not in PERMISSIONS:
            errors.append(f"{where}: permissions must be one of {', '.join(PERMISSIONS)}")
        for field in BOOLEAN_FIELDS:
            if not isinstance(wf.get(field), bool):
                found = "missing" if field not in wf else type(wf[field]).__name__
                errors.append(f"{where}: {field} must be true or false (found {found})")
        for field in STRING_LIST_FIELDS:
            value = wf.get(field)
            if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                errors.append(f"{where}: {field} must be a list of strings")
    return errors


def load_inventory(snapshot: Path) -> dict:
    """Return {token_id: {"value": ..., "state": ...}} from inventory.json."""
    data = read_json(snapshot / "inventory.json")
    errors = validate_inventory(data)
    if errors:
        raise SchemaError(errors)
    tokens = {}
    for entry in data["tokens"]:
        tokens[entry["token_id"]] = {"value": entry["value"], "state": entry["state"]}
    return tokens


def load_workflows(snapshot: Path) -> list:
    """Return the list of workflow dicts from ci.json."""
    data = read_json(snapshot / "ci.json")
    errors = validate_ci(data)
    if errors:
        raise SchemaError(errors)
    return data["workflows"]


def list_content_files(snapshot: Path) -> list:
    """Return sorted relative paths (as 'app/env.txt' strings) of scannable files."""
    files = []
    for dirname in SCANNED_DIRS:
        base = snapshot / dirname
        if not base.is_dir():
            continue
        for path in base.rglob("*"):
            if path.is_file() and path.name not in SKIPPED_FILENAMES:
                files.append(path.relative_to(snapshot).as_posix())
    return sorted(files)


def values_longest_first(tokens: dict) -> list:
    """(value, token_id) pairs, longest value first so a value that contains
    another value is matched (and redacted) as the longer one."""
    pairs = [(info["value"], token_id) for token_id, info in tokens.items()
             if info["value"].strip()]
    return sorted(pairs, key=lambda p: len(p[0]), reverse=True)


def inventory_warnings(tokens: dict) -> list:
    """Inventory entries that cannot be matched safely (blank value).

    A blank value would match every line, so it is excluded from S1 and
    reported here instead of producing noise."""
    return [
        {
            "kind": "inventory_warning",
            "token_id": token_id,
            "token_state": info["state"],
            "issue": "blank value; cannot be matched in content, S1 skipped for this token.",
            "next_action": "Fix the inventory entry so it holds the exact token value.",
        }
        for token_id, info in tokens.items()
        if not info["value"].strip()
    ]


def redact(text: str, tokens: dict) -> str:
    """Replace every known token value with [REDACTED:<token_id>]."""
    for value, token_id in values_longest_first(tokens):
        text = text.replace(value, f"[REDACTED:{token_id}]")
    return text


def scan_text(snapshot: Path, tokens: dict, files: list) -> tuple:
    """S1: find exact token values in content files.

    Returns (findings, benign). Every match produces exactly one record:
    a sensitive token is an S1 finding, a revoked/test token is a benign
    decision kept as evidence that it was seen and deliberately suppressed.
    """
    findings, benign = [], []
    pairs = values_longest_first(tokens)
    for rel_path in files:
        text = (snapshot / rel_path).read_text(encoding="utf-8", errors="replace")
        for line_no, line in enumerate(text.splitlines(), start=1):
            remaining = line
            for value, token_id in pairs:
                if value not in remaining:
                    continue
                # Blank out the match so a shorter value inside it is not re-matched.
                remaining = remaining.replace(value, " " * len(value))
                state = tokens[token_id]["state"]
                record = {
                    "rule_id": "S1",
                    "kind": "text",
                    "path": rel_path,
                    "line": line_no,
                    "token_id": token_id,
                    "token_state": state,
                    "evidence": redact(line.strip(), tokens),
                }
                if is_sensitive(state):
                    record["rationale"] = (
                        f"Token '{token_id}' is {state} and appears in plaintext; "
                        "filename or directory does not exempt it."
                    )
                    record["next_action"] = (
                        f"Rotate '{token_id}' now (the exposed value must be treated as "
                        f"compromised), then remove it from {rel_path}:{line_no} and git history."
                    )
                    findings.append(record)
                else:
                    record["rationale"] = (
                        f"Token '{token_id}' is {state}; it does not represent a "
                        "current credential exposure, so S1 is suppressed."
                    )
                    record["next_action"] = "None required; optionally tidy the marker."
                    benign.append(record)
    return findings, benign


def ci_record(rule_id: str, wf: dict, evidence: dict, rationale: str, next_action: str) -> dict:
    return {
        "rule_id": rule_id,
        "kind": "ci",
        "workflow_id": wf["workflow_id"],
        "evidence": evidence,
        "rationale": rationale,
        "next_action": next_action,
    }


def resolve_refs(wf: dict, tokens: dict) -> tuple:
    """Split a workflow's secret_refs into (sensitive, non_sensitive, unknown)."""
    sensitive, non_sensitive, unknown = [], [], []
    for ref in wf.get("secret_refs", []):
        if ref not in tokens:
            unknown.append(ref)
        elif is_sensitive(tokens[ref]["state"]):
            sensitive.append(ref)
        else:
            non_sensitive.append(ref)
    return sensitive, non_sensitive, unknown


def check_s2(wf: dict, tokens: dict) -> list:
    """S2: untrusted code with any active secret available."""
    sensitive, _, _ = resolve_refs(wf, tokens)
    if wf.get("runs_untrusted_code") is True and sensitive:
        return [ci_record(
            "S2", wf,
            {"runs_untrusted_code": True, "trigger": wf.get("trigger"), "active_secret_refs": sensitive},
            "Workflow runs untrusted code while active secrets are available to it. "
            "This is unsafe availability; it does not prove the secret was exfiltrated.",
            f"Remove {', '.join(sensitive)} from '{wf['workflow_id']}' or stop running untrusted code in it; "
            "move secret use to a trusted (tag) workflow.",
        )]
    return []


def permission_allowed(wf: dict) -> bool:
    """S3 policy: read-only always; release-write only for tag + no untrusted code."""
    perm = wf.get("permissions")
    if perm == "read-only":
        return True
    if perm == "release-write":
        return wf.get("trigger") == "tag" and wf.get("runs_untrusted_code") is False
    return False  # write-all, or anything unrecognised


def check_s3(wf: dict) -> list:
    if permission_allowed(wf):
        return []
    perm = wf.get("permissions")
    why = ("write-all is never permitted." if perm == "write-all"
           else f"'{perm}' requires trigger=tag and runs_untrusted_code=false.")
    return [ci_record(
        "S3", wf,
        {"permissions": perm, "trigger": wf.get("trigger"),
         "runs_untrusted_code": wf.get("runs_untrusted_code")},
        f"Permissions exceed policy: {why}",
        f"Set '{wf['workflow_id']}' permissions to read-only.",
    )]


def check_s4(wf: dict, tokens: dict) -> list:
    """S4: full environment logging while any active secret is present."""
    sensitive, _, _ = resolve_refs(wf, tokens)
    if wf.get("log_environment") is True and sensitive:
        return [ci_record(
            "S4", wf,
            {"log_environment": True, "active_secret_refs": sensitive},
            "Full environment logging would write the active secret values into build logs.",
            f"Set log_environment=false on '{wf['workflow_id']}'; log only named non-secret variables.",
        )]
    return []


def check_s5(wf: dict, files: list, sensitive_paths: tuple) -> list:
    """S5: an artifact pattern that expands to a configured sensitive file."""
    records = []
    for pattern in wf.get("artifact_paths", []):
        matched = [f for f in files if fnmatchcase(f, pattern) and f in sensitive_paths]
        if matched:
            records.append(ci_record(
                "S5", wf,
                {"artifact_pattern": pattern, "matches_sensitive": matched},
                f"Artifact pattern '{pattern}' publishes sensitive file(s) {', '.join(matched)}. "
                "Unsafe even if the token currently inside is revoked: future values would be published.",
                f"Replace '{pattern}' in '{wf['workflow_id']}' with explicit non-sensitive paths "
                "(e.g. build/report.txt).",
            ))
    return records


def check_ci(workflows: list, tokens: dict, files: list, sensitive_paths: tuple) -> tuple:
    """Run S2-S5 on every workflow. Returns (findings, benign, unresolved)."""
    findings, benign, unresolved = [], [], []
    for wf in workflows:
        findings += check_s2(wf, tokens)
        findings += check_s3(wf)
        findings += check_s4(wf, tokens)
        findings += check_s5(wf, files, sensitive_paths)

        sensitive, non_sensitive, unknown = resolve_refs(wf, tokens)
        for ref in unknown:
            unresolved.append({
                "kind": "unresolved_ref",
                "workflow_id": wf["workflow_id"],
                "secret_ref": ref,
                "rationale": "secret_ref is not in inventory.json; state unknown, no credential assumed.",
                "next_action": "Confirm what this ref names and add it to the inventory.",
            })

        # Benign decisions worth showing: the release-write exception, and
        # active secrets held by a workflow that is otherwise safe.
        if wf.get("permissions") == "release-write" and permission_allowed(wf):
            benign.append(ci_record(
                "S3", wf,
                {"permissions": "release-write", "trigger": "tag", "runs_untrusted_code": False},
                "release-write is the policy exception for trigger=tag with no untrusted code.",
                "None required.",
            ))
        if sensitive and wf.get("runs_untrusted_code") is False and wf.get("log_environment") is False:
            benign.append(ci_record(
                "S2/S4", wf,
                {"active_secret_refs": sensitive, "runs_untrusted_code": False, "log_environment": False},
                "Active secret is used by a trusted workflow that does not log the environment.",
                "None required.",
            ))
        if non_sensitive:
            benign.append(ci_record(
                "S2/S4", wf,
                {"non_sensitive_secret_refs": non_sensitive},
                "Referenced secrets are revoked/test only; not a current exposure.",
                "Optionally remove stale refs.",
            ))
    return findings, benign, unresolved


def location(record: dict) -> str:
    if record.get("kind") == "text":
        return f"{record['path']}:{record['line']}"
    return f"workflow:{record['workflow_id']}"


def audit(snapshot: Path, sensitive_paths: tuple = DEFAULT_SENSITIVE_PATHS) -> dict:
    """Run every rule on a snapshot and return the machine-readable report."""
    # Validate both inputs before raising, so one run reports every problem.
    errors = []
    try:
        tokens = load_inventory(snapshot)
    except SchemaError as exc:
        errors += exc.errors
    try:
        workflows = load_workflows(snapshot)
    except SchemaError as exc:
        errors += exc.errors
    if errors:
        raise SchemaError(errors)
    files = list_content_files(snapshot)

    warnings = inventory_warnings(tokens)
    text_findings, text_benign = scan_text(snapshot, tokens, files)
    ci_findings, ci_benign, unresolved = check_ci(workflows, tokens, files, sensitive_paths)

    findings = text_findings + ci_findings
    benign = text_benign + ci_benign
    for record in findings + benign:
        record["location"] = location(record)

    by_rule = {}
    for record in findings:
        by_rule[record["rule_id"]] = by_rule.get(record["rule_id"], 0) + 1

    return {
        "report_schema": "pinebuild-audit/1",
        "snapshot": snapshot.as_posix(),
        "scanned_files": files,
        "workflows": [w["workflow_id"] for w in workflows],
        "sensitive_paths": list(sensitive_paths),
        "summary": {
            "findings": len(findings),
            "findings_by_rule": dict(sorted(by_rule.items())),
            "benign_decisions": len(benign),
            "unresolved_refs": len(unresolved),
            "inventory_warnings": len(warnings),
        },
        "findings": findings,
        "benign_decisions": benign,
        "unresolved_refs": unresolved,
        "inventory_warnings": warnings,
    }


def assert_no_token_values(serialized: str, snapshot: Path) -> None:
    """Safety net: refuse to emit output that contains any full token value."""
    for token_id, info in load_inventory(snapshot).items():
        if info["value"].strip() and info["value"] in serialized:
            raise RuntimeError(f"refusing to output unredacted value of '{token_id}'")


def format_evidence(evidence) -> str:
    if isinstance(evidence, str):
        return evidence
    parts = []
    for key, value in evidence.items():
        if isinstance(value, list):
            value = ", ".join(value)
        parts.append(f"{key}={value}")
    return "; ".join(parts)


def format_summary(report: dict) -> str:
    s = report["summary"]
    by_rule = " ".join(f"{k}:{v}" for k, v in s["findings_by_rule"].items()) or "none"
    lines = [
        f"PineBuild secrets/CI audit: {report['snapshot']}",
        f"Scanned files: {', '.join(report['scanned_files'])}",
        f"Workflows: {', '.join(report['workflows'])}",
        f"Sensitive paths (S5): {', '.join(report['sensitive_paths'])}",
        f"Result: {s['findings']} findings ({by_rule}), "
        f"{s['benign_decisions']} benign decisions, {s['unresolved_refs']} unresolved refs, "
        f"{s['inventory_warnings']} inventory warnings",
        "",
        "FINDINGS",
    ]

    def block(record: dict) -> list:
        head = f"[{record['rule_id']}] {record['location']}"
        if record.get("kind") == "text":
            head += f"  token_id={record['token_id']} ({record['token_state']})"
        return [
            head,
            f"    evidence: {format_evidence(record['evidence'])}",
            f"    why:      {record['rationale']}",
            f"    next:     {record['next_action']}",
        ]

    for record in report["findings"]:
        lines += block(record)
    if not report["findings"]:
        lines.append("  none")
    lines += ["", "BENIGN DECISIONS (seen and deliberately not flagged)"]
    for record in report["benign_decisions"]:
        lines += block(record)[:3]
    if not report["benign_decisions"]:
        lines.append("  none")
    lines += ["", "UNRESOLVED SECRET REFS"]
    for record in report["unresolved_refs"]:
        lines.append(f"  workflow:{record['workflow_id']}  ref={record['secret_ref']}  {record['rationale']}")
    if not report["unresolved_refs"]:
        lines.append("  none")
    lines += ["", "INVENTORY WARNINGS"]
    for record in report["inventory_warnings"]:
        lines.append(f"  token_id={record['token_id']} ({record['token_state']})  {record['issue']}")
    if not report["inventory_warnings"]:
        lines.append("  none")
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Audit a PineBuild snapshot directory.")
    parser.add_argument("snapshot", type=Path, help="path to a snapshot directory")
    parser.add_argument(
        "--sensitive-path", action="append", dest="sensitive_paths", metavar="PATH",
        help="S5 sensitive file (repeatable); default: " + ", ".join(DEFAULT_SENSITIVE_PATHS),
    )
    parser.add_argument("--json", type=Path, metavar="FILE", help="write the JSON report to FILE")
    parser.add_argument("--summary", type=Path, metavar="FILE", help="also write the summary to FILE")
    parser.add_argument("--fail-on-findings", action="store_true",
                        help="exit with status 1 when any finding is reported")
    args = parser.parse_args(argv)
    sensitive_paths = tuple(args.sensitive_paths or DEFAULT_SENSITIVE_PATHS)

    snapshot = args.snapshot
    if not (snapshot / "inventory.json").is_file() or not (snapshot / "ci.json").is_file():
        print(f"error: {snapshot} must contain inventory.json and ci.json", file=sys.stderr)
        return 2

    try:
        report = audit(snapshot, sensitive_paths)
    except SchemaError as exc:
        print(f"error: {snapshot} does not match the audit schema:", file=sys.stderr)
        for problem in exc.errors:
            print(f"  - {problem}", file=sys.stderr)
        return 2
    report_json = json.dumps(report, indent=2) + "\n"
    summary = format_summary(report)
    assert_no_token_values(report_json + summary, snapshot)

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(report_json, encoding="utf-8")
    if args.summary:
        args.summary.parent.mkdir(parents=True, exist_ok=True)
        args.summary.write_text(summary, encoding="utf-8")
    sys.stdout.write(summary)

    if args.fail_on_findings and report["findings"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
