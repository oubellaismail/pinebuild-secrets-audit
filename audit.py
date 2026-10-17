#!/usr/bin/env python3
"""Offline secrets and CI auditor for the fictional PineBuild snapshots.

Usage:
    python3 audit.py <snapshot-dir>

Python 3.10+ standard library only. Reads files, never contacts a network.
"""

import argparse
import json
import sys
from dataclasses import dataclass, fields
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Constants (from policy.md)
# ---------------------------------------------------------------------------

# The four content directories the policy allows us to text-scan.
SCANNED_DIRS = ("app", "tests", "docs", "build")

# OS metadata files that are never content. Other dotfiles (e.g. app/.env)
# are scanned: they are a common place for real secrets.
SKIPPED_FILENAMES = (".DS_Store", "Thumbs.db")

# S5 sensitive files from the policy; override with --sensitive-path.
DEFAULT_SENSITIVE_PATHS = ("app/env.txt", "docs/rotation.txt")

# Token states. Only these two are known to be harmless; anything else
# (active_in_fixture, or an unknown future state) is handled as sensitive.
NON_SENSITIVE_STATES = ("revoked_in_fixture", "test_only")

# Allowed CI values. Anything else is a schema error, so a malformed flag
# such as "true" (a string) cannot silently pass S2/S4.
TRIGGER_PULL_REQUEST = "pull_request"
TRIGGER_TAG = "tag"
TRIGGERS = (TRIGGER_PULL_REQUEST, TRIGGER_TAG)

PERM_READ_ONLY = "read-only"
PERM_RELEASE_WRITE = "release-write"
PERM_WRITE_ALL = "write-all"
PERMISSIONS = (PERM_READ_ONLY, PERM_RELEASE_WRITE, PERM_WRITE_ALL)

BOOLEAN_FIELDS = ("runs_untrusted_code", "log_environment")
STRING_LIST_FIELDS = ("secret_refs", "artifact_paths")

# {token_id: {"value": ..., "state": ...}}
Tokens = dict[str, dict[str, str]]
# One validated entry of ci.json "workflows".
Workflow = dict[str, Any]


def is_sensitive(state: str) -> bool:
    """True unless the state is one the policy says is not a current exposure."""
    return state not in NON_SENSITIVE_STATES


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------

@dataclass(kw_only=True)
class Record:
    """One finding or benign decision. Text records (S1) carry path/line/token;
    CI records (S2-S5) carry workflow_id. Field order is the JSON key order."""

    rule_id: str
    kind: str  # "text" or "ci"
    path: str | None = None
    line: int | None = None
    token_id: str | None = None
    token_state: str | None = None
    workflow_id: str | None = None
    evidence: str | dict
    rationale: str
    next_action: str

    @property
    def location(self) -> str:
        if self.kind == "text":
            return f"{self.path}:{self.line}"
        return f"workflow:{self.workflow_id}"

    def to_dict(self) -> dict:
        """JSON form: unset fields are omitted, location is appended last."""
        data = {f.name: getattr(self, f.name) for f in fields(self) if getattr(self, f.name) is not None}
        data["location"] = self.location
        return data


# ---------------------------------------------------------------------------
# Loading and schema validation
# ---------------------------------------------------------------------------

class SchemaError(Exception):
    """Input does not match the assessment schema; carries every problem found."""

    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__("; ".join(errors))


def read_json(path: Path) -> Any:
    """Parse a JSON file, turning parse errors into a SchemaError."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SchemaError([f"{path.name}: invalid JSON ({exc.msg} at line {exc.lineno}, column {exc.colno})"])
    except UnicodeDecodeError:
        raise SchemaError([f"{path.name}: not valid UTF-8 text"])


def validate_inventory(data: Any) -> list[str]:
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


def validate_ci(data: Any) -> list[str]:
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


def load_inventory(snapshot: Path) -> Tokens:
    """Return {token_id: {"value": ..., "state": ...}} from inventory.json."""
    data = read_json(snapshot / "inventory.json")
    errors = validate_inventory(data)
    if errors:
        raise SchemaError(errors)
    tokens = {}
    for entry in data["tokens"]:
        tokens[entry["token_id"]] = {"value": entry["value"], "state": entry["state"]}
    return tokens


def load_workflows(snapshot: Path) -> list[Workflow]:
    """Return the list of workflow dicts from ci.json."""
    data = read_json(snapshot / "ci.json")
    errors = validate_ci(data)
    if errors:
        raise SchemaError(errors)
    return data["workflows"]


def load_snapshot(snapshot: Path) -> tuple[Tokens, list[Workflow]]:
    """Load and validate both inputs. Problems from both files are collected
    before raising, so one run reports every problem."""
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
    return tokens, workflows


def list_content_files(snapshot: Path) -> list[str]:
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


# ---------------------------------------------------------------------------
# Token matching and redaction
# ---------------------------------------------------------------------------

def values_longest_first(tokens: Tokens) -> list[tuple[str, str]]:
    """(value, token_id) pairs, longest value first so a value that contains
    another value is matched (and redacted) as the longer one."""
    pairs = [(info["value"], token_id) for token_id, info in tokens.items()
             if info["value"].strip()]
    return sorted(pairs, key=lambda p: len(p[0]), reverse=True)


def inventory_warnings(tokens: Tokens) -> list[dict]:
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


def redact(text: str, tokens: Tokens) -> str:
    """Replace every known token value with [REDACTED:<token_id>]."""
    for value, token_id in values_longest_first(tokens):
        text = text.replace(value, f"[REDACTED:{token_id}]")
    return text


# ---------------------------------------------------------------------------
# Record builders: the explanation text for each rule
# ---------------------------------------------------------------------------

def s1_record(rel_path: str, line_no: int, token_id: str, state: str,
              evidence: str, sensitive: bool) -> Record:
    if sensitive:
        rationale = (f"Token '{token_id}' is {state} and appears in plaintext; "
                     "filename or directory does not exempt it.")
        next_action = (f"Rotate '{token_id}' now (the exposed value must be treated as "
                       f"compromised), then remove it from {rel_path}:{line_no} and git history.")
    else:
        rationale = (f"Token '{token_id}' is {state}; it does not represent a "
                     "current credential exposure, so S1 is suppressed.")
        next_action = "None required; optionally tidy the marker."
    return Record(rule_id="S1", kind="text", path=rel_path, line=line_no, token_id=token_id,
                  token_state=state, evidence=evidence, rationale=rationale, next_action=next_action)


def ci_record(rule_id: str, wf: Workflow, evidence: dict, rationale: str, next_action: str) -> Record:
    return Record(rule_id=rule_id, kind="ci", workflow_id=wf["workflow_id"], evidence=evidence,
                  rationale=rationale, next_action=next_action)


def s2_record(wf: Workflow, sensitive_refs: list[str]) -> Record:
    return ci_record(
        "S2", wf,
        {"runs_untrusted_code": True, "trigger": wf["trigger"], "active_secret_refs": sensitive_refs},
        "Workflow runs untrusted code while active secrets are available to it. "
        "This is unsafe availability; it does not prove the secret was exfiltrated.",
        f"Remove {', '.join(sensitive_refs)} from '{wf['workflow_id']}' or stop running untrusted code in it; "
        "move secret use to a trusted (tag) workflow.",
    )


def s3_record(wf: Workflow) -> Record:
    perm = wf["permissions"]
    why = (f"{PERM_WRITE_ALL} is never permitted." if perm == PERM_WRITE_ALL
           else f"'{perm}' requires trigger={TRIGGER_TAG} and runs_untrusted_code=false.")
    return ci_record(
        "S3", wf,
        {"permissions": perm, "trigger": wf["trigger"], "runs_untrusted_code": wf["runs_untrusted_code"]},
        f"Permissions exceed policy: {why}",
        f"Set '{wf['workflow_id']}' permissions to {PERM_READ_ONLY}.",
    )


def s4_record(wf: Workflow, sensitive_refs: list[str]) -> Record:
    return ci_record(
        "S4", wf,
        {"log_environment": True, "active_secret_refs": sensitive_refs},
        "Full environment logging would write the active secret values into build logs.",
        f"Set log_environment=false on '{wf['workflow_id']}'; log only named non-secret variables.",
    )


def s5_record(wf: Workflow, pattern: str, matched: list[str]) -> Record:
    return ci_record(
        "S5", wf,
        {"artifact_pattern": pattern, "matches_sensitive": matched},
        f"Artifact pattern '{pattern}' publishes sensitive file(s) {', '.join(matched)}. "
        "Unsafe even if the token currently inside is revoked: future values would be published.",
        f"Replace '{pattern}' in '{wf['workflow_id']}' with explicit non-sensitive paths "
        "(e.g. build/report.txt).",
    )


def unresolved_record(wf: Workflow, ref: str) -> dict:
    return {
        "kind": "unresolved_ref",
        "workflow_id": wf["workflow_id"],
        "secret_ref": ref,
        "rationale": "secret_ref is not in inventory.json; state unknown, no credential assumed.",
        "next_action": "Confirm what this ref names and add it to the inventory.",
    }


# ---------------------------------------------------------------------------
# S1: text scan
# ---------------------------------------------------------------------------

def scan_text(snapshot: Path, tokens: Tokens, files: list[str]) -> tuple[list[Record], list[Record]]:
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
                sensitive = is_sensitive(state)
                record = s1_record(rel_path, line_no, token_id, state,
                                   redact(line.strip(), tokens), sensitive)
                (findings if sensitive else benign).append(record)
    return findings, benign


# ---------------------------------------------------------------------------
# S2-S5: CI checks
# ---------------------------------------------------------------------------

def resolve_refs(wf: Workflow, tokens: Tokens) -> tuple[list[str], list[str], list[str]]:
    """Split a workflow's secret_refs into (sensitive, non_sensitive, unknown)."""
    sensitive, non_sensitive, unknown = [], [], []
    for ref in wf["secret_refs"]:
        if ref not in tokens:
            unknown.append(ref)
        elif is_sensitive(tokens[ref]["state"]):
            sensitive.append(ref)
        else:
            non_sensitive.append(ref)
    return sensitive, non_sensitive, unknown


def check_s2(wf: Workflow, sensitive_refs: list[str]) -> list[Record]:
    """S2: untrusted code with any active secret available."""
    if wf["runs_untrusted_code"] is True and sensitive_refs:
        return [s2_record(wf, sensitive_refs)]
    return []


def permission_allowed(wf: Workflow) -> bool:
    """S3 policy: read-only always; release-write only for tag + no untrusted code."""
    perm = wf["permissions"]
    if perm == PERM_READ_ONLY:
        return True
    if perm == PERM_RELEASE_WRITE:
        return wf["trigger"] == TRIGGER_TAG and wf["runs_untrusted_code"] is False
    return False  # write-all, or anything unrecognised


def check_s3(wf: Workflow) -> list[Record]:
    """S3: permissions beyond what the policy allows for this trigger."""
    if permission_allowed(wf):
        return []
    return [s3_record(wf)]


def check_s4(wf: Workflow, sensitive_refs: list[str]) -> list[Record]:
    """S4: full environment logging while any active secret is present."""
    if wf["log_environment"] is True and sensitive_refs:
        return [s4_record(wf, sensitive_refs)]
    return []


def check_s5(wf: Workflow, files: list[str], sensitive_paths: tuple[str, ...]) -> list[Record]:
    """S5: an artifact pattern that expands to a configured sensitive file."""
    records = []
    for pattern in wf["artifact_paths"]:
        matched = [f for f in files if fnmatchcase(f, pattern) and f in sensitive_paths]
        if matched:
            records.append(s5_record(wf, pattern, matched))
    return records


def ci_benign(wf: Workflow, sensitive_refs: list[str], non_sensitive_refs: list[str]) -> list[Record]:
    """Benign decisions worth showing: the release-write exception, active
    secrets held by a workflow that is otherwise safe, and stale refs."""
    benign = []
    if wf["permissions"] == PERM_RELEASE_WRITE and permission_allowed(wf):
        benign.append(ci_record(
            "S3", wf,
            {"permissions": PERM_RELEASE_WRITE, "trigger": TRIGGER_TAG, "runs_untrusted_code": False},
            f"{PERM_RELEASE_WRITE} is the policy exception for trigger={TRIGGER_TAG} with no untrusted code.",
            "None required.",
        ))
    if sensitive_refs and wf["runs_untrusted_code"] is False and wf["log_environment"] is False:
        benign.append(ci_record(
            "S2/S4", wf,
            {"active_secret_refs": sensitive_refs, "runs_untrusted_code": False, "log_environment": False},
            "Active secret is used by a trusted workflow that does not log the environment.",
            "None required.",
        ))
    if non_sensitive_refs:
        benign.append(ci_record(
            "S2/S4", wf,
            {"non_sensitive_secret_refs": non_sensitive_refs},
            "Referenced secrets are revoked/test only; not a current exposure.",
            "Optionally remove stale refs.",
        ))
    return benign


def check_ci(workflows: list[Workflow], tokens: Tokens, files: list[str],
             sensitive_paths: tuple[str, ...]) -> tuple[list[Record], list[Record], list[dict]]:
    """Run S2-S5 on every workflow. Returns (findings, benign, unresolved)."""
    findings, benign, unresolved = [], [], []
    for wf in workflows:
        sensitive_refs, non_sensitive_refs, unknown_refs = resolve_refs(wf, tokens)
        findings += check_s2(wf, sensitive_refs)
        findings += check_s3(wf)
        findings += check_s4(wf, sensitive_refs)
        findings += check_s5(wf, files, sensitive_paths)
        unresolved += [unresolved_record(wf, ref) for ref in unknown_refs]
        benign += ci_benign(wf, sensitive_refs, non_sensitive_refs)
    return findings, benign, unresolved


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def build_report(snapshot: Path, tokens: Tokens, workflows: list[Workflow],
                 sensitive_paths: tuple[str, ...]) -> dict:
    """Run every rule on loaded inputs and return the machine-readable report."""
    files = list_content_files(snapshot)
    warnings = inventory_warnings(tokens)
    text_findings, text_benign = scan_text(snapshot, tokens, files)
    ci_findings, ci_benign_records, unresolved = check_ci(workflows, tokens, files, sensitive_paths)

    findings = [r.to_dict() for r in text_findings + ci_findings]
    benign = [r.to_dict() for r in text_benign + ci_benign_records]

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


def audit(snapshot: Path, sensitive_paths: tuple[str, ...] = DEFAULT_SENSITIVE_PATHS) -> dict:
    """Load, validate and audit a snapshot directory; return the report."""
    tokens, workflows = load_snapshot(snapshot)
    return build_report(snapshot, tokens, workflows, sensitive_paths)


def assert_no_token_values(serialized: str, tokens: Tokens) -> None:
    """Safety net: refuse to emit output that contains any full token value."""
    for token_id, info in tokens.items():
        if info["value"].strip() and info["value"] in serialized:
            raise RuntimeError(f"refusing to output unredacted value of '{token_id}'")


def format_evidence(evidence: str | dict) -> str:
    """Evidence as one line: text as-is, CI evidence as key=value pairs."""
    if isinstance(evidence, str):
        return evidence
    parts = []
    for key, value in evidence.items():
        if isinstance(value, list):
            value = ", ".join(value)
        parts.append(f"{key}={value}")
    return "; ".join(parts)


def format_summary(report: dict) -> str:
    """Readable summary of a report: findings, benign decisions, unresolved refs, warnings."""
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

    def block(record: dict) -> list[str]:
        head = f"[{record['rule_id']}] {record['location']}"
        if record["kind"] == "text":
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


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    """Command-line entry point. Returns the exit code (0 ok, 1 findings with
    --fail-on-findings, 2 unusable input)."""
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
        tokens, workflows = load_snapshot(snapshot)
    except SchemaError as exc:
        print(f"error: {snapshot} does not match the audit schema:", file=sys.stderr)
        for problem in exc.errors:
            print(f"  - {problem}", file=sys.stderr)
        return 2
    report = build_report(snapshot, tokens, workflows, sensitive_paths)
    report_json = json.dumps(report, indent=2) + "\n"
    summary = format_summary(report)
    assert_no_token_values(report_json + summary, tokens)

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
