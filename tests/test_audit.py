"""Decision checks for audit.py.

Run from the candidate/ directory:
    python3 -m unittest discover -s tests -v

Most tests build a small synthetic snapshot in a temp directory, so they
check rule decisions directly instead of depending on the supplied fixtures.
The last class pins the expected results for the two supplied snapshots.
"""

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import audit  # noqa: E402

ACTIVE = "active_in_fixture"
REVOKED = "revoked_in_fixture"
TEST = "test_only"


def workflow(**overrides) -> dict:
    """A workflow that passes every rule; override fields to break one."""
    wf = {
        "workflow_id": "wf",
        "trigger": "pull_request",
        "runs_untrusted_code": True,
        "secret_refs": [],
        "permissions": "read-only",
        "log_environment": False,
        "artifact_paths": ["build/report.txt"],
    }
    wf.update(overrides)
    return wf


class SnapshotCase(unittest.TestCase):
    """Helper that writes a synthetic same-schema snapshot and audits it."""

    def make_snapshot(self, tokens: dict, workflows: list, files: dict) -> Path:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        inventory = {"schema_version": 1, "tokens": [
            {"token_id": tid, "value": value, "state": state}
            for tid, (value, state) in tokens.items()
        ]}
        (root / "inventory.json").write_text(json.dumps(inventory))
        (root / "ci.json").write_text(json.dumps({"workflows": workflows}))
        for rel, content in files.items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        return root

    def run_audit(self, tokens, workflows, files, **kwargs) -> dict:
        return audit.audit(self.make_snapshot(tokens, workflows, files), **kwargs)

    @staticmethod
    def keys(records) -> set:
        return {(r["rule_id"], r["location"]) for r in records}


class TestS1ActiveTextDetection(SnapshotCase):
    def test_active_token_in_test_file_is_finding_with_line_and_redaction(self):
        report = self.run_audit(
            {"live": ("DEMO_ACTIVE_X1", ACTIVE)},
            [workflow()],
            {"tests/fixture.txt": "header\nKEY=DEMO_ACTIVE_X1\n"},
        )
        s1 = [f for f in report["findings"] if f["rule_id"] == "S1"]
        self.assertEqual(len(s1), 1)
        self.assertEqual(s1[0]["location"], "tests/fixture.txt:2")
        self.assertEqual(s1[0]["token_id"], "live")
        self.assertEqual(s1[0]["evidence"], "KEY=[REDACTED:live]")
        self.assertNotIn("DEMO_ACTIVE_X1", json.dumps(report))

    def test_inventory_and_unscanned_dirs_are_not_findings(self):
        report = self.run_audit(
            {"live": ("DEMO_ACTIVE_X1", ACTIVE)},
            [workflow()],
            {"other/notes.txt": "DEMO_ACTIVE_X1\n", "app/ok.txt": "nothing here\n"},
        )
        self.assertEqual(report["findings"], [])

    def test_unknown_token_state_is_treated_as_sensitive(self):
        report = self.run_audit(
            {"odd": ("DEMO_ODD_1", "pending_review")},
            [workflow()],
            {"docs/a.txt": "DEMO_ODD_1\n"},
        )
        self.assertEqual(self.keys(report["findings"]), {("S1", "docs/a.txt:1")})

    def test_dotfile_is_scanned_but_os_metadata_is_not(self):
        report = self.run_audit(
            {"live": ("DEMO_ACTIVE_X1", ACTIVE)},
            [workflow()],
            {"app/.env": "KEY=DEMO_ACTIVE_X1\n", "app/.DS_Store": "DEMO_ACTIVE_X1\n"},
        )
        self.assertEqual(self.keys(report["findings"]), {("S1", "app/.env:1")})
        self.assertNotIn("app/.DS_Store", report["scanned_files"])

    def test_blank_inventory_value_is_warning_not_match(self):
        report = self.run_audit(
            {"blank": ("  ", ACTIVE), "live": ("DEMO_ACTIVE_X1", ACTIVE)},
            [workflow()],
            {"app/a.txt": "hello world\nKEY=DEMO_ACTIVE_X1\n"},
        )
        self.assertEqual(self.keys(report["findings"]), {("S1", "app/a.txt:2")})
        self.assertEqual(report["findings"][0]["evidence"], "KEY=[REDACTED:live]")
        self.assertEqual([w["token_id"] for w in report["inventory_warnings"]], ["blank"])

    def test_nested_folder_is_scanned(self):
        report = self.run_audit(
            {"live": ("DEMO_ACTIVE_X1", ACTIVE)}, [workflow()],
            {"app/config/env.txt": "a\nKEY=DEMO_ACTIVE_X1\n"},
        )
        self.assertEqual(self.keys(report["findings"]), {("S1", "app/config/env.txt:2")})

    def test_same_token_twice_on_one_line_is_one_record(self):
        # Both copies must be blanked: a shorter value hidden inside the second
        # copy must not produce an extra match.
        report = self.run_audit(
            {"live": ("DEMO_ACTIVE_X1", ACTIVE), "short": ("DEMO_ACTIVE", REVOKED)}, [workflow()],
            {"docs/n.txt": "A=DEMO_ACTIVE_X1 B=DEMO_ACTIVE_X1\n"},
        )
        self.assertEqual([f["token_id"] for f in report["findings"]], ["live"])
        self.assertEqual(report["findings"][0]["evidence"], "A=[REDACTED:live] B=[REDACTED:live]")
        self.assertEqual(report["benign_decisions"], [])

    def test_next_action_rotates_before_cleanup(self):
        report = self.run_audit(
            {"live": ("DEMO_ACTIVE_X1", ACTIVE)}, [workflow()], {"docs/n.txt": "DEMO_ACTIVE_X1\n"})
        action = report["findings"][0]["next_action"]
        self.assertLess(action.index("Rotate"), action.index("remove"))


class TestS1TestAndRevokedSuppression(SnapshotCase):
    def test_test_and_revoked_tokens_are_benign_not_findings(self):
        report = self.run_audit(
            {"t": ("DEMO_TEST_A", TEST), "r": ("DEMO_REVOKED_B", REVOKED)},
            [workflow()],
            {"tests/mock.txt": "X=DEMO_TEST_A\n", "app/env.txt": "Y=DEMO_REVOKED_B\n"},
        )
        self.assertEqual([f for f in report["findings"] if f["rule_id"] == "S1"], [])
        benign = {(r["location"], r["token_state"]) for r in report["benign_decisions"] if r["rule_id"] == "S1"}
        self.assertEqual(benign, {("tests/mock.txt:1", TEST), ("app/env.txt:1", REVOKED)})

    def test_same_line_mixed_states_only_flags_active(self):
        report = self.run_audit(
            {"a": ("DEMO_ACTIVE_Z", ACTIVE), "r": ("DEMO_REVOKED_Z", REVOKED)},
            [workflow()],
            {"docs/rotation.txt": "old DEMO_REVOKED_Z new DEMO_ACTIVE_Z\n"},
        )
        s1 = [f for f in report["findings"] if f["rule_id"] == "S1"]
        self.assertEqual([f["token_id"] for f in s1], ["a"])
        self.assertEqual(s1[0]["evidence"], "old [REDACTED:r] new [REDACTED:a]")

    def test_value_containing_another_value_matches_longer_only(self):
        # A revoked value that is a prefix of an active one must not hide or
        # double-count the active match.
        report = self.run_audit(
            {"short": ("DEMO_K", REVOKED), "long": ("DEMO_K_LIVE", ACTIVE)},
            [workflow()],
            {"app/x.txt": "DEMO_K_LIVE\n"},
        )
        self.assertEqual([f["token_id"] for f in report["findings"]], ["long"])
        self.assertEqual(report["benign_decisions"], [])


class TestS3PermissionTriggerPolicy(unittest.TestCase):
    CASES = [
        # (permissions, trigger, runs_untrusted_code, allowed)
        ("read-only", "pull_request", True, True),
        ("read-only", "tag", False, True),
        ("release-write", "tag", False, True),
        ("release-write", "tag", True, False),
        ("release-write", "pull_request", False, False),
        ("release-write", "pull_request", True, False),
        ("write-all", "tag", False, False),
        ("write-all", "pull_request", True, False),
        ("admin", "tag", False, False),  # unknown permission fails closed
    ]

    def test_exact_policy_table(self):
        for perm, trigger, untrusted, allowed in self.CASES:
            with self.subTest(perm=perm, trigger=trigger, untrusted=untrusted):
                wf = workflow(permissions=perm, trigger=trigger, runs_untrusted_code=untrusted)
                self.assertEqual(audit.permission_allowed(wf), allowed)
                self.assertEqual(len(audit.check_s3(wf)), 0 if allowed else 1)


class TestS5ArtifactWildcardExpansion(SnapshotCase):
    FILES = {
        "app/env.txt": "TENANT=red\n",
        "app/readme.txt": "hi\n",
        "docs/rotation.txt": "note\n",
        "build/report.txt": "ok\n",
    }

    def s5_patterns(self, patterns, sensitive=audit.DEFAULT_SENSITIVE_PATHS):
        report = self.run_audit({}, [workflow(artifact_paths=patterns)], self.FILES,
                                sensitive_paths=sensitive)
        return {f["evidence"]["artifact_pattern"]: f["evidence"]["matches_sensitive"]
                for f in report["findings"] if f["rule_id"] == "S5"}

    def test_wildcards_expand_to_sensitive_files(self):
        hits = self.s5_patterns(["app/*", "docs/rot*.txt", "*", "build/report.txt", "app/readme.txt"])
        self.assertEqual(hits, {
            "app/*": ["app/env.txt"],
            "docs/rot*.txt": ["docs/rotation.txt"],
            "*": ["app/env.txt", "docs/rotation.txt"],
        })

    def test_s5_fires_with_no_tokens_at_all(self):
        # Protects future credentials: no active token needed.
        self.assertIn("app/*", self.s5_patterns(["app/*"]))

    def test_pattern_for_file_not_supplied_does_not_match(self):
        self.assertEqual(self.s5_patterns(["secrets/*", "app/env.bak"]), {})

    def test_sensitive_paths_are_configurable(self):
        self.assertEqual(self.s5_patterns(["app/*"], sensitive=("app/readme.txt",)),
                         {"app/*": ["app/readme.txt"]})


class TestS2S4SecretIntersection(SnapshotCase):
    def ci_rules(self, wf, tokens):
        report = self.run_audit(tokens, [wf], {})
        return sorted(f["rule_id"] for f in report["findings"]), report

    def test_untrusted_with_active_secret_is_s2(self):
        rules, _ = self.ci_rules(workflow(secret_refs=["k"]), {"k": ("DEMO_A", ACTIVE)})
        self.assertEqual(rules, ["S2"])

    def test_untrusted_with_revoked_secret_is_not_s2(self):
        rules, _ = self.ci_rules(workflow(secret_refs=["k"]), {"k": ("DEMO_A", REVOKED)})
        self.assertEqual(rules, [])

    def test_trusted_with_active_secret_is_not_s2(self):
        rules, _ = self.ci_rules(
            workflow(trigger="tag", runs_untrusted_code=False, secret_refs=["k"]),
            {"k": ("DEMO_A", ACTIVE)})
        self.assertEqual(rules, [])

    def test_env_logging_with_active_secret_is_s4_even_when_trusted(self):
        rules, _ = self.ci_rules(
            workflow(trigger="tag", runs_untrusted_code=False, log_environment=True, secret_refs=["k"]),
            {"k": ("DEMO_A", ACTIVE)})
        self.assertEqual(rules, ["S4"])

    def test_unknown_token_state_in_ref_counts_for_s2(self):
        rules, _ = self.ci_rules(workflow(secret_refs=["k"]), {"k": ("DEMO_A", "pending_review")})
        self.assertEqual(rules, ["S2"])

    def test_unknown_ref_is_unresolved_not_invented(self):
        rules, report = self.ci_rules(
            workflow(secret_refs=["ghost"], log_environment=True), {})
        self.assertEqual(rules, [])
        self.assertEqual([(u["workflow_id"], u["secret_ref"]) for u in report["unresolved_refs"]],
                         [("wf", "ghost")])


class TestCiBenignDecisions(SnapshotCase):
    """CI benign decisions are evidence the README requires; assert them."""

    def test_trusted_release_workflow_is_recorded_as_benign(self):
        report = self.run_audit(
            {"k": ("DEMO_A", ACTIVE), "old": ("DEMO_OLD", REVOKED)},
            [workflow(workflow_id="rel", trigger="tag", runs_untrusted_code=False,
                      permissions="release-write", secret_refs=["k", "old"])],
            {},
        )
        self.assertEqual(report["findings"], [])
        benign = [(r["rule_id"], r["location"], r["evidence"]) for r in report["benign_decisions"]]
        self.assertEqual(benign, [
            ("S3", "workflow:rel",
             {"permissions": "release-write", "trigger": "tag", "runs_untrusted_code": False}),
            ("S2/S4", "workflow:rel",
             {"active_secret_refs": ["k"], "runs_untrusted_code": False, "log_environment": False}),
            ("S2/S4", "workflow:rel", {"non_sensitive_secret_refs": ["old"]}),
        ])

    def test_disallowed_release_write_is_finding_not_benign(self):
        report = self.run_audit({}, [workflow(permissions="release-write")], {})
        self.assertEqual(self.keys(report["findings"]), {("S3", "workflow:wf")})
        self.assertEqual(report["benign_decisions"], [])


class TestCommandLine(SnapshotCase):
    """Documented command-line behaviour: options, files and exit codes."""

    FILES = {"app/env.txt": "x\n", "build/report.txt": "ok\n"}

    def cli(self, *args) -> tuple:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = audit.main([str(a) for a in args])
        return code, out.getvalue(), err.getvalue()

    def test_sensitive_path_flag_replaces_defaults(self):
        root = self.make_snapshot({}, [workflow(artifact_paths=["app/*", "build/report.txt"])], self.FILES)
        out_file = root / "r.json"
        code, _, _ = self.cli(root, "--sensitive-path", "build/report.txt", "--json", out_file)
        report = json.loads(out_file.read_text())
        self.assertEqual(code, 0)
        self.assertEqual(report["sensitive_paths"], ["build/report.txt"])
        # app/env.txt is no longer sensitive, so app/* is not a finding.
        self.assertEqual([f["evidence"]["artifact_pattern"] for f in report["findings"]], ["build/report.txt"])

    def test_fail_on_findings_exit_codes(self):
        risky = self.make_snapshot({}, [workflow(artifact_paths=["app/*"])], self.FILES)
        clean = self.make_snapshot({}, [workflow()], self.FILES)
        self.assertEqual(self.cli(risky, "--fail-on-findings")[0], 1)
        self.assertEqual(self.cli(clean, "--fail-on-findings")[0], 0)
        self.assertEqual(self.cli(risky)[0], 0)  # findings alone are not an error

    def test_summary_file_matches_stdout(self):
        root = self.make_snapshot({}, [workflow(artifact_paths=["app/*"])], self.FILES)
        summary_file = root / "out" / "summary.txt"
        code, out, _ = self.cli(root, "--summary", summary_file)
        self.assertEqual(code, 0)
        self.assertEqual(summary_file.read_text(), out)
        self.assertIn("[S5] workflow:wf", out)

    def test_missing_input_file_exits_2(self):
        root = self.make_snapshot({}, [], {})
        (root / "ci.json").unlink()
        code, out, err = self.cli(root)
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertEqual(err, f"error: {root} must contain inventory.json and ci.json\n")


class TestInputValidation(SnapshotCase):
    """Malformed input is rejected with a clear message and exit 2, never
    silently passed. Before validation, runs_untrusted_code="true" gave no S2."""

    TOKENS = {"k": ("DEMO_ACTIVE_V", ACTIVE)}

    def cli(self, root: Path) -> tuple:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = audit.main([str(root)])
        return code, out.getvalue(), err.getvalue()

    def test_string_flag_is_rejected_not_passed(self):
        root = self.make_snapshot(self.TOKENS, [workflow(runs_untrusted_code="true", secret_refs=["k"])], {})
        with self.assertRaises(audit.SchemaError) as ctx:
            audit.audit(root)
        self.assertEqual(ctx.exception.errors,
                         ["ci.json: workflow 'wf': runs_untrusted_code must be true or false (found str)"])
        code, out, err = self.cli(root)
        self.assertEqual(code, 2)
        self.assertEqual(out, "")  # no partial report

    def test_unknown_trigger_and_permission_rejected_together(self):
        root = self.make_snapshot({}, [workflow(trigger="push", permissions="admin")], {})
        code, _, err = self.cli(root)
        self.assertEqual(code, 2)
        self.assertIn("trigger must be one of pull_request, tag", err)
        self.assertIn("permissions must be one of read-only, release-write, write-all", err)

    def test_missing_field_is_reported(self):
        wf = workflow()
        del wf["log_environment"]
        root = self.make_snapshot({}, [wf], {})
        self.assertIn("log_environment must be true or false (found missing)", self.cli(root)[2])

    def test_malformed_json_is_clear_error(self):
        root = self.make_snapshot({}, [], {})
        (root / "ci.json").write_text("{not json")
        code, _, err = self.cli(root)
        self.assertEqual(code, 2)
        self.assertIn("ci.json: invalid JSON", err)
        self.assertNotIn("Traceback", err)

    def test_errors_from_both_files_reported_in_one_run(self):
        root = self.make_snapshot({}, [workflow(trigger="push")], {})
        (root / "inventory.json").write_text(json.dumps({"tokens": [{"token_id": "k", "value": 5, "state": ACTIVE}]}))
        code, _, err = self.cli(root)
        self.assertEqual(code, 2)
        self.assertIn("inventory.json: tokens[0].value must be a string", err)
        self.assertIn("workflow 'wf': trigger must be one of", err)

    def test_error_messages_never_contain_token_values(self):
        root = self.make_snapshot({}, [], {})
        (root / "inventory.json").write_text(json.dumps({"tokens": [
            {"token_id": "k", "value": "DEMO_ACTIVE_V", "state": 3}]}))
        code, out, err = self.cli(root)
        self.assertEqual(code, 2)
        self.assertNotIn("DEMO_ACTIVE_V", out + err)


class TestSuppliedSnapshots(unittest.TestCase):
    """Regression: expected decisions on the two supplied snapshots."""

    def keys(self, records):
        return {(r["rule_id"], r["location"]) for r in records}

    def test_snapshot_one(self):
        report = audit.audit(ROOT / "inputs" / "snapshot-one")
        self.assertEqual(self.keys(report["findings"]), {
            ("S1", "app/env.txt:2"),
            ("S2", "workflow:pr-build"),
            ("S3", "workflow:pr-build"),
            ("S4", "workflow:pr-build"),
            ("S5", "workflow:pr-build"),
        })
        self.assertTrue({("S1", "tests/mock.txt:2"), ("S1", "docs/rotation.txt:1")}
                        <= self.keys(report["benign_decisions"]))

    def test_snapshot_two_rotation_did_not_fix_everything(self):
        report = audit.audit(ROOT / "inputs" / "snapshot-two")
        self.assertEqual(self.keys(report["findings"]), {
            ("S1", "docs/rotation.txt:2"),
            ("S5", "workflow:pr-build"),
        })
        s1 = next(f for f in report["findings"] if f["rule_id"] == "S1")
        self.assertEqual(s1["token_id"], "release-rotated")
        # The old value in app/env.txt is now revoked: benign, not S1.
        self.assertIn(("S1", "app/env.txt:2"), self.keys(report["benign_decisions"]))

    def test_cli_output_never_contains_token_values(self):
        for name in ("snapshot-one", "snapshot-two"):
            with self.subTest(snapshot=name):
                buf = io.StringIO()
                with tempfile.TemporaryDirectory() as tmp, redirect_stdout(buf):
                    out = Path(tmp) / "r.json"
                    code = audit.main([str(ROOT / "inputs" / name), "--json", str(out)])
                    written = out.read_text()
                self.assertEqual(code, 0)
                self.assertNotIn("DEMO_", buf.getvalue() + written)

    def test_safety_net_refuses_output_cleanly(self):
        # Simulate a redaction bug: the safety net must stop with exit 2 and
        # a clear message, print no token value and write no file.
        err = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(audit, "redact", lambda text, pairs: text), \
                redirect_stdout(io.StringIO()) as out, redirect_stderr(err):
            out_file = Path(tmp) / "r.json"
            code = audit.main([str(ROOT / "inputs" / "snapshot-two"), "--json", str(out_file)])
            written = out_file.exists()
        self.assertEqual(code, 2)
        self.assertRegex(err.getvalue(),
                         r"^error: refusing to output unredacted value of '[\w-]+'; no output written\n$")
        self.assertNotIn("DEMO_", out.getvalue() + err.getvalue())
        self.assertFalse(written)

    def test_cli_handles_blank_inventory_value(self):
        # The output safety net must not treat a blank value as "found everywhere".
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "inventory.json").write_text(json.dumps({"tokens": [
                {"token_id": "blank", "value": "", "state": ACTIVE}]}))
            (root / "ci.json").write_text(json.dumps({"workflows": []}))
            (root / "app").mkdir()
            (root / "app" / "a.txt").write_text("hello\n")
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = audit.main([str(root)])
        self.assertEqual(code, 0)
        self.assertIn("token_id=blank", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
