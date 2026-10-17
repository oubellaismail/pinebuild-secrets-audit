"""Break audit.py on purpose (in temp copies) and confirm the tests fail."""
import shutil, subprocess, sys, tempfile
from pathlib import Path

root = Path(sys.argv[1]).resolve()
src = (root / "audit.py").read_text()
MUTANTS = {
    "S3 ignores runs_untrusted_code": (
        'return wf["trigger"] == TRIGGER_TAG and wf["runs_untrusted_code"] is False',
        'return wf["trigger"] == TRIGGER_TAG'),
    "S1 flags every state": ("sensitive = is_sensitive(state)", "sensitive = True"),
    "S5 exact match only (no wildcard)": (
        "fnmatchcase(f, pattern) and f in sensitive_paths", "f == pattern and f in sensitive_paths"),
    "S2 counts revoked refs": (
        'if wf["runs_untrusted_code"] is True and sensitive_refs:',
        'if wf["runs_untrusted_code"] is True and wf["secret_refs"]:'),
    "redaction disabled": ('text = text.replace(value, f"[REDACTED:{token_id}]")', "pass"),
    "CI schema validation skipped": ("    errors = validate_ci(data)\n", "    errors = []\n"),
}
for name, (old, new) in MUTANTS.items():
    assert src.count(old) == 1, f"mutant target not found exactly once: {name}"
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp / "audit.py").write_text(src.replace(old, new, 1))
        shutil.copytree(root / "tests", tmp / "tests")
        (tmp / "inputs").symlink_to(root / "inputs")
        r = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests"],
                           cwd=tmp, capture_output=True, text=True)
        last = r.stderr.strip().splitlines()[-1]
        print(f"{'CAUGHT' if r.returncode else 'MISSED'}  {name}: {last}")
