"""Break audit.py on purpose (in temp copies) and confirm the tests fail."""
import shutil, subprocess, sys, tempfile
from pathlib import Path

root = Path(sys.argv[1]).resolve()
src = (root / "audit.py").read_text()
MUTANTS = {
    "S3 ignores runs_untrusted_code": (
        'return wf.get("trigger") == "tag" and wf.get("runs_untrusted_code") is False',
        'return wf.get("trigger") == "tag"'),
    "S1 flags every state": ("if is_sensitive(state):", "if True:"),
    "S5 exact match only (no wildcard)": (
        "fnmatchcase(f, pattern) and f in sensitive_paths", "f == pattern and f in sensitive_paths"),
    "S2 counts revoked refs": (
        'if wf.get("runs_untrusted_code") is True and sensitive:',
        'if wf.get("runs_untrusted_code") is True and wf.get("secret_refs"):'),
    "redaction disabled": ('text = text.replace(value, f"[REDACTED:{token_id}]")', "pass"),
}
for name, (old, new) in MUTANTS.items():
    assert old in src, name
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp / "audit.py").write_text(src.replace(old, new, 1))
        shutil.copytree(root / "tests", tmp / "tests")
        (tmp / "inputs").symlink_to(root / "inputs")
        r = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests"],
                           cwd=tmp, capture_output=True, text=True)
        last = r.stderr.strip().splitlines()[-1]
        print(f"{'CAUGHT' if r.returncode else 'MISSED'}  {name}: {last}")
