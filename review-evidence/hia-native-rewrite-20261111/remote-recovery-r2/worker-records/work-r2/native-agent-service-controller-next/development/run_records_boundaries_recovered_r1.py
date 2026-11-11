"""Run each remaining record boundary under its unchanged child resource limits."""
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import time
ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "development/test_records_boundaries_recovered_r1.py"
OUT = ROOT / "development/records-boundaries-suite-recovered-r1"
OUT.mkdir(parents=True, exist_ok=False)
script_raw = SCRIPT.read_bytes()
rows = []
summary = dict(status="INCOMPLETE", scope="NEW_DEVELOPMENT_COMPONENT_TESTS_NOT_COLD",
               child_cpu_limit_seconds=90, child_address_space_bytes=1 << 30,
               script=dict(path=str(SCRIPT), bytes=len(script_raw), sha256=sha256(script_raw).hexdigest()))
try:
    for mode in ("small", "exact", "plusone"):
        case_out = ROOT / ("development/records-boundary-" + mode + "-recovered-r1")
        stdout_path = OUT / (mode + ".stdout.log")
        stderr_path = OUT / (mode + ".stderr.log")
        args = [sys.executable, str(SCRIPT), str(case_out), mode]
        start = time.monotonic_ns()
        with stdout_path.open("wb") as out, stderr_path.open("wb") as err:
            child = subprocess.Popen(args, cwd=ROOT, stdout=out, stderr=err)
            pid, status, usage = os.wait4(child.pid, 0)
            child.returncode = os.waitstatus_to_exitcode(status)
        row = dict(mode=mode, argv=args, pid=pid, wait_status=status, exit_code=child.returncode,
                   user_cpu_seconds=usage.ru_utime, system_cpu_seconds=usage.ru_stime,
                   max_rss_kib=usage.ru_maxrss, wall_ns=time.monotonic_ns() - start,
                   stdout=dict(path=str(stdout_path), bytes=stdout_path.stat().st_size, sha256=sha256(stdout_path.read_bytes()).hexdigest()),
                   stderr=dict(path=str(stderr_path), bytes=stderr_path.stat().st_size, sha256=sha256(stderr_path.read_bytes()).hexdigest()))
        if (case_out / "summary.json").exists():
            row["summary"] = json.loads((case_out / "summary.json").read_bytes())
        rows.append(row)
        (OUT / (mode + ".process.json")).write_text(json.dumps(row, indent=2, sort_keys=True) + "\n")
        print(json.dumps(row, sort_keys=True), flush=True)
        if child.returncode != 0:
            raise RuntimeError(("child boundary failed", mode, child.returncode))
    summary.update(status="PASS", children=rows)
finally:
    summary.setdefault("children", rows)
    if summary["status"] != "PASS":
        summary["status"] = "FAIL"
    summary["script_unchanged"] = SCRIPT.read_bytes() == script_raw
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, sort_keys=True), flush=True)
    assert summary["script_unchanged"]
