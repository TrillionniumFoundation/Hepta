"""Record one already registered native study without retrying or changing it."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=("stream-ndu", "prepared-runtime"))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    scope = "hia_ndu_graph_eval" if args.kind == "stream-ndu" else "hia_stateful_eval"
    evidence = root / "experiments" / scope / "round3_20261028"
    output = Path("/tmp/hepta-round3-ndu-graph-01" if args.kind == "stream-ndu"
                  else "/tmp/hepta-round3-owned-runtime-01")
    record_path = evidence / "trial01.outer.json"
    stdout_path = evidence / "trial01.stdout.txt"
    stderr_path = evidence / "trial01.stderr.txt"
    if output.exists() or any(p.exists() for p in (record_path, stdout_path, stderr_path)):
        raise FileExistsError("This fixed trial already has output; no automatic retry")
    command = [sys.executable, "tools/qualify_hia_registered_followup.py", "run",
               "--protocol", str(evidence / "PROTOCOL.json"),
               "--registration", str(evidence / "REGISTRATION.json"),
               "--output", str(output), "--clang", os.environ["CLANG"]]
    if args.kind == "stream-ndu":
        command += ["--native-identity", os.environ["HEPTA_NDU_IDENTITY"]]
    record = {"schema": "hepta.hia.registered-followup.outer.v1", "kind": args.kind,
              "command": command, "cwd": str(root), "output": str(output),
              "recorder_sha256": sha256(Path(__file__).read_bytes()).hexdigest(),
              "environment_script_sha256": sha256(Path("/tmp/hepta-round3-env.sh").read_bytes()).hexdigest(),
              "automatic_retries": 0, "scientific_gate_authority": False,
              "cost_scope": "whole child command including Python startup and final report; nested in this outer observation, not added again to registered costs",
              "excluded": ["environment setup before recorder", "recorder startup", "final outer record write", "later lossless archival", "earlier tool acquisition and engineering"]}
    with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
        usage_before = resource.getrusage(resource.RUSAGE_CHILDREN)
        started = time.monotonic_ns()
        record["started_unix_ns"] = time.time_ns()
        process = None
        try:
            process = subprocess.Popen(command, cwd=root, stdout=stdout, stderr=stderr,
                                       start_new_session=True)
            record["exit_code"] = process.wait()
        except BaseException as error:
            record["error"] = type(error).__name__ + ": " + str(error)
            if process is not None and process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
                record["exit_code"] = process.returncode
                record["owned_process_group_cancelled"] = True
            raise
        finally:
            record["finished_unix_ns"] = time.time_ns()
            record["outer_wall_ns"] = time.monotonic_ns() - started
            usage_after = resource.getrusage(resource.RUSAGE_CHILDREN)
            record["child_cpu_ns"] = int(((usage_after.ru_utime + usage_after.ru_stime)
                - (usage_before.ru_utime + usage_before.ru_stime)) * 1_000_000_000)
            record["child_peak_rss_kib"] = usage_after.ru_maxrss
            stdout.flush()
            stderr.flush()
            record["stdout"] = {"file": stdout_path.name, "bytes": stdout_path.stat().st_size,
                                "sha256": sha256(stdout_path.read_bytes()).hexdigest()}
            record["stderr"] = {"file": stderr_path.name, "bytes": stderr_path.stat().st_size,
                                "sha256": sha256(stderr_path.read_bytes()).hexdigest()}
            with record_path.open("x") as stream:
                json.dump(record, stream, indent=2, sort_keys=True)
                stream.write("\n")
    print(json.dumps(record, sort_keys=True))
    return record["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
