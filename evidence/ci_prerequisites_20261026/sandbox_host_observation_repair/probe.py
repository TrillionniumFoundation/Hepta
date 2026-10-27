#!/usr/bin/env python3
"""Actual namespace/native controls; only host stat or synthetic canary mount is injected."""
import argparse
from contextlib import nullcontext
import errno
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

sys.path.insert(0, str(Path.cwd()))
from experiments.agent_eval import sandbox_qualification as qualification
from tools.release_check import require_collected_qualification


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rustc", required=True)
    args = parser.parse_args()
    args.output.mkdir()
    before = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    assert not subprocess.check_output(["git", "diff", "--name-only", "HEAD"])
    result = {"schema": "hepta.sandbox-host-observation-controls.v1", "source_commit": before,
              "probe_sha256": sha256(Path(__file__).read_bytes()).hexdigest(),
              "scope": "Actual sandbox/native controls with explicit trusted fault injection; no model run.",
              "planned_cases": 3, "completed_cases": 0, "ok": False, "cases": []}
    original_stat = Path.stat
    original_wrap = qualification.wrap_command

    def checkpoint():
        (args.output / "review.json").write_text(json.dumps(result, indent=2) + "\n")

    checkpoint()
    for name in ("ordinary_host_metadata", "denied_host_proc_stat", "readable_canary_negative_control"):
        denied = []

        def denied_stat(path, *positional, **keywords):
            if str(path).startswith("/proc/1/root/"):
                denied.append(str(path))
                raise PermissionError(errno.EACCES, "injected host-only procfs stat denial", str(path))
            return original_stat(path, *positional, **keywords)

        def expose_only_canary(command, capsule, **options):
            argv = original_wrap(command, capsule, **options)
            marker = capsule.parent / "parent_oracle_canary"
            assert marker.read_text() == "qualification-only parent oracle marker\n"
            offset = argv.index("--")
            argv[offset:offset] = ["--ro-bind", str(marker), str(marker)]
            return argv

        entry = {"name": name, "status": "running", "passed_control": False}
        result["cases"].append(entry)
        checkpoint()
        with (patch.object(Path, "stat", denied_stat) if name != "ordinary_host_metadata" else nullcontext()), \
                (patch.object(qualification, "wrap_command", expose_only_canary)
                 if name == "readable_canary_negative_control" else nullcontext()):
            observed = qualification.qualify_sandbox(args.rustc)
        raw = (json.dumps(observed, indent=2, sort_keys=True) + "\n").encode()
        filename = name + ".json"
        (args.output / filename).write_bytes(raw)
        entry.update(status="completed", report=filename, bytes=len(raw), sha256=sha256(raw).hexdigest(),
                     denied_host_stat_paths=denied, qualified=observed["qualified"], checks=observed["checks"])
        result["completed_cases"] += 1
        checkpoint()
        if name != "ordinary_host_metadata":
            assert len(denied) == 1, entry
            host = observed["boundary"]["paths"]["proc_init_root_escape"]
            assert host["host_exists"] is None and host["host_stat_status"] == "unobservable", host
            assert host["host_stat_errno"] == errno.EACCES, host
        if name == "readable_canary_negative_control":
            assert observed["qualified"] is False
            assert observed["checks"]["parent_paths_unreadable"]["status"] == "failed"
            assert observed["boundary"]["inside"]["path_checks"]["parent_oracle_canary"]["unreadable"] is False
            assert observed["checks"]["hepta_rust_native"]["status"] == "not_run"
            try:
                require_collected_qualification("strict_namespace_execution", observed)
            except ValueError:
                entry["release_collector_rejected"] = True
            else:
                raise AssertionError("Release collector accepted an exposed canary")
        else:
            assert observed["qualified"] is True, observed
            assert len(observed["checks"]) == 10
            assert all(item["status"] == "passed" for item in observed["checks"].values())
            assert observed["native_process"]["returncode"] == 0
            require_collected_qualification("strict_namespace_execution", observed)
            entry["release_collector_accepted"] = True
        entry["passed_control"] = True
        checkpoint()
        print(json.dumps({"case": name, "qualified": observed["qualified"], "passed_control": True}), flush=True)
    after = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    assert before == after and not subprocess.check_output(["git", "diff", "--name-only", "HEAD"])
    result["unchanged_git_head_and_tracked_files"] = True
    result["ok"] = all(item["passed_control"] for item in result["cases"])
    checkpoint()
    print(json.dumps({"ok": result["ok"], "completed_cases": result["completed_cases"]}), flush=True)


if __name__ == "__main__":
    main()
