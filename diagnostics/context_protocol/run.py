"""Run the complete new context-protocol Source controls on exact product bytes."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import platform
import re
import signal
import subprocess
import sys
import time


def identity(path):
    data = path.read_bytes()
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    args = parser.parse_args()
    repository = args.repository.resolve()
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    here = Path(__file__).resolve().parent
    manifest = json.loads((here / "source-manifest.json").read_bytes())

    def git(*arguments):
        return subprocess.check_output(["git", *arguments], cwd=repository, text=True).rstrip("\n")

    assert platform.python_implementation() == "CPython"
    assert sys.version_info[:2] == (3, 14), sys.version
    assert git("rev-parse", "HEAD") == manifest["product_head"]
    assert git("rev-parse", "HEAD^{tree}") == manifest["product_tree"]
    assert git("status", "--porcelain", "--untracked-files=all") == ""
    assert len(manifest["source"]) == 4
    assert len(manifest["complete_test_ids"]) == 9
    assert len(set(manifest["complete_test_ids"])) == 9
    before = {}
    for name, entry in manifest["source"].items():
        target = repository / name
        observed = identity(target) if target.exists() else None
        assert observed == entry["before"], name
        source = here / "source" / name
        assert identity(source) == entry["after"], name
        before[name] = observed
    save(evidence / "source-before.json", before)
    for name in manifest["source"]:
        target = repository / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((here / "source" / name).read_bytes())
    patched = {name: identity(repository / name) for name in manifest["source"]}
    save(evidence / "source-selected.json", patched)
    runtime = {"sys_version": sys.version, "executable": sys.executable,
               "resolved_executable": str(Path(sys.executable).resolve()),
               "executable_identity": identity(Path(sys.executable).resolve()),
               "implementation": platform.python_implementation()}
    save(evidence / "runtime.json", runtime)
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith("HEPTA_HIA_") and key not in ("PYTHONPATH", "PYTHONHOME")}
    environment.update(PYTHONDONTWRITEBYTECODE="1", PYTHON_COLORS="0")
    command = [sys.executable, "-B", "tools/run_hia_unittest_gate.py", "tests.test_hia_context_protocol"]
    child = None
    signals = []
    failure = None
    started = time.monotonic()
    code = None
    with (evidence / "stdout.log").open("xb") as stdout, (evidence / "stderr.log").open("xb") as stderr:
        try:
            child = subprocess.Popen(command, cwd=repository, env=environment,
                                     stdout=stdout, stderr=stderr, start_new_session=True)
            save(evidence / "start.json", {"pid": child.pid, "command": command,
                 "source_test_budget_seconds": 60, "scope": "new Source controls only"})
            code = child.wait(timeout=60)
        except BaseException as error:
            failure = {"type": type(error).__name__, "message": str(error)}
            if child is not None:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                    signals.append("SIGKILL-own-process-group")
                except ProcessLookupError:
                    pass
                code = child.wait()
    elapsed = time.monotonic() - started
    group_absent = child is None
    if child is not None:
        try:
            os.killpg(child.pid, 0)
        except ProcessLookupError:
            group_absent = True
        else:
            try:
                os.killpg(child.pid, signal.SIGKILL)
                signals.append("SIGKILL-own-residual-process-group")
            except ProcessLookupError:
                pass
    after = {name: identity(repository / name) for name in manifest["source"]}
    save(evidence / "source-after.json", after)
    raw = (evidence / "stderr.log").read_text()
    terminal = re.findall(r"^test_[^\n]+ \((tests\.test_hia_context_protocol\.[^)]+)\) \.\.\. (ok|FAIL|ERROR|skipped[^\n]*)$", raw, re.M)
    summaries = re.findall(r"^Ran (\d+) tests in ([0-9.]+)s$", raw, re.M)
    dirty = git("status", "--porcelain", "--untracked-files=all")
    actual_paths = sorted(line[3:] for line in dirty.splitlines())
    passed = (code == 0 and failure is None and group_absent and not signals
              and patched == after
              and actual_paths == sorted(manifest["source"])
              and len(terminal) == 9
              and sorted(name for name, _ in terminal) == sorted(manifest["complete_test_ids"])
              and all(status == "ok" for _, status in terminal)
              and len(summaries) == 1 and summaries[0][0] == "9")
    report = {"schema": "hepta.context-protocol-source-diagnostic.v1",
              "status": "PASS" if passed else "HOLD", "product_head": manifest["product_head"],
              "product_tree": manifest["product_tree"], "source_manifest": identity(here / "source-manifest.json"),
              "runtime": runtime, "returncode": code, "failure": failure,
              "outer_seconds": elapsed, "unittest_summaries": summaries,
              "planned_test_ids": manifest["complete_test_ids"], "terminal_tests": terminal,
              "source_unchanged": patched == after, "git_status": dirty,
              "signals_sent": signals, "owned_process_group_absent": group_absent,
              "stdout": identity(evidence / "stdout.log"), "stderr": identity(evidence / "stderr.log"),
              "qualification_scope": "complete new Source regression module on exact four-file patch only",
              "native_executed": False, "vm_executed": False, "current_source_cold_qualified": False,
              "whole_native_delivery_qualified": False, "old_stack_can_be_removed": False,
              "production_activated": False}
    save(evidence / "report.json", report)
    print(json.dumps(report, indent=2, sort_keys=True), flush=True)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
