#!/usr/bin/env python3
"""Run the integrated HIA gates against one unchanged, committed source tree.

An actual compiler/test/native run is required for every planned gate. The
collector records skips and failures and continues independent gates. Scoped
success never upgrades the six-part research/production request to complete.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.clang_capture import CaptureRejected, run_bounded
from hepta.pipeline import compiler_hash
from tools.release_check import snapshot


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write_new(path, data):
    with path.open("xb") as stream:
        stream.write(data)


def _command(argv, timeout=1800):
    started = time.monotonic()
    try:
        value = run_bounded(list(map(str, argv)), timeout=timeout, stdin_limit=0,
                            stdout_limit=4 * 1024 * 1024, stderr_limit=8 * 1024 * 1024)
        return {"argv": list(map(str, argv)), "returncode": value.returncode,
                "stdout": value.stdout, "stderr": value.stderr,
                "seconds": time.monotonic() - started}
    except CaptureRejected as exc:
        return {"argv": list(map(str, argv)), "returncode": None,
                "stdout": "", "stderr": str(exc), "capture_error": exc.code,
                "seconds": time.monotonic() - started}


def unittest_outcome(stderr, returncode):
    """Retain failed-run counts without accepting partial or skipped runs."""
    match = re.search(
        r"(?m)^Ran ([0-9]+) tests? in [0-9.]+s\s+"
        r"(OK|FAILED)(?: \(([^\n]*)\))?\s*\Z", stderr)
    result = {"tests_run": None, "skipped": None, "failures": None,
              "errors": None, "passed": False}
    if match is None:
        return result
    result.update(tests_run=int(match.group(1)), skipped=0, failures=0, errors=0)
    details = match.group(3)
    if details:
        for item in details.split(", "):
            field = re.fullmatch(r"(skipped|failures|errors)=([0-9]+)", item)
            if field is None:
                # Expected/unexpected successes or a changed summary format
                # require an explicit policy before the aggregate can pass.
                return result
            result[field.group(1)] = int(field.group(2))
    result["passed"] = (returncode == 0 and match.group(2) == "OK"
                        and result["tests_run"] > 0
                        and result["skipped"] == 0
                        and result["failures"] == 0
                        and result["errors"] == 0)
    return result


def qualify(output, *, clang, rustc, qemu_aarch64, qemu_system_arm, linker):
    output = Path(output).absolute()
    if output.exists() or output.is_symlink():
        raise ValueError("output directory must be new")
    before = snapshot()
    commit = _command(["git", "-C", ROOT, "rev-parse", "HEAD"], 10)
    dirty = _command(["git", "-C", ROOT, "status", "--porcelain", "--untracked-files=no"], 10)
    if commit["returncode"] != 0 or dirty["returncode"] != 0 or dirty["stdout"].strip():
        raise ValueError("commit tracked implementation before running the qualification")
    output.mkdir(parents=True)
    python = sys.executable
    plan = [
        ("unit_regression", [python, "-m", "unittest", "discover", "-s", "tests", "-q"], None),
        ("standalone_native", [python, "tools/qualify_hia_program.py", "--clang", clang,
                               "--output", output / "native.json"], output / "native.json"),
        ("standalone_resources", [python, "tools/qualify_hia_program_resources.py",
                                  "--output", output / "resources.json"], output / "resources.json"),
        ("source_migration", [python, "tools/qualify_hia_migration.py", "--clang", clang,
                              "--clangxx", str(Path(clang).with_name("clang++")),
                              "--workdir", output / "migration"], output / "migration/qualification.json"),
        ("standalone_aarch64_qemu", [python, "tools/qualify_hia_program_aarch64.py", "--clang", clang,
                                   "--linker", linker, "--qemu-aarch64", qemu_aarch64,
                                   "--output", output / "aarch64.json"], output / "aarch64.json"),
        ("legacy_executable_core", [python, "-m", "hepta.executable_core_qualify", "--clang", clang,
                                    "--rustc", rustc, "--report", output / "legacy-core.json"], output / "legacy-core.json"),
        ("legacy_hosted_composition", [python, "-m", "tools.qualify_lifecycle_composition",
                                       "--rustc", rustc, "--output", output / "hosted-composition.json"], output / "hosted-composition.json"),
        ("legacy_cortex_m4_qemu", [python, "tools/validate_board.py", "--rustc", rustc,
                                   "--qemu", qemu_system_arm, "--output", output / "board.json"], output / "board.json"),
        ("standalone_performance", [python, "tools/qualify_hia_program_perf.py", "--clang", clang,
                                    "--rustc", rustc, "--output", output / "performance.json"], output / "performance.json"),
    ]
    report = {"schema": "hepta.hia.unified-qualification.v1", "git_commit": commit["stdout"].strip(),
        "compiler_tree_sha256": compiler_hash(), "source_snapshot_before": before,
        "temporary_directory": tempfile.gettempdir(),
        "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "planned_gates": [name for name, _, _ in plan], "gates": [],
        "full_six_deliverables_complete": False,
        "scope_limits": ["General ADT/lifetime/task/cancellation composition is not closed in standalone HIA",
            "C/C++ migration covers declared finite profiles, not arbitrary historical libraries",
            "QEMU is not physical hardware or device timing/protocol qualification",
            "Agent productivity and independent total development-cost improvement require their own qualified trials",
            "Whole-compiler soundness and Rust-wide performance superiority are unproved"]}
    write_new(output / "plan.json", (json.dumps({"git_commit": report["git_commit"],
        "source_snapshot_sha256": before["sha256"],
        "commands": [{"name": name, "argv": list(map(str, argv))} for name, argv, _ in plan]},
        indent=2, sort_keys=True) + "\n").encode())
    previous_cwd, old_path = Path.cwd(), os.environ.get("PATH", "")
    old_rustc, old_clang = os.environ.get("RUSTC"), os.environ.get("CLANG")
    try:
        os.chdir(ROOT)
        with tempfile.TemporaryDirectory(prefix="hepta-hia-gate-tools-") as directory:
            bin_dir = Path(directory)
            if Path(qemu_aarch64).is_file():
                (bin_dir / "qemu-aarch64").symlink_to(Path(qemu_aarch64).resolve())
            if Path(linker).is_file():
                (bin_dir / "ld.lld").symlink_to(Path(linker).resolve())
            os.environ["PATH"] = os.pathsep.join([str(bin_dir), str(Path(clang).parent),
                                                  str(Path(rustc).parent), old_path])
            os.environ["RUSTC"], os.environ["CLANG"] = rustc, clang
            os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
            for name, argv, evidence in plan:
                print(json.dumps({"gate": name, "status": "running"}), flush=True)
                executed = _command(argv)
                row = {k: v for k, v in executed.items() if k not in {"stdout", "stderr"}}
                row["name"], row["passed"] = name, False
                for channel in ("stdout", "stderr"):
                    raw = executed[channel].encode()
                    logfile = output / (name + "." + channel + ".log")
                    write_new(logfile, raw)
                    row[channel] = {"path": str(logfile.relative_to(output)), "sha256": sha(raw), "bytes": len(raw)}
                if evidence is None:
                    row.update(unittest_outcome(executed["stderr"], executed["returncode"]))
                elif evidence.is_file() and not evidence.is_symlink():
                    raw = evidence.read_bytes()
                    payload = json.loads(raw)
                    row["evidence"] = {"path": str(evidence.relative_to(output)), "sha256": sha(raw),
                                       "status": payload.get("status"), "ok": payload.get("ok")}
                    scoped_ok = payload.get("ok") is True or (name == "legacy_cortex_m4_qemu" and payload.get("status") == "passed")
                    row["passed"] = executed["returncode"] == 0 and scoped_ok
                report["gates"].append(row)
                print(json.dumps({"gate": name, "passed": row["passed"], "seconds": row["seconds"],
                                  "returncode": row["returncode"]}), flush=True)
    finally:
        os.chdir(previous_cwd)
        os.environ["PATH"] = old_path
        for name, value in (("RUSTC", old_rustc), ("CLANG", old_clang)):
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
    report["source_snapshot_after"] = snapshot()
    report["unchanged_source"] = before == report["source_snapshot_after"]
    report["completed_gates"] = len(report["gates"])
    report["passed_gates"] = sum(row["passed"] for row in report["gates"])
    report["ok"] = report["unchanged_source"] and report["completed_gates"] == len(plan) and all(row["passed"] for row in report["gates"])
    report["status"] = "all_scoped_gates_passed" if report["ok"] else "scoped_gates_not_all_qualified"
    report["finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    write_new(output / "qualification.json", (json.dumps(report, indent=2, sort_keys=True) + "\n").encode())
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-directory", required=True)
    parser.add_argument("--clang", default=shutil.which("clang") or "clang")
    parser.add_argument("--rustc", default=os.environ.get("RUSTC") or shutil.which("rustc") or "rustc")
    parser.add_argument("--qemu-aarch64", required=True)
    parser.add_argument("--qemu-system-arm", default=shutil.which("qemu-system-arm") or "qemu-system-arm")
    parser.add_argument("--linker", required=True)
    args = parser.parse_args()
    result = qualify(args.output_directory, clang=args.clang, rustc=args.rustc,
                     qemu_aarch64=args.qemu_aarch64, qemu_system_arm=args.qemu_system_arm, linker=args.linker)
    print(json.dumps({key: result[key] for key in ("ok", "status", "passed_gates", "completed_gates", "unchanged_source", "full_six_deliverables_complete")}))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
