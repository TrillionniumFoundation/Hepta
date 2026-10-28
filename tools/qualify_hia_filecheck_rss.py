#!/usr/bin/env python3
"""Supplementary RSS diagnosis using unchanged, SHA-bound filecheck binaries.

The original timing experiment is immutable. This program compiles only a tiny
supervisor, obtains resource observations and preserves incidental child timing
fields without ranking performance. Launcher padding is an explicit control.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import shutil
import statistics
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL_PATH = ROOT / "experiments/hia_filecheck/RSS_DIAGNOSTIC_PROTOCOL_20261028.json"
SUPERVISOR_SOURCE = ROOT / "examples/hia_filecheck/rss_supervisor.c"


def require(condition, message):
    if not condition:
        raise ValueError("E_FILECHECK_RSS: " + message)


def identity(path):
    path = Path(path).absolute()
    data = path.read_bytes()
    return {"path": str(path), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def write_new(path, data):
    with Path(path).open("x") as stream:
        json.dump(data, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")


def source_bindings():
    return {str(p.relative_to(ROOT)): identity(p)["sha256"]
            for p in (Path(__file__), PROTOCOL_PATH, SUPERVISOR_SOURCE)}


def parent_memory():
    fields = {}
    for line in Path("/proc/self/status").read_text().splitlines():
        if line.startswith(("VmHWM:", "VmRSS:")):
            key, value, unit = line.split()
            require(unit == "kB", "unknown proc status unit")
            fields[key[:-1] + "_kib"] = int(value)
    require(len(fields) == 2, "launcher proc memory fields missing")
    fields["self_ru_maxrss_kib"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return fields


def stats(values):
    require(values, "empty resource group")
    return {"count": len(values), "minimum": min(values),
            "median": statistics.median(values), "maximum": max(values)}


class Diagnostic:
    def __init__(self, original_report, output, clang):
        self.original_path = Path(original_report).absolute()
        self.original_identity = identity(self.original_path)
        self.original = json.loads(self.original_path.read_text())
        self.protocol = json.loads(PROTOCOL_PATH.read_text())
        self.out = Path(output).absolute()
        require(not self.out.exists(), "new output directory required")
        require(platform.system() == "Linux", "Linux resource accounting required")
        require(self.original_identity["sha256"] == self.protocol["original_report_sha256"], "original report differs from preregistration")
        require(self.original["git"] == self.protocol["original_source_commit"] and self.original["ok"], "original qualification identity/status differs")
        require(len(self.original["samples"]) == self.protocol["original_performance_samples"] and
                sorted({r["observation"]["peak_rss_kib"] for r in self.original["samples"]}) == self.protocol["original_observed_rss_kib"],
                "original RSS trigger differs from preregistration")
        require(self.original["protocol"]["arms"] == self.protocol["arms"], "arm mismatch")
        self.clang = str(Path(shutil.which(clang) or clang).absolute())
        self.source = source_bindings()
        self.head = subprocess.check_output(["git", "-C", ROOT, "rev-parse", "HEAD"], text=True).strip()
        status = subprocess.check_output(["git", "-C", ROOT, "status", "--porcelain", "--untracked-files=no"], text=True)
        require(not status, "diagnostic source must be clean before observations")
        tracked = set(subprocess.check_output(["git", "-C", ROOT, "ls-files"], text=True).splitlines())
        require(set(self.source).issubset(tracked), "diagnostic source must be committed")
        self.out.mkdir(parents=True)
        self.rows = []
        self.report = {"schema": "hepta.hia.filecheck.rss-diagnostic.v1", "ok": False,
            "status": "started", "protocol": self.protocol,
            "protocol_sha256": identity(PROTOCOL_PATH)["sha256"],
            "diagnostic_source_commit": self.head, "diagnostic_source_bindings": self.source,
            "original_source_commit": self.original["git"], "original_report": self.original_identity,
            "original_report_performance_gate_unchanged": self.original["performance_advantage_gate"],
            "original_performance_samples_replaced": 0, "new_performance_samples": 0,
            "host": {"platform": platform.platform(), "machine": platform.machine(), "exclusive_host": False},
            "python": {**identity(Path(sys.executable).resolve()), "version": sys.version},
            "tools": {"clang": identity(self.clang)}, "target_artifacts": self.original["artifacts"],
            "target_input": self.original["inputs"]["held-out.bin"], "observations": self.rows}
        self.verify_targets()
        write_new(self.out / "REGISTRATION.json", {key: value for key, value in self.report.items() if key != "observations"})

    def verify_targets(self):
        require(identity(self.original_path) == self.original_identity, "original report was modified")
        for name, value in self.original["artifacts"].items():
            require(identity(value["path"]) == value, "original artifact drift: " + name)
        entry = self.original["inputs"]["held-out.bin"]
        require(identity(entry["path"]) == {key: entry[key] for key in ("path", "bytes", "sha256")}, "original input drift")

    def build_supervisor(self):
        binary = self.out / "rss-supervisor"
        argv = [self.clang, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", str(SUPERVISOR_SOURCE), "-o", str(binary)]
        process = subprocess.run(argv, text=True, capture_output=True, timeout=60)
        record = {"argv": argv, "returncode": process.returncode, "stdout": process.stdout, "stderr": process.stderr}
        write_new(self.out / "SUPERVISOR_BUILD.json", record)
        require(process.returncode == 0, "supervisor build failed")
        self.supervisor = binary
        self.supervisor_identity = identity(binary)
        self.report["supervisor"] = {"artifact": self.supervisor_identity, "source": identity(SUPERVISOR_SOURCE), "build": record}

    def observe(self, *, group, algorithm, arm, launch, phase, parent_profile):
        number = len(self.rows)
        driver = self.original["artifacts"]["host_driver"]
        library = self.original["artifacts"][arm]
        input_data = self.original["inputs"]["held-out.bin"]
        for entry in (driver, library):
            require(identity(entry["path"]) == entry, "target drift before invocation")
        require(identity(input_data["path"]) == {key: input_data[key] for key in ("path", "bytes", "sha256")}, "input drift before invocation")
        argv = [driver["path"], library["path"], "c_checksum_chunk" if arm.startswith("hia") else "checksum_chunk",
                input_data["path"], str(self.original["protocol"]["algorithms"][algorithm])]
        child_argv = list(argv)
        receipt = self.out / (f"supervisor-{number:03}.json")
        if launch == "c_supervisor_fork_exec":
            require(identity(self.supervisor) == self.supervisor_identity, "supervisor drift")
            argv = [str(self.supervisor), str(receipt), *argv]
        row = {"index": number, "phase": phase, "group": group, "algorithm": algorithm, "arm": arm,
            "launch": launch, "parent_profile": parent_profile, "parent_before": parent_memory(),
            "argv": argv, "unchanged_child_argv": child_argv, "status": "started"}
        self.rows.append(row)
        try:
            process = subprocess.run(argv, cwd=self.original_path.parent, text=True, capture_output=True, timeout=60)
            row.update(returncode=process.returncode, stdout=process.stdout, stderr=process.stderr)
            if receipt.exists():
                row["supervisor_observation"] = json.loads(receipt.read_text())
            require(process.returncode == 0, "resource observation failed")
            observed = json.loads(process.stdout)
            row["observed"] = observed
            require(observed["checksum"] == input_data["checksums"][algorithm] and observed["bytes"] == input_data["bytes"] and
                    observed["calls"] == (input_data["bytes"] + 7) // 8, "unchanged program result differs")
            if launch == "c_supervisor_fork_exec":
                wrapped = row["supervisor_observation"]
                require(wrapped["child_exit_code"] == 0 and wrapped["child_signal"] == 0, "child did not return normally")
                require(all(type(value) is int and value >= 0 for value in wrapped.values()), "missing resource floor")
            for entry in (driver, library):
                require(identity(entry["path"]) == entry, "target drift during invocation")
            row["status"] = "completed"
        except Exception as error:
            row.update(status="failed", error={"type": type(error).__name__, "message": str(error)})
            raise
        finally:
            row["parent_after"] = parent_memory()
            with (self.out / "OBSERVATIONS.jsonl").open("a") as stream:
                stream.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")

    def run(self):
        try:
            self.build_supervisor()
            arms = self.protocol["arms"]
            for group in range(self.protocol["groups"]):
                for index, algorithm in enumerate(self.protocol["algorithms"]):
                    shift = (group + index) % len(arms)
                    ordered = arms[shift:] + arms[:shift]
                    if group % 2:
                        ordered = list(reversed(ordered))
                    for arm in ordered:
                        self.observe(group=group, algorithm=algorithm, arm=arm, launch="c_supervisor_fork_exec",
                                     phase="resource_matrix", parent_profile="ordinary_python")
            controls = self.protocol["parent_memory_control"]
            padding = None
            for parent_profile in controls["profiles_in_order"]:
                if parent_profile == "python_with_64MiB_touched_live_padding":
                    padding = bytearray(controls["padding_bytes"])
                    for offset in range(0, len(padding), 4096):
                        padding[offset] = 1
                for group in range(controls["groups_each"]):
                    order = controls["launches"] if not group % 2 else list(reversed(controls["launches"]))
                    for launch in order:
                        self.observe(group=group, algorithm=controls["algorithm"], arm=controls["anchor_arm"], launch=launch,
                                     phase="parent_memory_control", parent_profile=parent_profile)
            require(padding is not None and sum(padding[::4096]) == len(padding) // 4096, "padding not retained")
            self.verify_targets()
            require(source_bindings() == self.source and identity(self.clang) == self.report["tools"]["clang"] and
                    identity(self.supervisor) == self.supervisor_identity, "diagnostic source/tool drift")
            require(len(self.rows) == 60 and all(row["status"] == "completed" for row in self.rows), "incomplete diagnostic")
            self.report["resource_summary"] = {}
            for algorithm in self.protocol["algorithms"]:
                self.report["resource_summary"][algorithm] = {}
                for arm in arms:
                    rows = [row for row in self.rows if row["phase"] == "resource_matrix" and row["algorithm"] == algorithm and row["arm"] == arm]
                    self.report["resource_summary"][algorithm][arm] = {
                        "child_self_ru_maxrss_kib": stats([row["observed"]["peak_rss_kib"] for row in rows]),
                        "child_wait4_ru_maxrss_kib": stats([row["supervisor_observation"]["child_wait4_ru_maxrss_kib"] for row in rows]),
                        "supervisor_vm_hwm_kib": stats([row["supervisor_observation"]["supervisor_vm_hwm_kib"] for row in rows]),
                        "child_preexec_vm_hwm_kib": stats([row["supervisor_observation"]["child_preexec_vm_hwm_kib"] for row in rows])}
            self.report["control_summary"] = {}
            for profile in controls["profiles_in_order"]:
                self.report["control_summary"][profile] = {}
                for launch in controls["launches"]:
                    rows = [row for row in self.rows if row["phase"] == "parent_memory_control" and row["parent_profile"] == profile and row["launch"] == launch]
                    self.report["control_summary"][profile][launch] = {
                        "child_self_ru_maxrss_kib": stats([row["observed"]["peak_rss_kib"] for row in rows]),
                        "python_vm_rss_kib": stats([row["parent_before"]["VmRSS_kib"] for row in rows]),
                        "python_vm_hwm_kib": stats([row["parent_before"]["VmHWM_kib"] for row in rows])}
            control = self.report["control_summary"]
            plain, padded = (control[name] for name in controls["profiles_in_order"])
            direct = padded["direct_subprocess"]["child_self_ru_maxrss_kib"]["median"] - plain["direct_subprocess"]["child_self_ru_maxrss_kib"]["median"]
            supervised = padded["c_supervisor_fork_exec"]["child_self_ru_maxrss_kib"]["median"] - plain["c_supervisor_fork_exec"]["child_self_ru_maxrss_kib"]["median"]
            self.report["interpretation"] = {"direct_padding_delta_kib": direct, "supervised_padding_delta_kib": supervised,
                "supports_launcher_history_contribution": direct > controls["padding_bytes"] // 2048 and abs(supervised) < direct,
                "mechanistic_kernel_proof": False, "strict_process_memory_bound_proved": False,
                "performance_winners_recomputed": False, "original_112_samples_replaced": False,
                "scope": "Finite post-hoc resource diagnostic of exact original artifacts; RSS includes runtime/loader/shared pages and remaining small launch floor. No universal resource superiority claim."}
            self.report.update(ok=True, status="completed", observations_count=len(self.rows))
        except Exception as error:
            self.report.update(ok=False, status="failed", error={"type": type(error).__name__, "message": str(error)})
        finally:
            self.report["observations"] = {"path": "OBSERVATIONS.jsonl", "count": len(self.rows)}
            if (self.out / "OBSERVATIONS.jsonl").exists():
                self.report["observations"]["sha256"] = identity(self.out / "OBSERVATIONS.jsonl")["sha256"]
            write_new(self.out / "DIAGNOSTIC.json", self.report)
        return self.report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--original-report", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--clang", default=os.environ.get("CLANG", "clang"))
    args = parser.parse_args()
    result = Diagnostic(args.original_report, args.output, args.clang).run()
    print(json.dumps({key: result[key] for key in ("ok", "status", "observations_count", "interpretation", "error") if key in result}, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
