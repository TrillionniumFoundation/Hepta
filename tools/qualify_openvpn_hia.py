#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Oracle: OpenVPN 2.7.8, dc1f569087135894ac2703aeabd7a960ee9452d4.
"""Build genuine verified HIA, compare with unmodified OpenVPN C, retain evidence.

A configured upstream OpenVPN build supplies config.h. This experiment neither
constructs a TUN device nor substitutes a synthetic loop for a real tunnel.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
EXPERIMENT = ROOT / "experiments/openvpn_hia_20261105"
sys.path.insert(0, str(ROOT))
from hepta.hia_program import verify_program
from hepta.hia_program_llvm import emit_program_llvm, compile_program_llvm


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--openvpn-source", type=Path, required=True)
    parser.add_argument("--openvpn-build", type=Path, required=True)
    parser.add_argument("--clang", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--benchmark", action="store_true")
    parser.add_argument("--sanitize", action="store_true",
                        help="instrument C harness/oracle/adapter with ASan+UBSan; HIA object remains uninstrumented")
    args = parser.parse_args()
    source, build, compiler, output = (p.resolve() for p in
        (args.openvpn_source, args.openvpn_build, args.clang, args.output))
    if output.exists():
        parser.error("output must be new; earlier evidence must never be overwritten")
    output.mkdir(parents=True)
    command_rows = []
    report = {"schema": "hepta.openvpn.packet-qualification.v1", "ok": False,
              "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "scope": "finite packet codec and application ABI, not tunnel/DCO qualification",
              "upstream_source": str(source), "upstream_build": str(build),
              "host": {"system": platform.platform(), "machine": platform.machine(),
                       "python": platform.python_version()},
              "sanitizer_scope": "C harness/oracle/adapter only; HIA bounded accesses separately exercise guard pages"}

    def run(label, command, timeout=60, environment=None):
        begin = time.monotonic()
        row = {"label": label, "command": list(map(str, command)), "cwd": str(ROOT)}
        command_rows.append(row)
        env = None
        if environment:
            row["environment_overrides"] = environment
            env = dict(os.environ, **environment)
        try:
            proc = subprocess.run(row["command"], cwd=ROOT, capture_output=True, timeout=timeout, env=env)
            row.update(returncode=proc.returncode, elapsed_seconds=time.monotonic()-begin)
            (output/(label+".stdout")).write_bytes(proc.stdout)
            (output/(label+".stderr")).write_bytes(proc.stderr)
            save(output/"commands.json", command_rows)
            if proc.returncode:
                raise RuntimeError(f"{label} failed ({proc.returncode}); retained stdout/stderr")
            return proc.stdout.decode("utf-8")
        except subprocess.TimeoutExpired as exc:
            row.update(returncode=None, timeout=True, elapsed_seconds=time.monotonic()-begin)
            (output/(label+".stdout")).write_bytes(exc.stdout or b"")
            (output/(label+".stderr")).write_bytes(exc.stderr or b"")
            save(output/"commands.json", command_rows)
            raise

    try:
        lock = json.loads((EXPERIMENT/"packet-source-lock.json").read_text())
        report["source_lock"] = lock
        for relative, expected in lock["files"].items():
            if digest(source/relative) != expected:
                raise RuntimeError("upstream source differs from lock: " + relative)
        if not (build/"config.h").is_file():
            raise RuntimeError("configured official build config.h is required")
        report["config_h_sha256"] = digest(build/"config.h")
        tarball = source.parent / lock["archive_name"]
        if tarball.is_file():
            report["observed_tar_sha256"] = digest(tarball)
            if report["observed_tar_sha256"] != lock["archive_sha256"]:
                raise RuntimeError("upstream archive differs from pinned release")
        compiler_version = run("compiler-version", [compiler,"--version"])
        if "clang version 20.1.8" not in compiler_version:
            raise RuntimeError("frozen experiment requires exact Clang 20.1.8")
        report["compiler"] = {"path": str(compiler), "sha256": digest(compiler),
                              "version": compiler_version.splitlines()[0]}
        if hasattr(os, "sched_getaffinity"):
            cpus = sorted(os.sched_getaffinity(0))
            report["host"]["allowed_cpus_before"] = cpus
            os.sched_setaffinity(0, {cpus[0]})
            report["host"]["pinned_cpu"] = cpus[0]
        cpuinfo = Path("/proc/cpuinfo")
        if cpuinfo.exists():
            report["host"]["cpu_model"] = next((line.split(":",1)[1].strip() for line in
                 cpuinfo.read_text().splitlines() if line.startswith("model name")), "unknown")
        report["host"]["load_average_before"] = os.getloadavg()
        snapshot = output/"source_snapshot"
        snapshot.mkdir()
        local_files = sorted(EXPERIMENT.glob("packet*.c")) + [
            EXPERIMENT/"packet_program.py", EXPERIMENT/"openvpn_hia_adapter.c",
            EXPERIMENT/"openvpn_hia_adapter.h", Path(__file__).resolve()]
        report["local_sources"] = {}
        for path in local_files:
            shutil.copyfile(path, snapshot/path.name)
            report["local_sources"][str(path.relative_to(ROOT))] = digest(path)
        shutil.copyfile(build/"config.h", snapshot/"config.h")
        specification = importlib.util.spec_from_file_location("packet_generator", EXPERIMENT/"packet_program.py")
        generator = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(generator)
        document = generator.write_program(output/"packet.hia.json")
        program = verify_program(document)
        ir = emit_program_llvm(program, foreign_buffer_exports=tuple(
            (function["name"], generator.MAX_BYTES) for function in document["functions"]))
        (output/"packet.ll").write_text(ir.text)
        native_commands = []
        try:
            receipt = compile_program_llvm(ir, program=program, output=str(output/"packet.o"),
                                           clang=str(compiler), kind="object", command_log=native_commands)
        finally:
            save(output/"hia-commands.json", native_commands)
        save(output/"hia-build.json", receipt)
        report["hia_receipt"] = receipt
        flags = ["--target=x86_64-unknown-linux-gnu", "-O3", "-fPIC", "-ffunction-sections",
                 "-fdata-sections", "-DHAVE_CONFIG_H", "-I"+str(build),
                 "-I"+str(source/"src/openvpn"), "-I"+str(source/"include"),
                 "-I"+str(source/"src/compat"), "-I"+str(EXPERIMENT)]
        report["c_flags"] = flags
        sources = {"upstream-packet-id": source/"src/openvpn/packet_id.c",
                   "adapter": EXPERIMENT/"openvpn_hia_adapter.c",
                   "c-buffer-control": EXPERIMENT/"packet_c_buffer_control.c",
                   "differential": EXPERIMENT/"packet_differential.c",
                   "guard-pages": EXPERIMENT/"packet_guard_pages.c",
                   "admission": EXPERIMENT/"packet_admission.c"}
        for label, path in sources.items():
            run("compile-"+label,[compiler,*flags,"-c",path,"-o",output/(label+".o")])
        common = [output/(s+".o") for s in ("upstream-packet-id","adapter","c-buffer-control")] + [output/"packet.o"]
        results = {}
        for label in ("differential","guard-pages","admission"):
            extra = ["-Wl,--wrap=free"] if label == "admission" else []
            run("link-"+label,[compiler,"-O3","-Wl,--gc-sections",*extra,*common,
                                  output/(label+".o"),"-o",output/label])
            benchmark = ["--benchmark"] if label=="differential" and args.benchmark else []
            stdout = run(label,[output/label,*benchmark],timeout=60)
            rows = [json.loads(line) for line in stdout.splitlines() if line.strip()]
            results[label] = rows
        report["qualification"] = {key: rows[0] for key, rows in results.items()}
        report["benchmark"] = {}
        modes = ["long_write", "long_read", "epoch_write", "epoch_read"]
        for mode, name in enumerate(modes):
            rows = [r for r in results["differential"] if r["kind"]=="benchmark" and r["mode"]==mode]
            if not rows:
                continue
            samples = {arm: [r[field]/r["calls"] for r in rows] for arm, field in (
                ("c_original","c_ns"),("hia_raw","hia_raw_ns"),
                ("hia_adapter","hia_adapter_ns"),("c_same_buffer_abi","c_buffer_ns"))}
            report["benchmark"][name] = {arm: {"samples": len(values), "median_ns_per_call": statistics.median(values),
                                                "minimum_ns_per_call": min(values), "maximum_ns_per_call": max(values)}
                                         for arm, values in samples.items()}
        report["benchmark_notes"] = [
            "All observations retained, including slow samples; no outlier exclusion.",
            "18 measured samples of 1000000 calls per mode/arm after 10000 warmup calls.",
            "C/rawHIA/adapterHIA use six predetermined orders, each repeated three times.",
            "C same-buffer-ABI control alternates before and after the triplet.",
            "Every iteration resets offset/length and sinks return values and observed packet bytes/state.",
            "Timing differences are observations, not an exact additive adapter-cost decomposition.",
            "Pinned CPU without exclusive host isolation; C and HIA are separately compiled with identical Clang20.1.8 -O3; no LTO.",
            "HIA raw includes bounded foreign-call admission and the 32-byte state ABI.",
            "C same-buffer-ABI control delegates to original C in a separate translation unit without LTO; its timing does not establish a pure language advantage.",
            "These microbenchmarks do not predict tunnel throughput, DCO performance, or deployment value."]
        if not args.benchmark:
            report["benchmark_notes"] = ["No benchmark requested; this run supplies correctness evidence only."]
        if args.sanitize:
            sanitized = output/"sanitized"
            sanitized.mkdir()
            sanflags = ["-fsanitize=address,undefined","-fno-omit-frame-pointer"]
            for label, path in sources.items():
                run("san-compile-"+label,[compiler,*flags,*sanflags,"-c",path,"-o",sanitized/(label+".o")])
            common_san = [sanitized/(s+".o") for s in ("upstream-packet-id","adapter","c-buffer-control")] + [output/"packet.o"]
            report["sanitizer"] = {}
            report["leak_sanitizer"] = "disabled: this managed host cannot inspect /proc threads under ptrace; ownership checked separately with --wrap=free"
            for label in ("differential","admission"):
                extra = ["-Wl,--wrap=free"] if label == "admission" else []
                run("san-link-"+label,[compiler,*sanflags,"-Wl,--gc-sections",*extra,*common_san,
                                      sanitized/(label+".o"),"-o",sanitized/label])
                text = run("san-"+label,[sanitized/label],timeout=60,
                           environment={"ASAN_OPTIONS": "detect_leaks=0", "UBSAN_OPTIONS": "halt_on_error=1"})
                report["sanitizer"][label] = json.loads(text)
        report["artifact_sha256"] = {p.name: digest(p) for p in output.iterdir()
                                      if p.is_file() and (p.suffix==".o" or p.name in ("differential","guard-pages","admission"))}
        report["host"]["load_average_after"] = os.getloadavg()
        report["ok"] = True
        report["status"] = ("finite_packet_codec_qualified_performance_observed" if args.benchmark
                            else "finite_packet_codec_qualified_correctness_only")
        report["tunnel_qualified"] = False
        report["dco_qualified"] = False
        report["replay_window_replaced"] = False
    except Exception as exc:
        report["error"] = repr(exc)
        raise
    finally:
        report["finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        save(output/"summary.json", report)
    print(json.dumps({"ok": report["ok"], "summary": str(output/"summary.json"),
                      "qualification": report["qualification"], "benchmark": report["benchmark"]}, indent=2))


if __name__ == "__main__":
    main()
