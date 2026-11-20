"""Reproduce the fixed same-host verified-kernel microbenchmark protocol.

Builds, final-image queries, tool identities, every sample and subprocess logs
are retained in a fresh output directory. A failure stops the campaign without
discarding completed rows. CPU affinity does not imply exclusive CPU use.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import random
import shutil
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from hepta.hia_program import verify_program
from hepta.hia_program_native import emit_program_machine, compile_program_machine
from hepta.hia_verified_kernel import build_verified_kernel


def multiply_add_program():
    params = [{"name": name, "type": "u64"} for name in ("a", "b", "c")]
    return {"schema": "hepta.hia.program.v1", "module": "verified_kernel_benchmark", "functions": [{
        "name": "multiply_add", "params": params, "returns": ["u64"], "effects": [], "entry": "entry",
        "blocks": [{"id": "entry", "params": params, "ops": [
            {"op": "int.mul.wrap", "args": ["a", "b"], "out": [{"name": "product", "type": "u64"}], "attrs": {}},
            {"op": "int.add.wrap", "args": ["product", "c"], "out": [{"name": "answer", "type": "u64"}], "attrs": {}},
        ], "term": {"op": "ret", "values": ["answer"]}}],
    }]}


def benchmark(output, *, cpu, cc="gcc", rustc="rustc"):
    from hepta.hia_verified_simd import simd_kernel_program
    destination = Path(output).absolute()
    destination.mkdir(parents=False, exist_ok=False)
    protocol_path = ROOT / "benchmarks/hia_verified_kernels/PROTOCOL.json"
    protocol = json.loads(protocol_path.read_text())
    report = {"schema": protocol["schema"], "status": "running", "ok": False,
              "started_utc": datetime.now(timezone.utc).isoformat(),
              "protocol": protocol, "protocol_sha256": sha256(protocol_path.read_bytes()).hexdigest(),
              "host": {"node": platform.node(), "platform": platform.platform(), "cpu": cpu,
                       "initial_affinity": sorted(os.sched_getaffinity(0)),
                       "cpuinfo": Path("/proc/cpuinfo").read_text(),
                       "loadavg_before": Path("/proc/loadavg").read_text().strip()},
              "commands": [], "builds": {}, "rows": [], "source_identity": {}}
    for path in [Path(__file__), *sorted((ROOT / "benchmarks/hia_verified_kernels").glob("*"))]:
        if path.is_file():
            report["source_identity"][path.relative_to(ROOT).as_posix()] = sha256(path.read_bytes()).hexdigest()
    (destination / "protocol.json").write_bytes(protocol_path.read_bytes())
    started = time.monotonic()

    def save():
        (destination / "RESULT.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")

    def run(command, label, timeout=120):
        tick = time.monotonic()
        try:
            result = subprocess.run([str(word) for word in command], cwd=ROOT,
                                    capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            stdout, stderr = exc.stdout or b"", exc.stderr or b""
            (destination / (label + ".stdout")).write_bytes(stdout)
            (destination / (label + ".stderr")).write_bytes(stderr)
            report["commands"].append({"argv": [str(word) for word in command], "label": label,
                                       "returncode": None, "timed_out": True,
                                       "elapsed_seconds": time.monotonic()-tick,
                                       "stdout_sha256": sha256(stdout).hexdigest(),
                                       "stderr_sha256": sha256(stderr).hexdigest()})
            save()
            raise
        (destination / (label + ".stdout")).write_bytes(result.stdout)
        (destination / (label + ".stderr")).write_bytes(result.stderr)
        report["commands"].append({"argv": [str(word) for word in command], "label": label,
                                   "returncode": result.returncode, "elapsed_seconds": time.monotonic() - tick,
                                   "timed_out": False,
                                   "stdout_sha256": sha256(result.stdout).hexdigest(),
                                   "stderr_sha256": sha256(result.stderr).hexdigest()})
        save()
        if result.returncode:
            raise RuntimeError(label + " failed: " + result.stderr.decode(errors="replace")[-4000:])
        return result.stdout.decode()

    save()
    try:
        if cpu not in os.sched_getaffinity(0):
            raise ValueError("selected CPU is outside allowed affinity")
        os.sched_setaffinity(0, {cpu})
        report["host"]["actual_affinity"] = sorted(os.sched_getaffinity(0))
        report["source_commit"] = run(["git", "rev-parse", "HEAD"], "source-commit", 10).strip()
        status = run(["git", "status", "--porcelain=v1", "--untracked-files=no"], "source-status-before", 10)
        if status.strip():
            raise RuntimeError("benchmark requires a clean committed tracked tree")
        libraries = {}
        scalar = verify_program(multiply_add_program())
        (destination / "multiply_add.core.hepta").write_bytes(scalar.canonical_bytes)
        direct = emit_program_machine(scalar)
        (destination / "scalar-direct.o").write_bytes(direct.object_bytes)
        direct_path = destination / "scalar-direct.so"
        report["builds"]["scalar-direct"] = compile_program_machine(direct, program=scalar, output=direct_path)
        libraries["scalar-direct"] = (direct_path, "multiply_add")
        sources = {"scalar-verified": scalar}
        for kind in ("sum_u8", "all_zero_u8", "copy_u8"):
            sources[kind] = verify_program(simd_kernel_program(kind))
        for label, core in sources.items():
            (destination / (label + ".core.hepta")).write_bytes(core.canonical_bytes)
            library = destination / (label + ".so")
            artifacts = destination / (label + "-artifacts")
            artifacts.mkdir()
            report["builds"][label] = build_verified_kernel(
                core, library, query_directory=destination / (label + "-queries"), timeout_ms=60000,
                artifact_directory=artifacts)
            libraries[label] = (library, core.as_dict()["functions"][0]["name"])
            save()
        # Retain the original 16-byte loop as a simultaneous control. Both
        # images have the same Core and ABI and pass the same independent
        # consumer before the unchanged driver measures their native calls.
        for kind in ("sum_u8", "all_zero_u8", "copy_u8"):
            label = kind + "-sse2-16"
            core = sources[kind]
            library = destination / (label + ".so")
            artifacts = destination / (label + "-artifacts")
            artifacts.mkdir()
            report["builds"][label] = build_verified_kernel(
                core, library, strategy="simd", simd_unroll=1,
                query_directory=destination / (label + "-queries"), timeout_ms=60000,
                artifact_directory=artifacts)
            libraries[label] = (library, core.as_dict()["functions"][0]["name"])
            save()
        # Both explicit wide candidates retain the same Core/ABI. The builder
        # derives required features from final instructions and freshly probes
        # every CPU in the (already pinned) campaign affinity before publishing.
        for isa, width in (("avx2", 128), ("avx512", 256)):
            for kind in ("sum_u8", "all_zero_u8", "copy_u8"):
                label = kind + "-" + isa + "-" + str(width)
                core = sources[kind]
                library = destination / (label + ".so")
                artifacts = destination / (label + "-artifacts")
                artifacts.mkdir()
                report["builds"][label] = build_verified_kernel(
                    core, library, strategy="simd", simd_isa=isa,
                    simd_copy_tail="endpoints" if kind == "copy_u8" else None,
                    simd_reduce_tail="byte" if kind != "copy_u8" else None,
                    query_directory=destination / (label + "-queries"), timeout_ms=60000,
                    artifact_directory=artifacts)
                libraries[label] = (library, core.as_dict()["functions"][0]["name"])
                save()
        # Keep both previous wide copy images as simultaneous controls. The
        # complete original matrix remains; endpoint changes cannot erase a
        # slower row or be compared only with a selectively rerun baseline.
        for isa, width in (("avx2", 128), ("avx512", 256)):
            label = "copy_u8-" + isa + "-" + str(width) + "-byte-tail"
            core = sources["copy_u8"]
            library = destination / (label + ".so")
            artifacts = destination / (label + "-artifacts")
            artifacts.mkdir()
            report["builds"][label] = build_verified_kernel(
                core, library, strategy="simd", simd_isa=isa, simd_copy_tail="byte",
                query_directory=destination / (label + "-queries"), timeout_ms=60000,
                artifact_directory=artifacts)
            libraries[label] = (library, core.as_dict()["functions"][0]["name"])
            save()
        # Preserve all v4 arms byte-for-byte and add the new defaults as
        # separately named simultaneous candidates. Every original row and
        # length remains in the deterministic complete campaign.
        for isa, width in (("avx2", 128), ("avx512", 256)):
            for kind in ("sum_u8", "all_zero_u8", "copy_u8"):
                tail = "endpoints-fast" if kind == "copy_u8" else "bounded-tail"
                label = kind + "-" + isa + "-" + str(width) + "-" + tail
                core = sources[kind]
                library = destination / (label + ".so")
                artifacts = destination / (label + "-artifacts")
                artifacts.mkdir()
                report["builds"][label] = build_verified_kernel(
                    core, library, strategy="simd", simd_isa=isa,
                    query_directory=destination / (label + "-queries"), timeout_ms=60000,
                    artifact_directory=artifacts)
                libraries[label] = (library, core.as_dict()["functions"][0]["name"])
                save()
        # The established direct foreign-buffer ABI returns packed u32. Keep
        # its original wrapper/checks and narrow only the final Core return.
        # All measured counts and sums are <2**32; invalid-input contracts
        # remain different and are explicitly outside this microbenchmark.
        direct_spans = {}
        for kind in ("sum_u8", "all_zero_u8", "copy_u8"):
            document = sources[kind].as_dict()
            function = document["functions"][0]
            done = next(block for block in function["blocks"] if block["id"] == "done")
            returned = done["term"]["values"][0]
            done["ops"].append({"op": "int.cast", "args": [returned],
                               "out": [{"name": "packed_result", "type": "u32"}], "attrs": {"mode": "wrap"}})
            done["term"]["values"] = ["packed_result"]
            function["returns"] = ["u32"]
            baseline = verify_program(document)
            label = kind + "-direct-packed-u32"
            (destination / (label + ".core.hepta")).write_bytes(baseline.canonical_bytes)
            image = emit_program_machine(baseline, foreign_buffer_exports=((function["name"], 65536),))
            (destination / (label + ".o")).write_bytes(image.object_bytes)
            library = destination / (label + ".so")
            report["builds"][label] = compile_program_machine(image, program=baseline, output=library)
            direct_spans[kind] = (library, function["name"])
            save()
        source = ROOT / "benchmarks/hia_verified_kernels"
        tools = {}
        for name, supplied in (("cc", cc), ("rustc", rustc)):
            path = shutil.which(supplied)
            if path is None:
                raise ValueError(name + " is required by this protocol")
            # rustc is commonly an argv[0]-selected rustup proxy. Resolving
            # that symlink before invoking it would execute `rustup` instead.
            path = str(Path(path).absolute())
            tools[name] = path
            report.setdefault("toolchain", {})[name] = {
                "path": path, "resolved_path": str(Path(path).resolve()),
                "sha256": sha256(Path(path).read_bytes()).hexdigest(),
                "version": run([path, "--version"], name + "-version", 10).strip(),
            }
        sysroot = Path(run([tools["rustc"], "--print", "sysroot"], "rust-sysroot", 10).strip())
        compiler = sysroot / "bin/rustc"
        if not compiler.is_file():
            raise RuntimeError("cannot identify the actual Rust compiler behind its launcher")
        report["toolchain"]["rustc"].update(compiler_path=str(compiler),
            compiler_sha256=sha256(compiler.read_bytes()).hexdigest())
        driver = destination / "driver"
        run([tools["cc"], "-O3", "-std=c11", str(source / "driver.c"), "-ldl", "-o", str(driver)], "build-driver")
        runtime_probe = destination / "runtime-identity"
        run([tools["cc"], "-O2", "-march=x86-64", "-std=c11", str(source / "runtime_identity.c"),
             "-ldl", "-o", str(runtime_probe)], "build-runtime-identity")
        runtime = run([runtime_probe], "runtime-identity").splitlines()
        if len(runtime) != 3 or not runtime[2].isdigit():
            raise RuntimeError("incomplete runtime/IFUNC identity")
        libc_path = Path(runtime[1]).resolve(strict=True)
        report["runtime_dependency"] = {"glibc_version": runtime[0], "libc_path": str(libc_path),
            "libc_sha256": sha256(libc_path.read_bytes()).hexdigest(),
            "memcpy_ifunc_offset": int(runtime[2]), "binding": "same-affinity baseline-ISA subprocess"}
        c_library, rust_library = destination / "reference-c.so", destination / "reference-rust.so"
        run([tools["cc"], *protocol["compiler_flags_c"], str(source / "reference.c"), "-o", str(c_library)], "build-c")
        run([tools["rustc"], *protocol["compiler_flags_rust"], str(source / "reference.rs"), "-o", str(rust_library)], "build-rust")
        all_libraries = [v[0] for v in [*libraries.values(), *direct_spans.values()]]
        for path in [driver, runtime_probe, c_library, rust_library, *all_libraries]:
            report.setdefault("binaries", {})[path.name] = {"sha256": sha256(path.read_bytes()).hexdigest(),
                                                           "bytes": path.stat().st_size}
        if shutil.which("objdump"):
            for path in [c_library, rust_library, *all_libraries]:
                run(["objdump", "-d", str(path)], "disassembly-" + path.stem)
        cases = []
        for arm in ("scalar-direct", "scalar-verified"):
            cases.append(("scalar", arm, *libraries[arm], 0))
        for arm, library in (("c", c_library), ("rust", rust_library)):
            cases.append(("scalar", arm, library, "reference_madd", 0))
        for kind, mode in (("sum_u8", "sum"), ("all_zero_u8", "zero"), ("copy_u8", "copy")):
            for length in protocol["lengths"]:
                cases.append((mode, "verified-sse2-64", *libraries[kind], length))
                cases.append((mode, "verified-sse2-16", *libraries[kind + "-sse2-16"], length))
                cases.append((mode, "verified-avx2-128", *libraries[kind + "-avx2-128"], length))
                cases.append((mode, "verified-avx512-256", *libraries[kind + "-avx512-256"], length))
                if mode == "copy":
                    for isa, width in (("avx2", 128), ("avx512", 256)):
                        label = kind + "-" + isa + "-" + str(width) + "-byte-tail"
                        cases.append((mode, "verified-" + isa + "-copy-byte-tail", *libraries[label], length))
                for isa, width in (("avx2", 128), ("avx512", 256)):
                    tail = "endpoints-fast" if mode == "copy" else "bounded-tail"
                    label = kind + "-" + isa + "-" + str(width) + "-" + tail
                    arm = "verified-" + isa + ("-copy-" if mode == "copy" else "-") + tail
                    cases.append((mode, arm, *libraries[label], length))
                cases.append((mode, "direct-packed-u32", *direct_spans[kind], length))
                for arm, library in (("c", c_library), ("rust", rust_library)):
                    cases.append((mode, arm, library, "reference_" + mode, length))
        if len(cases) != protocol["cases"]:
            raise RuntimeError("complete benchmark inventory differs from the fixed protocol")
        random.Random(20261119).shuffle(cases)
        report["case_order"] = [{"mode": mode, "arm": arm, "length": length}
                                 for mode, arm, _, _, length in cases]
        save()
        for index, (mode, arm, library, symbol, length) in enumerate(cases):
            calls = protocol["scalar_iterations"] if mode == "scalar" else protocol["span_iterations"][str(length)]
            label = f"case-{index:02d}-{mode}-{arm}-{length}"
            raw = run([driver, mode, library, symbol, protocol["samples_per_case"], calls, length], label)
            samples = [json.loads(line) for line in raw.splitlines()]
            if len(samples) != 21 or [s["batch"] for s in samples] != list(range(21)):
                raise RuntimeError("incomplete or out-of-order batch inventory")
            if any(s["calls"] != calls or s["elapsed_ns"] <= 0 for s in samples):
                raise RuntimeError("invalid timing sample")
            report["rows"].append({"mode": mode, "arm": arm, "length": length, "symbol": symbol,
                                   "library": library.name, "samples": samples,
                                   "median_ns_per_call": statistics.median(s["ns_per_call"] for s in samples),
                                   "max_ns_per_call": max(s["ns_per_call"] for s in samples)})
            save()
        if run(["git", "rev-parse", "HEAD"], "source-commit-after", 10).strip() != report["source_commit"] or \
                run(["git", "status", "--porcelain=v1", "--untracked-files=no"], "source-status-after", 10).strip():
            raise RuntimeError("tracked source changed during the campaign")
        if sha256(libc_path.read_bytes()).hexdigest() != report["runtime_dependency"]["libc_sha256"]:
            raise RuntimeError("runtime dependency changed during the campaign")
        if run([runtime_probe], "runtime-identity-after").splitlines() != runtime:
            raise RuntimeError("runtime IFUNC choice changed during the campaign")
        report.update(ok=True, status="completed")
    except Exception as exc:
        report.update(status="failed", error={"type": type(exc).__name__, "message": str(exc)})
    finally:
        report["host"]["loadavg_after"] = Path("/proc/loadavg").read_text().strip()
        report.update(completed_utc=datetime.now(timezone.utc).isoformat(), elapsed_seconds=time.monotonic()-started)
        save()
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--cpu", required=True, type=int)
    parser.add_argument("--cc", default="gcc")
    parser.add_argument("--rustc", default="rustc")
    args = parser.parse_args(argv)
    result = benchmark(args.output, cpu=args.cpu, cc=args.cc, rustc=args.rustc)
    print(json.dumps({"ok": result["ok"], "status": result["status"], "rows": len(result["rows"]),
                      "output": str(Path(args.output).absolute()), "error": result.get("error")}, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
