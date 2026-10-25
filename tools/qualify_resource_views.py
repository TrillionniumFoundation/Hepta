"""Execute owned generic/fallible construction with independently checked local views.

The existing checker and Rust lifetime gate remain mandatory. The separate
JSON verifier checks real stored loans; this is not whole-language refinement.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

from hepta.backend import compile_rust
from hepta.pipeline import analyze_project, compiler_hash
from hepta.resource_ir import read_resource_ir, verify_resource_ir
from hepta.resource_lowering import lower_resource_ir
from hepta.resource_source import verify_resource_source
from tools.evidence_checks import command, is_sha, native_build, normalized_errors, require, strict_equal

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "examples/resource_views/owned_buffer.hepta"
CASES = [(0, 0, -1), (4, 0, 7), (4, 1, -2), (4, 2, 11), (65519, 0, -1),
         (4, 0, 7), (65519, 1, -1), (4, 2, 11), (65536, 0, -3)]
SCHEMA = "hepta.local-resource-views-qualification.v1"
CLOSED = {"whole_language_soundness_proved": False, "source_refinement_proved": False,
          "mixed_generic_lifetime_parameters_supported": False,
          "stored_view_parameters_or_returns_supported": False}
VERIFIER_CODE = ("import json,sys;from hepta.resource_ir import read_resource_ir,verify_resource_ir;"
                "r=verify_resource_ir(read_resource_ir(sys.argv[1]));"
                "r['frontend_modules_imported']=[m for m in ('hepta.parser','hepta.checker') if m in sys.modules];"
                "print(json.dumps(r));sys.exit(0 if r['ok'] and not r['frontend_modules_imported'] else 1)")
ALLOCATOR = r'''
struct ViewFaultAllocator;
static VIEW_LIVE: std::sync::atomic::AtomicIsize = std::sync::atomic::AtomicIsize::new(0);
static VIEW_REFUSALS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
unsafe impl std::alloc::GlobalAlloc for ViewFaultAllocator {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        if layout.size() == 65519 {
            VIEW_REFUSALS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            return core::ptr::null_mut();
        }
        let pointer = std::alloc::System.alloc(layout);
        if !pointer.is_null() { VIEW_LIVE.fetch_add(1, std::sync::atomic::Ordering::SeqCst); }
        pointer
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: std::alloc::Layout) {
        std::alloc::System.dealloc(pointer, layout);
        VIEW_LIVE.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}
#[global_allocator] static VIEW_ALLOCATOR: ViewFaultAllocator = ViewFaultAllocator;
#[no_mangle] pub extern "C" fn view_live() -> isize { VIEW_LIVE.load(std::sync::atomic::Ordering::SeqCst) }
#[no_mangle] pub extern "C" fn view_refusals() -> usize { VIEW_REFUSALS.load(std::sync::atomic::Ordering::SeqCst) }
'''
DRIVER = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
extern int32_t exercise(size_t, uint8_t);
extern intptr_t view_live(void);
extern size_t view_refusals(void);
int main(void) {
    const size_t sizes[] = {0,4,4,4,65519,4,65519,4,65536};
    const uint8_t modes[] = {0,0,1,2,0,0,1,2,0};
    const int32_t expected[] = {-1,7,-2,11,-1,7,-1,11,-3};
    for (unsigned i=0; i<9; ++i) {
        int32_t result=exercise(sizes[i], modes[i]);
        intptr_t live=view_live();
        printf("{\"size\":%zu,\"mode\":%u,\"result\":%d,\"live\":%ld}\n",
               sizes[i], (unsigned)modes[i], result, (long)live);
        if (result!=expected[i] || live!=0) return 10+(int)i;
    }
    printf("{\"allocator_refusals\":%zu}\n",view_refusals());
    return view_refusals()==2 ? 0 : 30;
}
'''


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def identities():
    return {path: sha((ROOT / path).read_bytes()) for path in
            ("examples/resource_views/owned_buffer.hepta", "tools/qualify_resource_views.py")}


def _process(report, key, argv, *, timeout):
    started = time.monotonic()
    row = {"argv": argv, "returncode": None, "stdout": "", "stderr": ""}
    report[key] = row
    try:
        result = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, timeout=timeout)
        row.update(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)
        return result
    except subprocess.TimeoutExpired as exc:
        row["timed_out"] = True
        for name, value in (("stdout", exc.stdout), ("stderr", exc.stderr)):
            data = value.encode() if isinstance(value, str) else value or b""
            row[name] = data.decode(errors="replace")
            row[name + "_bytes_base64"] = base64.b64encode(data).decode()
        raise
    finally:
        row["seconds"] = time.monotonic() - started


def _execute(report, output, *, rustc, cc):
    with tempfile.TemporaryDirectory(prefix="hepta-view-native-") as td:
        directory = Path(td)
        analysis = analyze_project(ENTRY, rustc=rustc, crate_type="staticlib")
        report["source_validation"] = analysis.report
        if not analysis.report["ok"]:
            raise ValueError("Fresh native lifetime validation failed: " + json.dumps(analysis.report["diagnostics"]))
        graph = lower_resource_ir(analysis.program, analysis.checked, project_sha256=analysis.project.identity)
        data = (json.dumps(graph, indent=2, sort_keys=True) + "\n").encode()
        graph_path = output.with_suffix(".graph.json")
        with graph_path.open("xb") as stream:
            stream.write(data)
        evidence_path = str(graph_path.relative_to(ROOT)) if graph_path.is_relative_to(ROOT) else str(graph_path)
        report["graph"] = {"path": evidence_path, "sha256": sha(data), "schema": graph["schema"]}
        # A new process loads the data verifier without parser/checker modules.
        argv = [sys.executable, "-c", VERIFIER_CODE, evidence_path]
        independent = _process(report, "independent_process", argv, timeout=20)
        if independent.returncode:
            raise ValueError("Standalone resource verifier failed")
        report["resource_verification"] = json.loads(independent.stdout)
        report["source_replay"] = verify_resource_source(ENTRY, graph, rustc=rustc)
        if report["source_replay"]["ok"] is not True:
            raise ValueError("Source replay failed: " + json.dumps(report["source_replay"]["diagnostics"]))
        library = directory / "views.a"
        instrumented = analysis.rust + ALLOCATOR
        report["allocator_source_sha256"] = sha(ALLOCATOR.encode())
        report["instrumented_rust_sha256"] = sha(instrumented.encode())
        report["native_build"] = compile_rust(instrumented, rustc=rustc, crate_type="staticlib", output=library)
        if report["native_build"]["ok"] is not True:
            raise ValueError("Actual owning library did not compile")
        driver = directory / "driver.c"
        driver.write_text(DRIVER)
        report["driver_source_sha256"] = sha(DRIVER.encode())
        executable = directory / "views"
        compiler = str(Path(shutil.which(cc) or cc).resolve())
        report["driver_compiler"] = {"path": compiler, "executable_sha256": sha(Path(compiler).read_bytes())}
        argv = [compiler, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", str(driver), str(library), "-pthread", "-ldl", "-lm", "-o", str(executable)]
        build = _process(report, "driver_build", argv, timeout=60)
        if build.returncode:
            raise ValueError("Native caller did not link: " + build.stderr)
        executable_hash = sha(executable.read_bytes())
        report["driver_build"]["artifact_sha256"] = executable_hash
        run = _process(report, "execution", [str(executable)], timeout=30)
        report["execution"]["executable_sha256"] = sha(executable.read_bytes())
        rows = [json.loads(line) for line in run.stdout.splitlines()]
        expected = [{"size": n, "mode": mode, "result": result, "live": 0} for n, mode, result in CASES]
        expected += [{"allocator_refusals": 2}]
        if run.returncode or not strict_equal(rows, expected):
            raise ValueError("Native error/recovery/cleanup observations differed")
        report["observations"] = rows
    if sha(ENTRY.read_bytes()) != report["source_sha256"] or compiler_hash() != report["compiler_sha256"] or identities() != report["inputs"]:
        raise ValueError("Source or compiler changed during qualification")
    report.update(ok=True, status="passed")
    validate_report(report)


def qualify(output: Path, *, rustc=None, cc="cc") -> dict:
    output = Path(output).resolve()
    graph = output.with_suffix(".graph.json")
    if any(path.exists() or path.is_symlink() for path in (output, graph)):
        raise ValueError("Qualification and graph paths must be new")
    output.parent.mkdir(parents=True, exist_ok=True)
    report = {"schema": SCHEMA, "ok": False, "status": "failed",
              "source_sha256": sha(ENTRY.read_bytes()), "compiler_sha256": compiler_hash(),
              "inputs": identities(), **CLOSED}
    try:
        _execute(report, output, rustc=rustc, cc=cc)
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, AttributeError, subprocess.TimeoutExpired) as exc:
        report.update(ok=False, status="failed", validation_error=type(exc).__name__ + ": " + str(exc))
    with output.open("x", encoding="utf-8") as destination:
        json.dump(report, destination, indent=2, sort_keys=True)
        destination.write("\n")
    return report


def _native_frontend(actual, expected):
    require(set(actual) == set(expected) | {"backend"}, "Native source check has unexpected fields")
    for key in expected:
        if key not in {"status", "checks", "borrowed_storage"}:
            require(strict_equal(actual[key], expected[key]), "Native source identity changed: " + key)
    require(actual["status"] == "checked" and strict_equal(actual["checks"],
            dict(expected["checks"], rust_borrows_types="rustc_checked")), "Fresh native source validation missing")
    require(strict_equal(actual["borrowed_storage"], dict(expected["borrowed_storage"], native_lifetimes_checked=True)),
            "General borrowed-storage scope changed")
    native_build(actual["backend"], "rust", check_only=True, crate_type=expected["profile"]["crate_type"],
                 source_sha256=expected["rust_sha256"])


@normalized_errors
def validate_report(report):
    """Bind retained observations to current inputs; do not rerun native tools.

    Like the other local evidence validators, this is consistency validation,
    not authentication of an arbitrary third-party claim to have executed.
    """
    require(isinstance(report, dict) and report.get("schema") == SCHEMA and report.get("ok") is True
            and report.get("status") == "passed", "Not a passing local-view qualification")
    fields = {"schema", "ok", "status", "source_sha256", "compiler_sha256", "inputs", "source_validation",
              "graph", "independent_process", "resource_verification", "source_replay", "allocator_source_sha256",
              "instrumented_rust_sha256", "native_build", "driver_source_sha256", "driver_compiler",
              "driver_build", "execution", "observations"} | set(CLOSED)
    require(set(report) == fields and strict_equal({key: report[key] for key in CLOSED}, CLOSED), "Qualification scope changed")
    require(report["compiler_sha256"] == compiler_hash() and strict_equal(report["inputs"], identities())
            and report["source_sha256"] == sha(ENTRY.read_bytes()), "Current compiler/source inputs differ")
    analysis = analyze_project(ENTRY, native=False, crate_type="staticlib")
    require(analysis.report["ok"] is True, "Current source no longer checks")
    _native_frontend(report["source_validation"], analysis.report)
    graph_path = Path(report["graph"]["path"])
    graph_path = graph_path if graph_path.is_absolute() else ROOT / graph_path
    graph = read_resource_ir(graph_path)
    require(report["graph"]["sha256"] == sha(graph_path.read_bytes())
            and report["graph"]["schema"] == graph["schema"] == "hepta.resource-ir.v4", "Retained graph bytes/schema differ")
    expected_graph = lower_resource_ir(analysis.program, analysis.checked, project_sha256=analysis.project.identity)
    require(strict_equal(graph, expected_graph), "Retained graph differs from the current resource projection")
    verified = verify_resource_ir(graph)
    independent = dict(verified, frontend_modules_imported=[])
    require(strict_equal(report["resource_verification"], independent), "Standalone resource result differs")
    process = report["independent_process"]
    command(process)
    require(process["argv"] == [sys.executable, "-c", VERIFIER_CODE, report["graph"]["path"]]
            and process["returncode"] == 0 and process["stderr"] == ""
            and process["stdout"] == json.dumps(independent) + "\n", "Standalone verifier process did not observe this graph")
    replay = report["source_replay"]
    expected_replay = verify_resource_source(ENTRY, graph, native=False)
    require(expected_replay["ok"] is True, "Current source replay failed")
    _native_frontend(replay["source_validation"], expected_replay["source_validation"])
    expected_replay["source_validation"] = replay["source_validation"]
    expected_replay["status"] = "source_replayed"
    expected_replay["source_binding"]["native_reference"] = "rustc_checked"
    expected_replay.pop("sha256")
    expected_replay["sha256"] = sha(json.dumps(expected_replay, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode())
    require(strict_equal(replay, expected_replay), "Source replay identity, native validation or closed claims changed")
    source_hash = sha((analysis.rust + ALLOCATOR).encode())
    require(report["allocator_source_sha256"] == sha(ALLOCATOR.encode())
            and report["driver_source_sha256"] == sha(DRIVER.encode())
            and report["instrumented_rust_sha256"] == source_hash, "Actual fixture or allocation instrumentation changed")
    built = report["native_build"]
    native_build(built, "rust", check_only=False, crate_type="staticlib", source_sha256=source_hash)
    for frontend in (report["source_validation"], replay["source_validation"]):
        require(strict_equal(frontend["backend"]["toolchain"], built["toolchain"])
                and frontend["backend"]["target"] == built["target"], "Native source check/build identity differs")
    tool = built["toolchain"]
    require(tool["version"].startswith("rustc 1.90.0 ")
            and tool["executable_sha256"] == sha(Path(tool["path"]).read_bytes()), "Pinned Rust identity is stale")
    ctool = report["driver_compiler"]
    require(is_sha(ctool["executable_sha256"]) and ctool["executable_sha256"] == sha(Path(ctool["path"]).read_bytes()),
            "Native caller compiler identity changed")
    driver, run = report["driver_build"], report["execution"]
    command(driver)
    command(run)
    library = Path(built["artifact"])
    executable = library.parent / "views"
    require(driver["argv"] == [ctool["path"], "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", str(library.parent / "driver.c"),
            str(library), "-pthread", "-ldl", "-lm", "-o", str(executable)]
            and driver["returncode"] == 0 and driver["stderr"] == "" and driver["stdout"] == ""
            and run["argv"] == [str(executable)] and run["returncode"] == 0 and run["stderr"] == ""
            and is_sha(run["executable_sha256"]) and run["executable_sha256"] == driver["artifact_sha256"],
            "Native caller link/execution evidence is missing or inconsistent")
    expected = [{"size": n, "mode": mode, "result": result, "live": 0} for n, mode, result in CASES] + [{"allocator_refusals": 2}]
    require(strict_equal(report["observations"], expected)
            and run["stdout"] == "".join(json.dumps(row, separators=(",", ":")) + "\n" for row in expected),
            "Nine actual calls and both allocation refusals must retain their exact results and cleanup observations")
    require(analysis.project.unchanged() and report["compiler_sha256"] == compiler_hash(), "Inputs changed during evidence validation")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rustc", default=os.environ.get("RUSTC"))
    parser.add_argument("--cc", default="cc")
    args = parser.parse_args(argv)
    result = qualify(args.output, rustc=args.rustc, cc=args.cc)
    print(json.dumps({"ok": result["ok"], "output": str(args.output)}))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
