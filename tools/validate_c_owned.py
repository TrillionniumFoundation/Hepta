#!/usr/bin/env python3
"""Execute and retain the independently checked owned C backend profile."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from hepta.backend import compile_rust
from hepta.c_backend import compile_c
from hepta.pipeline import analyze, analyze_project, compiler_hash
from hepta.resource_ir import verify_resource_ir
from hepta.resource_lowering import lower_resource_ir

SCHEMA = "hepta.c-owned-backend-qualification.v1"
CLAIMS = {"whole_language_soundness_proved": False, "source_to_ir_refinement_proved": False,
          "source_to_c_refinement_proved": False, "whole_c_backend_coverage": False,
          "whole_project_blockers_closed": False, "general_performance_advantage_proved": False}
REJECTIONS = {
    "overlapping_generic_loans": ("fn pair<T:Owned>(a:mut T,b:read T)->Unit effects {} {}fn main()->Unit effects {alloc,block,panic} {let mut b=buffer(4);pair::<Buffer<u8>>(mut b,read b);drop(move b);}", "E_C_RESOURCE_IR"),
    "move_under_loan": ("fn f(a:read Buffer<u8>,b:take Buffer<u8>)->Unit effects {alloc,block} {drop(move b);}fn main()->Unit effects {alloc,block,panic} {let x=buffer(7);f(read x,move x);}", "E_C_RESOURCE_IR"),
    "unused_generic_leak": ("fn unused<T:Owned>(value:take T)->Unit effects {} {}fn main()->Unit effects {} {}", "E_LINEAR_UNCONSUMED"),
    "raw_owned_combination": ("fn main()->Unit effects {alloc,block,panic,unsafe} {let x=buffer(1);unsafe {let p=ptr_read(read x);}drop(move x);}", "E_C_RESOURCE_IR"),
    "unbounded_specialization": ("struct Box<T>{value:T}fn grow<T:Copy>(x:T)->Unit effects {} {grow::<Box<T>>(Box{value:x});}fn main()->Unit effects {} {grow::<u64>(1);}", "E_C_SPECIALIZATION_LIMIT"),
    "scoped_task_runtime": ("fn main()->Unit effects {alloc,block,panic,write} {let group=task_group(0,0,1);group_cancel_and_join(move group);}", "E_C_RESOURCE_IR"),
}


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def identity(path: Path) -> dict:
    data = path.read_bytes()
    return {"path": str(path.resolve()), "bytes": len(data), "sha256": digest(data)}


def run(artifact: str) -> dict:
    result = subprocess.run([artifact], capture_output=True, text=True, timeout=30)
    return {"returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr,
            "stdout_sha256": digest(result.stdout.encode()), "stderr_sha256": digest(result.stderr.encode())}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def _sha(value):
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _execution(value, stdout, success=True):
    require(isinstance(value, dict) and type(value.get("returncode")) is int, "missing native process result")
    require((value["returncode"] == 0) if success else (value["returncode"] != 0), "unexpected native exit")
    require(value.get("stdout") == stdout and value.get("stderr") == "", "unexpected native observation")
    require(value.get("stdout_sha256") == digest(stdout.encode()) and value.get("stderr_sha256") == digest(b""), "native output identity differs")


def _build(value, backend):
    require(isinstance(value, dict) and value.get("ok") is True and value.get("check_only") is False, "missing actual final native build")
    require(type(value.get("artifact_bytes")) is int and value["artifact_bytes"] > 0, "empty native artifact")
    require(_sha(value.get("artifact_sha256")) and value.get("validation_artifact_sha256") == value["artifact_sha256"], "native artifact identity differs")
    require(_sha(value.get("source_sha256" if backend == "c" else "rust_sha256")), "native source identity missing")
    artifact = Path(value.get("artifact", ""))
    require(artifact.is_file() and 0 < artifact.stat().st_size <= 128 * 1024 * 1024, "native artifact missing/oversized")
    raw = artifact.read_bytes()
    require(len(raw) == value["artifact_bytes"] and digest(raw) == value["artifact_sha256"], "actual native artifact identity differs")
    if backend == "c":
        require(value.get("backend") == "c11-gcc" and value.get("rustc_used") is False, "C run used a different backend")
        require("-fsanitize=undefined" in value.get("flags", []) and "-fno-sanitize-recover=all" in value.get("flags", []), "C UB sanitizer qualification missing")
    else:
        require(value.get("status") == "rustc_checked", "Rust reference did not compile")


def _source(row, backend, harness=None):
    info = row.get("source", {})
    path = Path(info.get("path", ""))
    require(path.is_file() and 0 < path.stat().st_size <= 16 * 1024 * 1024, "generated native source missing/oversized")
    data = path.read_bytes()
    require(type(info.get("bytes")) is int and info["bytes"] == len(data) and info.get("sha256") == digest(data), "generated source identity differs")
    native_key = "source_sha256" if backend == "c" else "rust_sha256"
    require(row["build"][native_key] == digest(data), "final build used a different source")
    if harness is not None:
        tail = harness.read_bytes()
        require(data.endswith(tail), "allocator harness does not match the frozen source")
        data = data[:-len(tail)]
    frontend = row.get("frontend", {})
    require(frontend.get("ok") is True, "frontend check missing")
    key = "c_sha256" if backend == "c" else "rust_sha256"
    require(frontend.get(key) == digest(data), "frontend and final build identities differ")
    native = frontend.get("backend", {})
    require(native.get("ok") is True and native.get("check_only") is True and native.get(native_key) == digest(data), "native frontend check missing or mismatched")
    if backend == "c":
        require(frontend.get("checks", {}).get("rust_borrows_types") == "not_run" and native.get("rustc_used") is False, "independent C check used Rust")


def _pairs(pairs):
    require(isinstance(pairs, dict) and set(pairs) == {"c", "rust"}, "both native backends required")


def validate_c_owned_qualification(report: dict) -> dict:
    """Reject incomplete/claim-inflated reports and replay the retained CFG."""
    require(isinstance(report, dict) and report.get("schema") == SCHEMA and report.get("ok") is True, "C owned qualifier did not pass")
    require(report.get("compiler_sha256") == compiler_hash(), "C owned evidence is from another compiler")
    require(report.get("claims") == CLAIMS, "C owned claims were upgraded")
    require(report.get("source_semantics") == "explicit_owned_and_immediate_borrows_hosted_abort", "unknown C owned profile")
    graph_info = report.get("resource_ir", {})
    graph_path = Path(graph_info.get("path", ""))
    require(graph_path.is_file() and 0 < graph_path.stat().st_size <= 16 * 1024 * 1024, "retained resource graph missing or oversized")
    raw = graph_path.read_bytes()
    require(graph_info.get("bytes") == len(raw) and graph_info.get("sha256") == digest(raw), "retained graph identity changed")
    def unique(pairs):
        out = {}
        for key, value in pairs:
            require(key not in out, "duplicate graph key")
            out[key] = value
        return out
    def finite(value):
        raise ValueError("nonfinite graph value")
    graph = json.loads(raw, object_pairs_hook=unique, parse_constant=finite)
    verified = verify_resource_ir(graph)
    require(verified.get("ok") is True and verified == report.get("resource_verification"), "retained graph verification differs")
    require(graph.get("project_sha256") == report.get("project_sha256"), "resource graph belongs to a different project")
    observations = report.get("differential", {})
    require(observations.get("paired_calls") == 256 and type(observations.get("paired_calls")) is int, "differential denominator changed")
    require(observations.get("checksum") == 13504 and type(observations.get("checksum")) is int, "differential oracle changed")
    _pairs(observations.get("backends"))
    for backend, row in observations["backends"].items():
        _build(row.get("build"), backend)
        _source(row, backend)
        _execution(row.get("execution"), "13504\n")
    allocation = report.get("allocations", {})
    _pairs(allocation)
    for backend, row in allocation.items():
        _build(row.get("build"), backend)
        _source(row, backend, ROOT / ("tools/fixtures/c_owned_allocator." + ("c" if backend == "c" else "rs")))
        _execution(row.get("execution"), "3 3 0 1\n")
        require(row.get("calls") == 6 and type(row.get("calls")) is int, "allocator case denominator changed")
    negative = report.get("native_leak_control", {})
    _build(negative.get("build"), "c")
    _execution(negative.get("execution"), "3 0 3 1\n", success=False)
    require(negative.get("mutation") == "remove_buffer_free" and negative["build"]["source_sha256"] != allocation["c"]["build"]["source_sha256"], "negative control was not a different native implementation")
    controls = report.get("rejections", [])
    require(isinstance(controls, list) and len(controls) == len(REJECTIONS), "missing C rejection controls")
    require([r.get("name") for r in controls] == list(REJECTIONS), "C rejection controls duplicated or missing")
    for row, (source, code) in zip(controls, REJECTIONS.values()):
        require(row.get("source_sha256") == digest(source.encode()) and row.get("ok") is False and row.get("c_emitted") is False, "rejection control source/result differs")
        require(row.get("codes") == [code], "wrong rejection cause")
    source_files = report.get("sources", {})
    expected = ["examples/c_owned_backend/owned.hepta", "examples/c_owned_backend/main.hepta",
                "tools/fixtures/c_owned_allocator.c", "tools/fixtures/c_owned_allocator.rs", "tools/validate_c_owned.py"]
    require(isinstance(source_files, dict) and set(source_files) == set(expected), "qualification source inventory differs")
    for name in expected:
        require(source_files[name] == digest((ROOT / name).read_bytes()), "qualification source identity differs")
    return {"ok": True, "paired_calls": 256, "allocator_calls_per_backend": 6,
            "actual_allocator_refusals_per_backend": 1, "negative_native_controls": 1,
            "rejection_controls": len(REJECTIONS), "resource_ir_sha256": verified["ir_sha256"]}


def qualify(output: Path, rustc=None) -> dict:
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    require(not output.exists(), "refusing to overwrite an existing qualification report")
    files = output.parent / (output.stem + ".files")
    files.mkdir()
    report = {"schema": SCHEMA, "ok": False, "compiler_sha256": compiler_hash(), "claims": dict(CLAIMS),
              "source_semantics": "explicit_owned_and_immediate_borrows_hosted_abort"}
    try:
        entry = ROOT / "examples/c_owned_backend/main.hepta"
        project = analyze_project(entry, backend="c", crate_type="bin")
        require(project.report["ok"], str(project.report))
        graph = lower_resource_ir(project.program, project.checked, project_sha256=project.project.identity)
        graph_file = files / "resource-ir.json"
        graph_file.write_text(json.dumps(graph, indent=2, sort_keys=True) + "\n")
        report.update(project_sha256=project.project.identity, resource_ir=identity(graph_file),
                      resource_verification=verify_resource_ir(graph))
        differential = {}
        for backend in ("c", "rust"):
            analysis = project if backend == "c" else analyze_project(entry, rustc=rustc, crate_type="bin")
            require(analysis.report["ok"], str(analysis.report))
            emitted = analysis.c if backend == "c" else analysis.rust
            source_file = files / ("differential." + ("c" if backend == "c" else "rs"))
            source_file.write_text(emitted)
            build = (compile_c(emitted, output=files / "differential-c", sanitize=True) if backend == "c" else
                     compile_rust(emitted, rustc=rustc, crate_type="bin", output=files / "differential-rust"))
            require(build["ok"], str(build))
            differential[backend] = {"frontend": analysis.report, "source": identity(source_file), "build": build, "execution": run(build["artifact"])}
        report["differential"] = {"paired_calls": 256, "checksum": 13504, "backends": differential}
        source = (ROOT / "examples/c_owned_backend/owned.hepta").read_text()
        allocations = {}
        for backend in ("c", "rust"):
            analysis = analyze(source, path=str(ROOT / "examples/c_owned_backend/owned.hepta"), backend=backend, rustc=rustc)
            require(analysis.report["ok"], str(analysis.report))
            harness = (ROOT / ("tools/fixtures/c_owned_allocator." + ("c" if backend == "c" else "rs"))).read_text()
            emitted = (analysis.c if backend == "c" else analysis.rust) + harness
            source_file = files / ("allocation." + ("c" if backend == "c" else "rs"))
            source_file.write_text(emitted)
            flags = ["-fno-builtin-calloc", "-fno-builtin-free", "-Wl,--wrap=calloc", "-Wl,--wrap=free"]
            build = (compile_c(emitted, output=files / "allocation-c", sanitize=True, link_args=flags) if backend == "c" else
                     compile_rust(emitted, rustc=rustc, crate_type="bin", output=files / "allocation-rust"))
            require(build["ok"], str(build))
            allocations[backend] = {"calls": 6, "frontend": analysis.report, "source": identity(source_file), "build": build, "execution": run(build["artifact"])}
            if backend == "c":
                require(emitted.count("free(value.data);") == 1, "buffer destructor mutation target changed")
                wrong = emitted.replace("free(value.data);", "(void)value;")
                (files / "allocation-leak.c").write_text(wrong)
                mutated = compile_c(wrong, output=files / "allocation-leak", sanitize=True, link_args=flags)
                require(mutated["ok"], str(mutated))
                report["native_leak_control"] = {"mutation": "remove_buffer_free", "build": mutated, "execution": run(mutated["artifact"])}
        report["allocations"] = allocations
        controls = []
        for name, (source, _) in REJECTIONS.items():
            analysis = analyze(source, backend="c", native=False)
            controls.append({"name": name, "source_sha256": digest(source.encode()), "ok": analysis.report["ok"],
                             "c_emitted": analysis.c is not None, "codes": [d["code"] for d in analysis.report["diagnostics"]]})
        report["rejections"] = controls
        report["sources"] = {name: digest((ROOT / name).read_bytes()) for name in [
            "examples/c_owned_backend/owned.hepta", "examples/c_owned_backend/main.hepta",
            "tools/fixtures/c_owned_allocator.c", "tools/fixtures/c_owned_allocator.rs", "tools/validate_c_owned.py"]}
        report["ok"] = True
        report["validation"] = validate_c_owned_qualification(report)
    except Exception as error:
        report["ok"] = False
        report["error"] = {"type": type(error).__name__, "message": str(error)}
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/c-owned-backend.json")
    parser.add_argument("--rustc", default=os.environ.get("RUSTC"))
    args = parser.parse_args()
    report = qualify(args.output, args.rustc)
    print(json.dumps({"ok": report["ok"], "output": str(args.output), "validation": report.get("validation"), "error": report.get("error")}))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
