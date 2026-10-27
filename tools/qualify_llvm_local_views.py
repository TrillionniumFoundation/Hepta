"""Untimed source-bound qualification of local stored u8-slice views.

Independent LLVM and C objects execute the same Hepta source as an
instrumented Rust reference. No performance or general lifetime claim.
"""
from __future__ import annotations

import argparse
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import tempfile
from unittest.mock import patch

from hepta.backend import compile_rust
from hepta.c_backend import compile_c, emit_c
from hepta.llvm_owned_backend import PROFILE, TARGET, LLVMOwnedRejected, compile_owned_llvm, emit_owned_llvm
from hepta.llvm_owned_pipeline import build_llvm_owned_source
from hepta.native_tool_identity import digest_executable
from hepta.pipeline import analyze, analyze_project, compiler_hash
from hepta.resource_ir import ResourceIRError, verify_resource_ir
from hepta.resource_lowering import lower_resource_ir
from hepta.resource_source import verify_resource_source
from tools.evidence_checks import is_sha, native_build, normalized_errors, require, strict_equal
from tools.qualify_llvm_owned import execute, process, successful
from tools.qualify_resource_views import _native_frontend
from tools.resource_view_cases import FRONTEND_REJECTIONS, NATIVE_REJECTIONS

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "examples/llvm_local_views/main.hepta"
FIXTURE = ENTRY.parent
SCHEMA = "hepta.llvm-local-views-qualification.v1"
BACKENDS = ("llvm", "c", "rust")
LINK_FLAGS = ["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-fsanitize=undefined", "-fno-sanitize-recover=all"]
WRAP_FLAGS = ["-fno-builtin-malloc", "-fno-builtin-calloc", "-fno-builtin-free",
              "-Wl,--wrap=malloc", "-Wl,--wrap=calloc", "-Wl,--wrap=free"]
CLAIMS = {"independent_llvm_machine_code": True, "independent_c_machine_code": True,
          "fresh_rust_reference_required": True, "source_resource_replayed": True,
          "local_shared_copy_and_exclusive_move_qualified": True,
          "actual_allocator_failures_and_cleanup_observed": True,
          "stored_view_parameters_or_returns_supported": False, "labelled_views_supported": False,
          "mixed_generic_lifetime_parameters_supported": False, "fallback_used": False,
          "backend_refinement_proved": False, "whole_language_soundness_proved": False,
          "cross_target_execution_qualified": False, "performance_qualified": False}
REJECTED_BUILD_CLAIMS = {"actual_source_replayed": False, "independent_resource_cfg_verified": False,
    "native_rust_reference_required": True, "native_artifact_compiled": False,
    "rust_codegen_used": False, "c_codegen_used": False, "fallback_used": False,
    "native_execution_qualified": False, "owned_foreign_abi_qualified": False,
    "backend_refinement_proved": False, "whole_language_memory_safety_proved": False,
    "cross_target_execution_qualified": False}
UNSUPPORTED = {
    "non_slice_storage": "struct V<'a>{data:read 'a u64} fn main()->Unit effects {} {}",
    "labelled_view": "struct V<'a>{data:read 'a [u8],tag:u64} fn main()->Unit effects {} {}",
    "escaping_view": "struct V<'a>{data:read 'a [u8]} fn f<'a>(x:read 'a [u8])->V<'a> effects {} {return V{data:read x};}",
    "nested_view": "struct V<'a>{data:read 'a [u8]} struct N<'a>{view:V<'a>} fn main()->Unit effects {} {}",
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def inputs():
    paths = [ENTRY, *(FIXTURE / name for name in ("driver.c", "observer.c", "observer.rs")),
             *(ROOT / "tools" / name for name in ("qualify_llvm_local_views.py", "resource_view_cases.py",
               "qualify_llvm_owned.py", "qualify_resource_views.py", "evidence_checks.py"))]
    return {str(path.relative_to(ROOT)): sha(path.read_bytes()) for path in paths}


def oracle(size, mode, reject):
    result, attempts, allocations, refusals = -1, 0, 0, 0
    if size > 65535:
        result = -3
    elif size:
        attempts = 1
        if reject == 1:
            refusals = 1
        else:
            allocations = 1
            if mode == 1:
                result = -2
            elif mode == 2:
                result = 11
            else:
                attempts = 2
                if reject == 2:
                    refusals, result = 1, -101
                else:
                    allocations, result = 2, size + 15
    return {"size": size, "mode": mode, "reject": reject, "result": result,
            "attempts": attempts, "allocations": allocations, "releases": allocations,
            "refusals": refusals, "live": 0}


def observations():
    rows = []
    for size in (0, 1, 2, 4, 31, 65535, 65536):
        for mode in (0, 1, 2, 255):
            for reject in (0, 1, 0, 2, 0):
                rows.append({"case": len(rows), **oracle(size, mode, reject)})
    return rows


def cases_header():
    fields = ("size", "mode", "reject", "result", "attempts", "allocations", "refusals")
    return ("struct Case {size_t size; uint8_t mode; size_t reject; int32_t result; "
            "size_t attempts, allocations, refusals;};\nstatic const struct Case cases[] = {\n"
            + ",\n".join("{" + ",".join(str(row[key]) for key in fields) + "}" for row in observations()) + "\n};\n")


def output_text(rows):
    return "".join(json.dumps(row, separators=(",", ":")) + "\n" for row in rows)


def negative_sources():
    return {**{name: value[0] for name, value in NATIVE_REJECTIONS.items()},
            **{name: value[0] for name, value in FRONTEND_REJECTIONS.items()}, **UNSUPPORTED}


def static_rejection(source, path):
    analysis = analyze(source, path, native=False)
    if not analysis.report["ok"]:
        return {"stage": "frontend", "codes": [row["code"] for row in analysis.report["diagnostics"]]}
    try:
        emit_owned_llvm(analysis.program, analysis.checked)
    except ResourceIRError as error:
        return {"stage": "resource", "code": error.code}
    except LLVMOwnedRejected as error:
        return {"stage": "native_profile", "code": str(error).split(":", 1)[0]}
    raise ValueError("A fixed invalid or unsupported candidate was accepted")


def tamper_checks(analysis, ir, directory):
    changed = ir.text.replace("ret i32 11", "ret i32 12")
    require(changed != ir.text, "Fixed native branch mutation no longer changes code")
    mutants = {"rehashed_native_branch": replace(ir, text=changed, sha256=sha(changed.encode())),
               "resource_verification_identity": replace(ir, resource_verification_sha256="0" * 64),
               "semantic_identity": replace(ir, semantic_sha256="0" * 64)}
    rows = {}
    for name, mutant in mutants.items():
        destination = directory / (name + ".o")
        with patch("hepta.llvm_owned_backend._clang_run") as native:
            try:
                compile_owned_llvm(mutant, program=analysis.program, checked=analysis.checked,
                    project_sha256=analysis.project.identity, output=destination, kind="object")
            except LLVMOwnedRejected as error:
                rows[name] = {"code": str(error).split(":", 1)[0], "native_invoked": native.called,
                              "artifact_exists": destination.exists()}
            else:
                raise ValueError("Mutated LLVM/source identity was accepted")
    return rows


def artifact(path):
    data = Path(path).read_bytes()
    return {"path": str(path), "sha256": sha(data), "bytes": len(data)}


def link_command(cc, directory, name, library):
    argv = [cc, *LINK_FLAGS, str(directory / "driver.c")]
    if name != "rust":
        argv += [str(directory / "observer.c"), *WRAP_FLAGS]
    return [*argv, str(library), "-pthread", "-ldl", "-lm", "-o", str(directory / (name + "-run"))]


def record_command(report, key, argv):
    row = execute(argv, timeout=60)
    report[key] = row
    return row


def generated_sources(analysis, ir):
    c = emit_c(analysis.program, analysis.checked, crate_type="obj")
    rust = analysis.rust + (FIXTURE / "observer.rs").read_text()
    return c, rust, {"llvm": ir.text, "llvm_sha256": ir.sha256, "c_sha256": sha(c.encode()),
        "rust_sha256": sha(analysis.rust.encode()), "instrumented_rust_sha256": sha(rust.encode()),
        "cases_sha256": sha(cases_header().encode())}


def _execute(report, *, rustc, clang, cc):
    analysis = analyze_project(ENTRY, rustc=rustc, crate_type="staticlib")
    report["source_validation"] = analysis.report
    require(analysis.report["ok"] is True and not analysis.report["assumptions"], "Fresh native reference failed")
    graph = lower_resource_ir(analysis.program, analysis.checked, project_sha256=analysis.project.identity)
    report["resource_graph"], report["resource_verification"] = graph, verify_resource_ir(graph)
    report["source_replay"] = verify_resource_source(ENTRY, graph, rustc=rustc)
    require(report["source_replay"]["ok"] is True and graph["schema"] == "hepta.resource-ir.v4", "Fresh v4 source replay failed")
    ir = emit_owned_llvm(analysis.program, analysis.checked, project_sha256=analysis.project.identity)
    c, rust, report["generated_sources"] = generated_sources(analysis, ir)
    cc, clang = (str(Path(shutil.which(name) or name).resolve()) for name in (cc, clang))
    report["driver_compiler"] = artifact(cc)
    with tempfile.TemporaryDirectory(prefix="hepta-local-views-") as td:
        directory = Path(td)
        for name in ("driver.c", "observer.c"):
            (directory / name).write_bytes((FIXTURE / name).read_bytes())
        (directory / "cases.h").write_text(cases_header())
        report["builds"], report["native"] = {}, {}
        libraries = {name: directory / ("views-" + name + (".a" if name == "rust" else ".o")) for name in BACKENDS}
        report["builds"]["llvm"] = build_llvm_owned_source(ENTRY, libraries["llvm"], rustc=rustc, clang=clang, kind="object")
        require(report["builds"]["llvm"]["ok"] is True, "Source-bound LLVM build rejected")
        report["builds"]["c"] = compile_c(c, cc=cc, crate_type="obj", output=libraries["c"], sanitize=True)
        report["builds"]["rust"] = compile_rust(rust, rustc=rustc, crate_type="staticlib", output=libraries["rust"])
        for name in BACKENDS:
            require(report["builds"][name]["ok"] is True, "Native " + name + " build failed")
            row = {"library": artifact(libraries[name])}
            report["native"][name] = row
            successful(record_command(row, "link", link_command(cc, directory, name, libraries[name])))
            binary = directory / (name + "-run")
            row["executable"] = row["link"]["artifact"] = artifact(binary)
            run = record_command(row, "execution", [str(binary)])
            run["executable"] = artifact(binary)
            require(successful(run) == output_text(observations()), "Observed " + name + " values/faults/cleanup differ")
            row["observations"] = [json.loads(line) for line in run["stdout"].splitlines()]
            bounds = record_command(row, "bounds", [str(binary), "bounds"])
            bounds["executable"] = artifact(binary)
            require(bounds.get("returncode") == -signal.SIGABRT and "capture_error" not in bounds, "Stored slice bounds guard did not abort")
            require(artifact(binary) == row["executable"], "Executed native binary changed")
        report["tamper_rejections"] = tamper_checks(analysis, ir, directory)
        # Deliberate wrong code outside the production source gate, solely
        # to ensure that real owner leaks trigger the actual observer.
        wrong = ir.text.replace("call void @free(ptr %data)", "; negative control: omitted owner release")
        require(wrong != ir.text, "Fixed leak mutation no longer changes cleanup")
        wrong_path, wrong_object = directory / "wrong.ll", directory / "wrong.o"
        wrong_path.write_text(wrong)
        negative = {"source_sha256": sha(wrong.encode())}
        report["negative_control"] = negative
        successful(record_command(negative, "compile", [clang, "-x", "ir", "-O3", "-c", str(wrong_path), "-o", str(wrong_object)]))
        negative["object"] = negative["compile"]["artifact"] = artifact(wrong_object)
        successful(record_command(negative, "link", link_command(cc, directory, "wrong", wrong_object)))
        wrong_binary = directory / "wrong-run"
        negative["executable"] = negative["link"]["artifact"] = artifact(wrong_binary)
        run = record_command(negative, "execution", [str(wrong_binary)])
        run["executable"] = artifact(wrong_binary)
        require(run.get("returncode") == 86 and "capture_error" not in run, "Real owner leak escaped observation")
        negative["observations"] = [json.loads(line) for line in run["stdout"].splitlines()]
        report["source_rejections"] = {}
        for name, source in negative_sources().items():
            path, output = directory / (name + ".hepta"), directory / (name + "-invalid.o")
            path.write_text(source)
            row = {"source_sha256": sha(source.encode()), "static": static_rejection(source, str(path))}
            report["source_rejections"][name] = row
            row["build"] = build_llvm_owned_source(path, output, rustc=rustc, clang=clang, kind="object")
            row["artifact_exists"] = output.exists()
            require(row["build"]["ok"] is False and not row["artifact_exists"], "Invalid source published LLVM")
    require(analysis.project.unchanged() and report["compiler_sha256"] == compiler_hash()
            and report["inputs"] == inputs(), "Qualification inputs changed")
    report.update(ok=True, status="passed", claims=dict(CLAIMS))
    validate_report(report)


def qualify(output, *, rustc=None, clang="clang", cc="gcc"):
    output = Path(output)
    if output.exists() or output.is_symlink() or not output.parent.is_dir():
        raise ValueError("Qualification output must be a new file in an existing directory")
    report = {"schema": SCHEMA, "ok": False, "status": "failed", "claims": dict.fromkeys(CLAIMS, False),
              "compiler_sha256": compiler_hash(), "inputs": inputs()}
    try:
        _execute(report, rustc=rustc, clang=clang, cc=cc)
    except (ValueError, OSError, RuntimeError, KeyError, TypeError, AttributeError) as error:
        report.update(ok=False, status="failed", claims=dict.fromkeys(CLAIMS, False),
                      validation_error=type(error).__name__ + ": " + str(error))
    with output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")
    return report


def _artifact(value):
    require(set(value) == {"path", "sha256", "bytes"} and isinstance(value["path"], str)
            and is_sha(value["sha256"]) and type(value["bytes"]) is int and value["bytes"] > 0,
            "Native artifact identity missing")


def _source_replay(actual, expected):
    expected = json.loads(json.dumps(expected))
    require(expected["ok"] is True, "Current source replay failed")
    _native_frontend(actual["source_validation"], expected["source_validation"])
    expected["source_validation"] = actual["source_validation"]
    expected["status"] = "source_replayed"
    expected["source_binding"]["native_reference"] = "rustc_checked"
    expected.pop("sha256")
    expected["sha256"] = sha(json.dumps(expected, sort_keys=True, separators=(",", ":"),
                                         ensure_ascii=False, allow_nan=False).encode())
    require(strict_equal(actual, expected), "Source replay identity or closed scope changed")


def _llvm_build(build, analysis, ir, verification):
    require(set(build) == {"schema", "profile", "ok", "status", "source", "output", "kind", "claims",
                          "reference_validation", "resource_verification", "source_binding", "native_backend"},
            "Source-facing LLVM fields changed")
    require(build["schema"] == "hepta.build-llvm-owned.v1" and build["ok"] is True
            and build["status"] == "native_compiled_not_executed" and build["kind"] == "object"
            and build["source"] == str(ENTRY) and build["profile"] == PROFILE, "Source-bound LLVM build missing")
    _native_frontend(build["reference_validation"], analyze_project(ENTRY, native=False, crate_type="rlib").report)
    require(strict_equal(build["resource_verification"], verification) and strict_equal(build["source_binding"], {
        "project_sha256": analysis.project.identity, "sources": dict(analysis.project.sources),
        "compiler_sha256": ir.compiler_sha256, "semantic_sha256": ir.semantic_sha256,
        "resource_ir_sha256": ir.resource_ir_sha256, "resource_verification_sha256": ir.resource_verification_sha256,
        "llvm_ir_sha256": ir.sha256, "exports": list(ir.functions), "specializations": list(ir.specializations)}),
        "Source-bound LLVM identities differ")
    require(strict_equal(build["claims"], {"actual_source_replayed": True, "independent_resource_cfg_verified": True,
        "native_rust_reference_required": True, "native_artifact_compiled": True, "rust_codegen_used": False,
        "c_codegen_used": False, "fallback_used": False, "native_execution_qualified": False,
        "owned_foreign_abi_qualified": False, "backend_refinement_proved": False,
        "whole_language_memory_safety_proved": False, "cross_target_execution_qualified": False}), "Source build scope changed")
    native = build["native_backend"]
    require(set(native) == {"schema", "ok", "status", "profile", "kind", "target", "output", "artifact_sha256",
        "artifact_bytes", "dynamic_abi", "target_layout_probe", "llvm_ir_sha256", "semantic_sha256", "resource_ir_sha256",
        "resource_verification_sha256", "compiler_sha256", "toolchain", "flags", "claims"}, "Actual LLVM native fields changed")
    require(native["schema"] == "hepta.llvm-owned-native.v1" and native["ok"] is True
            and native["status"] == "native_compiled_not_executed" and native["target"] == TARGET
            and native["profile"] == PROFILE and native["kind"] == "object" and native["dynamic_abi"] is None,
            "Actual LLVM object compilation missing")
    for key, value in {"llvm_ir_sha256": ir.sha256, "semantic_sha256": ir.semantic_sha256,
        "resource_ir_sha256": ir.resource_ir_sha256, "resource_verification_sha256": ir.resource_verification_sha256,
        "compiler_sha256": ir.compiler_sha256}.items():
        require(native[key] == value, "LLVM native origin differs: " + key)
    require(strict_equal(native["flags"], ["--target=" + TARGET, "-x", "ir", "-O3", "-fPIC", "-c"])
        and strict_equal(native["claims"], {"checked_ast_resource_origin_replayed": True,
            "rust_codegen_used": False, "c_codegen_used": False, "fallback_used": False,
            "native_execution_qualified": False, "backend_refinement_proved": False,
            "whole_language_memory_safety_proved": False, "cross_target_execution_qualified": False}), "LLVM flags or claims differ")
    tool = native["toolchain"]
    require(set(tool) == {"path", "sha256", "version", "default_target"}
            and digest_executable(Path(tool["path"])) == tool["sha256"]
            and tool["default_target"] in {TARGET, "x86_64-pc-linux-gnu"}, "Selected Clang identity differs")
    version = re.search(r"\bclang version ([0-9]+)\.", tool["version"])
    require(version is not None and int(version.group(1)) >= 20,
            "LLVM compilation requires a Clang 20+ version identity")
    from hepta.owned_target_layout import _SOURCE
    layout = dict(native["target_layout_probe"])
    require(is_sha(layout.pop("probe_object_sha256", None)), "Target layout probe object identity missing")
    size = layout.pop("probe_object_bytes", None)
    require(type(size) is int and 0 < size <= 1_048_576, "Target layout probe artifact size invalid")
    require(strict_equal(layout, {"schema": "hepta.owned-target-layout.v1",
        "status": "target_c_static_assertions_compiled_not_executed", "target": TARGET, "machine": 62,
        "c_source_sha256": sha(_SOURCE.encode("ascii")), "bound_llvm_sha256": ir.sha256, "compiler_checked": True,
        "observed_requirements": {"little_endian": True, "char_bits": 8, "pointer_bits": 64,
            "usize_bits": 64, "long_bits": 64, "buffer_bytes": 16, "buffer_alignment": 8, "data_offset": 0, "len_offset": 8},
        "llvm_layout_equivalence_proved": False, "native_abi_execution_qualified": False, "physical_target_executed": False}),
        "Layout probe source, native requirements or proof scope changed")


@normalized_errors
def validate_report(report):
    """Pure current-source/evidence consistency checks; never rerun natives.

    This does not authenticate arbitrary third-party reports. Temporary
    binaries can be removed once their exact build/execution hashes remain.
    """
    fields = {"schema", "ok", "status", "claims", "compiler_sha256", "inputs", "source_validation",
        "resource_graph", "resource_verification", "source_replay", "generated_sources", "driver_compiler",
        "builds", "native", "tamper_rejections", "negative_control", "source_rejections"}
    require(isinstance(report, dict) and set(report) == fields and report["schema"] == SCHEMA
            and report["ok"] is True and report["status"] == "passed", "Not a complete passing qualification")
    require(strict_equal(report["claims"], CLAIMS), "Scope exceeds the local profile")
    require(report["compiler_sha256"] == compiler_hash() and strict_equal(report["inputs"], inputs()), "Current inputs differ")
    analysis = analyze_project(ENTRY, native=False, crate_type="staticlib")
    require(analysis.report["ok"] is True, "Current source no longer checks")
    _native_frontend(report["source_validation"], analysis.report)
    graph = lower_resource_ir(analysis.program, analysis.checked, project_sha256=analysis.project.identity)
    require(graph["schema"] == "hepta.resource-ir.v4" and strict_equal(report["resource_graph"], graph), "Exact current v4 graph differs")
    verified = verify_resource_ir(graph)
    require(verified["ok"] is True and strict_equal(report["resource_verification"], verified), "Resource verification differs")
    _source_replay(report["source_replay"], verify_resource_source(ENTRY, graph, native=False))
    ir = emit_owned_llvm(analysis.program, analysis.checked, project_sha256=analysis.project.identity)
    c, rust, generated = generated_sources(analysis, ir)
    require(strict_equal(report["generated_sources"], generated), "Generated code or fixed oracle differs")
    require(set(report["builds"]) == set(report["native"]) == set(BACKENDS), "Backend denominator changed")
    _llvm_build(report["builds"]["llvm"], analysis, ir, verified)
    native_build(report["builds"]["c"], "c", check_only=False, crate_type="obj", source_sha256=sha(c.encode()))
    native_build(report["builds"]["rust"], "rust", check_only=False, crate_type="staticlib", source_sha256=sha(rust.encode()))
    require("-fsanitize=undefined" in report["builds"]["c"]["flags"]
            and "-fno-sanitize-recover=all" in report["builds"]["c"]["flags"], "C UB checks were removed")
    rust_tool = report["builds"]["rust"]["toolchain"]
    require(rust_tool["version"].startswith("rustc 1.90.0 ")
            and digest_executable(Path(rust_tool["path"])) == rust_tool["executable_sha256"]
            and rust_tool["host"] == report["builds"]["rust"]["target"] == TARGET,
            "Pinned host Rust identity differs")
    for frontend in (report["source_validation"], report["source_replay"]["source_validation"], report["builds"]["llvm"]["reference_validation"]):
        require(strict_equal(frontend["backend"]["toolchain"], rust_tool)
                and frontend["backend"]["target"] == report["builds"]["rust"]["target"], "Native reference/build identities differ")
    ctool, tool = report["builds"]["c"]["toolchain"], report["driver_compiler"]
    _artifact(tool)
    require(artifact(tool["path"]) == tool and Path(ctool["path"]).resolve() == Path(tool["path"])
            and ctool["executable_sha256"] == tool["sha256"], "C library/caller compiler identities differ")
    require(report["builds"]["c"]["target"] in {TARGET, "x86_64-linux-gnu", "x86_64-pc-linux-gnu"},
            "C library target differs from the qualified Linux x86-64 ABI")
    expected = observations()
    directory = Path(report["native"]["llvm"]["library"]["path"]).parent
    for name in BACKENDS:
        row, built = report["native"][name], report["builds"][name]
        require(set(row) == {"library", "link", "executable", "execution", "observations", "bounds"}, "Native observation fields changed")
        _artifact(row["library"])
        _artifact(row["executable"])
        library, binary = directory / ("views-" + name + (".a" if name == "rust" else ".o")), directory / (name + "-run")
        receipt = built["native_backend"] if name == "llvm" else built
        artifact_key = "output" if name == "llvm" else "artifact"
        require(row["library"]["path"] == receipt[artifact_key] == str(library)
                and row["library"]["sha256"] == receipt["artifact_sha256"]
                and row["library"]["bytes"] == receipt["artifact_bytes"] and row["executable"]["path"] == str(binary), "Native library identity differs")
        if name == "llvm":
            require(built["output"] == str(library), "Published source artifact differs")
        process(row["link"], link_command(tool["path"], directory, name, library))
        require(row["link"]["stdout"] == row["link"]["stderr"] == "", "Caller build was not clean")
        for evidence, field in (("link", "artifact"), ("execution", "executable"), ("bounds", "executable")):
            require(strict_equal(row[evidence][field], row["executable"]), "Built/executed native binary identity differs")
        process(row["execution"], [str(binary)])
        require(row["execution"]["stdout"] == output_text(expected) and row["execution"]["stderr"] == ""
                and strict_equal(row["observations"], expected), "Complete 140-call results, failures or cleanup differ")
        process(row["bounds"], [str(binary), "bounds"], code=-signal.SIGABRT)
        require(row["bounds"]["stdout"] == "", "Bounds control returned a value")
    require(strict_equal(report["tamper_rejections"], {name: {"code": "E_LLVM_OWNED_ORIGIN", "native_invoked": False,
        "artifact_exists": False} for name in ("rehashed_native_branch", "resource_verification_identity", "semantic_identity")}), "Origin mutations were not rejected before Clang")
    negative = report["negative_control"]
    require(set(negative) == {"source_sha256", "compile", "object", "link", "executable", "execution", "observations"}, "Leak control fields differ")
    wrong = ir.text.replace("call void @free(ptr %data)", "; negative control: omitted owner release")
    require(wrong != ir.text and negative["source_sha256"] == sha(wrong.encode()), "Leak control source differs")
    clang = report["builds"]["llvm"]["native_backend"]["toolchain"]["path"]
    process(negative["compile"], [clang, "-x", "ir", "-O3", "-c", str(directory / "wrong.ll"), "-o", str(directory / "wrong.o")])
    process(negative["link"], link_command(tool["path"], directory, "wrong", directory / "wrong.o"))
    process(negative["execution"], [str(directory / "wrong-run")], code=86)
    for key in ("object", "executable"):
        _artifact(negative[key])
    require(negative["object"]["path"] == str(directory / "wrong.o") and negative["executable"]["path"] == str(directory / "wrong-run")
            and strict_equal(negative["compile"]["artifact"], negative["object"])
            and strict_equal(negative["link"]["artifact"], negative["executable"])
            and strict_equal(negative["execution"]["executable"], negative["executable"]), "Leak-control artifact identity differs")
    stop = next(i for i, row in enumerate(expected) if row["allocations"])
    wrong_rows = [dict(row) for row in expected[:stop + 1]]
    wrong_rows[-1].update(releases=0, live=wrong_rows[-1]["allocations"])
    require(strict_equal(negative["observations"], wrong_rows) and negative["execution"]["stdout"] == output_text(wrong_rows)
            and negative["execution"]["stderr"] == "", "Actual native leak observation differs")
    require(set(report["source_rejections"]) == set(negative_sources()), "Rejected-source denominator differs")
    for name, source in negative_sources().items():
        row, path, output = report["source_rejections"][name], directory / (name + ".hepta"), directory / (name + "-invalid.o")
        require(set(row) == {"source_sha256", "static", "build", "artifact_exists"} and row["source_sha256"] == sha(source.encode())
                and row["artifact_exists"] is False and strict_equal(row["static"], static_rejection(source, str(path))), "Negative source/static rejection differs")
        build = row["build"]
        require(set(build) == {"schema", "profile", "ok", "status", "source", "output", "kind", "claims",
                             "reference_validation", "diagnostics"}
                and build.get("schema") == "hepta.build-llvm-owned.v1" and build.get("ok") is False and build.get("status") == "rejected"
                and build.get("profile") == PROFILE and build.get("source") == str(path) and build.get("output") == str(output)
                and build.get("kind") == "object" and build.get("diagnostics")
                and strict_equal(build["claims"], REJECTED_BUILD_CLAIMS),
                "Rejected source fields or closed native/proof scope changed")
        reference = build["reference_validation"]
        # Recreate the exact single-file project in memory after temporary
        # sources have been removed. A source hash alone did not bind its
        # module graph, profile, borrow scope or native reference identity.
        candidate = analyze_project(path, source_overrides={str(path): source}, native=False, crate_type="rlib")
        require(reference["source_sha256"] == candidate.report["source_sha256"] and reference["compiler_sha256"] == compiler_hash(), "Rejected source identity differs")
        if name in FRONTEND_REJECTIONS:
            require(strict_equal(reference, candidate.report)
                    and reference["ok"] is False and reference["checks"]["types_effects_resources"] == "rejected"
                    and FRONTEND_REJECTIONS[name][1] in {d["code"] for d in reference["diagnostics"]},
                    "Exact frontend rejection differs")
        elif name in NATIVE_REJECTIONS:
            native = reference["backend"]
            require(set(reference) == set(candidate.report) | {"backend"}, "Rejected native reference fields changed")
            for key, value in candidate.report.items():
                if key not in {"ok", "status", "checks", "diagnostics"}:
                    require(strict_equal(reference[key], value), "Rejected native reference differs: " + key)
            require(reference["ok"] is False and reference["checks"]["types_effects_resources"] == "passed_in_supported_subset"
                    and reference["status"] == "rejected"
                    and strict_equal(reference["checks"], dict(candidate.report["checks"], rust_borrows_types="rejected"))
                    and native["ok"] is False and native["check_only"] is True and native["crate_type"] == "rlib"
                    and native["rust_sha256"] == sha(candidate.rust.encode())
                    and native["target"] == TARGET
                    and strict_equal(native["toolchain"], rust_tool)
                    and strict_equal(native["flags"], report["builds"]["rust"]["flags"])
                    and NATIVE_REJECTIONS[name][1].intersection({d["code"] for d in reference["diagnostics"]}), "Actual Rust lifetime rejection missing")
        else:
            _native_frontend(reference, candidate.report)
            require(strict_equal(reference["backend"]["toolchain"], rust_tool)
                    and reference["backend"]["target"] == TARGET
                    and strict_equal(reference["backend"]["flags"], report["builds"]["rust"]["flags"]),
                    "Unsupported shape native reference identity differs")
    require(analysis.project.unchanged() and compiler_hash() == report["compiler_sha256"] and inputs() == report["inputs"], "Inputs changed during validation")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rustc", default=os.environ.get("RUSTC"))
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--cc", default="gcc")
    args = parser.parse_args(argv)
    report = qualify(args.output, rustc=args.rustc, clang=args.clang, cc=args.cc)
    print(json.dumps({"ok": report["ok"], "status": report["status"], "output": str(args.output)}))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
