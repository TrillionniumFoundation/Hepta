"""Execute actual composed C++ migration through the independent LLVM backend.

This gate runs the same frozen cases as validate_cpp_composed. Its machine code
contains only the migrated Hepta implementation emitted directly as LLVM and
the C observation harness. The original C++/Rust/C routes have their own gate.
No performance claim, general C++ translation proof, or foreign attestation is
inferred from the finite executions or the retained-report consistency check.
"""
from __future__ import annotations

import argparse
from collections import Counter
import copy
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from hepta.ast import HeptaError
from hepta.cpp_composed_migrate import migrate_cpp_composed, translate_cpp_composed
from hepta.llvm_owned_backend import PROFILE, TARGET, emit_owned_llvm
from hepta.llvm_owned_pipeline import build_llvm_owned_source
from hepta.object_structure import qualified_object
from hepta.object_symbols import inspect_object_symbols
from hepta.owned_target_layout import probe_owned_target_layout
from hepta.pipeline import analyze_project, compiler_hash
from hepta.resource_ir import verify_resource_ir
from hepta.resource_lowering import lower_resource_ir
from tools.evidence_checks import native_build, normalized_errors, require, strict_equal
from tools.validate_cpp_composed import EXAMPLE, INPUTS, VARIANTS, cases, case_sources, observation_oracle
from tools.validate_cpp_composed import _word
from tools.validate_cpp_owned import WRAP_FLAGS, _canonical, _exception_record, _identity, _process, _run, _sha

SCHEMA = "hepta.cpp-composed-to-llvm-qualification.v1"
STATUS = "native_composed_llvm_qualified"
CLAIMS = {
    "actual_cpp_composite_implementation_migrated": True,
    "actual_migrated_source_compiled_by_llvm": True,
    "original_cpp_linked": False,
    "original_cpp_executed_by_this_gate": False,
    "rust_codegen_used_for_machine_code": False,
    "c_codegen_used_for_machine_code": False,
    "native_rust_reference_required": True,
    "fallback_used": False,
    "general_cpp_raii_migration": False,
    "source_equivalence_proved": False,
    "whole_language_soundness_proved": False,
    "performance_qualified_by_this_gate": False,
}
BUILD_CLAIMS = {
    "actual_source_replayed": True, "independent_resource_cfg_verified": True,
    "native_rust_reference_required": True, "native_artifact_compiled": True,
    "rust_codegen_used": False, "c_codegen_used": False, "fallback_used": False,
    "native_execution_qualified": False, "owned_foreign_abi_qualified": False,
    "backend_refinement_proved": False, "whole_language_memory_safety_proved": False,
    "cross_target_execution_qualified": False,
}
NATIVE_CLAIMS = {
    "checked_ast_resource_origin_replayed": True,
    "rust_codegen_used": False, "c_codegen_used": False, "fallback_used": False,
    "native_execution_qualified": False, "backend_refinement_proved": False,
    "whole_language_memory_safety_proved": False, "cross_target_execution_qualified": False,
}
IR_FLAGS = ["--target=" + TARGET, "-x", "ir", "-O3", "-fPIC", "-c"]
LINK_FLAGS = ["-std=c11", "-O2", "-fno-lto", "-Werror=implicit-function-declaration",
              "-Werror=implicit-int", "-Werror=strict-prototypes", *WRAP_FLAGS]
NEGATIVES = ("leak", "destruction_order")


def inputs():
    return {name: _sha((ROOT / name).read_bytes()) for name in
            (*INPUTS, "tools/qualify_cpp_composed_llvm.py")}


def _closed(record, keys, label):
    require(type(record) is dict and set(record) == set(keys.split()), "Closed " + label + " schema required")


def _file(record, expected):
    expected = Path(expected)
    require(not expected.is_symlink() and expected.is_file()
            and strict_equal(record, _identity(expected)), "Retained native artifact/source differs: " + str(expected))


def _tool(name):
    selected = shutil.which(name)
    require(selected is not None, "Required native tool unavailable: " + name)
    return {"driver": selected, **_identity(selected)}


def _check_tool(record):
    _closed(record, "driver path bytes sha256", "native tool")
    require(strict_equal({key: record[key] for key in ("path", "bytes", "sha256")},
                         _identity(record["driver"])), "Native executable identity changed")


def _command(row, field, argv, expected_code=0):
    # Record before testing return status so all completed/partial observations
    # survive a failed native build or execution.
    row[field] = _run(argv)
    _process(row[field], expected_code)
    return row[field]


def _check_command(record, expected, code=0):
    _process(record, code)
    require(record["command"] == list(map(str, expected)), "Actual native command differs")


def _native_object(path):
    data = Path(path).read_bytes()
    require(qualified_object(data, "ELF64", 62), "Expected a complete x86-64 ELF relocatable object")
    symbols = inspect_object_symbols(data, "ELF64", 62)
    require(symbols["defined"] == frozenset({"composed_case"})
            and symbols["undefined"] <= frozenset({"malloc", "calloc", "free", "memset", "abort"}),
            "LLVM implementation object contains an unexpected public symbol or foreign dependency")
    return {key: sorted(value) for key, value in symbols.items()}


def _destructor_symbol(analysis, ir):
    functions = analysis.program.functions
    require(all(not fn.type_params for fn in functions) and len(functions) == len(ir.specializations),
            "Negative control requires the fully instantiated concrete function inventory")
    pairs = [(fn.name, symbol) for fn, symbol in zip(functions, ir.specializations)
             if fn.name.endswith("_HeptaComposite_drop")]
    require(len(pairs) == 1, "Exactly one emitted composite destructor must drive the order control")
    return pairs[0][1]


def mutate_llvm(text, mutation, *, destructor, count):
    """Create deliberately wrong LLVM; never route it through the safe compiler."""
    if mutation == "leak":
        target = "  call void @free(ptr %data)"
        require(text.count(target) == 1, "Expected one actual byte deallocation helper")
        result = text.replace(target, "  ; qualification negative control: omitted deallocation")
    elif mutation == "destruction_order":
        pattern = r"(define internal void @" + re.escape(destructor) + r"\([^\n]+\) \{\n)(.*?)(\n\})"
        found = re.search(pattern, text, re.S)
        require(found is not None, "Actual composite destructor not found in emitted LLVM")
        slots = r"(getelementptr %hepta\.type[0-9]+, ptr %v[0-9]+, i32 0, i32 )([0-9]+)"
        order = [int(match[1]) for match in re.findall(slots, found[2])]
        require(order == list(reversed(range(count)))
                and len(re.findall(r"call void @__hepta_owned_fn[0-9]+\(", found[2])) == count,
                "Negative destructor mutation requires the exact reverse field order")
        changed = re.sub(slots, lambda match: match[1] + str(count - 1 - int(match[2])), found[2])
        result = text[:found.start(2)] + changed + text[found.end(2):]
    else:
        raise ValueError("Unknown LLVM negative control")
    require(result != text, "Negative control did not change emitted LLVM")
    return result


def _link_command(cc, directory, obj, executable):
    return [cc, *LINK_FLAGS, "-I" + str(directory), str(EXAMPLE / "harness.c"), str(obj), "-o", str(executable)]


def negative_oracle(name, mutation):
    first = cases(name)[0]
    count = VARIANTS[name]
    require(first["family"] == "borrowed_read_success" and first["allocated"] == count
            and first["refusals"] == 0, "First control case must exercise every live resource")
    allocation = [event for event in first["events"] if event[0] == 1]
    release = [event for event in first["events"] if event[0] == 2]
    require(len(allocation) == count and len(release) == count, "Control resource event inventory differs")
    events = allocation if mutation == "leak" else allocation + list(reversed(release))
    trace = 14695981039346656037
    for event in events:
        for word in event:
            trace = _word(trace, word)
    return {"ok": False, "failure": "lifecycle", "case": 0, "allocated": count,
            "freed": 0 if mutation == "leak" else count, "live": count if mutation == "leak" else 0,
            "refusals": 0, "trace": f"{trace:016x}", "expected_trace": f"{first['trace']:016x}"}


def _negative(variant, mutation, analysis, ir, tools):
    count = VARIANTS[variant["name"]]
    directory = Path(variant["directory"])
    row = {"status": "in_progress", "stage": "llvm_mutation", "mutation": mutation,
           "qualified_compiler_output": False, "foreign_cpp_link_inputs": []}
    variant["negative_controls"][mutation] = row
    text = mutate_llvm(ir.text, mutation, destructor=_destructor_symbol(analysis, ir), count=count)
    source, obj, executable = (directory / (mutation + suffix) for suffix in (".ll", ".o", "-native"))
    source.write_text(text, encoding="ascii")
    row["llvm_source"] = _identity(source); row["stage"] = "native_compile"
    _command(row, "compile", [tools["clang"]["driver"], *IR_FLAGS, str(source), "-o", str(obj)])
    row["object"] = _identity(obj); row["symbols"] = _native_object(obj)
    row["stage"] = "native_link"
    _command(row, "link", _link_command(tools["cc"]["driver"], directory, obj, executable))
    row["artifact"] = _identity(executable); row["stage"] = "native_execution"
    executed = _command(row, "execution", [str(executable)], 3)
    row["observed"] = json.loads(executed["stdout"])
    row.update(status="completed", stage="native_failure_observed")


def qualify_cpp_composed_llvm(workdir, *, clang="clang", clangxx="clang++", rustc=None, cc="gcc"):
    requested = Path(workdir)
    work = requested.resolve()
    if requested.is_symlink() or work.exists():
        raise ValueError("A new composed LLVM qualification directory is required")
    work.mkdir(parents=True)
    report = {"schema": SCHEMA, "ok": False, "status": "failed", "workdir": str(work),
              "compiler_sha256": compiler_hash(), "inputs": inputs(), "claims": copy.deepcopy(CLAIMS),
              "foreign_cpp_link_inputs": [], "diagnostics": [], "variants": {}, "tools": {},
              "performance": {"status": "not_run"}, "inputs_unchanged": False}
    try:
        report["tools"] = {"clang": _tool(clang), "clangxx": _tool(clangxx), "cc": _tool(cc)}
        for name, count in VARIANTS.items():
            directory = work / name; directory.mkdir()
            row = {"name": name, "directory": str(directory), "status": "in_progress", "stage": "migration",
                   "foreign_cpp_link_inputs": [], "negative_controls": {}}
            report["variants"][name] = row
            original, migrated, entry = (directory / n for n in ("original.cpp", "migrated.hepta", "consumer.hepta"))
            original.write_bytes((EXAMPLE / (name + ".cpp")).read_bytes())
            row["migration"] = migrate_cpp_composed(original, migrated, clangxx=clangxx)
            require(row["migration"]["ok"] is True, "Actual composed C++ migration rejected")
            entry.write_bytes((EXAMPLE / "consumer.hepta").read_bytes())
            row["sources"] = {"original": _identity(original), "migrated": _identity(migrated), "consumer": _identity(entry)}
            vectors = cases(name); header, _ = case_sources(vectors)
            (directory / "cases.h").write_text(header)
            row.update(case_header=_identity(directory / "cases.h"), case_sha256=_sha(_canonical(vectors)),
                       case_families=dict(Counter(vector["family"] for vector in vectors)))
            row["stage"] = "source_native_build"
            row["build"] = build_llvm_owned_source(entry, directory / "implementation.o", clang=clang, rustc=rustc, kind="object")
            require(row["build"]["ok"] is True, "Actual migrated source LLVM compilation rejected: " + json.dumps(row["build"]))
            row["object"] = _identity(directory / "implementation.o")
            row["symbols"] = _native_object(directory / "implementation.o")
            analysis = analyze_project(entry, native=False, crate_type="rlib")
            require(analysis.report["ok"] is True, "Current source frontend failed after native build")
            ir = emit_owned_llvm(analysis.program, analysis.checked, project_sha256=analysis.project.identity)
            (directory / "implementation.ll").write_text(ir.text, encoding="ascii")
            row["llvm_source"] = _identity(directory / "implementation.ll")
            row["stage"] = "native_link"
            executable = directory / "implementation-native"
            _command(row, "link", _link_command(report["tools"]["cc"]["driver"], directory, directory / "implementation.o", executable))
            row["artifact"] = _identity(executable); row["stage"] = "native_execution"
            executed = _command(row, "execution", [str(executable)])
            row["observed"] = json.loads(executed["stdout"])
            require(strict_equal(row["observed"], observation_oracle(vectors)), "LLVM lifecycle differs from independent oracle")
            row["stage"] = "negative_controls"
            for mutation in NEGATIVES:
                _negative(row, mutation, analysis, ir, report["tools"])
            row.update(status="completed", stage="all_native_routes_recorded")
        report["inputs_unchanged"] = report["inputs"] == inputs() and report["compiler_sha256"] == compiler_hash()
        report.update(ok=True, status=STATUS)
        validate_report(report, clang=clang, clangxx=clangxx)
    except (HeptaError, OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        report.update(ok=False, status="failed")
        report["diagnostics"].append(_exception_record(error))
    return report


def _replay_build(row, analysis, ir, report, selected_clang):
    build = row["build"]; directory = Path(row["directory"])
    _closed(build, "schema profile ok status source output kind claims reference_validation resource_verification source_binding native_backend", "source-facing LLVM build")
    require(build["schema"] == "hepta.build-llvm-owned.v1" and build["profile"] == PROFILE
            and build["ok"] is True and build["status"] == "native_compiled_not_executed"
            and build["kind"] == "object" and build["source"] == str(directory / "consumer.hepta")
            and build["output"] == str(directory / "implementation.o")
            and strict_equal(build["claims"], BUILD_CLAIMS), "Incomplete or broadened source-facing native build")
    graph = lower_resource_ir(analysis.program, analysis.checked, project_sha256=analysis.project.identity)
    require(strict_equal(build["resource_verification"], verify_resource_ir(graph)), "Current independent resource verification differs")
    expected_binding = {"project_sha256": analysis.project.identity, "sources": analysis.project.sources,
        "compiler_sha256": compiler_hash(), "semantic_sha256": ir.semantic_sha256,
        "resource_ir_sha256": ir.resource_ir_sha256, "resource_verification_sha256": ir.resource_verification_sha256,
        "llvm_ir_sha256": ir.sha256, "exports": list(ir.functions), "specializations": list(ir.specializations)}
    require(strict_equal(build["source_binding"], expected_binding), "Current source/resource/LLVM origin differs")
    reference = build["reference_validation"]
    require(reference["ok"] is True and reference["status"] == "checked"
            and reference["checks"]["rust_borrows_types"] == "rustc_checked"
            and reference["compiler_sha256"] == report["compiler_sha256"]
            and reference["diagnostics"] == [] and reference["assumptions"] == [], "Native Rust reference gate missing")
    for key in ("source_sha256", "interface_sha256", "project", "effects", "claims"):
        require(strict_equal(reference[key], analysis.report[key]), "Fresh reference source identity differs: " + key)
    native_build(reference["backend"], "rust", check_only=True, crate_type="rlib", source_sha256=_sha(analysis.rust.encode()))
    native = build["native_backend"]
    _closed(native, "schema ok status profile kind target output artifact_sha256 artifact_bytes dynamic_abi target_layout_probe llvm_ir_sha256 semantic_sha256 resource_ir_sha256 resource_verification_sha256 compiler_sha256 toolchain flags claims", "owned LLVM native")
    require(native["schema"] == "hepta.llvm-owned-native.v1" and native["ok"] is True
            and native["status"] == "native_compiled_not_executed" and native["profile"] == PROFILE
            and native["kind"] == "object" and native["target"] == TARGET and native["dynamic_abi"] is None
            and strict_equal(native["claims"], NATIVE_CLAIMS) and native["flags"] == IR_FLAGS,
            "Wrong LLVM native profile, flags or scope")
    for key in ("llvm_ir_sha256", "semantic_sha256", "resource_ir_sha256", "resource_verification_sha256", "compiler_sha256"):
        require(native[key] == expected_binding[key], "Native origin does not match freshly replayed source: " + key)
    require(native["output"] == row["object"]["path"] and native["artifact_sha256"] == row["object"]["sha256"]
            and type(native["artifact_bytes"]) is int and native["artifact_bytes"] == row["object"]["bytes"], "Native object receipt differs")
    compiler = report["tools"]["clang"]
    require(native["toolchain"]["path"] == compiler["path"] and native["toolchain"]["sha256"] == compiler["sha256"],
            "Selected Clang identity differs from native build")
    # Recompile only the independent finite layout assertions. Native program
    # observations remain retained observations, not validator re-executions.
    require(strict_equal(native["target_layout_probe"], probe_owned_target_layout(selected_clang["path"], TARGET, ir.text)),
            "Independent current target-layout probe differs")


@normalized_errors
def validate_report(report, *, clang="clang", clangxx="clang++"):
    _closed(report, "schema ok status workdir compiler_sha256 inputs claims foreign_cpp_link_inputs diagnostics variants tools performance inputs_unchanged", "composed LLVM qualification")
    require(report["schema"] == SCHEMA and report["ok"] is True and report["status"] == STATUS
            and report["diagnostics"] == [], "Successful composed LLVM qualification required")
    require(strict_equal(report["claims"], CLAIMS) and report["foreign_cpp_link_inputs"] == []
            and report["performance"] == {"status": "not_run"}, "Broadened LLVM migration claims")
    require(report["compiler_sha256"] == compiler_hash() and report["inputs"] == inputs()
            and report["inputs_unchanged"] is True and set(report["variants"]) == set(VARIANTS), "Stale/incomplete input identities")
    require(set(report["tools"]) == {"clang", "clangxx", "cc"}, "Complete native tool inventory required")
    for tool in report["tools"].values():
        _check_tool(tool)
    selected_tools = {"clang": _tool(clang), "clangxx": _tool(clangxx)}
    for name, selected in selected_tools.items():
        require({key: report["tools"][name][key] for key in ("path", "sha256", "bytes")}
                == {key: selected[key] for key in ("path", "sha256", "bytes")}, "Caller-selected Clang tool differs")
    work = Path(report["workdir"])
    require(work.is_absolute() and not work.is_symlink() and work.is_dir(), "Exact work directory required")
    for name, row in report["variants"].items():
        _closed(row, "name directory status stage foreign_cpp_link_inputs negative_controls migration sources case_header case_sha256 case_families build object symbols llvm_source link artifact execution observed", "variant")
        directory = work / name
        require(row["name"] == name and row["directory"] == str(directory)
                and row["status"] == "completed" and row["stage"] == "all_native_routes_recorded"
                and row["foreign_cpp_link_inputs"] == [] and set(row["negative_controls"]) == set(NEGATIVES),
                "Incomplete variant or foreign C++ input")
        require(set(row["sources"]) == {"original", "migrated", "consumer"}, "Migration source inventory differs")
        for label, filename in (("original", "original.cpp"), ("migrated", "migrated.hepta"), ("consumer", "consumer.hepta")):
            _file(row["sources"][label], directory / filename)
        require(row["sources"]["original"]["sha256"] == _sha((EXAMPLE / (name + ".cpp")).read_bytes())
                and row["sources"]["consumer"]["sha256"] == _sha((EXAMPLE / "consumer.hepta").read_bytes()), "Current original/caller differ")
        rendered, migration = translate_cpp_composed(directory / "original.cpp", clangxx=clangxx)
        require(strict_equal(row["migration"], {**migration, "output": str(directory / "migrated.hepta")})
                and rendered.encode() == (directory / "migrated.hepta").read_bytes()
                == (EXAMPLE / (name + ".hepta")).read_bytes(), "Actual C++ translation replay differs")
        vectors = cases(name); header, _ = case_sources(vectors)
        _file(row["case_header"], directory / "cases.h")
        require(row["case_header"]["sha256"] == _sha(header.encode()) and row["case_sha256"] == _sha(_canonical(vectors))
                and strict_equal(row["case_families"], dict(Counter(vector["family"] for vector in vectors))), "Frozen case denominator differs")
        analysis = analyze_project(directory / "consumer.hepta", native=False, crate_type="rlib")
        require(analysis.report["ok"] is True and analysis.report["assumptions"] == [] and analysis.project.unchanged(),
                "Current migrated frontend no longer checks")
        ir = emit_owned_llvm(analysis.program, analysis.checked, project_sha256=analysis.project.identity)
        _file(row["llvm_source"], directory / "implementation.ll")
        require((directory / "implementation.ll").read_bytes() == ir.text.encode(), "Rehashed LLVM text differs from actual source")
        _file(row["object"], directory / "implementation.o")
        require(strict_equal(row["symbols"], _native_object(directory / "implementation.o")), "Object symbol inventory differs")
        _replay_build(row, analysis, ir, report, selected_tools["clang"])
        executable = directory / "implementation-native"
        _file(row["artifact"], executable)
        _check_command(row["link"], _link_command(report["tools"]["cc"]["driver"], directory, directory / "implementation.o", executable))
        _check_command(row["execution"], [str(executable)])
        require(strict_equal(row["observed"], json.loads(row["execution"]["stdout"]))
                and strict_equal(row["observed"], observation_oracle(vectors)), "Actual LLVM lifecycle observations differ")
        for mutation, negative in row["negative_controls"].items():
            _closed(negative, "status stage mutation qualified_compiler_output foreign_cpp_link_inputs llvm_source compile object symbols link artifact execution observed", "negative control")
            require(negative["status"] == "completed" and negative["stage"] == "native_failure_observed"
                    and negative["mutation"] == mutation and negative["qualified_compiler_output"] is False
                    and negative["foreign_cpp_link_inputs"] == [], "Negative control execution or scope differs")
            source, obj, executable = (directory / (mutation + suffix) for suffix in (".ll", ".o", "-native"))
            expected = mutate_llvm(ir.text, mutation, destructor=_destructor_symbol(analysis, ir), count=VARIANTS[name])
            for label, path in (("llvm_source", source), ("object", obj), ("artifact", executable)):
                _file(negative[label], path)
            require(source.read_bytes() == expected.encode(), "Wrong LLVM negative mutation")
            require(strict_equal(negative["symbols"], _native_object(obj)), "Negative object symbol inventory differs")
            _check_command(negative["compile"], [report["tools"]["clang"]["driver"], *IR_FLAGS, str(source), "-o", str(obj)])
            _check_command(negative["link"], _link_command(report["tools"]["cc"]["driver"], directory, obj, executable))
            _check_command(negative["execution"], [str(executable)], 3)
            observed = negative["observed"]
            require(strict_equal(observed, json.loads(negative["execution"]["stdout"]))
                    and strict_equal(observed, negative_oracle(name, mutation)),
                    "Actual leak/order control differs from the independent resource-event oracle")
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--clangxx", default="clang++")
    parser.add_argument("--rustc", default=os.environ.get("RUSTC"))
    parser.add_argument("--cc", default=os.environ.get("CC", "gcc"))
    args = parser.parse_args(argv)
    if args.output.exists() or args.output.is_symlink():
        parser.error("New report output required")
    report = qualify_cpp_composed_llvm(args.workdir, clang=args.clang, clangxx=args.clangxx, rustc=args.rustc, cc=args.cc)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as stream:
        json.dump(report, stream, indent=2, sort_keys=True); stream.write("\n")
    print(json.dumps({"ok": report["ok"], "status": report["status"], "output": str(args.output), "diagnostics": report["diagnostics"]}))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
