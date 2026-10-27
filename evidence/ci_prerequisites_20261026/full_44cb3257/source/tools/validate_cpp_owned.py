"""Execute a migrated exclusive C++ byte owner without linking its implementation.

Original C++, Hepta/Rust and Hepta/C run identical dynamic input vectors and
real allocator refusal. Every call checks output, allocation count and exact
cleanup, including constructor rejection, moves and early error exits.
"""
from __future__ import annotations

import argparse
import base64
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import sys

from hepta.ast import HeptaError
from hepta.backend import compile_rust
from hepta.c_backend import compile_c
from hepta.cpp_owned_migrate import PROFILE, migrate_cpp_owned
from hepta.pipeline import analyze, analyze_project, compiler_hash
from hepta.resource_ir import verify_resource_ir
from hepta.resource_lowering import lower_resource_ir
from hepta.resource_source import verify_resource_source
from hepta.semantic_ir import lower_checked_program
from tools.evidence_checks import is_sha, native_build, normalized_errors, require, strict_equal

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples/cpp/owned_migration"
SCHEMA = "hepta.cpp-owned-qualification.v1"
SEED = 0xB0FFEE
INPUTS = ("hepta/cpp_owned_migrate.py", "tools/validate_cpp_owned.py", "tools/evidence_checks.py",
          *("examples/cpp/owned_migration/" + name for name in
            ("owned_bytes.cpp", "expected.hepta", "consumer.hepta", "reference.cpp", "harness.c", "harness.rs")))
LIMITS = {"whole_cpp_raii_supported": False, "source_equivalence_proved": False,
          "cpp_class_abi_preserved": False, "whole_language_memory_safety_proved": False,
          "foreign_cpp_implementation_retained": False, "general_performance_advantage_proved": False}
WRAP_FLAGS = ["-fno-builtin-calloc", "-fno-builtin-malloc", "-fno-builtin-free",
              "-Wl,--wrap=calloc", "-Wl,--wrap=malloc", "-Wl,--wrap=free"]
CPP_FLAGS = ["-std=c++20", "-O2", "-fno-lto", "-fsanitize=undefined", "-fno-sanitize-recover=all"]


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _identity(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    return {"path": str(path), "bytes": len(data), "sha256": _sha(data)}


def _inputs():
    return {name: _sha((ROOT / name).read_bytes()) for name in INPUTS}


def _captured_streams(stdout=None, stderr=None):
    """Retain exact bytes as well as readable text, including timeout prefixes."""
    result = {}
    for channel, value in (("stdout", stdout), ("stderr", stderr)):
        raw = value.encode("utf-8") if isinstance(value, str) else bytes(value or b"")
        readable = raw.decode("utf-8", errors="replace")
        result.update({channel: readable, channel + "_sha256": _sha(readable.encode()),
                       channel + "_bytes_base64": base64.b64encode(raw).decode("ascii"),
                       channel + "_bytes_sha256": _sha(raw), channel + "_bytes": len(raw)})
    return result


def _exception_record(error):
    record = {"kind": type(error).__name__, "message": str(error)}
    if isinstance(error, subprocess.SubprocessError):
        command = getattr(error, "cmd", None)
        record["command"] = ([str(part) for part in command] if isinstance(command, (list, tuple)) else command)
        record.update(_captured_streams(getattr(error, "stdout", None), getattr(error, "stderr", None)))
    if isinstance(error, subprocess.TimeoutExpired):
        record.update(status="timeout", timeout_seconds=error.timeout, returncode=None)
    elif isinstance(error, subprocess.CalledProcessError):
        record.update(status="failed", returncode=error.returncode)
    return record


def _run(command):
    command = [str(part) for part in command]
    record = {"command": command, "returncode": None, "status": "not_completed"}
    try:
        process = subprocess.run(command, capture_output=True, timeout=120, cwd=ROOT)
        record.update(status="completed", returncode=process.returncode,
                      **_captured_streams(process.stdout, process.stderr))
    except subprocess.TimeoutExpired as error:
        record.update(status="timeout", timeout_seconds=error.timeout,
                      error={"kind": type(error).__name__, "message": str(error)},
                      **_captured_streams(error.stdout, error.stderr))
    except OSError as error:
        record.update(status="not_started", error=_exception_record(error), **_captured_streams())
    return record


def _process(record, code=0):
    require(isinstance(record, dict) and record.get("status") == "completed"
            and type(record.get("returncode")) is int and record["returncode"] == code,
            "Exact executed process exit status required")
    require(isinstance(record.get("command"), list) and record["command"]
            and all(isinstance(value, str) and value for value in record["command"]), "Executed command missing")
    for channel in ("stdout", "stderr"):
        require(isinstance(record.get(channel), str)
                and record.get(channel + "_sha256") == _sha(record[channel].encode()), "Native output identity differs")
        raw = base64.b64decode(record[channel + "_bytes_base64"], validate=True)
        require(type(record[channel + "_bytes"]) is int and record[channel + "_bytes"] == len(raw)
                and record[channel + "_bytes_sha256"] == _sha(raw)
                and raw.decode("utf-8", errors="replace") == record[channel], "Native output bytes differ")


def cases():
    inputs = [(7, 13, 0, 0, 0, 0), (65519, 19, 0, 0, 0, 1), (17, 21, 16, 0, 0, 0)]
    for size in (0, 1, 7, 4093, 65519):
        for value in (0, 90, 255):
            for index in sorted({0, max(size - 1, 0), size}):
                for reject, early, refuse in ((0, 0, 0), (1, 0, 0), (0, 1, 0), (1, 1, 0), (0, 0, 1), (1, 0, 1)):
                    inputs.append((size, value, index, reject, early, refuse))
    rng = random.Random(SEED)
    for _ in range(256):
        size = rng.randrange(1025)
        inputs.append((size, rng.randrange(256), rng.randrange(size + 3), int(rng.randrange(5) == 0),
                       int(rng.randrange(5) == 0), int(rng.randrange(8) == 0)))
    result = []
    for size, value, index, reject, early, refuse in inputs:
        refused = int(size != 0 and refuse != 0)
        allocated = int(size != 0 and refused == 0)
        if refused:
            expected, family = 1001, "allocation_refusal"
        elif reject:
            expected, family = 1002, "constructor_rejection"
        elif early:
            expected, family = 2002, "early_after_move"
        elif index >= size:
            expected, family = 2003, "range_error_after_move"
        else:
            expected, family = size + 2 * (value ^ 90 if index == 0 else value), "borrowed_read_success"
        result.append({"size": size, "value": value, "index": index, "reject": reject, "early": early,
                       "refuse": refuse, "expected": expected, "allocated": allocated,
                       "refusals": refused, "family": family})
    return result


def _observation_oracle(vectors):
    digest, allocated, refusals = 14695981039346656037, 0, 0
    for index, row in enumerate(vectors):
        allocated += row["allocated"]
        refusals += row["refusals"]
        for word in (index, row["expected"], row["allocated"], row["allocated"], row["refusals"]):
            for shift in range(0, 64, 8):
                digest = ((digest ^ ((word >> shift) & 255)) * 1099511628211) % 2**64
    return {"ok": True, "cases": len(vectors), "observations_fnv64": f"{digest:016x}",
            "allocations": allocated, "frees": allocated, "refusals": refusals, "live": 0}


def _case_sources(vectors):
    keys = ("size", "value", "index", "reject", "early", "refuse", "expected", "allocated", "refusals")
    rows = [[row[key] for key in keys] for row in vectors]
    c = ("struct OwnedCase { size_t size; uint8_t value; size_t index; uint32_t reject, early, refuse; "
         "uint64_t expected; size_t allocated, refusals; };\n"
         f"#define OWNED_CASE_COUNT {len(rows)}\nstatic const struct OwnedCase owned_cases[] = {{\n" +
         "\n".join("    {" + ", ".join(str(value) for value in row) + "}," for row in rows) + "\n};\n")
    rust = (f"const OWNED_CASES: [(usize,u8,usize,u32,u32,u32,u64,usize,usize); {len(rows)}] = [\n" +
            "\n".join("    (" + ", ".join(str(value) for value in row) + ")," for row in rows) + "\n];\n")
    return c, rust


def _build(entry, directory, backend, vectors, *, rustc=None, cc="gcc", leak=False, record=None):
    row = {} if record is None else record
    row.update(status="in_progress", stage="directory", foreign_cpp_link_inputs=[])
    try:
        return _build_stages(entry, directory, backend, vectors, rustc=rustc, cc=cc, leak=leak, row=row)
    except (HeptaError, OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        row.update(status="failed", failure=_exception_record(error))
        raise


def _build_stages(entry, directory, backend, vectors, *, rustc, cc, leak, row):
    directory.mkdir()
    row["stage"] = "frontend"
    checked = analyze_project(entry, backend=backend, crate_type="obj", rustc=rustc, cc=cc)
    row["frontend"] = checked.report
    require(checked.report["ok"] is True and checked.report["assumptions"] == [], "Owned frontend/native check failed")
    row["stage"] = "resource_lowering"
    graph = lower_resource_ir(checked.program, checked.checked, project_sha256=checked.project.identity)
    row["resource_ir"] = graph
    row["stage"] = "resource_verification"
    row["resource_verification"] = verify_resource_ir(graph)
    row["stage"] = "source_binding"
    row["source_binding"] = verify_resource_source(entry, graph, native=False)
    require(row["source_binding"]["ok"] is True, "Owner source/resource graph replay failed")
    row["stage"] = "source_generation"
    emitted = checked.rust if backend == "rust" else checked.c
    row["emitted_source"] = emitted
    row["emitted_sha256"] = _sha(emitted.encode())
    if leak:
        changed = emitted.replace("free(value.data);", "(void)value;")
        require(changed != emitted, "Actual C drop mutation did not alter the implementation")
        emitted = changed
    row["compiled_emitted_sha256"] = _sha(emitted.encode())
    c_cases, rust_cases = _case_sources(vectors)
    harness = (EXAMPLE / ("harness.c" if backend == "c" else "harness.rs")).read_text()
    row["harness_source"] = harness
    if backend == "c":
        (directory / "cases.h").write_text(c_cases)
        row["case_header"] = _identity(directory / "cases.h")
        # Append the exact resource-observation harness; no C++ implementation.
        source = emitted + "\n" + harness
        flags = [*WRAP_FLAGS, "-I" + str(directory)]
    else:
        source = emitted + "\n" + rust_cases + "\n" + harness
        flags = []
    generated = directory / ("program.c" if backend == "c" else "program.rs")
    generated.write_text(source)
    row["compiled_source"] = _identity(generated)
    row["stage"] = "native_compile"
    row["native"] = (compile_c(source, cc=cc, crate_type="bin", output=directory / "native", sanitize=True, link_args=flags)
                     if backend == "c" else compile_rust(source, rustc=rustc, crate_type="bin", output=directory / "native"))
    require(row["native"]["ok"] is True, "Actual owned native build failed: " + json.dumps(row["native"]))
    row["artifact"] = _identity(row["native"]["artifact"])
    if backend == "c":
        require(row["case_header"] == _identity(directory / "cases.h"), "Case header changed during native build")
    row["stage"] = "native_execution"
    row["execution"] = _run([row["native"]["artifact"]])
    _process(row["execution"], 3 if leak else 0)
    row.update(status="completed", stage="execution_recorded")
    return row


def _replay_migrated_source(report):
    """Bind the standalone migration graph to its actual current source too."""
    source = Path(report["migrated_source"]["path"])
    try:
        data = source.read_bytes()
        require(_sha(data) == report["migration"]["output_sha256"], "E_CPP_OWNED_SOURCE_CHANGED: migrated source differs")
        fresh = analyze(data.decode("utf-8"), str(source), backend="rust", native=False, crate_type="obj")
        require(fresh.report["ok"] is True and fresh.report["assumptions"] == [], "E_CPP_OWNED_SOURCE_REPLAY: migrated frontend rejected")
        expected = lower_resource_ir(fresh.program, fresh.checked)
        require(strict_equal(expected, report["migration"]["resource_ir"]),
                "E_CPP_OWNED_SOURCE_GRAPH: migration resource graph differs from current source")
        require(fresh.report["compiler_sha256"] == report["hepta_compiler_sha256"]
                and fresh.report["rust_sha256"] == report["migration"]["hepta_checks"]["rust"]["rust_sha256"]
                and source.read_bytes() == data, "E_CPP_OWNED_SOURCE_REPLAY: migrated code/compiler changed")
    except (HeptaError, OSError, UnicodeError) as error:
        raise ValueError("E_CPP_OWNED_SOURCE_REPLAY: " + str(error)) from error


def _replay_backend_source(row, backend, report):
    """Recompute code, full resource CFG and typed semantics with the real frontend.

    A data-only verifier can correctly accept a different resource-safe graph.
    Caller-supplied source hashes and self-seals cannot make that graph the
    projection of this source. Never use a receipt's AST/type table here.
    """
    recorded = row["frontend"]
    entry = Path(recorded["project"]["entry"])
    expected_entry = Path(report["migrated_source"]["path"]).parent / "consumer.hepta"
    require(entry == expected_entry, "E_CPP_OWNED_SOURCE_REPLAY: consumer entry path differs")
    try:
        require(_sha(entry.read_bytes()) == report["inputs"]["examples/cpp/owned_migration/consumer.hepta"],
                "E_CPP_OWNED_SOURCE_CHANGED: consumer source differs")
        fresh = analyze_project(entry, backend=backend, native=False, crate_type="obj")
        require(fresh.report["ok"] is True and fresh.report["status"] == "frontend_only"
                and fresh.report["assumptions"] == [] and fresh.project is not None,
                "E_CPP_OWNED_SOURCE_REPLAY: current project rejected")
        require(fresh.report["compiler_sha256"] == report["hepta_compiler_sha256"]
                and strict_equal(fresh.report["project"], recorded["project"])
                and fresh.report["source_sha256"] == recorded["source_sha256"]
                and fresh.report["interface_sha256"] == recorded["interface_sha256"]
                and strict_equal(fresh.report["effects"], recorded["effects"]),
                "E_CPP_OWNED_SOURCE_REPLAY: current project/type/effect identities differ")
        expected = lower_resource_ir(fresh.program, fresh.checked, project_sha256=fresh.project.identity)
        require(strict_equal(expected, row["resource_ir"]),
                "E_CPP_OWNED_SOURCE_GRAPH: backend resource graph differs from current checked source")
        emitted = fresh.c if backend == "c" else fresh.rust
        key = "c_sha256" if backend == "c" else "rust_sha256"
        require(emitted == row["emitted_source"] and fresh.report[key] == recorded[key],
                "E_CPP_OWNED_SOURCE_CODEGEN: emitted implementation differs from current source")
        semantic = lower_checked_program(fresh.program, fresh.checked, project_sha256=fresh.project.identity)
        binding = row["source_binding"]["source_binding"]
        require(semantic["all_expressions_typed"] is True and semantic["untyped_expressions"] == []
                and semantic["schema"] == binding["canonical_semantic_schema"]
                and semantic["sha256"] == binding["canonical_semantic_sha256"]
                and strict_equal(semantic["external_obligations"], binding["canonical_external_obligations"])
                and strict_equal(semantic["foreign_assumptions"], binding["canonical_foreign_assumptions"])
                and fresh.project.unchanged(), "E_CPP_OWNED_SOURCE_SEMANTICS: current typed semantics differ")
    except (HeptaError, OSError, UnicodeError) as error:
        raise ValueError("E_CPP_OWNED_SOURCE_REPLAY: " + str(error)) from error


@normalized_errors
def validate_report(report, *, current_inputs=True):
    """Validate current qualification by default, including fresh source replay.

    ``current_inputs=False`` is structural inspection of archival bytes only;
    it makes no current-source qualification claim and is not a release gate.
    Neither mode authenticates arbitrary receipts.
    """
    require(type(current_inputs) is bool, "Current-source replay option must be an explicit boolean")
    require(report.get("schema") == SCHEMA and report.get("profile") == PROFILE and report.get("ok") is True,
            "Successful selected owned migration qualification required")
    require(all(report.get(name) is value for name, value in LIMITS.items()), "Owned migration claims broadened")
    require(set(report["inputs"]) == set(INPUTS) and all(is_sha(value) for value in report["inputs"].values()),
            "Complete qualification input identities required")
    require(is_sha(report["hepta_compiler_sha256"]) and (not current_inputs or
            (report["inputs"] == _inputs() and report["hepta_compiler_sha256"] == compiler_hash())), "Stale compiler/inputs")
    vectors = cases()
    expected = _observation_oracle(vectors)
    require(report["cases_sha256"] == _sha(_canonical(vectors))
            and strict_equal(report["case_families"], dict(Counter(row["family"] for row in vectors))), "Wrong case denominator")
    migration = report["migration"]
    require(migration["ok"] is True and migration["protocol_verified"] is True
            and migration["selected_resource_raii_translated"] is True
            and migration["lifecycle_early_exits_translated"] is True
            and migration["foreign_cpp_implementation_retained"] is False
            and type(migration["foreign_cpp_calls"]) is int and migration["foreign_cpp_calls"] == 0
            and type(migration["source_declarations"]) is int and migration["source_declarations"] == 2
            and type(migration["converted_source_declarations"]) is int and migration["converted_source_declarations"] == 2
            and migration["unconverted_members"] == [] and len(migration["declaration_inventory"]) == 15
            and is_sha(migration["complete_ast_sha256"]) and migration["complete_ast_sha256"] == migration["protocol_ast_sha256"]
            and migration["hepta_compiler_sha256"] == report["hepta_compiler_sha256"]
            and migration["source_sha256"] == report["inputs"]["examples/cpp/owned_migration/owned_bytes.cpp"]
            and migration["output_sha256"] == report["migrated_source"]["sha256"]
            == report["inputs"]["examples/cpp/owned_migration/expected.hepta"], "Incomplete implementation/protocol binding")
    require(migration["native_traits"]["trivially_destructible"] is False
            and migration["native_traits"]["copy_constructible"] is False
            and migration["native_traits"]["nothrow_move_constructible"] is True
            and migration["native_traits"]["nothrow_destructible"] is True, "Real exclusive resource lifecycle missing")
    require(all(migration[name] is False for name in ("whole_cpp_raii_supported", "source_equivalence_proved",
            "cpp_class_abi_preserved", "whole_language_memory_safety_proved")), "Migration claims exceed selected protocol")
    migrated_verification = verify_resource_ir(migration["resource_ir"])
    require(migrated_verification["ok"] is True and strict_equal(migration["resource_verification"], migrated_verification)
            and migration["resource_ir"]["source_sha256"] == migration["output_sha256"], "Migrated resource graph rejected/misbound")
    require(set(migration["hepta_checks"]) == {"rust", "c"}, "Both migrated frontend paths required")
    for frontend in migration["hepta_checks"].values():
        require(frontend["ok"] is True and frontend["status"] == "frontend_only" and frontend["assumptions"] == []
                and frontend["compiler_sha256"] == report["hepta_compiler_sha256"]
                and frontend["source_sha256"] == migration["output_sha256"], "Migrated frontend is missing or misbound")
    if current_inputs:
        _replay_migrated_source(report)
    reference = report["reference"]
    for record in reference["commands"]:
        _process(record)
    require(len(reference["commands"]) == 3 and is_sha(reference["artifact"]["sha256"]), "Reference compile/link evidence missing")
    require(reference["compiler"]["sha256"] == migration["target_model"]["compiler_sha256"], "Native Clang identities differ")
    require(is_sha(reference["linker"]["sha256"]), "C++ sanitizer link driver identity missing")
    for label, filename in (("reference", "reference.cpp"), ("owner", "owned_bytes.cpp"), ("harness", "harness.c")):
        require(reference["sources"][label]["sha256"] == report["inputs"]["examples/cpp/owned_migration/" + filename],
                "Original C++ compilation source identity differs")
    case_c, _ = _case_sources(vectors)
    require(reference["case_header"]["sha256"] == _sha(case_c.encode()), "Reference case header differs")
    cpp_object, harness_object = reference["objects"]
    for record in (cpp_object, harness_object, reference["artifact"]):
        require(is_sha(record["sha256"]) and type(record["bytes"]) is int and record["bytes"] > 0, "Empty C++ object/artifact identity")
    expected_commands = [
        [reference["compiler_driver"], *CPP_FLAGS, "-c", reference["sources"]["reference"]["path"], "-o", cpp_object["path"]],
        [reference["compiler_driver"], *CPP_FLAGS, "-x", "c++", "-I" + str(Path(reference["case_header"]["path"]).parent),
         "-c", reference["sources"]["harness"]["path"], "-o", harness_object["path"]],
        [reference["link_driver"], *CPP_FLAGS, cpp_object["path"], harness_object["path"], "-o", reference["artifact"]["path"]],
    ]
    require([command["command"] for command in reference["commands"]] == expected_commands, "Native C++ build/link command inputs differ")
    _process(reference["execution"])
    require(reference["execution"]["command"] == [reference["artifact"]["path"]]
            and strict_equal(json.loads(reference["execution"]["stdout"]), expected), "Original C++ lifecycle/oracle mismatch")

    def check_backend(row, backend, *, mutated=False):
        require(row["status"] == "completed" and row["stage"] == "execution_recorded", "Backend did not complete execution")
        frontend = row["frontend"]
        emitted_key = "c_sha256" if backend == "c" else "rust_sha256"
        require(frontend["ok"] is True and frontend["status"] == "checked"
                and frontend["diagnostics"] == [] and frontend["assumptions"] == []
                and frontend["compiler_sha256"] == report["hepta_compiler_sha256"]
                and frontend["source_sha256"] == report["inputs"]["examples/cpp/owned_migration/consumer.hepta"]
                and set(frontend["project"]["sources"].values()) == {
                    migration["output_sha256"], report["inputs"]["examples/cpp/owned_migration/consumer.hepta"]}
                and len(frontend["project"]["sources"]) == 2, "Owned backend source binding mismatch")
        native_build(frontend["backend"], backend, check_only=True, crate_type="obj", source_sha256=frontend[emitted_key])
        native_build(row["native"], backend, check_only=False, crate_type="bin", source_sha256=row["compiled_source"]["sha256"])
        require(row["native"]["toolchain"] == frontend["backend"]["toolchain"]
                and row["native"]["artifact"] == row["artifact"]["path"]
                and row["native"]["artifact_sha256"] == row["artifact"]["sha256"]
                and type(row["artifact"]["bytes"]) is int and row["native"]["artifact_bytes"] == row["artifact"]["bytes"]
                and row["foreign_cpp_link_inputs"] == [] and row["emitted_sha256"] == frontend[emitted_key], "Independent owned native build differs")
        emitted = row["emitted_source"]
        require(isinstance(emitted, str) and _sha(emitted.encode()) == row["emitted_sha256"], "Emitted source identity missing")
        compiled_emitted = emitted.replace("free(value.data);", "(void)value;") if mutated else emitted
        require(_sha(compiled_emitted.encode()) == row["compiled_emitted_sha256"]
                and (compiled_emitted != emitted) is mutated, "Compiled mutation identity inconsistent")
        harness_name = "harness.c" if backend == "c" else "harness.rs"
        harness = row["harness_source"]
        require(isinstance(harness, str) and _sha(harness.encode()) == report["inputs"]["examples/cpp/owned_migration/" + harness_name],
                "Native lifecycle harness not bound to the input source")
        c_cases, rust_cases = _case_sources(vectors)
        compiled_source = compiled_emitted + "\n" + (harness if backend == "c" else rust_cases + "\n" + harness)
        require(_sha(compiled_source.encode()) == row["compiled_source"]["sha256"], "Native compilation used a different source/harness")
        verification = verify_resource_ir(row["resource_ir"])
        require(row["source_binding"]["ok"] is True and row["source_binding"]["source_binding_verified"] is True
                and verification["ok"] is True and strict_equal(row["resource_verification"], verification)
                and row["resource_ir"]["project_sha256"] == frontend["project"]["sha256"], "Owned resource/source verification missing")
        binding_report = row["source_binding"]
        binding = binding_report["source_binding"]
        binding_limits = {"external_contracts_proved", "functional_equivalence_proved", "native_codegen_uses_this_ir",
                          "scalar_value_semantics_verified", "source_to_ir_refinement_proved", "termination_proved",
                          "user_program_executed", "whole_language_soundness_proved"}
        require(binding_report["status"] == "frontend_only_source_replayed"
                and binding_report["diagnostics"] == [] and set(binding_report["claims"]) == binding_limits
                and all(value is False for value in binding_report["claims"].values())
                and binding["resource_ir_sha256"] == verification["ir_sha256"]
                and strict_equal(binding_report["resource_verification"], verification)
                and binding["compiler_sha256"] == report["hepta_compiler_sha256"]
                and binding["source_inventory"] == frontend["project"]["sources"]
                and binding["project_sha256"] == frontend["project"]["sha256"]
                and binding["source_sha256"] == frontend["source_sha256"]
                and binding["external_obligations"] == {} and binding["canonical_foreign_assumptions"] == [],
                "Resource projection is not bound to the actually compiled source graph")
        seal = {key: value for key, value in binding_report.items() if key != "sha256"}
        require(binding_report["sha256"] == _sha(json.dumps(seal, sort_keys=True, separators=(",", ":"),
                                                           ensure_ascii=False, allow_nan=False).encode()), "Resource source receipt identity differs")
        if current_inputs:
            _replay_backend_source(row, backend, report)
        if backend == "c":
            require(row["native"]["link_args"][:len(WRAP_FLAGS)] == WRAP_FLAGS
                    and len(row["native"]["link_args"]) == len(WRAP_FLAGS) + 1
                    and row["native"]["link_args"][-1] == "-I" + str(Path(row["case_header"]["path"]).parent)
                    and row["case_header"]["sha256"] == _sha(c_cases.encode())
                    and "-fsanitize=undefined" in row["native"]["flags"], "C allocator observation/UBSan profile differs")
        else:
            require(row["native"]["link_args"] == [] and row["native"]["rustc_crate_type"] == "bin", "Rust links foreign implementation")
        _process(row["execution"], 3 if mutated else 0)
        require(row["execution"]["command"] == [row["artifact"]["path"]], "Executed owned artifact differs")
        outcome = json.loads(row["execution"]["stdout"])
        if mutated:
            require(outcome["ok"] is False and outcome["failure"] == "lifecycle"
                    and type(outcome["live"]) is int and outcome["live"] > 0
                    and outcome["freed"] < outcome["allocated"], "Real compiled destructor mutation was not detected")
        else:
            require(strict_equal(outcome, expected), "Native ownership observations differ from complete integer/allocation oracle")

    for backend in ("rust", "c"):
        check_backend(report["backends"][backend], backend)
    check_backend(report["negative_control"], "c", mutated=True)
    require(report["inputs_unchanged"] is True and report["performance"]["status"] == "not_run", "Inputs changed or timing overstated")
    if current_inputs:
        require(report["inputs"] == _inputs() and report["hepta_compiler_sha256"] == compiler_hash(),
                "Compiler/qualification inputs changed during source replay")
    return True


def qualify_cpp_owned(directory, *, clangxx="clang++", rustc=None, cc="gcc"):
    report = {"schema": SCHEMA, "profile": PROFILE, "ok": False, "status": "not_run", **LIMITS,
              "inputs": _inputs(), "hepta_compiler_sha256": compiler_hash(), "diagnostics": [],
              "performance": {"status": "not_run"}}
    try:
        work = Path(directory).resolve() / "cpp-owned"
        work.mkdir(parents=True)
        migrated = work / "migrated.hepta"
        report["migration"] = migrate_cpp_owned(EXAMPLE / "owned_bytes.cpp", migrated, clangxx=clangxx)
        require(report["migration"]["ok"] is True, "Owned source migration failed: " + json.dumps(report["migration"]))
        report["migrated_source"] = _identity(migrated)
        require(migrated.read_bytes() == (EXAMPLE / "expected.hepta").read_bytes(), "Shared backend fixture differs from actual migration")
        entry = work / "consumer.hepta"
        entry.write_bytes((EXAMPLE / "consumer.hepta").read_bytes())
        vectors = cases()
        report["cases_sha256"] = _sha(_canonical(vectors))
        report["case_families"] = dict(Counter(row["family"] for row in vectors))
        case_c, _ = _case_sources(vectors)
        (work / "cases.h").write_text(case_c)
        compiler = shutil.which(clangxx)
        require(compiler is not None, "Native Clang C++ driver missing")
        linker = shutil.which("g++")
        require(linker is not None, "G++ driver for the qualified libubsan/libstdc++ link is missing")
        reference = {"compiler": _identity(compiler), "linker": _identity(linker), "commands": [],
                     "compiler_driver": compiler, "link_driver": linker,
                     "sources": {"reference": _identity(EXAMPLE / "reference.cpp"),
                                 "owner": _identity(EXAMPLE / "owned_bytes.cpp"), "harness": _identity(EXAMPLE / "harness.c")},
                     "case_header": _identity(work / "cases.h")}
        report["reference"] = reference
        flags = CPP_FLAGS
        commands = [[compiler, *flags, "-c", str(EXAMPLE / "reference.cpp"), "-o", str(work / "reference.o")],
                    [compiler, *flags, "-x", "c++", "-I" + str(work), "-c", str(EXAMPLE / "harness.c"), "-o", str(work / "harness.o")],
                    [linker, *flags, str(work / "reference.o"), str(work / "harness.o"), "-o", str(work / "reference-native")]]
        for command in commands:
            reference["commands"].append(_run(command))
            _process(reference["commands"][-1])
        reference["objects"] = [_identity(work / "reference.o"), _identity(work / "harness.o")]
        reference["artifact"] = _identity(work / "reference-native")
        reference["execution"] = _run([reference["artifact"]["path"]])
        _process(reference["execution"])
        report["backends"] = {}
        for backend in ("rust", "c"):
            report["backends"][backend] = {}
            _build(entry, work / backend, backend, vectors, rustc=rustc, cc=cc, record=report["backends"][backend])
            _process(report["backends"][backend]["execution"])
        report["negative_control"] = {}
        _build(entry, work / "leaking-c", "c", vectors, cc=cc, leak=True, record=report["negative_control"])
        report["inputs_unchanged"] = (report["inputs"] == _inputs() and report["hepta_compiler_sha256"] == compiler_hash()
                                      and reference["compiler"] == _identity(compiler) and reference["linker"] == _identity(linker))
        report.update(ok=True, status="native_owned_implementation_and_cleanup_qualified")
        validate_report(report)
    except (HeptaError, OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        report.update(ok=False, status="failed")
        report["diagnostics"].append({"message": str(error)})
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--clangxx", default="clang++")
    parser.add_argument("--rustc", default=os.environ.get("RUSTC"))
    parser.add_argument("--cc", default=os.environ.get("CC", "gcc"))
    args = parser.parse_args()
    result = qualify_cpp_owned(args.workdir, clangxx=args.clangxx, rustc=args.rustc, cc=args.cc)
    with args.out.open("x") as output:
        json.dump(result, output, indent=2, sort_keys=True)
        output.write("\n")
    print(json.dumps(result, sort_keys=True))
    return 0 if result["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
