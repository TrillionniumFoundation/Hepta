"""Native source-bound qualification of two/three/four-resource C++ migrations.

Current validation re-runs actual C++ translation and canonical Hepta lowering,
including full resource graphs and emitted code. Self-hashes do not authenticate
third-party reports; validation does not re-execute retained native observations.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import random
import re
import shutil
import subprocess

from hepta.ast import HeptaError
from hepta.backend import compile_rust
from hepta.c_backend import compile_c
from hepta.cpp_composed_migrate import LIMITS, PROFILE, migrate_cpp_composed, translate_cpp_composed
from hepta.pipeline import analyze_project, compiler_hash
from hepta.resource_ir import verify_resource_ir
from hepta.resource_lowering import lower_resource_ir
from hepta.resource_source import verify_resource_source
from hepta.semantic_ir import lower_checked_program
from tools.evidence_checks import is_sha, native_build, normalized_errors, require, strict_equal
from tools.validate_cpp_owned import CPP_FLAGS, WRAP_FLAGS, _canonical, _exception_record, _identity, _process, _run, _sha

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples/cpp/composed_migration"
SCHEMA = "hepta.cpp-composed-qualification.v1"
VARIANTS = {"pair": 2, "triple": 3, "quad": 4}
INPUTS = ("hepta/cpp_composed_migrate.py", "hepta/cpp_owned_migrate.py", "tools/validate_cpp_composed.py",
          "tools/validate_cpp_owned.py", "tools/evidence_checks.py",
          *("examples/cpp/composed_migration/" + name for name in
            ("pair.cpp", "triple.cpp", "quad.cpp", "pair.hepta", "triple.hepta", "quad.hepta", "consumer.hepta", "harness.c", "harness.rs")))
CLAIMS = {**LIMITS, "general_performance_advantage_proved": False, "actual_composite_implementation_migrated": True,
          "constructor_partial_failure_observed": True, "reverse_destruction_order_observed": True,
          "multiple_distinct_source_algorithms": True}


def _inputs():
    return {name: _sha((ROOT / name).read_bytes()) for name in INPUTS}


def _word(state, word):
    for shift in range(0, 64, 8):
        state = ((state ^ ((word >> shift) & 255)) * 1099511628211) % 2**64
    return state


def _oracle(variant, raw):
    """Independent integer/resource model, not read from the translated code."""
    left, right, value, index, reject, early, refuse_at = raw
    count = VARIANTS[variant]
    sizes = [left, right] if count == 2 else [right, left, (right + 1) % 2**64]
    if count == 4:
        sizes.append((left + 2) % 2**64)
    held, events, allocated, attempts, refusals, expected, family = [], [], 0, 0, 0, None, None
    for field, size in enumerate(sizes, 1):
        if size:
            attempts += 1
            if attempts == refuse_at:
                refusals += 1; events.append((3, attempts, size)); expected = 1001
                family = "allocation_refusal_" + str(attempts)
                break
            allocated += 1; held.append((allocated, size)); events.append((1, allocated, size))
        if reject == field:
            expected, family = 1002, "leaf_constructor_rejection_" + str(field)
            break
    if expected is None and reject == count + 1:
        expected, family = 1000 + count + 1, "composite_constructor_rejection"
    if expected is None:
        prefix = count * 1000
        if early == 1:
            expected, family = prefix + 1, "early_before_move"
        elif count == 2 and early == 2:
            expected, family = prefix + 2, "early_after_move"
        elif index >= min(left, right):
            expected, family = prefix + 3, "range_error_after_move"
        elif early == 2:
            expected, family = prefix + 2, "early_after_move"
        else:
            if count == 2:
                expected = (value ^ 91 if index == 0 else value) * 3 + (value ^ 37) + left + right
            else:
                body = value ^ (7 if index == 0 else 19)
                expected = (value + (value ^ 173)) * (5 if count == 3 else 7) + body + right + 1
                expected += 11 if count == 3 else (value ^ 61) + 17
            expected %= 2**64
            family = "borrowed_read_success"
    events += [(2, ident, size) for ident, size in reversed(held)]
    trace = 14695981039346656037
    for event in events:
        for part in event:
            trace = _word(trace, part)
    return dict(zip(("left", "right", "value", "index", "reject", "early", "refuse_at"), raw),
                expected=expected, allocated=allocated, refusals=refusals, trace=trace, family=family,
                events=[list(event) for event in events])


def cases(variant):
    count = VARIANTS[variant]
    vectors = [(3, 5, 7, 0, 0, 0, 0)]
    for left, right in ((0, 0), (0, 3), (3, 0), (1, 1), (3, 5), (257, 513)):
        for value in (0, 255):
            for index in sorted({0, max(min(left, right) - 1, 0), min(left, right)}):
                for reject in range(count + 2):
                    for refuse_at in range(count + 1):
                        vectors.append((left, right, value, index, reject, 0, refuse_at))
                for early in (1, 2):
                    vectors.append((left, right, value, index, 0, early, 0))
    rng = random.Random(0xC0A905ED + count)
    for _ in range(128):
        left, right = rng.randrange(1025), rng.randrange(1025)
        vectors.append((left, right, rng.randrange(256), rng.randrange(min(left, right) + 2),
                        rng.randrange(count + 2), rng.randrange(3), rng.randrange(count + 1)))
    return [_oracle(variant, raw) for raw in vectors]


def observation_oracle(vectors):
    digest, allocated, refusals = 14695981039346656037, 0, 0
    for index, row in enumerate(vectors):
        allocated += row["allocated"]; refusals += row["refusals"]
        for word in (index, row["expected"], row["trace"], row["allocated"], row["allocated"], row["refusals"]):
            digest = _word(digest, word)
    return {"ok": True, "cases": len(vectors), "observations_fnv64": f"{digest:016x}",
            "allocations": allocated, "frees": allocated, "refusals": refusals, "live": 0}


def case_sources(vectors):
    keys = ("left", "right", "value", "index", "reject", "early", "refuse_at", "expected", "allocated", "refusals", "trace")
    rows = [[row[key] for key in keys] for row in vectors]
    c = ("struct ComposedCase { size_t left, right; uint8_t value; size_t index; uint32_t reject, early; "
         "size_t refuse_at; uint64_t expected; size_t allocated, refusals; uint64_t trace; };\n"
         f"#define COMPOSED_CASE_COUNT {len(rows)}\nstatic const struct ComposedCase composed_cases[] = {{\n")
    c += "\n".join("    {" + ", ".join(str(value) + ("ULL" if index in {7, 10} else "") for index, value in enumerate(row)) + "}," for row in rows) + "\n};\n"
    rust = (f"const COMPOSED_CASES: [(usize,usize,u8,usize,u32,u32,usize,u64,usize,usize,u64); {len(rows)}] = [\n"
            + "\n".join("    (" + ", ".join(map(str, row)) + ")," for row in rows) + "\n];\n")
    return c, rust


def reference_source(variant):
    return ('#include <cstddef>\n#include <cstdint>\n#include "original.cpp"\n'
            'extern "C" std::uint64_t composed_case(std::size_t left, std::size_t right, std::uint8_t value, '
            'std::size_t index, std::uint32_t reject, std::uint32_t early) noexcept {\n'
            f'    return run_{variant}(left, right, value, index, reject, early);\n}}\n')


def _mutate(emitted, mutation):
    if mutation is None:
        return emitted
    if mutation == "leak":
        changed = emitted.replace("free(value.data);", "(void)value;")
    elif mutation == "destruction_order":
        pattern = r"(void [A-Za-z0-9_]*HeptaComposite_drop\([^\n]*\) \{\n)(.*?)(\n\})"
        found = re.search(pattern, emitted, re.S)
        require(found is not None, "Composite destructor definition not found for native order control")
        body = found[2]
        indices = [int(value) for value in re.findall(r"\(h_owner\)\.h_resource([0-9]+)", body)]
        require(len(indices) in {2, 3, 4} and indices == list(reversed(range(len(indices))))
                and body.count("HeptaLeaf_drop(") == len(indices), "Composite drop call denominator differs")
        reversed_body = re.sub(r"(\(h_owner\)\.h_resource)([0-9]+)", lambda match: match[1] + str(len(indices) - 1 - int(match[2])), body)
        changed = emitted[:found.start(2)] + reversed_body + emitted[found.end(2):]
    else:
        raise ValueError("Unknown native mutation")
    require(changed != emitted, "Native mutation did not change compiled implementation")
    return changed


def _build(entry, directory, backend, vectors, row, *, rustc=None, cc="gcc", mutation=None):
    row.update(status="in_progress", stage="directory", foreign_cpp_link_inputs=[], mutation=mutation)
    try:
        directory.mkdir(); row["stage"] = "frontend"
        checked = analyze_project(entry, backend=backend, crate_type="obj", rustc=rustc, cc=cc); row["frontend"] = checked.report
        require(checked.report["ok"] is True and checked.report["assumptions"] == [], "Composed native frontend failed")
        row["stage"] = "resource_graph"
        row["resource_ir"] = lower_resource_ir(checked.program, checked.checked, project_sha256=checked.project.identity)
        row["resource_verification"] = verify_resource_ir(row["resource_ir"])
        row["source_binding"] = verify_resource_source(entry, row["resource_ir"], native=False)
        require(row["source_binding"]["ok"] is True, "Resource source binding failed")
        emitted = checked.c if backend == "c" else checked.rust
        row.update(emitted_source=emitted, emitted_sha256=_sha(emitted.encode()))
        compiled = _mutate(emitted, mutation); row["compiled_emitted_sha256"] = _sha(compiled.encode())
        header, rust_cases = case_sources(vectors)
        harness = (EXAMPLE / ("harness.c" if backend == "c" else "harness.rs")).read_text(); row["harness_source"] = harness
        if backend == "c":
            (directory / "cases.h").write_text(header); row["case_header"] = _identity(directory / "cases.h")
        source = compiled + "\n" + (harness if backend == "c" else rust_cases + "\n" + harness)
        target = directory / ("program.c" if backend == "c" else "program.rs")
        target.write_text(source); row["compiled_source"] = _identity(target); row["stage"] = "native_compile"
        row["native"] = (compile_c(source, cc=cc, crate_type="bin", output=directory / "native", sanitize=True,
                                  link_args=[*WRAP_FLAGS, "-I" + str(directory)]) if backend == "c" else
                         compile_rust(source, rustc=rustc, crate_type="bin", output=directory / "native"))
        require(row["native"]["ok"] is True, "Composed native build failed: " + json.dumps(row["native"]))
        row["artifact"] = _identity(row["native"]["artifact"]); row["stage"] = "native_execution"
        row["execution"] = _run([row["native"]["artifact"]]); _process(row["execution"], 3 if mutation else 0)
        row.update(status="completed", stage="execution_recorded")
    except (HeptaError, OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        row.update(status="failed", failure=_exception_record(error)); raise


def _current_identity(record):
    require(isinstance(record, dict) and is_sha(record.get("sha256")) and type(record.get("bytes")) is int
            and record["bytes"] > 0 and isinstance(record.get("path"), str), "Artifact/source identity incomplete")
    require(strict_equal(record, _identity(record["path"])), "Current retained artifact/source differs")


def _replay_backend(row, variant, backend, report):
    frontend = row["frontend"]; entry = Path(variant["entry_source"]["path"])
    require(frontend["project"]["entry"] == str(entry), "Backend entry path differs")
    fresh = analyze_project(entry, backend=backend, native=False, crate_type="obj")
    require(fresh.report["ok"] is True and fresh.report["assumptions"] == [] and fresh.project.unchanged(), "Fresh source replay failed")
    require(fresh.report["compiler_sha256"] == report["hepta_compiler_sha256"] and strict_equal(fresh.report["project"], frontend["project"])
            and fresh.report["source_sha256"] == frontend["source_sha256"] and fresh.report["interface_sha256"] == frontend["interface_sha256"]
            and strict_equal(fresh.report["effects"], frontend["effects"]), "Current frontend identities differ")
    graph = lower_resource_ir(fresh.program, fresh.checked, project_sha256=fresh.project.identity)
    require(strict_equal(graph, row["resource_ir"]), "E_CPP_COMPOSED_SOURCE_GRAPH: current graph differs")
    require((fresh.c if backend == "c" else fresh.rust) == row["emitted_source"], "E_CPP_COMPOSED_SOURCE_CODEGEN: emitted source differs")
    semantic = lower_checked_program(fresh.program, fresh.checked, project_sha256=fresh.project.identity)
    binding = row["source_binding"]["source_binding"]
    require(semantic["all_expressions_typed"] is True and semantic["untyped_expressions"] == []
            and semantic["sha256"] == binding["canonical_semantic_sha256"] and semantic["schema"] == binding["canonical_semantic_schema"]
            and strict_equal(semantic["external_obligations"], binding["canonical_external_obligations"])
            and strict_equal(semantic["foreign_assumptions"], binding["canonical_foreign_assumptions"]), "Current typed semantics differ")


@normalized_errors
def validate_report(report, *, clangxx="clang++"):
    """Current source replay is mandatory. The selected local Clang is caller-owned."""
    require(report.get("schema") == SCHEMA and report.get("profile") == PROFILE and report.get("ok") is True
            and report.get("status") == "native_composed_implementation_and_cleanup_qualified", "Successful composed qualification required")
    require(all(report.get(key) is value for key, value in CLAIMS.items()), "Composed scope claims differ")
    require(report["performance"] == {"status": "not_run"} and report["diagnostics"] == [], "Performance/diagnostic scope differs")
    require(report["inputs"] == _inputs() and report["hepta_compiler_sha256"] == compiler_hash()
            and report["inputs_unchanged"] is True and set(report["variants"]) == set(VARIANTS), "Stale/incomplete current input identities")
    selected = shutil.which(clangxx)
    require(selected is not None, "Current Clang selection unavailable")
    local_compiler = _identity(selected)
    for name, variant in report["variants"].items():
        require(variant["status"] == "completed" and variant["stage"] == "all_native_routes_recorded", "Variant did not finish")
        vectors = cases(name); expected = observation_oracle(vectors); migration = variant["migration"]
        require(variant["cases_sha256"] == _sha(_canonical(vectors)) and
                strict_equal(variant["case_families"], dict(Counter(row["family"] for row in vectors))), "Case denominator differs")
        require(migration["ok"] is True and migration["profile"] == PROFILE and type(migration["resource_count"]) is int
                and migration["resource_count"] == VARIANTS[name] and migration["unconverted_declarations"] == []
                and type(migration["active_declarations"]) is int and migration["active_declarations"] == len(migration["declaration_inventory"])
                and type(migration["foreign_cpp_calls"]) is int and migration["foreign_cpp_calls"] == 0
                and type(migration["source_declarations"]) is int and migration["source_declarations"] == 3
                and type(migration["converted_source_declarations"]) is int and migration["converted_source_declarations"] == 3
                and all(migration[key] is value for key, value in LIMITS.items()), "Complete implementation ledger missing")
        require(migration["source_sha256"] == report["inputs"]["examples/cpp/composed_migration/" + name + ".cpp"]
                and migration["output_sha256"] == variant["migrated_source"]["sha256"]
                == report["inputs"]["examples/cpp/composed_migration/" + name + ".hepta"]
                and migration["hepta_compiler_sha256"] == report["hepta_compiler_sha256"]
                and migration["target_model"]["compiler_sha256"] == local_compiler["sha256"]
                and migration["target_model"]["compiler"] == local_compiler["path"], "Source/compiler/implementation binding differs")
        for identity in (variant["migrated_source"], variant["entry_source"]):
            _current_identity(identity)
        require(variant["entry_source"]["sha256"] == report["inputs"]["examples/cpp/composed_migration/consumer.hepta"], "Consumer source differs")
        rendered, replayed = translate_cpp_composed(migration["source"], clangxx=selected)
        retained = {key: value for key, value in migration.items() if key != "output"}
        require(strict_equal(replayed, retained) and rendered.encode() == Path(variant["migrated_source"]["path"]).read_bytes(),
                "E_CPP_COMPOSED_SOURCE_TRANSLATION: original C++ translation replay differs")
        reference = variant["reference"]
        for key in ("compiler", "linker", "artifact", "case_header"):
            _current_identity(reference[key])
        for item in (*reference["objects"], *reference["sources"].values()):
            _current_identity(item)
        require(reference["compiler"] == local_compiler
                and str(Path(reference["compiler_driver"]).resolve()) == reference["compiler"]["path"]
                and str(Path(reference["link_driver"]).resolve()) == reference["linker"]["path"]
                and reference["sources"]["original"]["sha256"] == migration["source_sha256"]
                and reference["sources"]["harness"]["sha256"] == report["inputs"]["examples/cpp/composed_migration/harness.c"]
                and reference["sources"]["reference"]["sha256"] == _sha(reference_source(name).encode()), "Reference compilation sources/tool identities differ")
        header, _ = case_sources(vectors)
        require(reference["case_header"]["sha256"] == _sha(header.encode()), "Reference vectors differ")
        first, second = reference["objects"]
        commands = [[reference["compiler_driver"], *CPP_FLAGS, "-c", reference["sources"]["reference"]["path"], "-o", first["path"]],
                    [reference["compiler_driver"], *CPP_FLAGS, "-x", "c++", "-I" + str(Path(reference["case_header"]["path"]).parent),
                     "-c", reference["sources"]["harness"]["path"], "-o", second["path"]],
                    [reference["link_driver"], *CPP_FLAGS, first["path"], second["path"], "-o", reference["artifact"]["path"]]]
        require([row["command"] for row in reference["commands"]] == commands, "Reference executed commands differ")
        for process in reference["commands"]:
            _process(process)
        _process(reference["execution"])
        require(reference["execution"]["command"] == [reference["artifact"]["path"]]
                and strict_equal(json.loads(reference["execution"]["stdout"]), expected), "Original native oracle mismatch")
        require(set(variant["backends"]) == {"rust", "c"} and set(variant["negative_controls"]) == {"leak", "destruction_order"}, "Native route/negative denominator differs")
        for label, row in [*variant["backends"].items(), *variant["negative_controls"].items()]:
            mutation = label if label in {"leak", "destruction_order"} else None
            backend = "c" if mutation else label; frontend = row["frontend"]
            emitted_key = "c_sha256" if backend == "c" else "rust_sha256"
            require(row["status"] == "completed" and row["stage"] == "execution_recorded" and row["mutation"] == mutation
                    and row["foreign_cpp_link_inputs"] == [], "Native route did not complete independently")
            require(frontend["ok"] is True and frontend["status"] == "checked" and frontend["diagnostics"] == []
                    and frontend["assumptions"] == [] and frontend["compiler_sha256"] == report["hepta_compiler_sha256"]
                    and frontend["source_sha256"] == variant["entry_source"]["sha256"] and len(frontend["project"]["sources"]) == 2
                    and set(frontend["project"]["sources"].values()) == {variant["migrated_source"]["sha256"], variant["entry_source"]["sha256"]}, "Native frontend source/assumptions differ")
            native_build(frontend["backend"], backend, check_only=True, crate_type="obj", source_sha256=frontend[emitted_key])
            native_build(row["native"], backend, check_only=False, crate_type="bin", source_sha256=row["compiled_source"]["sha256"])
            require(row["native"]["toolchain"] == frontend["backend"]["toolchain"]
                    and row["native"]["artifact"] == row["artifact"]["path"] and row["native"]["artifact_sha256"] == row["artifact"]["sha256"]
                    and row["native"]["artifact_bytes"] == row["artifact"]["bytes"], "Native artifact/compiler identity differs")
            for identity in (row["artifact"], row["compiled_source"]):
                _current_identity(identity)
            require(row["emitted_sha256"] == _sha(row["emitted_source"].encode()) == frontend[emitted_key], "Generated implementation identity differs")
            compiled = _mutate(row["emitted_source"], mutation)
            require(row["compiled_emitted_sha256"] == _sha(compiled.encode()), "Native mutation identity differs")
            harness = row["harness_source"]
            require(_sha(harness.encode()) == report["inputs"]["examples/cpp/composed_migration/harness." + ("c" if backend == "c" else "rs")], "Observation harness differs")
            header, rust_cases = case_sources(vectors)
            source = compiled + "\n" + (harness if backend == "c" else rust_cases + "\n" + harness)
            require(_sha(source.encode()) == row["compiled_source"]["sha256"], "Native source/harness/vector composition differs")
            if backend == "c":
                _current_identity(row["case_header"])
                require(row["case_header"]["sha256"] == _sha(header.encode())
                        and row["native"]["link_args"] == [*WRAP_FLAGS, "-I" + str(Path(row["case_header"]["path"]).parent)]
                        and "-fsanitize=undefined" in row["native"]["flags"], "Actual allocator/UBSan boundary differs")
            else:
                require(row["native"]["link_args"] == [] and row["native"]["rustc_crate_type"] == "bin", "Unexpected Rust foreign link inputs")
            verification = verify_resource_ir(row["resource_ir"])
            require(verification["ok"] is True and strict_equal(verification, row["resource_verification"]), "Independent resource graph rejected")
            binding = verify_resource_source(variant["entry_source"]["path"], row["resource_ir"], native=False)
            require(binding["ok"] is True and strict_equal(binding, row["source_binding"]), "E_CPP_COMPOSED_SOURCE_GRAPH: source binding replay differs")
            _replay_backend(row, variant, backend, report)
            _process(row["execution"], 3 if mutation else 0)
            require(row["execution"]["command"] == [row["artifact"]["path"]], "Executed artifact differs")
            observed = json.loads(row["execution"]["stdout"])
            if mutation:
                require(observed["ok"] is False and observed["failure"] == "lifecycle" and type(observed["case"]) is int and observed["case"] == 0,
                        "Native lifetime negative control did not fail on the first real case")
                first_case = vectors[0]
                require(type(observed["allocated"]) is int and observed["allocated"] == first_case["allocated"]
                        and type(observed["refusals"]) is int and observed["refusals"] == 0
                        and type(observed["freed"]) is int and type(observed["live"]) is int, "Negative control allocation denominator differs")
                if mutation == "leak":
                    require(observed["freed"] == 0 and observed["live"] == first_case["allocated"], "Release-removal mutation did not leak")
                else:
                    require(observed["freed"] == observed["allocated"] and observed["live"] == 0 and
                            observed["trace"] != observed["expected_trace"] == f"{first_case['trace']:016x}", "Wrong release order was not detected independently of leaks")
            else:
                require(strict_equal(observed, expected), "Native scalar/allocation/destruction-order oracle mismatch")
    require(report["inputs"] == _inputs() and report["hepta_compiler_sha256"] == compiler_hash(), "Inputs/compiler changed during replay")
    return True


def qualify_cpp_composed(directory, *, clangxx="clang++", rustc=None, cc="gcc"):
    report = {"schema": SCHEMA, "profile": PROFILE, "ok": False, "status": "not_run", **CLAIMS,
              "inputs": _inputs(), "hepta_compiler_sha256": compiler_hash(), "variants": {},
              "diagnostics": [], "performance": {"status": "not_run"}}
    try:
        work = Path(directory).resolve() / "cpp-composed"; work.mkdir(parents=True)
        compiler, linker = shutil.which(clangxx), shutil.which("g++")
        require(compiler is not None and linker is not None, "Clang20/G++ toolchains required")
        for name in VARIANTS:
            variant = {"status": "in_progress", "stage": "migration", "backends": {}, "negative_controls": {}}
            report["variants"][name] = variant; current = work / name; current.mkdir()
            migrated, entry = current / "migrated.hepta", current / "consumer.hepta"
            variant["migration"] = migrate_cpp_composed(EXAMPLE / (name + ".cpp"), migrated, clangxx=clangxx)
            require(variant["migration"]["ok"] is True, "Composed migration failed: " + json.dumps(variant["migration"]))
            require(migrated.read_bytes() == (EXAMPLE / (name + ".hepta")).read_bytes(), "Documented output differs from actual translation")
            variant["migrated_source"] = _identity(migrated)
            entry.write_bytes((EXAMPLE / "consumer.hepta").read_bytes()); variant["entry_source"] = _identity(entry)
            vectors = cases(name); header, _ = case_sources(vectors)
            variant["cases_sha256"] = _sha(_canonical(vectors)); variant["case_families"] = dict(Counter(row["family"] for row in vectors))
            (current / "cases.h").write_text(header); (current / "original.cpp").write_bytes((EXAMPLE / (name + ".cpp")).read_bytes())
            (current / "reference.cpp").write_text(reference_source(name))
            reference = {"compiler": _identity(compiler), "linker": _identity(linker), "compiler_driver": compiler,
                "link_driver": linker, "commands": [], "sources": {"original": _identity(current / "original.cpp"),
                "reference": _identity(current / "reference.cpp"), "harness": _identity(EXAMPLE / "harness.c")}, "case_header": _identity(current / "cases.h")}
            variant["reference"] = reference; variant["stage"] = "reference_build"
            commands = [[compiler, *CPP_FLAGS, "-c", str(current / "reference.cpp"), "-o", str(current / "reference.o")],
                        [compiler, *CPP_FLAGS, "-x", "c++", "-I" + str(current), "-c", str(EXAMPLE / "harness.c"), "-o", str(current / "harness.o")],
                        [linker, *CPP_FLAGS, str(current / "reference.o"), str(current / "harness.o"), "-o", str(current / "reference-native")]]
            for command in commands:
                reference["commands"].append(_run(command)); _process(reference["commands"][-1])
            reference["objects"] = [_identity(current / "reference.o"), _identity(current / "harness.o")]
            reference["artifact"] = _identity(current / "reference-native"); variant["stage"] = "reference_execution"
            reference["execution"] = _run([reference["artifact"]["path"]]); _process(reference["execution"])
            variant["stage"] = "backends"
            for backend in ("rust", "c"):
                variant["backends"][backend] = {}
                _build(entry, current / backend, backend, vectors, variant["backends"][backend], rustc=rustc, cc=cc)
            variant["stage"] = "negative_controls"
            for mutation in ("leak", "destruction_order"):
                variant["negative_controls"][mutation] = {}
                _build(entry, current / mutation, "c", vectors, variant["negative_controls"][mutation], cc=cc, mutation=mutation)
            variant.update(status="completed", stage="all_native_routes_recorded")
        report["inputs_unchanged"] = report["inputs"] == _inputs() and report["hepta_compiler_sha256"] == compiler_hash()
        report.update(ok=True, status="native_composed_implementation_and_cleanup_qualified"); validate_report(report, clangxx=clangxx)
    except (HeptaError, OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        report.update(ok=False, status="failed"); report["diagnostics"].append(_exception_record(error))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", type=Path, required=True); parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--clangxx", default="clang++"); parser.add_argument("--rustc", default=os.environ.get("RUSTC"))
    parser.add_argument("--cc", default=os.environ.get("CC", "gcc")); args = parser.parse_args()
    report = qualify_cpp_composed(args.workdir, clangxx=args.clangxx, rustc=args.rustc, cc=args.cc)
    with args.out.open("x") as output:
        json.dump(report, output, indent=2, sort_keys=True); output.write("\n")
    print(json.dumps({"ok": report["ok"], "status": report["status"], "out": str(args.out), "diagnostics": report["diagnostics"]}, sort_keys=True))
    return 0 if report["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
