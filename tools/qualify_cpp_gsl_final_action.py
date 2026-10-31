"""Reproduce the real Microsoft GSL final_action migration experiment.

The original is three separately compiled C++ translation units. The migrated
binary links only generated Hepta C and a C harness. An independently authored
scalar/event oracle checks both. This is a small closed specialization, not a
claim to have translated the entire GSL library or general C++ exception ABI.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import random
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from hepta.cpp_gsl_final_action import capture_and_lower, _identity
from hepta.hia_program_source import lower_source
from hepta.hia_program_llvm import native_host_profile, native_driver_matches_host
from hepta.pipeline import analyze, compiler_hash


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def command(log, argv, *, stdin=None, accepted=(0,), cwd=None):
    started = time.monotonic()
    result = subprocess.run([str(a) for a in argv], input=stdin, text=True,
                            capture_output=True, timeout=60, cwd=cwd)
    row = {"argv": [str(a) for a in argv], "returncode": result.returncode,
           "stdout": result.stdout, "stderr": result.stderr,
           "elapsed_seconds": time.monotonic() - started}
    log.append(row)
    require(result.returncode in accepted,
            "Command failed: " + str(argv[0]) + "\n" + result.stderr[:4000])
    return result


def oracle(seed, tag, mode, *, multiplier=31):
    """Do not call importer/interpreter/compiled implementation from here."""
    tags = [] if mode == 7 else ([9, tag] if mode == 5 else [tag])
    trace = seed
    for cleanup_tag in tags:
        trace = (trace * multiplier + cleanup_tag) % (1 << 64)
    status = {1: 2001, 2: 2002, 3: 2003, 4: 1004, 5: 2005,
              6: 1006, 7: 1007}.get(mode, 0)
    return trace, len(tags), status


def cases():
    values = (0, 1, 7, (1 << 32) - 1, 1 << 63, (1 << 64) - 1)
    rows = [(seed, tag, mode) for seed in values for tag in values for mode in range(8)]
    rng = random.Random(0x6A51)
    rows += [(rng.getrandbits(64), rng.getrandbits(64), rng.randrange(8))
             for _ in range(128)]
    return rows


def observation(log, executable, rows):
    result = command(log, [executable], stdin="".join("%d %d %d\n" % r for r in rows))
    lines = [tuple(map(int, line.split())) for line in result.stdout.splitlines()]
    require(len(lines) == len(rows) and all(len(line) == 3 for line in lines),
            "Native observation count or shape differs")
    return lines


def build_original(root, version, directory, log, *, cxx, cc, examples=None):
    examples = examples or root / "examples/cpp/gsl_final_action"
    includes = ["-I" + str(directory), "-I" + str(examples),
                "-I" + str(root / "tests/fixtures/gsl_final_action" / version / "include")]
    objects = []
    for name in ("original_entry.cpp", "original_consume.cpp", "callback.cpp"):
        obj = directory / (name + ".o")
        command(log, [cxx, "-std=c++20", "-O2", "-fno-lto", *includes,
                      "-c", examples / name, "-o", obj])
        objects.append(obj)
    harness = directory / "original_harness.o"
    command(log, [cc, "-std=c11", "-O2", "-c", examples / "harness.c", "-o", harness])
    executable = directory / "original"
    command(log, [cxx, *objects, harness, "-o", executable])
    return executable


def check_generated_signature(generated, directory, log, *, cc, label, reject=False):
    """Check the actual emitted C definition against the independent C caller.

    A symbol-name inventory cannot detect a narrowed return or a signed/wider
    argument. Compile a separate translation unit including the real emitted
    definition, so the check does not merely repeat the harness declaration.
    This is a finite compiler observation, not a general binary ABI proof.
    """
    generated = Path(generated).resolve()
    probe = Path(directory) / (label + ".abi-probe.c")
    source = ('#include <stdint.h>\n#include <limits.h>\n'
              '#include ' + json.dumps(str(generated)) + '\n'
              'typedef uint64_t (*hepta_expected_gsl_entry)(uint64_t, uint64_t, uint32_t, uint32_t);\n'
              '_Static_assert(CHAR_BIT == 8 && sizeof(uint64_t) == 8 && sizeof(uint32_t) == 4, "Hepta GSL scalar widths");\n'
              '_Static_assert(_Generic(&migrated_case, hepta_expected_gsl_entry: 1, default: 0), "Hepta GSL export signature mismatch");\n')
    probe.write_text(source)
    result = command(log, [cc, "-std=c11", "-Werror", "-fsyntax-only", probe],
                     accepted=(1,) if reject else (0,))
    if reject:
        require("Hepta GSL export signature mismatch" in result.stderr,
                "ABI negative failed for a reason other than the exact export contract")
    return {"status": "rejected_signature_mismatch" if reject else "compiler_checked",
            "symbol": "migrated_case", "returns": "u64", "parameters": ["u64", "u64", "u32", "u32"],
            "generated_c_sha256": sha256(generated.read_bytes()).hexdigest(),
            "probe_sha256": sha256(probe.read_bytes()).hexdigest(),
            "probe_path": str(probe), "whole_binary_abi_proved": False}


def build_migrated(source, directory, log, *, cc, root, label="migrated"):
    hepta = directory / (label + ".hepta")
    hepta.write_text(source)
    analysis = analyze(source, path=str(hepta), backend="c", native=False, crate_type="obj")
    require(analysis.report["ok"], "Hepta checker rejected generated source: " +
            json.dumps(analysis.report["diagnostics"]))
    core = lower_source(source, path=str(hepta))
    (directory / (label + ".core.json")).write_text(json.dumps(core.as_dict(), indent=2) + "\n")
    (directory / (label + ".check.json")).write_text(json.dumps(analysis.report, indent=2) + "\n")
    generated = directory / (label + ".c")
    generated.write_text(analysis.c)
    signature = check_generated_signature(generated, directory, log, cc=cc, label=label)
    (directory / (label + ".abi.json")).write_text(json.dumps(signature, indent=2) + "\n")
    obj = directory / (label + ".o")
    command(log, [cc, "-std=c11", "-O2", "-fno-lto", "-c", generated, "-o", obj])
    executable = directory / label
    command(log, [cc, "-std=c11", "-O2", "-DCASE_FUNCTION=migrated_case",
                  root / "examples/cpp/gsl_final_action/harness.c", obj, "-o", executable])
    return executable, analysis.report


def qualify(root, output, *, clang, cxx="g++", cc="gcc"):
    root, output = Path(root).resolve(), Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    compiler_before = compiler_hash()
    source_paths = [Path(__file__), root / "tests/fixtures/gsl_final_action/lock.json",
                    *sorted((root / "examples/cpp/gsl_final_action").iterdir())]
    source_bindings = {str(p): _identity(p) for p in source_paths if p.is_file()}
    tools = {name: _identity(shutil.which(str(path)) or str(path))
             for name, path in (("clang", clang), ("cxx", cxx), ("cc", cc))}
    host = native_host_profile()
    target_log, targets = [], {}
    for name, tool in tools.items():
        target = command(target_log, [tool["path"], "-dumpmachine"]).stdout.strip()
        require(native_driver_matches_host(target, host),
                "GSL native compiler target differs from the measured LP64 Linux host")
        targets[name] = target
    rows = cases()
    expected = [oracle(*r) for r in rows]
    report = {"schema": "hepta.gsl-final-action-qualification.v1", "ok": False,
              "component": "microsoft/GSL gsl::final_action<GslCallback>",
              "scope": "three real upstream class methods, instantiated finally factory, one authored closed callback body",
              "case_count_per_version": len(rows), "versions": {}, "negative_controls": {},
              "source_bindings": source_bindings, "native_tools": tools,
              "native_abi": {"host": host, "compiler_targets": targets, "commands": target_log,
                             "entry_signature": "u64(u64,u64,u32,u32)",
                             "scope": "actual_host_scalar_C_calls_only_not_Cpp_class_layout_or_cross_target"},
              "claims": {"whole_gsl_migrated": False, "general_cpp_migration": False,
                         "general_cpp_exceptions_translated": False,
                         "arbitrary_callable_or_pointer_lifetimes_supported": False,
                         "migration_speedup_claimed": False,
                         "full_semantic_equivalence_proved": False}}
    (output / "cases.json").write_text(json.dumps(
        [{"input": r, "expected": e} for r, e in zip(rows, expected)], indent=2) + "\n")
    report["cases_sha256"] = sha256((output / "cases.json").read_bytes()).hexdigest()
    lowered = {}
    for version in ("3.1.0", "4.0.0"):
        directory = output / version
        directory.mkdir(exist_ok=True)
        migration = capture_and_lower(root, version, directory, clang=clang)
        lowered[version] = migration
        log = []
        original = build_original(root, version, directory, log, cxx=cxx, cc=cc)
        migrated, checked = build_migrated(migration["source"], directory, log, cc=cc, root=root)
        before = observation(log, original, rows)
        after = observation(log, migrated, rows)
        require(before == expected, "Independent oracle rejected original " + version)
        require(after == expected, "Independent oracle rejected migrated " + version)
        examples = root / "examples/cpp/gsl_final_action"
        factory = directory / "factory_lvalue"
        result = command(log, [cxx, "-std=c++20", "-O2", "-I" + str(directory),
            "-I" + str(examples), "-I" + str(root / "tests/fixtures/gsl_final_action" / version / "include"),
            examples / "factory_lvalue.cpp", examples / "callback.cpp", "-o", factory],
            accepted=(0, 1))
        expected_compile = version == "4.0.0"
        require((result.returncode == 0) is expected_compile, "Upstream factory change disappeared")
        if expected_compile:
            command(log, [factory])
        else:
            require("GslCallback&" in result.stderr and "cannot bind" in result.stderr,
                    "Old factory failed for a reason other than its reference instantiation")
        factory_source = migration["component_source"] + "\n" + (examples / "factory_client.hepta").read_text()
        factory_check = analyze(factory_source, native=False, backend="c")
        require(factory_check.report["ok"] is expected_compile,
                "Migrated factory availability differs from the captured upstream type contract")
        factory_result = {"available": expected_compile,
                          "diagnostics": factory_check.report["diagnostics"]}
        if expected_compile:
            factory_migrated, _ = build_migrated(factory_source, directory, log, cc=cc, root=root, label="factory_migrated")
            factory_obj = directory / "factory_original.o"
            factory_harness = directory / "factory_harness.o"
            factory_original = directory / "factory_original"
            command(log, [cxx, "-std=c++20", "-O2", "-DHEPTA_FACTORY_LIBRARY",
                "-I" + str(directory), "-I" + str(examples),
                "-I" + str(root / "tests/fixtures/gsl_final_action" / version / "include"),
                "-c", examples / "factory_lvalue.cpp", "-o", factory_obj])
            command(log, [cc, "-std=c11", "-O2", "-DCASE_FUNCTION=original_factory_case",
                          "-c", examples / "harness.c", "-o", factory_harness])
            command(log, [cxx, factory_obj, directory / "callback.cpp.o", factory_harness, "-o", factory_original])
            factory_expected = [oracle(seed, tag, 0) for seed, tag, _ in rows]
            require(observation(log, factory_original, rows) == factory_expected, "Original lvalue factory differs from oracle")
            require(observation(log, factory_migrated, rows) == factory_expected, "Migrated lvalue factory differs from oracle")
            factory_result.update(case_count=len(rows), independent_original_and_migrated_match=True)

        # The two real releases implement const-lvalue construction through
        # different overload bodies. Independently run both original programs
        # and the standalone source-derived Hepta implementation.
        const_source = migration["component_source"] + "\n" + (examples / "factory_const_client.hepta").read_text()
        const_migrated, _ = build_migrated(const_source, directory, log, cc=cc, root=root,
                                         label="const_factory_migrated")
        const_object = directory / "const_factory_original.o"
        const_harness = directory / "const_factory_harness.o"
        const_original = directory / "const_factory_original"
        command(log, [cxx, "-std=c++20", "-O2", "-fno-lto", "-DHEPTA_FACTORY_LIBRARY",
                      "-I" + str(directory), "-I" + str(examples),
                      "-I" + str(root / "tests/fixtures/gsl_final_action" / version / "include"),
                      "-c", examples / "factory_const_lvalue.cpp", "-o", const_object])
        command(log, [cc, "-std=c11", "-O2", "-DCASE_FUNCTION=original_const_factory_case",
                      "-c", examples / "harness.c", "-o", const_harness])
        command(log, [cxx, const_object, directory / "callback.cpp.o", const_harness, "-o", const_original])
        const_expected = [oracle(seed, tag, 0) for seed, tag, _ in rows]
        require(observation(log, const_original, rows) == const_expected,
                "Original const-lvalue factory differs from independent oracle")
        require(observation(log, const_migrated, rows) == const_expected,
                "Migrated const-lvalue factory differs from independent oracle")
        const_binding = [row for row in migration["report"]["lowered_operations"]
                         if row.get("category") == "const_lvalue"]
        require(len(const_binding) == 1, "Const-lvalue factory body was not captured once")
        report["versions"][version] = {
            "migration": migration["report"], "commands": log,
            "native_original_matches_oracle": True, "standalone_migration_matches_oracle": True,
            "hepta_and_independent_core_checked": True,
            "factory_nonconst_lvalue": "compiles_and_runs_once" if expected_compile else "compile_rejected_reference_binding",
            "migrated_factory_nonconst_lvalue": factory_result,
            "migrated_factory_const_lvalue": {"case_count": len(rows),
                "distinct_seed_tag_cases": len({(seed, tag) for seed, tag, _ in rows}),
                "independent_original_and_migrated_match": True,
                "captured_parameter_binding": const_binding[0]["parameter_binding"],
                "original_binary_sha256": sha256(const_original.read_bytes()).hexdigest(),
                "migrated_binary_sha256": sha256(const_migrated.read_bytes()).hexdigest(),
                "migrated_linked_cpp_objects": []},
            "original_binary_sha256": sha256(original.read_bytes()).hexdigest(),
            "migrated_binary_sha256": sha256(migrated.read_bytes()).hexdigest(),
            "migrated_linked_cpp_objects": [], "check": checked}

    # Preserve the symbol name while changing real emitted declarations and
    # definitions. Name-only ELF inspection would miss both incompatibilities;
    # the exact typed contract must reject before an incompatible call executes.
    generated = (output / "4.0.0/migrated.c").read_text()
    signature = "uint64_t migrated_case(uint64_t h_seed, uint64_t h_tag, uint32_t h_mode, uint32_t h_field)"
    require(generated.count(signature) == 2, "Generated export declaration/definition anchor changed")
    for label, replacement in {
        "wrong_return_width": signature.replace("uint64_t migrated_case", "uint32_t migrated_case"),
        "wrong_argument_signedness": signature.replace("uint32_t h_mode", "int32_t h_mode"),
    }.items():
        altered = output / (label + ".c")
        altered.write_text(generated.replace(signature, replacement))
        log = []
        rejected = check_generated_signature(altered, output, log, cc=cc, label=label, reject=True)
        report["negative_controls"][label] = {"detected": True, "same_export_symbol": True,
                                               "incompatible_native_call_executed": False,
                                               "signature": rejected, "commands": log}

    # Same upstream component, changed real callback source: emitter must follow
    # the new captured expression. Neither the implementation nor oracle is
    # allowed to obtain answers by running the other.
    changed_examples = output / "callback_37_source"
    shutil.copytree(root / "examples/cpp/gsl_final_action", changed_examples, dirs_exist_ok=True)
    callback = changed_examples / "callback.cpp"
    require(callback.read_text().count("31ULL") == 1, "Callback mutation anchor changed")
    callback.write_text(callback.read_text().replace("31ULL", "37ULL"))
    changed_dir = output / "callback_37"
    changed_dir.mkdir(exist_ok=True)
    mutation = capture_and_lower(root, "4.0.0", changed_dir, clang=clang, examples=changed_examples)
    require(mutation["source"] != lowered["4.0.0"]["source"], "Emitter ignored actual callback body")
    log = []
    original = build_original(root, "4.0.0", changed_dir, log, cxx=cxx, cc=cc, examples=changed_examples)
    migrated, _ = build_migrated(mutation["source"], changed_dir, log, cc=cc, root=root)
    expected37 = [oracle(*r, multiplier=37) for r in rows]
    require(observation(log, original, rows) == expected37, "Changed original differs from oracle")
    require(observation(log, migrated, rows) == expected37, "Changed source was not translated")
    report["negative_controls"]["changed_actual_callback"] = {
        "passed": True, "new_multiplier": 37, "case_count": len(rows),
        "migration": mutation["report"], "commands": log}

    # Resource safety alone does not prove the callback result. Keep this
    # deliberately wrong but linear program in the evidence to check that
    # semantic verification has an independent way to fail.
    source = lowered["4.0.0"]["source"]
    require(source.count("wrapping_mul(state.trace, 31)") == 1, "Semantic control anchor changed")
    wrong = source.replace("wrapping_mul(state.trace, 31)", "wrapping_mul(state.trace, 32)")
    log = []
    binary, _ = build_migrated(wrong, output, log, cc=cc, root=root, label="wrong_but_linear")
    actual = observation(log, binary, rows)
    mismatches = sum(a != b for a, b in zip(actual, expected))
    require(mismatches > 0, "Independent oracle missed wrong but resource-safe code")
    report["negative_controls"]["wrong_but_linear"] = {
        "detected": True, "mismatch_count": mismatches,
        "hepta_and_core_resource_checks_passed": True, "commands": log}

    for label, replacement in {
        "duplicate_owner": "GslDestroy(move owner, mut state); GslDestroy(move owner, mut state); return 2001;",
        "lost_owner": "return 2001;",
    }.items():
        anchor = "GslDestroy(move owner, mut state); return 2001;"
        require(source.count(anchor) == 1, "Resource control anchor changed")
        bad = source.replace(anchor, replacement)
        checked = analyze(bad, backend="c", native=False)
        require(not checked.report["ok"], "Resource checker accepted " + label)
        report["negative_controls"][label] = {"detected": True,
                                               "diagnostics": checked.report["diagnostics"]}
    require(compiler_hash() == compiler_before, "Compiler changed while qualification was running")
    require(all(_identity(path) == identity for path, identity in source_bindings.items()),
            "Qualification input source changed")
    require(all(_identity(identity["path"]) == identity for identity in tools.values()),
            "Native compiler driver changed")
    report["compiler_sha256"] = compiler_before
    report["cost"] = {"qualification_wall_seconds": time.monotonic() - started,
                      "human_seconds": None, "human_seconds_status": "not_measured",
                      "generated_component_bytes": len(lowered["4.0.0"]["component_source"].encode()),
                      "authored_integration_client_bytes": len((root / "examples/cpp/gsl_final_action/client.hepta").read_bytes())}
    report["execution_denominator"] = {
        "cases_per_original_migrated_pair": len(rows),
        "original_migrated_pairs": 6,
        "positive_observation_rows": 12 * len(rows),
        "scalar_calls_per_observation_row": 3,
        "positive_native_scalar_calls": 36 * len(rows),
        "const_factory_pairs": 2,
        "const_factory_positive_native_scalar_calls": 12 * len(rows),
        "wrong_but_linear_observation_rows": len(rows),
        "wrong_but_linear_native_scalar_calls": 3 * len(rows),
        "incompatible_signature_controls_called": 0,
    }
    report["ok"] = True
    (output / "report.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clang", required=True)
    parser.add_argument("--cxx", default="g++")
    parser.add_argument("--cc", default="gcc")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = qualify(ROOT, args.output, clang=args.clang, cxx=args.cxx, cc=args.cc)
    print(json.dumps({"ok": report["ok"], "cases_per_version": report["case_count_per_version"],
                      "report": str(args.output / "report.json")}, indent=2))


if __name__ == "__main__":
    main()
