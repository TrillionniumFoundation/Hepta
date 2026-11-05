"""Qualify actual direct unique_ptr reset migration with an independent C caller."""
from __future__ import annotations

import argparse
from collections import Counter
import copy
from datetime import datetime, timezone
import gzip
from hashlib import sha256
import json
from pathlib import Path
import random
import re
import resource
import shutil
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from hepta.cpp_unique_reset import lower_unique_reset_project
from hepta.c_migrate import MigrationRejected
from hepta.hia_program_llvm import build_program_native
from hepta.hia_program_source import lower_source
from hepta.object_symbols import inspect_object_symbols
from hepta.pipeline import compiler_hash
from tools.evidence_checks import require, strict_equal
from tools.qualify_cpp_unique_project import WRAPPER
from tools.validate_cpp_composed import _word, case_sources, observation_oracle
from tools.validate_cpp_owned import CPP_FLAGS, WRAP_FLAGS, _identity, _process, _run

EXAMPLE = ROOT / "examples/cpp/unique_reset_migration"

SOURCE_REFUSALS = (
    ("raw_pointer_escape", "        destination.reset(source.release());",
     "        auto* escaped = source.release();\n        destination.reset(escaped);", "E_CPP_COMPOSED_TYPE"),
    ("self_adoption_from_get", "destination.reset(source.release());",
     "destination.reset(destination.get());", "E_CPP_RESET_CALL"),
    ("repeated_release", "destination.reset(destination.release());",
     "destination.reset(source.release());", "E_CPP_RESET_OWNER"),
    ("unguarded_subscript", "if (index < left) { source[index] = value; }",
     "source[index] = value;", "E_CPP_RESET_BOUNDS"),
    ("missing_capacity_guard", "        if (left > 4096) { return 4001; }\n", "", "E_CPP_RESET_CAPACITY"),
    ("continuing_owner_change", "        destination.reset(source.release());",
     "        if (reject == 2) { destination.reset(source.release()); }\n"
     "        destination.reset(source.release());", "E_CPP_RESET_JOIN"),
    ("library_macro_change", "#include <memory>",
     "#define _GLIBCXX_ASSERTIONS 1\n#include <memory>", "E_CPP_RESET_STDLIB"),
)


def oracle(raw, *, weight):
    """Independent chronological allocation identities, without reading Core."""
    left, right, value, index, reject, early, refuse_at = raw
    events, allocations, attempts, refusals = [], 0, 0, 0

    def release(owner):
        if owner is not None:
            events.append((2, *owner))

    def allocate(size):
        nonlocal allocations, attempts, refusals
        if not size:
            return None, False
        attempts += 1
        if attempts == refuse_at:
            refusals += 1
            events.append((3, attempts, size))
            return None, True
        allocations += 1
        owner = (allocations, size)
        events.append((1, *owner))
        return owner, False

    if left > 4096 or right > 4096:
        expected, family = 4001, "capacity_guard"
    else:
        source, failed = allocate(left)
        if failed:
            expected, family = 1001, "allocation_refusal_1"
        else:
            destination, failed = allocate(right)
            if failed:
                release(source)
                expected, family = 1001, "allocation_refusal_" + str(attempts)
            elif reject == 1:
                release(destination); release(source)
                expected, family = 1007, "throw_after_acquisition"
            elif early == 1:
                release(destination); release(source)
                expected, family = 2001, "early_before_reset"
            else:
                # release() nulls the source; reset() deletes the OLD target.
                # The subsequent self release/reset does not delete its resource.
                release(destination)
                destination = source
                if early == 2:
                    expected, family = 2002, "null_reset_default"
                elif early == 3:
                    expected, family = 2004, "null_reset_explicit"
                elif index >= left:
                    expected, family = 2003, "range_after_reset"
                else:
                    expected, family = value * weight + left + right, "release_reset_value"
                release(destination)
    trace = 14695981039346656037
    for event in events:
        for part in event:
            trace = _word(trace, part)
    return dict(zip(("left", "right", "value", "index", "reject", "early", "refuse_at"), raw),
        expected=expected, allocated=allocations, refusals=refusals, trace=trace,
        family=family, events=[list(event) for event in events])


def cases(weight):
    # First vector makes the independently mutated exception cleanup order observable.
    raw = [(3, 5, 7, 0, 1, 0, 0)]
    for left, right in ((0, 0), (0, 3), (3, 0), (1, 1), (3, 5), (257, 513), (4096, 4096)):
        for value in (0, 255):
            for index in sorted({0, max(left - 1, 0), left, left + 1}):
                for reject in (0, 1):
                    for early in (0, 1, 2, 3):
                        for refuse in (0, 1, 2):
                            raw.append((left, right, value, index, reject, early, refuse))
    for left, right in ((4097, 0), (0, 4097), (2**64 - 1, 1), (1, 2**64 - 1)):
        for refuse in (0, 1, 2):
            raw.append((left, right, 255, 2**64 - 1, 1, 3, refuse))
    rng = random.Random(0xC105ED)
    for _ in range(128):
        left, right = rng.randrange(4097), rng.randrange(4097)
        raw.append((left, right, rng.randrange(256), rng.randrange(left + 2),
                    rng.randrange(3), rng.randrange(5), rng.randrange(4)))
    return [oracle(row, weight=weight) for row in raw]


def bindings(*, reusable_released_owners=False, owner_swaps=False):
    paths = [Path(__file__), ROOT / "hepta/cpp_unique_reset.py", ROOT / "hepta/cpp_unique_project.py",
             ROOT / "hepta/cpp_unique_capture.py", ROOT / "hepta/cpp_composed_migrate.py",
             ROOT / "tools/validate_cpp_composed.py", ROOT / "tools/validate_cpp_owned.py",
             ROOT / "tools/qualify_cpp_unique_project.py", ROOT / "tools/evidence_checks.py",
             *EXAMPLE.iterdir()]
    if reusable_released_owners:
        paths.extend([ROOT / "tools/qualify_cpp_unique_reuse.py",
                      * (ROOT / "examples/cpp/unique_reuse_migration").iterdir()])
    if owner_swaps:
        paths.extend([ROOT / "tools/qualify_cpp_unique_swap.py",
                      * (ROOT / "examples/cpp/unique_swap_migration").iterdir()])
    return {str(path.relative_to(ROOT)): sha256(path.read_bytes()).hexdigest()
            for path in paths if path.is_file()}


def command(records, argv, *, expected=0):
    started = time.perf_counter_ns()
    observation = _run(argv)
    observation["wall_ns"] = time.perf_counter_ns() - started
    records.append(observation)
    _process(observation, expected)
    return observation


def reference_wrapper(name):
    return f'''#include <cstddef>
#include <cstdint>
unsigned long long {name}(unsigned long, unsigned long, unsigned char,
                          unsigned long, unsigned int, unsigned int) noexcept;
extern "C" std::uint64_t composed_case(std::size_t left, std::size_t right, std::uint8_t value,
    std::size_t index, std::uint32_t reject, std::uint32_t early) noexcept {{
    return {name}(left, right, value, index, reject, early);
}}
'''


def qualify(directory, *, clangxx="clang++", clang="clang", cc="gcc", reusable_released_owners=False,
            owner_swaps=False):
    work = Path(directory).absolute()
    if work.exists():
        raise ValueError("A new reset qualification directory is required")
    work.mkdir(parents=True)
    started = time.perf_counter_ns()
    before, inputs = compiler_hash(), bindings(reusable_released_owners=reusable_released_owners,
                                               owner_swaps=owner_swaps)
    example = (ROOT / "examples/cpp/unique_swap_migration" if owner_swaps else
               ROOT / "examples/cpp/unique_reuse_migration" if reusable_released_owners else EXAMPLE)
    if owner_swaps:
        from tools.qualify_cpp_unique_swap import cases as selected_cases
    elif reusable_released_owners:
        from tools.qualify_cpp_unique_reuse import cases as selected_cases
    else:
        selected_cases = cases
    report = {"schema": ("hepta.cpp-unique-swap-native-qualification.v3" if owner_swaps else
                         "hepta.cpp-unique-reuse-native-qualification.v2" if reusable_released_owners else "hepta.cpp-unique-reset-native-qualification.v1"), "ok": False,
        "started_utc": datetime.now(timezone.utc).isoformat(), "compiler_sha256": before,
        "source_bindings": inputs, "variants": [], "negative_controls": {},
        "costs": {"human_engineering_seconds": None, "performance_comparison_performed": False},
        "claims": {"actual_component_translated_from_clang_ast": True,
            "independent_c_abi_caller_for_both_implementations": True,
            "original_cpp_objects_in_hia_target": False, "whole_cpp_supported": False,
            "standard_library_implementation_migrated": False, "whole_cpp_abi_preserved": False,
            "source_equivalence_formally_proved": False, "real_upstream_library_upgrade_tested": False,
            "maintenance_variant_is_authored_project_api_change": True,
            "abort_process_crash_recovery_tested": False, "performance_advantage_proved": False}}
    try:
        for name, weight, function in (("original", 3, "run_reset"), ("api_maintenance", 5, "run_reset_v2")):
            target = work / name; target.mkdir()
            project = target / "project"; shutil.copytree(example, project)
            if name == "api_maintenance":
                component = project / "component.cpp"
                text = component.read_text().replace("run_reset(", "run_reset_v2(")
                require(text.count("]) * 3 +") == 1, "Expected actual source algorithm multiplier")
                component.write_text(text.replace("]) * 3 +", "]) * 5 +"))
            row = {"name": name, "costs": {}, "reference": {"commands": []},
                "standalone_hia": {"commands": [], "original_cpp_link_inputs": []}}
            report["variants"].append(row)
            migration = lower_unique_reset_project(project / "compile_commands.json", clangxx=clangxx,
                reusable_released_owners=reusable_released_owners, owner_swaps=owner_swaps)
            # Preserve the complete 46k+ library census without repeatedly
            # inflating the main report. This is lossless evidence storage.
            library = migration.pop("standard_library_declarations")
            census = json.dumps(library, sort_keys=True, separators=(",", ":")).encode()
            census_path = target / "standard-library-census.json.gz"
            census_path.write_bytes(gzip.compress(census, compresslevel=9, mtime=0))
            migration["standard_library_declaration_count"] = len(library)
            migration["standard_library_census"] = {**_identity(census_path),
                "uncompressed_sha256": sha256(census).hexdigest(), "uncompressed_bytes": len(census),
                "declarations": len(library), "format": "gzip-compressed canonical JSON"}
            row["migration"] = {key: value for key, value in migration.items() if key != "program"}
            require(migration["project_function"] == function, "Captured API name differs")
            source = migration["source"] + WRAPPER
            (target / "migrated.hepta").write_text(source)
            vectors = selected_cases(weight); expected = observation_oracle(vectors)
            row.update(case_count=len(vectors), expected=expected,
                       families=dict(Counter(case["family"] for case in vectors)))
            (target / "cases.json").write_text(json.dumps(vectors, indent=2) + "\n")
            (target / "cases.h").write_text(case_sources(vectors)[0])
            (target / "reference.cpp").write_text(reference_wrapper(function))
            commands = row["reference"]["commands"]
            build_start = time.perf_counter_ns()
            original_objects = []
            for path in (project / "component.cpp", project / "allocator.cpp", target / "reference.cpp"):
                obj = target / (path.stem + ".cpp.o"); original_objects.append(obj)
                command(commands, [clangxx, *CPP_FLAGS, "-c", str(path), "-o", str(obj)])
            caller = target / "reference-c-caller.o"
            command(commands, [cc, "-std=c11", "-O2", "-fno-lto", "-DREFERENCE_CPP", "-I" + str(target),
                               "-c", str(project / "harness.c"), "-o", str(caller)])
            reference = target / "cpp-reference"
            command(commands, ["g++", *CPP_FLAGS, *map(str, original_objects), str(caller), "-o", str(reference)])
            row["costs"]["reference_build_wall_ns"] = time.perf_counter_ns() - build_start
            observation = command(commands, [str(reference)])
            row["reference"].update(execution=observation, c_caller=_identity(caller),
                linked_original_objects=[_identity(path) for path in original_objects], artifact=_identity(reference))
            require(strict_equal(json.loads(observation["stdout"]), expected), "Original C++ differs from independent oracle")
            native = row["standalone_hia"]; build_start = time.perf_counter_ns()
            program = lower_source(source, path=str(target / "migrated.hepta"))
            document = program.as_dict()
            (target / "standalone.core.json").write_text(json.dumps(document, indent=2) + "\n")
            obj, binary = target / "standalone.o", target / "hia-native"
            native["build"] = build_program_native(document, obj, clang=clang, kind="object")
            symbols = inspect_object_symbols(obj.read_bytes(), "ELF64", 62)
            require("composed_case" in symbols["defined"] and symbols["undefined"] <= frozenset(
                {"malloc", "calloc", "free", "memset", "abort"}), "Target imports unaccounted original implementation")
            native["symbols"] = {key: sorted(value) for key, value in symbols.items()}
            command(native["commands"], [cc, "-std=c11", "-O2", "-fno-lto", *WRAP_FLAGS, "-I" + str(target),
                                        str(project / "harness.c"), str(obj), "-o", str(binary)])
            row["costs"]["hia_source_core_native_build_wall_ns"] = time.perf_counter_ns() - build_start
            observation = command(native["commands"], [str(binary)])
            native.update(execution=observation, artifact=_identity(binary))
            require(strict_equal(json.loads(observation["stdout"]), expected), "Standalone HIA differs from independent oracle")
            row["costs"]["native_execution_checks_wall_ns"] = (
                row["reference"]["execution"]["wall_ns"] + observation["wall_ns"])
            # A resource-safe, behaviorally incorrect mutation must still be caught.
            match = re.search(r"(?P<indent> +)drop\(move (?P<a>owner\d+)\);\n(?P=indent)drop\(move (?P<b>owner\d+)\);", source)
            require(match is not None, "Expected actual two-owner exception cleanup")
            replacement = (match["indent"] + "drop(move " + match["b"] + ");\n" +
                           match["indent"] + "drop(move " + match["a"] + ");")
            wrong = source[:match.start()] + replacement + source[match.end():]
            wrong_path = target / "wrong-cleanup-order.hepta"; wrong_path.write_text(wrong)
            wrong_object, wrong_binary = target / "wrong-order.o", target / "wrong-order"
            control = {"commands": [], "scope": "deliberately_mutated_generated_source", "detected": False}
            report["negative_controls"][name + "_wrong_cleanup_order"] = control
            control["build"] = build_program_native(lower_source(wrong, path=str(wrong_path)).as_dict(),
                                                     wrong_object, clang=clang, kind="object")
            control["resource_check_passed"] = True
            command(control["commands"], [cc, "-std=c11", "-O2", "-fno-lto", *WRAP_FLAGS, "-I" + str(target),
                                           str(project / "harness.c"), str(wrong_object), "-o", str(wrong_binary)])
            observation = command(control["commands"], [str(wrong_binary)], expected=3)
            result = json.loads(observation["stdout"])
            require(result.get("failure") == "lifecycle" and result.get("case") == 0 and result.get("live") == 0,
                    "Oracle failed to distinguish safety from source lifecycle equivalence")
            control.update(detected=True, execution=observation, artifact=_identity(wrong_binary))
            # A malformed linear target is refused before any artifact is published.
            malformed = copy.deepcopy(document); changed = False
            for func in malformed["functions"]:
                for block in func["blocks"]:
                    for index, operation in enumerate(block["ops"]):
                        if operation["op"] == "owner.drop":
                            del block["ops"][index]; changed = True; break
                    if changed: break
                if changed: break
            require(changed, "No actual owner drop for safety negative control")
            refused = target / "missing-drop.o"
            try:
                build_program_native(malformed, refused, clang=clang, kind="object")
            except ValueError as error:
                report["negative_controls"][name + "_missing_drop"] = {
                    "rejected": True, "diagnostic": str(error), "artifact_exists": refused.exists()}
                require(not refused.exists(), "Invalid Core was partially published")
            else:
                raise ValueError("Missing owner drop accepted")
        require(report["variants"][0]["expected"]["observations_fnv64"] !=
                report["variants"][1]["expected"]["observations_fnv64"], "Actual source/API change must alter observed results")
        require(compiler_hash() == before and bindings(reusable_released_owners=reusable_released_owners,
                                                     owner_swaps=owner_swaps) == inputs,
                "Source/compiler changed during qualification")
        report.update(ok=True, source_bindings_unchanged=True)
    except Exception as error:
        report["error"] = {"kind": type(error).__name__, "message": str(error)}
    report["finished_utc"] = datetime.now(timezone.utc).isoformat()
    report["costs"].update(complete_qualification_wall_ns=time.perf_counter_ns() - started,
        process_peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        child_peak_rss_kib=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss)
    (work / "qualification.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def qualify_source_refusals(directory, *, clangxx="clang++"):
    """Fresh Clang capture of each actual changed source, never AST replay."""
    work = Path(directory).absolute()
    if work.exists():
        raise ValueError("A new source-refusal directory is required")
    work.mkdir(parents=True)
    started = time.perf_counter_ns()
    before, inputs = compiler_hash(), bindings()
    report = {"schema": "hepta.cpp-unique-reset-source-refusals.v1", "ok": False,
        "started_utc": datetime.now(timezone.utc).isoformat(), "compiler_sha256": before,
        "source_bindings": inputs, "controls": [], "human_engineering_seconds": None}
    try:
        for name, original, replacement, code in SOURCE_REFUSALS:
            project = work / name; shutil.copytree(EXAMPLE, project)
            source = project / "component.cpp"; text = source.read_text()
            require(text.count(original) == 1, "Negative mutation must select exactly one actual source fragment")
            source.write_text(text.replace(original, replacement))
            control = {"name": name, "source": _identity(source), "expected_code": code,
                       "rejected": False, "fresh_clang_capture": True}
            report["controls"].append(control)
            start = time.perf_counter_ns()
            try:
                lower_unique_reset_project(project / "compile_commands.json", clangxx=clangxx)
            except MigrationRejected as error:
                control.update(rejected=True, diagnostic=str(error), code=error.code,
                               wall_ns=time.perf_counter_ns() - start)
                require(error.code == code, "Source refused at an unexpected gate: " + name)
            else:
                raise ValueError("Unsupported source was accepted: " + name)
        require(compiler_hash() == before and bindings() == inputs, "Compiler/source changed during source refusals")
        report.update(ok=True, source_bindings_unchanged=True)
    except Exception as error:
        report["error"] = {"kind": type(error).__name__, "message": str(error)}
    report["finished_utc"] = datetime.now(timezone.utc).isoformat()
    report["complete_qualification_wall_ns"] = time.perf_counter_ns() - started
    (work / "qualification.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", required=True)
    parser.add_argument("--clangxx", default="clang++")
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--cc", default="gcc")
    parser.add_argument("--source-refusals-only", action="store_true")
    args = parser.parse_args()
    if args.source_refusals_only:
        report = qualify_source_refusals(args.workdir, clangxx=args.clangxx)
        print(json.dumps(report))
        return 0 if report["ok"] else 1
    report = qualify(args.workdir, clangxx=args.clangxx, clang=args.clang, cc=args.cc)
    print(json.dumps({"ok": report["ok"], "error": report.get("error"), "variants": [
        {key: row.get(key) for key in ("name", "case_count", "expected", "costs")} for row in report["variants"]],
        "costs": report["costs"]}))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

