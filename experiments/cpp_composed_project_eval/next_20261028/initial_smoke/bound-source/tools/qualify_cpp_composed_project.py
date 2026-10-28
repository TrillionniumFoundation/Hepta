"""Native multi-configuration, multi-TU C++ ownership migration to standalone HIA."""
from __future__ import annotations

import argparse
from collections import Counter
import copy
from hashlib import sha256
import json
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from hepta.cpp_composed_project import lower_composed_matrix
from hepta.hia_program_llvm import build_program_native
from hepta.hia_program_source import lower_source
from hepta.object_symbols import inspect_object_symbols
from hepta.pipeline import compiler_hash
from tools.evidence_checks import require, strict_equal
from tools.validate_cpp_composed import (cases as pair_cases, case_sources, observation_oracle,
                                        EXAMPLE as HARNESS)
from tools.validate_cpp_owned import CPP_FLAGS, WRAP_FLAGS, _identity, _process, _run

EXAMPLE = ROOT / "examples/cpp/composed_project_migration"
WRAPPER = '''
pub fn composed_case(left: usize, right: usize, value: u8, index: usize, reject: u32, early: u32) -> u64 effects {alloc, block, panic, write} {
    return translated_run(left, right, value, index, reject, early);
}
'''
REFERENCE = '''#include "owners.h"
extern "C" unsigned long long composed_case(unsigned long left, unsigned long right, unsigned char value,
    unsigned long index, unsigned int reject, unsigned int early) noexcept {
    return run_pair(left, right, value, index, reject, early);
}
'''


def cases(variant):
    vectors = copy.deepcopy(pair_cases("pair"))
    weight, mask = {"three_weight": (3, 37), "five_weight": (5, 11)}[variant]
    for row in vectors:
        if row["family"] == "borrowed_read_success":
            left = row["value"] ^ 91 if row["index"] == 0 else row["value"]
            row["expected"] = (left * weight + (row["value"] ^ mask) + row["left"] + row["right"]) % 2**64
    return vectors


def command(record, key, argv, expected_code=0):
    observation = _run(argv)
    if key is None:
        record.append(observation)
    else:
        record[key] = observation
    _process(observation, expected_code)
    return observation


def qualify(directory, *, clangxx="clang++", clang="clang", cc="gcc"):
    work = Path(directory).absolute()
    if work.exists():
        raise ValueError("A new project qualification directory is required")
    work.mkdir(parents=True)
    start = compiler_hash()
    report = {"schema": "hepta.cpp-composed-project-native-qualification.v1", "ok": False,
              "compiler_sha256": start, "variants": [], "negative_controls": {},
              "claims": {"original_cpp_objects_in_target": False, "scalar_c_abi_preserved": True,
                         "cpp_class_or_mangled_abi_preserved": False, "all_builds_in_declared_matrix_executed": False,
                         "general_cpp_ownership_supported": False, "source_equivalence_formally_proved": False,
                         "performance_qualified": False}}
    try:
        project = work / "project"
        shutil.copytree(EXAMPLE, project)
        migrated = lower_composed_matrix(project / "matrix.json", clangxx=clangxx)
        report["capture"] = migrated["capture"]
        report["source_bindings"] = {str(path.relative_to(ROOT)): sha256(path.read_bytes()).hexdigest()
                                     for path in [ROOT / "hepta/cpp_composed_project.py", Path(__file__), *EXAMPLE.iterdir()] if path.is_file()}
        report["project_inputs"] = {path.name: _identity(path) for path in project.iterdir() if path.is_file()}
        for number, variant in enumerate(migrated["variants"], 1):
            name = variant["name"]
            target = work / name; target.mkdir()
            row = {"name": name, "migration": {key: value for key, value in variant.items() if key != "program"},
                   "reference": {"commands": []}, "standalone_hia": {"original_cpp_link_inputs": [], "commands": []}}
            report["variants"].append(row)
            vectors = cases(name); expected = observation_oracle(vectors)
            row.update(case_count=len(vectors), expected=expected, families=dict(Counter(v["family"] for v in vectors)))
            (target / "cases.json").write_text(json.dumps(vectors, indent=2) + "\n")
            (target / "cases.h").write_text(case_sources(vectors)[0])
            (target / "reference.cpp").write_text(REFERENCE)
            flags = [*CPP_FLAGS, "-DPROJECT_VARIANT=" + str(number), "-I" + str(project)]
            cpp_objects = []
            for source in (project / "entry.cpp", project / "consume.cpp", target / "reference.cpp"):
                obj = target / (source.stem + ".cpp.o"); cpp_objects.append(obj)
                command(row["reference"]["commands"], None, [clangxx, *flags, "-c", str(source), "-o", str(obj)])
            harness_obj = target / "reference-harness.o"
            command(row["reference"]["commands"], None, [clangxx, *CPP_FLAGS, "-x", "c++", "-I" + str(target),
                                                         "-c", str(HARNESS / "harness.c"), "-o", str(harness_obj)])
            reference_binary = target / "cpp-reference"
            command(row["reference"]["commands"], None, ["g++", *CPP_FLAGS, *map(str, cpp_objects), str(harness_obj), "-o", str(reference_binary)])
            command(row["reference"], "execution", [str(reference_binary)])
            require(strict_equal(json.loads(row["reference"]["execution"]["stdout"]), expected), "Original separate C++ objects differ from oracle")
            row["reference"]["linked_original_objects"] = [_identity(obj) for obj in cpp_objects]
            # Only source-derived Hepta is combined for this target. The HIA
            # compiler consumes the standalone Core document without C++ ASTs.
            source = variant["source"] + WRAPPER
            (target / "migrated.hepta").write_text(source)
            program = lower_source(source, path=str(target / "migrated.hepta"))
            document = program.as_dict()
            (target / "standalone.core.json").write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
            obj, binary = target / "standalone.o", target / "hia-native"
            native = row["standalone_hia"]
            native["build"] = build_program_native(document, obj, clang=clang, kind="object")
            symbols = inspect_object_symbols(obj.read_bytes(), "ELF64", 62)
            require("composed_case" in symbols["defined"]
                    and symbols["undefined"] <= frozenset({"malloc", "calloc", "free", "memset", "abort"}),
                    "Standalone HIA imported unaccounted original code")
            native["symbols"] = {key: sorted(value) for key, value in symbols.items()}
            command(native["commands"], None, [cc, "-std=c11", "-O2", "-fno-lto", *WRAP_FLAGS,
                                               "-I" + str(target), str(HARNESS / "harness.c"), str(obj), "-o", str(binary)])
            command(native, "execution", [str(binary)])
            require(strict_equal(json.loads(native["execution"]["stdout"]), expected), "Standalone HIA values/allocations/cleanup differ from oracle")
            native["artifact"] = _identity(binary)
            require(row["migration"]["unconverted_declarations"] == [] and row["migration"]["translation_statistics"]["cross_unit_owner_transfers"] > 0,
                    "Cross-TU source ownership transfer was not inventoried")
            # Compile a deliberately leaking actual standalone Core. Its
            # verified resource checker must refuse rather than run fallback.
            malformed = copy.deepcopy(document)
            changed = False
            for function in malformed["functions"]:
                for block in function["blocks"]:
                    for index, operation in enumerate(block["ops"]):
                        if operation["op"] == "owner.drop":
                            del block["ops"][index]
                            changed = True
                            break
                    if changed:
                        break
                if changed:
                    break
            require(changed, "No actual linear drop found for negative control")
            refused_path = target / "unreleased.o"
            try:
                build_program_native(malformed, refused_path, clang=clang, kind="object")
            except ValueError as error:
                report["negative_controls"][name + "_missing_drop"] = {"rejected": True, "diagnostic": str(error), "artifact_exists": refused_path.exists()}
                require(not refused_path.exists(), "Unsafe target was partially published")
            else:
                raise ValueError("Missing linear owner drop was accepted")
        report["claims"]["all_builds_in_declared_matrix_executed"] = True
        require(compiler_hash() == start, "Compiler changed during project qualification")
        report["ok"] = True
    except Exception as error:
        report["error"] = {"kind": type(error).__name__, "message": str(error)}
    (work / "qualification.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", required=True)
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--clangxx", default="clang++")
    parser.add_argument("--cc", default="gcc")
    args = parser.parse_args()
    report = qualify(args.workdir, clang=args.clang, clangxx=args.clangxx, cc=args.cc)
    print(json.dumps({"ok": report["ok"], "error": report.get("error"), "variants": [
        {key: row.get(key) for key in ("name", "case_count", "expected")} for row in report["variants"]]}))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
