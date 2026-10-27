"""Execute composable real C++ library lifetimes through one Hepta caller.

Both exact nlohmann/json releases and real libstdc++ vector/deque are retained
foreign implementations. Every allocation failure is observed independently;
foreign noexcept termination is preserved, never called recovered.
"""
from __future__ import annotations

import argparse
import base64
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import re
import shutil
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from hepta.backend import compile_rust, emit_header
from hepta.cpp_contracts import _Generator, _validate, bridge_cpp_contracts
from hepta.pipeline import analyze_project, compiler_hash
from tools.qualify_cpp_upgrade import (FIXTURES, SENTINEL, _dependencies, _dependency_paths,
                                       _run, _runtime_dependencies, cases as first_cases,
                                       digest, locked_libraries, value_digest)

EXAMPLE = ROOT / "examples/cpp/composed"
PROTOCOL = {
    "schema": "hepta.cpp-composed-protocol.v1", "versions": ["3.11.3", "3.12.0"],
    "pipelines": ["std::vector -> copied element -> std::deque",
                  "JSON Document -> copied sum -> JSON Document -> copied sum -> std::vector"],
    "routes": ["independent direct C++", "C caller -> Hepta -> generated C++ pipeline"],
    "upgrade": "unchanged contract, adapter, consumer and harness",
    "failure_denominator": "each route/pipeline calibrated on its actual binary before isolated injection at every observed site",
    "failure_acceptance": "caught exception must preserve output, restore allocation baseline and recover; SIGABRT retained as unqualified foreign noexcept recovery",
    "mutation_controls": ["native method signature mismatch", "generated wrong result", "actual missing destructor"],
    "cost": "source changes and observed generate/build/execute time; human effort and agent cost unmeasured",
}


def vector_cases():
    result = []
    for count in (0, 1, 2, 8, 31):
        for index in sorted({0, count, count + 1}):
            for other_count, other_index in ((0, 0), (1, 0), (3, 2), (3, 3)):
                result.append({"count": count, "initial": -7, "appended": 23, "index": index,
                               "other_count": other_count, "other_index": other_index})
    return result


def json_cases():
    result = [{"first": c["text"], "second": '{"values":[2,4,6,8]}',
               "index": c["index"], "replacement": c["value"], "count": 3, "final_index": 1}
              for c in first_cases()]
    for second in ('', '{', 'null', '{}', '{"values":[]}', '{"values":[true]}',
                   '{"values":[1.5]}', '{"values":[1000001]}', '{"values":[2,4,6]}'):
        result.append({"first": '{"values":[1,2,3]}', "second": second,
                       "index": 1, "replacement": 5, "count": 3, "final_index": 1})
    for count, index in ((0, 0), (1, 0), (1, 1), (64, 63), (64, 64)):
        result.append({"first": '{"values":[1,2,3]}', "second": '{"values":[2,4,6]}',
                       "index": 1, "replacement": 5, "count": count, "final_index": index})
    return result


def expected():
    output = {}
    for kind, inputs in (("vector_cases", vector_cases()), ("json_cases", json_cases())):
        rows = []
        for number, case in enumerate(inputs):
            status, value = 0, SENTINEL
            try:
                if kind == "vector_cases":
                    values = [case["initial"]] * case["count"] + [case["appended"]]
                    copied = values[case["index"]]
                    value = ([copied] * case["other_count"])[case["other_index"]]
                else:
                    def document(text):
                        obj = json.loads(text)
                        if type(obj) is not dict or type(obj.get("values")) is not list:
                            raise ValueError("object/array required")
                        values = obj["values"]
                        if len(values) > 64 or any(type(x) is not int or abs(x) > 1000000 for x in values):
                            raise ValueError("bounded integer array")
                        return values
                    first = document(case["first"])
                    if abs(case["replacement"]) > 1000000:
                        raise ValueError("replacement range")
                    first[case["index"]] = case["replacement"]
                    copied = sum(first)
                    second = document(case["second"])
                    if abs(copied) > 1000000:
                        raise ValueError("intermediate replacement range")
                    second[case["index"]] = copied
                    value = ([sum(second)] * case["count"])[case["final_index"]]
            except (ValueError, TypeError, IndexError):
                status, value = 3, SENTINEL
            rows.append({"id": number, "direct_status": status, "direct_value": value,
                         "hepta_status": status, "hepta_value": value, "live_delta": 0})
        output[kind] = rows
    return output


def case_header():
    text = "#pragma once\nstruct VectorCase {std::size_t count; std::int64_t initial,appended; std::size_t index,other_count,other_index;};\n"
    text += "struct JsonCase {const char* first; const char* second; std::size_t index; std::int64_t replacement; std::size_t count,final_index;};\n"
    text += "constexpr VectorCase vector_cases[]={\n"
    text += "".join("{" + ",".join(str(c[k]) for k in ("count", "initial", "appended", "index", "other_count", "other_index")) + "},\n" for c in vector_cases())
    text += "};\nconstexpr JsonCase json_cases[]={\n"
    text += "".join("{" + ",".join((json.dumps(c["first"]), json.dumps(c["second"]),
                                   *(str(c[k]) for k in ("index", "replacement", "count", "final_index")))) + "},\n" for c in json_cases())
    return text + "};\n"


def source_inputs():
    paths = [Path(__file__), ROOT / "hepta/cpp_contracts.py", ROOT / "examples/cpp/upgrade/adapter.hpp",
             *EXAMPLE.iterdir(), *FIXTURES.rglob("*")]
    return {str(p): digest(p) for p in sorted(paths) if p.is_file()}


def _flags(directory):
    return ["-std=c++20", "-O2", "-fPIC", "-pthread", "-Werror",
            "-I" + str(directory), "-I" + str(directory / "bridge")]


def _compile(compiler, source, directory, row, stage):
    obj = directory / (stage + ".o")
    dep = directory / (stage + ".d")
    _run([compiler, *_flags(directory), "-MD", "-MF", dep, "-c", source, "-o", obj],
         owner=row, directory=directory, stage=stage)
    row.setdefault("compile_dependencies", {})[stage] = {p: digest(p) for p in _dependency_paths(dep.read_text())}
    return obj


def _check_rows(observed):
    wanted = expected()
    return all(value_digest(observed.get(kind)) == value_digest(rows) for kind, rows in wanted.items())


def qualify(directory, *, cxx="g++", rustc=None):
    work = Path(directory).absolute()
    if work.exists():
        raise ValueError("Composed C++ qualification directory must be new")
    work.mkdir(parents=True)
    report = {"schema": "hepta.cpp-composed-qualification.v1", "ok": False,
              "protocol": PROTOCOL, "protocol_sha256": value_digest(PROTOCOL),
              "versions": [], "negative_controls": [], "source_before": source_inputs(),
              "compiler_hash_before": compiler_hash(),
              "claims": {"foreign_cpp_implementation_rewritten": False,
                         "native_implementation_migrations": 0, "bridge_upgrade_variants": 0,
                         "whole_library_memory_safety_proved": False,
                         "all_allocation_failure_paths_recovered": False,
                         "general_upgrade_compatibility_proved": False,
                         "total_development_cost_measured": False},
              "case_denominators_per_version": {k: len(v) for k, v in expected().items()}}
    def checkpoint():
        (work / "qualification.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    compiler = shutil.which(cxx)
    native_rustc = shutil.which(rustc or "rustc")
    try:
        if not compiler or not native_rustc:
            raise ValueError("C++ and pinned Rust compilers are required")
        rows = locked_libraries()
        report["locked_upstream_libraries"] = rows
        (work / "protocol.json").write_text(json.dumps(PROTOCOL, indent=2, sort_keys=True) + "\n")
        (work / "expected.json").write_text(json.dumps(expected(), indent=2, sort_keys=True) + "\n")
        for locked in rows:
            row = {"version": locked["version"], "ok": False, "processes": [], "allocation_failures": []}
            report["versions"].append(row)
            version = work / locked["version"]
            version.mkdir()
            started = time.monotonic()
            try:
                header = version / "selected.hpp"
                header.write_text("#pragma once\n#include " + json.dumps(str(FIXTURES / locked["header"])) +
                                  "\n#include " + json.dumps(str(EXAMPLE / "foreign.hpp")) + "\n")
                (version / "cases.hpp").write_text(case_header())
                row["dependencies_before"] = _dependencies(compiler, header, owner=row, directory=version, stage="headers_before")
                step = time.monotonic()
                bridge = bridge_cpp_contracts(header, EXAMPLE / "contract.json", version / "bridge", cxx=compiler, rustc=native_rustc)
                row["bridge_generation"] = bridge
                row["bridge_generation_seconds"] = time.monotonic() - step
                if not bridge["ok"]:
                    raise AssertionError("Pipeline bridge generation rejected")
                consumer = version / "bridge/consumer.hepta"
                shutil.copyfile(EXAMPLE / "consumer.hepta", consumer)
                step = time.monotonic()
                checked = analyze_project(consumer, rustc=native_rustc, crate_type="staticlib")
                row["consumer_check"] = checked.report
                if not checked.report["ok"]:
                    raise AssertionError("Hepta pipeline caller rejected")
                (version / "consumer.rs").write_text(checked.rust)
                exports = replace(checked.program, functions=[fn for fn in checked.program.functions if fn.export_c])
                (version / "bridge/hepta.h").write_text(emit_header(exports))
                library = version / "consumer.a"
                built = compile_rust(checked.rust, output=library, crate_type="staticlib", rustc=native_rustc)
                row["consumer_build"] = built
                if not built["ok"]:
                    raise AssertionError("Hepta pipeline caller native build rejected")
                row["hepta_check_build_seconds"] = time.monotonic() - step
                step = time.monotonic()
                bridge_obj = _compile(compiler, version / "bridge/bridge.cpp", version, row, "bridge")
                harness_obj = _compile(compiler, EXAMPLE / "harness.cpp", version, row, "harness")
                binary = version / "composed"
                _run([compiler, bridge_obj, harness_obj, library, "-pthread", "-ldl", "-lm", "-o", binary],
                     owner=row, directory=version, stage="link")
                row["cpp_compile_link_seconds"] = time.monotonic() - step
                execution = _run([binary], owner=row, directory=version, stage="normal")
                row["observed"] = json.loads(execution["stdout"])
                if (row["observed"].get("version") != locked["version"] or not _check_rows(row["observed"])
                        or row["observed"].get("pointer_guards") != 2 or row["observed"].get("ordinary_live_delta") != 0):
                    raise AssertionError("Actual native pipeline results differ from independent oracle")
                for kind in (0, 1):
                    for route in (0, 1):
                        prefix = "fault_" + str(kind) + "_" + str(route)
                        calibration = _run([binary, "--calibrate", str(kind), str(route)], owner=row, directory=version, stage=prefix + "_calibrate")
                        observed = json.loads(calibration["stdout"])
                        if (observed.get("kind") != kind or observed.get("route") != route
                                or type(observed.get("sites")) is not int or not 0 < observed["sites"] < 256
                                or observed.get("value") != (17 if kind else 11) or observed.get("live_delta") != 0):
                            raise AssertionError("Allocation calibration differs")
                        failure = {"pipeline": kind, "route": route, "calibration": observed,
                                   "sites": [{"site": i, "status": "not_started"} for i in range(1, observed["sites"] + 1)]}
                        row["allocation_failures"].append(failure)
                        checkpoint()
                        for site in failure["sites"]:
                            run = _run([binary, "--fault", str(kind), str(route), str(site["site"])], owner=row,
                                       directory=version, stage=prefix + "_" + str(site["site"]), allow_failure=True)
                            site["exit_code"] = run["exit_code"]
                            if run["exit_code"] == 0:
                                value = json.loads(run["stdout"])
                                if value != {"site": site["site"], "status": 3, "live_delta": 0,
                                             "output_preserved": True, "recovered": True}:
                                    raise AssertionError("Catchable refusal failed cleanup or recovery")
                                site.update(status="caught_recovered", recovery_qualified=True)
                            elif run["exit_code"] == -6 and "bad_alloc" in run["stderr"]:
                                site.update(status="foreign_noexcept_termination", recovery_qualified=False)
                            else:
                                site.update(status="unexpected_failure", recovery_qualified=False)
                                raise AssertionError("Unexpected allocation fault outcome")
                            checkpoint()
                row["dependencies_after"] = _dependencies(compiler, header, owner=row, directory=version, stage="headers_after")
                if row["dependencies_before"]["files"] != row["dependencies_after"]["files"]:
                    raise AssertionError("Native header dependency bytes changed")
                row["runtime_dependencies"] = _runtime_dependencies(binary, owner=row, directory=version, ldd=shutil.which("ldd"))
                nm = _run([shutil.which("nm"), "-g", "--defined-only", bridge_obj], owner=row, directory=version, stage="exports")
                actual_symbols = sorted({line.split()[-1] for line in nm["stdout"].splitlines()
                                         if line.split() and line.split()[-1].startswith("hepta_cpp_composed_")})
                public = sorted(re.findall(r"\b(hepta_cpp_composed_\w+)\(", (version / "bridge/bridge.h").read_text()))
                if actual_symbols != public:
                    raise AssertionError("Actual bridge C ABI symbols differ from generated declarations")
                row["export_symbols"] = actual_symbols
                row["artifacts"] = {str(p): digest(p) for p in (header, version / "cases.hpp", version / "consumer.rs", library,
                    version / "bridge/bridge.cpp", version / "bridge/bridge.h", version / "bridge/bridge.hepta",
                    consumer, version / "bridge/hepta.h", bridge_obj, harness_obj, binary)}
                row["ok"] = True
                report["claims"]["bridge_upgrade_variants"] += 1
            except (OSError, RuntimeError, ValueError, AssertionError) as exc:
                row["error"] = str(exc)
            finally:
                row["total_seconds"] = time.monotonic() - started
                checkpoint()
        if not all(row["ok"] for row in report["versions"]):
            raise AssertionError("At least one real-library variant did not complete")
        directories = [work / item["version"] for item in rows]
        for name in ("bridge.h", "bridge.hepta"):
            if (directories[0] / "bridge" / name).read_bytes() != (directories[1] / "bridge" / name).read_bytes():
                raise AssertionError("Public API bytes changed across frozen library versions")
        normalized = [(directory / "bridge/bridge.cpp").read_text().replace(str(directory), "<selected-version>") for directory in directories]
        if normalized[0] != normalized[1] or report["versions"][0]["export_symbols"] != report["versions"][1]["export_symbols"]:
            raise AssertionError("Generated implementation or native C exports changed across upgrade")
        report["upgrade"] = {"authored_contract_adapter_consumer_changes": 0,
                             "public_api_and_native_c_exports_unchanged": True,
                             "generated_cpp_equal_except_selected_header_path": True,
                             "human_review_hours": None, "agent_tokens": None}
        # Real rejected native type and executable mutation controls, separate
        # from the positive two-version denominator.
        negative = work / "negative"
        negative.mkdir()
        changed = json.loads((EXAMPLE / "contract.json").read_text())
        changed["handles"][-1]["methods"][-1]["cpp_method"] = "sum_does_not_exist"
        rejected = bridge_cpp_contracts(directories[-1] / "selected.hpp", changed, negative / "bad-contract",
                                        cxx=compiler, rustc=native_rustc)
        report["negative_controls"].append({"case": "native_method_mismatch", "rejection": rejected})
        if rejected["ok"]:
            raise AssertionError("Native mismatched method was accepted")
        chosen = directories[-1]
        for label, old, new in (("wrong_result", "*out = hepta_pipeline_result;", "*out = hepta_pipeline_result + 1;"),
                                ("missing_destructor", "auto hepta_pipeline_object0 = ", "auto& hepta_pipeline_object0 = *new ")):
            text = (chosen / "bridge/bridge.cpp").read_text()
            if text.count(old) != 2:
                raise AssertionError("Mutation target count changed")
            control = {"case": label, "processes": []}
            report["negative_controls"].append(control)
            mutant = negative / (label + ".cpp")
            mutant.write_text(text.replace(old, new))
            binary = negative / label
            _run([compiler, *_flags(chosen), mutant, chosen / "harness.o", chosen / "consumer.a", "-ldl", "-lm", "-o", binary],
                 owner=control, directory=negative, stage="build_" + label)
            observed = _run([binary], owner=control, directory=negative, stage="run_" + label, allow_failure=True)
            control["source_sha256"] = digest(mutant)
            control["binary_sha256"] = digest(binary)
            if label == "wrong_result":
                control["detected"] = observed["exit_code"] == 0 and not _check_rows(json.loads(observed["stdout"]))
            else:
                control["detected"] = observed["exit_code"] == 2 and "bridge leaked" in observed["stderr"]
            if not control["detected"]:
                raise AssertionError("Native pipeline mutation went undetected: " + label)
        report["source_after"] = source_inputs()
        report["compiler_hash_after"] = compiler_hash()
        if report["source_before"] != report["source_after"] or report["compiler_hash_before"] != report["compiler_hash_after"]:
            raise AssertionError("Compiler or source changed during qualification")
        faults = [site for row in report["versions"] for failure in row["allocation_failures"] for site in failure["sites"]]
        report["allocation_fault_summary"] = {"total": len(faults),
            "caught_recovered": sum(site["status"] == "caught_recovered" for site in faults),
            "foreign_noexcept_termination": sum(site["status"] == "foreign_noexcept_termination" for site in faults)}
        report["claims"]["all_allocation_failure_paths_recovered"] = all(site["recovery_qualified"] for site in faults)
        report["ok"] = True
        report["status"] = "complete_observation_with_foreign_termination" if not report["claims"]["all_allocation_failure_paths_recovered"] else "selected_composed_lifetimes_qualified"
        validate(report)
    except (OSError, RuntimeError, ValueError, AssertionError) as exc:
        report["ok"] = False
        report["error"] = str(exc)
    finally:
        checkpoint()
    return report


def validate(report):
    """Recheck retained native observations and bytes, without re-execution."""
    if (report.get("schema") != "hepta.cpp-composed-qualification.v1" or report.get("ok") is not True
            or report.get("protocol") != PROTOCOL or report.get("protocol_sha256") != value_digest(PROTOCOL)
            or [row["version"] for row in report["versions"]] != PROTOCOL["versions"]):
        raise ValueError("Incomplete composed C++ protocol identity")
    if (report["source_before"] != report["source_after"] or report["compiler_hash_before"] != report["compiler_hash_after"]
            or report["source_after"] != source_inputs()):
        raise ValueError("Composed source identity changed")
    faults = []
    for row in report["versions"]:
        if not row["ok"] or not _check_rows(row["observed"]):
            raise ValueError("Native composed results differ from oracle")
        processes = {p["stage"]: p for p in row["processes"]}
        if len(processes) != len(row["processes"]):
            raise ValueError("Duplicate native process stage")
        if value_digest(json.loads(processes["normal"]["stdout"])) != value_digest(row["observed"]):
            raise ValueError("Native case summary differs from retained execution output")
        if [(f["pipeline"], f["route"]) for f in row["allocation_failures"]] != [(0, 0), (0, 1), (1, 0), (1, 1)]:
            raise ValueError("Allocation routes missing")
        for failure in row["allocation_failures"]:
            prefix = "fault_" + str(failure["pipeline"]) + "_" + str(failure["route"])
            calibration = processes[prefix + "_calibrate"]
            if (calibration["exit_code"] != 0 or value_digest(json.loads(calibration["stdout"])) != value_digest(failure["calibration"])
                    or calibration["argv"][1:] != ["--calibrate", str(failure["pipeline"]), str(failure["route"])]):
                raise ValueError("Allocation calibration is not the retained actual native invocation")
            if [s["site"] for s in failure["sites"]] != list(range(1, failure["calibration"]["sites"] + 1)):
                raise ValueError("Allocation fault denominator changed")
            for site in failure["sites"]:
                if site["status"] not in {"caught_recovered", "foreign_noexcept_termination"}:
                    raise ValueError("Unobserved or unexpected allocation failure")
                expected_recovery = site["status"] == "caught_recovered"
                if site["recovery_qualified"] is not expected_recovery or site["exit_code"] != (0 if expected_recovery else -6):
                    raise ValueError("Foreign termination cannot be credited as recovery")
                process = processes[prefix + "_" + str(site["site"])]
                if (process["exit_code"] != site["exit_code"] or type(process["exit_code"]) is not int
                        or process["argv"] != [calibration["argv"][0], "--fault", str(failure["pipeline"]), str(failure["route"]), str(site["site"])]) :
                    raise ValueError("Fault summary differs from actual native invocation")
                if expected_recovery:
                    wanted = {"site": site["site"], "status": 3, "live_delta": 0, "output_preserved": True, "recovered": True}
                    if value_digest(json.loads(process["stdout"])) != value_digest(wanted):
                        raise ValueError("Native failure did not demonstrate cleanup and recovery")
                elif "bad_alloc" not in process["stderr"]:
                    raise ValueError("Foreign termination reason differs from retained stderr")
            faults.extend(failure["sites"])
        for path, identity in row["artifacts"].items():
            if digest(path) != identity:
                raise ValueError("Retained native artifact changed")
    for owner in [*report["versions"], *report["negative_controls"]]:
        for process in owner.get("processes", []):
            for stream in ("stdout", "stderr"):
                data = Path(process[stream + "_path"]).read_bytes()
                if (data != base64.b64decode(process[stream + "_bytes_base64"])
                        or hashlib.sha256(data).hexdigest() != process[stream + "_sha256"]
                        or data.decode("utf-8", errors="replace") != process[stream]):
                    raise ValueError("Retained native stream changed")
    if report["claims"]["all_allocation_failure_paths_recovered"] is not all(s["recovery_qualified"] for s in faults):
        raise ValueError("Allocation recovery claim differs from actual failures")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", type=Path, required=True)
    parser.add_argument("--cxx", default="g++")
    parser.add_argument("--rustc")
    args = parser.parse_args()
    result = qualify(args.workdir, cxx=args.cxx, rustc=args.rustc)
    print(json.dumps({"ok": result["ok"], "report": str(args.workdir / "qualification.json"),
                      "error": result.get("error"), "faults": result.get("allocation_fault_summary")}))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
