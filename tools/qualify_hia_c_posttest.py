#!/usr/bin/env python3
"""Retain same-source captured C post-test application and resource evidence.

The existing Ring-Buffer/musl project remains the input. Only its explicitly
authored checksum integration TU receives a post-test-loop maintenance edit.
This is correctness/lifecycle qualification, with no timing superiority claim.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import re
import shutil
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.c_project import verify_capture
from hepta.clang_capture import run_bounded
from hepta.hia_program_llvm import build_program_native, emit_program_llvm
from hepta.hia_program_runtime import execute_program
from hepta.hia_program_source import lower_c_project_views
from hepta.native_tool_identity import digest_executable, update_stable_regular_hash
from tools.qualify_hia_filecheck import RESOURCE_HARNESS, update
from tools.qualify_hia_integrated import _source_state
from tools.qualify_hia_legacy_queue import (ENTRY, SOURCES, compile_database,
                                           populate_project, verify_compare, verify_ring)


PROTOCOL = {
    "schema": "hepta.hia.c-posttest-protocol.v1",
    "host": "Linux x86_64 LP64",
    "application": "existing_ring_buffer_musl_compare_authored_checksum_integration",
    "original_source_tus": list(SOURCES),
    "modified_tu": "checksum.c",
    "upstream_body_edits": 0,
    "authored_migrated_body_edits": 1,
    "polynomials": [0xedb88320, 0x82f63b78],
    "counts": [0, 1, 2, 4, 7, 8, 9, 12],
    "packed_values": [0, 0xfedcba9876543210, 0xffffffffffffffff],
    "state": 0xffffffff,
    "resource_counts": [0, 1, 8, 9],
    "allocation_refusal_indices": [0, 1, 2, 3],
    "performance_comparison": "not_requested",
}

NATIVE_DRIVER = r'''import ctypes,json,sys
paths=json.loads(sys.argv[1]); cases=json.loads(open(sys.argv[2]).read())
libraries={key:ctypes.CDLL(path) for key,path in paths.items()}
functions={key:getattr(lib,"legacy_checksum_chunk") for key,lib in libraries.items()}
for fn in functions.values():
    fn.argtypes=[ctypes.c_size_t,ctypes.c_uint64,ctypes.c_uint32,ctypes.c_uint32]
    fn.restype=ctypes.c_uint64
for index,case in enumerate(cases):
    print(json.dumps({"index":index,"arguments":case["arguments"],
        "observed":{label:int(fn(*case["arguments"])) for label,fn in functions.items()}}),flush=True)
'''


def _write(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _identity(path):
    raw = Path(path).read_bytes()
    return {"bytes": len(raw), "sha256": sha256(raw).hexdigest()}


def _inputs(project):
    return {str(path.relative_to(project)): _identity(path)
            for path in sorted(project.rglob("*")) if path.is_file()}


def retain_dependencies(capture, output):
    """Retain the exact admitted project and external header bytes, bounded."""
    output.mkdir()
    rows = []
    for expected in capture["dependencies"]:
        class Collector:
            def __init__(self):
                self.parts, self.digest = [], sha256()

            def update(self, data):
                self.parts.append(data)
                self.digest.update(data)

        collector = Collector()
        update_stable_regular_hash(collector, expected["path"], max_bytes=8_000_000, allow_empty=True)
        raw = b"".join(collector.parts)
        _require(len(raw) == expected["bytes"] and collector.digest.hexdigest() == expected["sha256"],
                 "captured dependency changed before retention")
        name = expected["sha256"] + ".bin"
        path = output / name
        if path.exists():
            _require(path.read_bytes() == raw, "retained dependency identity collision")
        else:
            path.write_bytes(raw)
        rows.append({**expected, "retained_file": name})
    _write(output / "index.json", rows)
    return rows


def prepare_project(project):
    """Copy locked upstream bytes and edit only the already authored TU."""
    contracts = populate_project(project)
    checksum = project / "checksum.c"
    original = checksum.read_text()
    old = 'for (unsigned int bit = 0; bit < 8; ++bit) {'
    end = '    }\n    return value;'
    _require(original.count(old) == 1 and original.count(end) == 1,
             "authored checksum maintenance anchor changed")
    revised = original.replace(old, 'unsigned int bit = 0;\n    do {').replace(
        end, '        bit++;\n    } while (bit < 8);\n    return value;')
    checksum.write_text(revised, encoding="utf-8")
    return contracts, {"before_sha256": sha256(original.encode()).hexdigest(),
                       "after_sha256": sha256(revised.encode()).hexdigest(),
                       "upstream": False, "original_authored_source": original,
                       "maintenance_edit": "for_to_post_test_with_same_eight_iterations"}


def qualify(output, *, clang, expected_source, cc="gcc"):
    out = Path(output).absolute()
    _require(not out.exists() and not out.is_symlink(), "new output directory required")
    _require(not out.resolve().is_relative_to(ROOT), "evidence must be outside the source inventory")
    out.mkdir(parents=True)
    started = time.perf_counter_ns()
    report = {"schema": "hepta.hia.c-posttest-qualification.v1", "ok": False,
              "protocol": PROTOCOL, "expected_source": expected_source,
              "commands": [], "functional_cases": [], "resource_cases": [],
              "claims": {"whole_c_cpp_migrated": False, "source_equivalence_proved": False,
                         "foreign_pointer_contracts_inferred": False,
                         "foreign_pointer_native_abi_exposed": False,
                         "performance_superiority": False,
                         "upstream_implementation_rewritten": False}}
    _write(out / "PROTOCOL.json", PROTOCOL)

    def command(argv, stage, *, cwd=None, timeout=45):
        argv = list(map(str, argv))
        before = time.perf_counter_ns()
        row = {"stage": stage, "argv": argv, "cwd": str(cwd or ROOT)}
        report["commands"].append(row)
        try:
            run = run_bounded(argv, cwd=cwd or ROOT, timeout=timeout,
                              stdout_limit=4 * 1024 * 1024, stderr_limit=1024 * 1024)
            row.update(returncode=run.returncode, stdout=run.stdout, stderr=run.stderr)
            for stream in ("stdout", "stderr"):
                raw = getattr(run, "raw_" + stream)
                if raw is not None:
                    name = f"command-{len(report['commands']) - 1:03d}-{stream}.bin"
                    (out / name).write_bytes(raw)
                    row[stream + "_raw"] = {"path": name, **_identity(out / name)}
            _require(run.returncode == 0, f"{stage} failed: {run.stderr[-3000:]}")
            return run.stdout
        except (Exception, KeyboardInterrupt) as error:
            row["error"] = {"type": type(error).__name__, "message": str(error)}
            partial = getattr(error, "capture", None)
            if partial is not None:
                row["partial_capture"] = {
                    "returncode": partial.returncode,
                    "stdout": partial.stdout.decode("utf-8", errors="replace"),
                    "stderr": partial.stderr.decode("utf-8", errors="replace"),
                    "stdout_total_bytes": partial.stdout_total_bytes,
                    "stderr_total_bytes": partial.stderr_total_bytes}
            raise
        finally:
            row["wall_ns"] = time.perf_counter_ns() - before
            _write(out / "commands.json", report["commands"])

    try:
        _require(re.fullmatch(r"[a-f0-9]{40}", expected_source or ""), "exact source commit required")
        _require((platform.system(), platform.machine()) == ("Linux", "x86_64"),
                 "this actual native cohort requires Linux x86_64")
        before = _source_state()
        _write(out / "source-before.json", before)
        _require(before["head"] == expected_source and not before["status"],
                 "source must be the exact clean expected commit")
        tools = {name: str(Path(shutil.which(value) or value).resolve(strict=True))
                 for name, value in (("clang", clang), ("cc", cc))}
        report["tools"] = {name: {"path": path, "sha256": digest_executable(path),
            "version": command([path, "--version"], "tool_identity")}
            for name, path in tools.items()}
        report["upstream"] = {"ring": verify_ring(), "compare": verify_compare()}
        project = out / "project"
        contracts, edit = prepare_project(project)
        report["maintenance"] = edit
        _write(out / "maintenance.json", edit)
        inputs_before = _inputs(project)
        _write(out / "inputs-before.json", inputs_before)
        capture_dir = out / "capture"
        database = compile_database(project, capture_dir)
        begin = time.perf_counter_ns()
        migrated = lower_c_project_views(database, contracts=contracts, clang=tools["clang"],
            client_source=(project / "client.hepta").read_text(), retain_asts=True)
        report["capture_and_lower_wall_ns"] = time.perf_counter_ns() - begin
        core = migrated.pop("program")
        report["captured_dependency_snapshots"] = retain_dependencies(
            migrated["capture"], out / "captured-inputs")
        for index, text in migrated.pop("raw_asts").items():
            (capture_dir / f"clang-ast-{index}.json").write_text(text, encoding="utf-8")
        (capture_dir / "source.hepta").write_text(migrated["source"], encoding="utf-8")
        (capture_dir / "program.hia.json").write_bytes(core.canonical_bytes)
        (capture_dir / "program.ll").write_text(emit_program_llvm(core).text, encoding="ascii")
        _write(capture_dir / "migration.json", migrated)
        _require(migrated["translated_function_bodies"] == 12 and
                 migrated["authored_client_function_bodies"] == 1 and
                 migrated["declaration_inventory_complete"], "complete application inventory changed")
        report["migration"] = {"core_sha256": core.sha256,
            "translated_bodies": 12, "upstream_bodies": 11, "authored_migrated_bodies": 1,
            "authored_hia_client_bodies": 1, "original_c_link_inputs_in_hia_target": [],
            "claims": migrated["claims"]}
        hia = out / "hia.so"
        report["hia_build"] = build_program_native(core, hia, clang=tools["clang"])
        _write(out / "hia-build.json", report["hia_build"])
        flags = ["-std=c11", "-DNDEBUG", "-funsigned-char", "-fno-builtin",
                 "-Icompare/platform", "-O3"]
        native = {"hia": str(hia)}
        for label in ("clang", "cc"):
            path = out / ("original_" + label + ".so")
            command([tools[label], *flags, "-fPIC", "-shared", *SOURCES,
                     "client.c", "-o", path], "original_" + label + "_build", cwd=project)
            native["original_" + label] = str(path)
        cases = [{"arguments": [count, packed, PROTOCOL["state"], polynomial],
                  "expected": 1 << 32 if count > 8 else
                      update(PROTOCOL["state"], packed.to_bytes(8, "little")[:count], polynomial)}
                 for polynomial in PROTOCOL["polynomials"] for count in PROTOCOL["counts"]
                 for packed in PROTOCOL["packed_values"]]
        _write(out / "cases.json", cases)
        (out / "native_driver.py").write_text(NATIVE_DRIVER, encoding="utf-8")
        observed = command([sys.executable, out / "native_driver.py", json.dumps(native),
                            out / "cases.json"], "native_application_execution", timeout=60)
        (out / "native-results.jsonl").write_text(observed, encoding="utf-8")
        native_rows = [json.loads(line) for line in observed.splitlines()]
        _require(len(native_rows) == len(cases), "native differential is incomplete")
        for index, (case, actual) in enumerate(zip(cases, native_rows)):
            vm = execute_program(core, ENTRY, case["arguments"])
            ledger = vm["resources"]
            report["functional_cases"].append({**case, "native": actual, "vm": vm})
            _require(actual["index"] == index and actual["arguments"] == case["arguments"] and
                     actual["observed"] == {label: case["expected"] for label in native} and
                     vm["result"] == case["expected"] and ledger["live_owners"] == 0 and
                     ledger["loans_started"] == ledger["loans_ended"], "functional/resource mismatch")
        (out / "resource_harness.c").write_text(RESOURCE_HARNESS, encoding="utf-8")
        obj = out / "resource_hia.o"
        report["hia_object_build"] = build_program_native(core, obj, clang=tools["clang"], kind="object")
        for label in ("c", "hia"):
            inputs = [obj] if label == "hia" else [*SOURCES, "client.c"]
            command([tools["clang"], *flags, "-DENTRY=" + ENTRY, out / "resource_harness.c",
                     *inputs, "-Wl,--wrap=malloc", "-Wl,--wrap=calloc", "-Wl,--wrap=free",
                     "-o", out / ("resource_" + label)], "resource_observer_build", cwd=project)
        for count in PROTOCOL["resource_counts"]:
            args = [count, 0xfedcba9876543210, 0xffffffff, 0xedb88320]
            for refusal in PROTOCOL["allocation_refusal_indices"]:
                vm = execute_program(core, ENTRY, args, allocation_fail_at=refusal or None)
                ledger = vm["resources"]
                expected = {"result": vm["result"], "attempts": ledger["allocation_attempts"],
                            "allocations": ledger["allocations"], "frees": ledger["frees"], "live": 0}
                actual = {label: json.loads(command([out / ("resource_" + label), *args, refusal],
                                                     "native_resource_execution", timeout=15))
                          for label in ("c", "hia")}
                report["resource_cases"].append({"arguments": args, "refuse_at": refusal,
                                                 "vm": vm, "native": actual})
                _require(ledger["live_owners"] == 0 and all(row == expected for row in actual.values()),
                         "native failure/cleanup differential differs")
        verify_capture(migrated["capture"])
        inputs_after = _inputs(project)
        _write(out / "inputs-after.json", inputs_after)
        _require(inputs_after == inputs_before, "captured project inputs changed")
        after = _source_state()
        _write(out / "source-after.json", after)
        _require(before == after, "compiler source changed")
        _require(all(digest_executable(row["path"]) == row["sha256"]
                     for row in report["tools"].values()), "selected native compiler changed")
        report.update(ok=True, status="bounded_post_test_application_passed",
                      source_stable=True, functional_case_count=len(cases),
                      native_functional_calls=len(cases) * len(native),
                      resource_case_count=len(report["resource_cases"]),
                      native_resource_calls=len(report["resource_cases"]) * 2)
    except (Exception, KeyboardInterrupt) as error:
        report["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        report["qualification_wall_ns"] = time.perf_counter_ns() - started
        report["artifacts"] = {str(path.relative_to(out)): _identity(path)
                               for path in sorted(out.rglob("*")) if path.is_file()}
        _write(out / "RESULT.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--clang", default=os.environ.get("CLANG", "clang"))
    parser.add_argument("--cc", default="gcc")
    parser.add_argument("--expected-source", required=True)
    args = parser.parse_args()
    report = qualify(args.output, clang=args.clang, cc=args.cc, expected_source=args.expected_source)
    print(json.dumps({key: report.get(key) for key in
                      ("schema", "ok", "status", "functional_case_count", "native_functional_calls",
                       "resource_case_count", "native_resource_calls", "error")}, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
