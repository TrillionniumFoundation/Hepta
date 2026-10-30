#!/usr/bin/env python3
"""Qualify unchanged musl strncmp through captured C, HIA Core and direct LLVM.

This is a finite semantic/resource qualification, not a performance study,
whole-project migration, source-refinement proof or measured labor saving.
Every original-C native, HIA native and HIA VM observation is retained.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import random
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.c_project import verify_capture
from hepta.hia_program import execute_program, verify_program
from hepta.hia_program_source import lower_c_project_views
from hepta.hia_program_llvm import build_program_native, emit_program_llvm
from hepta.native_tool_identity import digest_executable


FIXTURE = ROOT / "tests/fixtures/c_migration/musl_strncmp"
CLIENT = ROOT / "examples/hia_musl_strncmp"
ENTRY = "strncmp_probe"
FLAGS = ("-std=c11", "-funsigned-char", "-fno-builtin", "-O2", "-fPIC", "-Iplatform")
UPSTREAM_HASHES = {
    "strncmp.c": "df801c43304b27dcda67f219a7a3ca34a8fb06f4e63d21e8a6bcb36b03c3c012",
    "COPYRIGHT": "f9bc4423732350eb0b3f7ed7e91d530298476f8fec0c6c427a1c04ade22655af",
    "UPSTREAM_README": "99be6432b41de50d702dbee423149c8abcd52d06e29dc1715013c25865a2eda8",
}
PROTOCOL = {
    "schema": "hepta.hia.musl-strncmp-protocol.v1",
    "entry": ENTRY, "flags": list(FLAGS), "target": "observed_linux_x86_64_lp64",
    "seed": 20261030, "seeded_pairs": 128, "maximum_bytes": 8,
    "refusal_indices": [0, 1, 2],
    "oracle": "first unsigned byte difference up to n or equal NUL; explicit allocation-refusal codes",
    "routes": ["original_c_native", "hia_llvm_native", "hia_python_vm"],
    "claims": {
        "unchanged_upstream_function_bodies": 1,
        "authored_scalar_client_bodies": 1,
        "original_c_implementation_linked_into_hia_target": False,
        "rust_codegen_used": False, "fallback_used": False,
        "source_equivalence_proved": False, "backend_refinement_proved": False,
        "foreign_pointer_abi_qualified": False, "arbitrary_c_cpp_supported": False,
        "performance_advantage_measured": False, "human_effort_measured": False,
    },
}


def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def identity(path):
    path = Path(path).resolve(strict=True)
    return {"path": str(path), "bytes": path.stat().st_size,
            "sha256": digest_executable(path)}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify_upstream(directory=FIXTURE):
    directory = Path(directory)
    metadata = json.loads((directory / "UPSTREAM.json").read_text())
    require(metadata["version"] == "1.2.5"
            and metadata["tag_commit"] == "0784374d561435f7c787a555aeab8ede699ed298"
            and metadata["release_archive"]["sha256"] == "a9a118bbe84d8764da0ea0d28b3ab3fae8477fc7e4085d90102b8596fc7c75e4"
            and metadata["source_modifications"] == []
            and {row["local_path"]: row["sha256"] for row in metadata["files"]} == UPSTREAM_HASHES,
            "frozen upstream component identity differs")
    for row in metadata["files"]:
        actual = identity(directory / row["local_path"])
        require(actual["bytes"] == row["bytes"] and actual["sha256"] == row["sha256"],
                "upstream bytes differ: " + row["local_path"])
    return metadata


def source_bindings():
    paths = [Path(__file__), *FIXTURE.rglob("*"), *CLIENT.iterdir(),
             *sorted((ROOT / "hepta").rglob("*.py"))]
    return {str(path.relative_to(ROOT)): identity(path)["sha256"]
            for path in sorted(paths) if path.is_file()}


def configured_frontend_libraries():
    """Record the extracted toolchain's explicit loader configuration only.

    The original-type reader separately binds its actual libclang identity.
    This supplements that binding for the local unpacked LLVM dependencies;
    it is not a complete operating-system or dynamic-loader attestation.
    """
    configured = os.environ.get("LD_LIBRARY_PATH")
    paths = set()
    for directory in (configured or "").split(os.pathsep):
        if directory:
            for pattern in ("libLLVM*.so*", "libclang*.so*"):
                paths.update(path.resolve() for path in Path(directory).glob(pattern) if path.is_file())
    return {"LD_LIBRARY_PATH": configured,
            "llvm_clang_libraries": [identity(path) for path in sorted(paths)],
            "all_system_dependencies_attested": False}


def prepare_project(directory, *, signed_char=False):
    verify_upstream()
    directory = Path(directory)
    shutil.copytree(FIXTURE, directory)
    for path in CLIENT.iterdir():
        if path.is_file():
            shutil.copyfile(path, directory / path.name)
    flags = ["-fsigned-char" if flag == "-funsigned-char" and signed_char else flag for flag in FLAGS]
    database = directory / "compile_commands.json"
    write(database, [{"directory": str(directory.absolute()), "file": "strncmp.c",
                      "arguments": ["clang", *flags, "-c", "strncmp.c", "-o", "strncmp.o"]}])
    return database, json.loads((directory / "contracts.json").read_text())


def byte_compare(left, right, count):
    for a, b in zip(left[:count], right[:count]):
        if a != b:
            return a - b
        if a == 0:
            break
    return 0


def cases():
    """Frozen boundary/short-circuit cases plus deterministic random byte pairs."""
    rows = []

    def add(category, count, left, right):
        require(len(left) <= 8 and len(right) <= 8, "bounded packed inputs required")
        a = int.from_bytes(left.ljust(8, b"\0"), "little")
        b = int.from_bytes(right.ljust(8, b"\0"), "little")
        rows.append({"case": len(rows), "category": category, "arguments": [count, a, b],
                     "expected": -259 if count > 8 else byte_compare(a.to_bytes(8, "little"), b.to_bytes(8, "little"), count)})

    for a in (0, 1, 2, 127, 128, 254, 255):
        for b in (0, 1, 2, 127, 128, 254, 255):
            add("single_byte_boundaries", 1, bytes([a]), bytes([b]))
    for count in range(9):
        add("zero_and_equal_length", count, b"\xff" * 8, b"\xff" * 8)
        add("left_early_nul", count, b"\0" + b"\xff" * 7, b"\xff" * 8)
        add("right_early_nul", count, b"\xff" * 8, b"\0" + b"\xff" * 7)
        for position in range(count):
            for a, b in ((0, 255), (255, 0), (127, 128), (255, 1)):
                left, right = bytearray(b"\x55" * 8), bytearray(b"\x55" * 8)
                left[position], right[position] = a, b
                add("each_first_difference", count, bytes(left), bytes(right))
            left, right = bytearray(b"\x55" * 8), bytearray(b"\x55" * 8)
            left[position] = right[position] = 0
            if position + 1 < 8:
                left[position + 1], right[position + 1] = 1, 255
            add("equal_nul_ignores_later_difference", count, bytes(left), bytes(right))
    rng = random.Random(PROTOCOL["seed"])
    for _ in range(PROTOCOL["seeded_pairs"]):
        left = rng.randbytes(8)
        right = rng.randbytes(8) if rng.randrange(2) else left
        add("seeded_pairs", rng.randrange(9), left, right)
    add("scalar_client_rejects_excess_length", 9, b"", b"")
    add("scalar_client_rejects_maximum_length", (1 << 64) - 1, b"", b"")
    return rows


def expected_resources(case, refusal):
    count = case["arguments"][0]
    if count == 0 or count > 8:
        return {"result": case["expected"], "attempts": 0, "allocations": 0, "frees": 0, "live": 0}
    if refusal:
        return {"result": -256 - refusal, "attempts": refusal,
                "allocations": refusal - 1, "frees": refusal - 1, "live": 0}
    return {"result": case["expected"], "attempts": 2, "allocations": 2, "frees": 2, "live": 0}


def run(*, output, clang, source_sha):
    started = time.monotonic_ns()
    out = Path(output).absolute()
    out.mkdir(parents=True, exist_ok=False)
    report = {"schema": "hepta.hia.musl-strncmp-qualification.v1", "ok": False,
              "status": "incomplete", "protocol": PROTOCOL, "commands": [],
              "completed_cases": 0, "native_observations": 0, "vm_observations": 0,
              "claims": dict(PROTOCOL["claims"])}

    def command(argv, label, *, cwd=None):
        argv = list(map(str, argv))
        before = time.monotonic_ns()
        row = {"argv": argv, "cwd": str(cwd or out), "stage": label}
        try:
            process = subprocess.run(argv, cwd=cwd or out, capture_output=True, text=True, timeout=60)
            row.update(returncode=process.returncode, stdout=process.stdout, stderr=process.stderr)
        except subprocess.TimeoutExpired as error:
            row.update(returncode=None, timed_out=True,
                       stdout=(error.stdout or b"").decode(errors="replace") if isinstance(error.stdout, bytes) else error.stdout or "",
                       stderr=(error.stderr or b"").decode(errors="replace") if isinstance(error.stderr, bytes) else error.stderr or "")
            raise
        finally:
            row["wall_ns"] = time.monotonic_ns() - before
            report["commands"].append(row)
            with (out / "processes.jsonl").open("a") as stream:
                stream.write(json.dumps(row, separators=(",", ":")) + "\n")
        require(row["returncode"] == 0, label + " failed: " + row.get("stderr", "")[-2000:])
        return row

    try:
        compiler = str(Path(shutil.which(clang) or clang).resolve(strict=True))
        report["source_bindings"] = source_bindings()
        report["source_commit"] = command(["git", "-C", ROOT, "rev-parse", "HEAD"], "source_head")["stdout"].strip()
        require(len(source_sha) == 40 and report["source_commit"] == source_sha, "exact implementation commit required")
        status = command(["git", "-C", ROOT, "status", "--porcelain", "--untracked-files=no"], "source_status")["stdout"]
        tracked = set(command(["git", "-C", ROOT, "ls-files"], "source_files")["stdout"].splitlines())
        require(not status and set(report["source_bindings"]) <= tracked, "clean committed qualification source required")
        report["tool"] = {**identity(compiler), "version": command([compiler, "--version"], "tool_version")["stdout"]}
        report["frontend_loader"] = configured_frontend_libraries()
        report["python"] = {**identity(sys.executable), "version": sys.version}
        report["host"] = {"platform": platform.platform(), "machine": platform.machine(), "exclusive_host": False}
        report["upstream"] = verify_upstream()
        project = out / "project"
        database, contracts = prepare_project(project)
        before = time.monotonic_ns()
        migrated = lower_c_project_views(database, contracts=contracts, clang=compiler,
            client_source=(project / "client.hepta").read_text(), retain_asts=True)
        core, asts = migrated.pop("program"), migrated.pop("raw_asts")
        require(len(migrated["functions"]) == 1 and migrated["functions"][0]["name"] == "strncmp"
                and migrated["authored_client_function_bodies"] == 1
                and migrated["declaration_inventory_complete"], "complete one-body component inventory required")
        require(not migrated["claims"]["rust_backend_required"]
                and not migrated["claims"]["original_c_implementation_linked_into_target"], "independent Core route required")
        capture = out / "capture"
        capture.mkdir()
        write(capture / "migration.json", migrated)
        (capture / "source.hepta").write_text(migrated["source"])
        (capture / "program.hia.json").write_bytes(core.canonical_bytes)
        llvm = emit_program_llvm(core)
        (capture / "program.ll").write_text(llvm.text)
        for index, text in asts.items():
            (capture / ("clang-ast-" + str(index) + ".json")).write_text(text)
        require(len(asts) == 1 and '"isPostfix": true' in asts[0], "original postfix AST evidence required")
        verify_capture(migrated["capture"])
        require(verify_program(core.canonical_bytes).sha256 == core.sha256, "Core re-admission changed")
        report["migration"] = {"wall_ns": time.monotonic_ns() - before, "program_sha256": core.sha256,
            "manifest": identity(capture / "migration.json"), "original_ast": identity(capture / "clang-ast-0.json"),
            "core": identity(capture / "program.hia.json"), "llvm": identity(capture / "program.ll"),
            "manual_migrated_body_edits": 0, "input_contracts": contracts,
            "domain": "two initialized read slices each at least n bytes; unsigned-char LP64 captured build only"}
        build = build_program_native(core, out / "hia.o", kind="object", clang=compiler)
        require(build["ok"] and not any(build["claims"][key] for key in ("rust_codegen_used", "c_codegen_used", "fallback_used")),
                "direct LLVM native build required")
        require(build["llvm_ir_sha256"] == identity(capture / "program.ll")["sha256"], "retained LLVM differs from consumed IR")
        report["native_build"] = build
        command([compiler, *FLAGS, "-c", "strncmp.c", "-o", out / "original.o"], "original_c_capture_replay", cwd=project)
        command([compiler, *FLAGS, "-c", "client.c", "-o", out / "client.o"], "authored_c_client", cwd=project)
        command([compiler, "-std=c11", "-O2", "-fno-builtin", "-c", project / "observer.c", "-o", out / "observer.o"], "observer_build")
        executables = {}
        for route, objects in (("original_c_native", [out / "original.o", out / "client.o"]),
                               ("hia_llvm_native", [out / "hia.o"])):
            executable = out / route
            command([compiler, out / "observer.o", *objects, "-Wl,--wrap=malloc", "-Wl,--wrap=calloc",
                     "-Wl,--wrap=free", "-o", executable], route + "_link")
            executables[route] = executable
        report["executables"] = {route: identity(path) for route, path in executables.items()}
        rows = cases()
        write(out / "input-cases.json", rows)
        report["planned_cases"] = len(rows) * len(PROTOCOL["refusal_indices"])
        with (out / "observations.jsonl").open("x") as stream:
            for case in rows:
                for refusal in PROTOCOL["refusal_indices"]:
                    expected = expected_resources(case, refusal)
                    row = {**case, "refuse_at": refusal, "resource_expected": expected, "native": {}}
                    report["pending_case"] = {"case": case["case"], "refuse_at": refusal}
                    for route, executable in executables.items():
                        native = command([executable, *case["arguments"], refusal], "native_observation")
                        row["native"][route] = {"observed": json.loads(native["stdout"]),
                            "command_index": len(report["commands"]) - 1, "wall_ns": native["wall_ns"]}
                        report["native_observations"] += 1
                    before = time.monotonic_ns()
                    observed = execute_program(core, ENTRY, case["arguments"], allocation_fail_at=refusal or None)
                    row["vm"] = {"observed": observed, "wall_ns": time.monotonic_ns() - before}
                    report["vm_observations"] += 1
                    stream.write(json.dumps(row, separators=(",", ":")) + "\n")
                    stream.flush()
                    require(all(native["observed"] == expected for native in row["native"].values()), "native output or allocation cleanup differs")
                    stats = observed["resources"]
                    require(observed["result"] == expected["result"] and stats["live_owners"] == 0
                            and stats["loans_started"] == stats["loans_ended"]
                            and all(stats[a] == expected[b] for a, b in (("allocation_attempts", "attempts"),
                                    ("allocations", "allocations"), ("frees", "frees"))), "VM output or resource cleanup differs")
                    report["completed_cases"] += 1
                    report["pending_case"] = None
        require(report["completed_cases"] == report["planned_cases"], "incomplete finite matrix")
        require(source_bindings() == report["source_bindings"], "implementation source drift")
        require(identity(compiler) == {k: report["tool"][k] for k in ("path", "bytes", "sha256")}, "compiler drift")
        require(configured_frontend_libraries() == report["frontend_loader"], "frontend loader configuration or library drift")
        require({route: identity(path) for route, path in executables.items()} == report["executables"], "native artifact drift")
        verify_capture(migrated["capture"])
        verify_upstream(project)
        report.update(ok=True, status="completed_finite_component_qualification")
    except Exception as error:
        report.update(ok=False, status="failed", error={"type": type(error).__name__,
            "code": getattr(error, "code", None), "message": str(error)})
    finally:
        report["whole_qualification_wall_ns"] = time.monotonic_ns() - started
        report["retained_files"] = [identity(path) for path in sorted(out.rglob("*")) if path.is_file()]
        for row in report["commands"]:
            row.pop("stdout", None)
            row.pop("stderr", None)
        write(out / "qualification.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--clang", default=os.environ.get("CLANG", "clang"))
    result = run(**vars(parser.parse_args()))
    print(json.dumps({key: result[key] for key in ("ok", "status", "completed_cases", "native_observations", "vm_observations", "whole_qualification_wall_ns", "error") if key in result}))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
