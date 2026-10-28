#!/usr/bin/env python3
"""Check the selected host's real Clang/original-type reader before migration.

This is a small frontend preflight, not a native component qualification. On
macOS xcrun resolves the active installation; /usr/bin/clang is only a shim.
The existing original-type reader remains the sole type-admission mechanism.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import shutil
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.c_migrate import migrate_c_project
from hepta.c_parameter_types import original_type_reader_identity
from hepta.clang_capture import CaptureRejected, run_bounded

SCHEMA = "hepta.c-original-type-host-preflight.v1"
CASES = {
    "fixed_array": "unsigned int probe(unsigned int n, const unsigned int data[8]) { return n; }\n",
    "vla_entry": "unsigned int probe(unsigned int n, const unsigned int data[++n]) { return n; }\n",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write(path, value):
    Path(path).write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8", newline="\n")


def observe(argv, folder, records):
    """Retain bounded identity-command streams, including failed observations."""
    row = {"argv": list(map(str, argv)), "cwd": str(ROOT), "timeout_seconds": 10,
           "stdout_limit": 128_000, "stderr_limit": 128_000,
           "stream_representation": "UTF-8; shared capture normalizes CRLF/CR to LF"}
    records.append(row)
    started = time.monotonic()
    try:
        result = run_bounded(row["argv"], cwd=ROOT, timeout=10,
                             stdin_limit=0, stdout_limit=128_000, stderr_limit=128_000)
        row.update(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)
    except CaptureRejected as exc:
        row.update(returncode=None, error={"code": exc.code, "message": str(exc)})
        if exc.capture is not None:
            row["returncode"] = exc.capture.returncode
            row["retained_failure_prefixes"] = {
                "stdout_hex": exc.capture.stdout.hex(), "stderr_hex": exc.capture.stderr.hex(),
                "stdout_total_bytes": exc.capture.stdout_total_bytes,
                "stderr_total_bytes": exc.capture.stderr_total_bytes}
        raise
    finally:
        row["elapsed_seconds"] = time.monotonic() - started
        write(folder / "identity-commands.json", records)
    require(result.returncode == 0, "identity command failed: " + json.dumps(row))
    return result.stdout


def select_clang(requested, system, invoke):
    if system == "Darwin":
        # Apple's active developer directory, including DEVELOPER_DIR, decides
        # this path. Do not guess an Xcode version or search global libraries.
        output = invoke(["/usr/bin/xcrun", "--find", "clang"])
        lines = output.splitlines()
        require(len(lines) == 1 and lines[0] == lines[0].strip(), "xcrun did not return one compiler path")
        chosen = Path(lines[0])
        require(chosen.is_absolute() and chosen.is_file(), "xcrun compiler is not an existing absolute file")
        chosen = chosen.resolve(strict=True)
        require(chosen.parent.name == "bin" and chosen != Path("/usr/bin/clang"), "xcrun returned a compiler shim")
        if requested not in {"clang", "/usr/bin/clang"}:
            found = shutil.which(requested)
            require(found is not None and Path(found).resolve() == chosen,
                    "requested compiler differs from the active Xcode compiler")
    else:
        found = shutil.which(requested)
        require(found is not None, "requested capture Clang is unavailable")
        chosen = Path(found).resolve(strict=True)
    require(chosen.is_file() and not any(c in str(chosen) for c in "\r\n\0"), "invalid selected compiler path")
    return chosen


def check_identity(identity, chosen, version, target, system):
    require(identity.get("schema") == "hepta.c-original-type-reader-identity.v1", "wrong reader identity schema")
    compiler, reader = identity["compiler"], identity["reader"]
    require(compiler["path"] == str(chosen) and compiler["executable_sha256"] == sha(chosen),
            "reader did not use the selected compiler bytes")
    require(compiler["version"] == version.splitlines()[0] == reader["version"]
            and compiler["target"] == target.strip(), "compiler/reader version or target differs")
    if system == "Darwin":
        adjacent = chosen.parent.parent / "lib" / "libclang.dylib"
        require(adjacent.is_file() and adjacent.resolve(strict=True) == Path(reader["path"]),
                "reader is not the selected Xcode installation's libclang.dylib")
    for name in ("reader", "worker", "python"):
        item = identity[name]
        require(Path(item["path"]).stat().st_size == item["bytes"] and sha(item["path"]) == item["sha256"],
                "original-type identity bytes changed: " + name)


def check_case(name, report, identity, work):
    receipts = report.get("source_type_admission", [])
    require(len(receipts) == 1, "missing original-type admission receipt")
    receipt = receipts[0]
    require(receipt["schema"] == "hepta.c-original-parameter-types.v2"
            and receipt["compiler"] == identity["compiler"]
            and receipt["reader"] == identity["reader"]
            and receipt["worker"] == identity["worker"]
            and receipt["python"] == identity["python"]
            and receipt["capture_sha256"] == report["build"]["sha256"],
            "original-type receipt is not bound to the selected reader/capture")
    require(len(receipt["functions"]) == 1, "unexpected preflight declaration inventory")
    function = receipt["functions"][0]
    require(function["declaration"]["name"] == "probe"
            and function["declaration"]["file"] == str((work / "input.c").resolve()),
            "preflight declaration has a different physical source")
    parameters = function["parameters"]
    require(len(parameters) == 2 and [p["name"] for p in parameters] == ["n", "data"],
            "preflight parameter inventory differs")
    parameter = parameters[1]
    require(parameter["binding"]["file"] == str((work / "input.c").resolve())
            and parameter["binding"]["offset"] == CASES[name].index("data"),
            "preflight array parameter has a different physical spelling")
    shape = parameter["shape"]
    # The actual Clang 20 canonical receipt retains this qualifier on the
    # array node. Accept an explicitly qualified element as well; never drop
    # the qualifier or substitute an adjusted pointer for the original array.
    require(shape.get("element", {}).get("kind") == "UInt"
            and (shape.get("const") is True or shape["element"].get("const") is True),
            "preflight lost the original const unsigned element type")
    if name == "fixed_array":
        require(report["ok"] is True and report["native_validation"] == "not_run"
                and parameter["state"] == "fixed" and shape["kind"] == "ConstantArray"
                and type(shape["extent"]) is int and shape["extent"] == 8,
                "fixed array was not admitted with its original extent")
    else:
        require(report["ok"] is False and parameter["state"] == "variable"
                and shape["kind"] == "VariableArray" and shape["extent"] is None
                and "E_C_VLA_PARAMETER" in [d["code"] for d in report["diagnostics"]]
                and not (work / "translated").exists(),
                "entry-time VLA was not explicitly refused with its original shape")
    return {"name": name, "expected_migration_ok": name == "fixed_array",
            "observed_state": parameter["state"], "observed_shape": shape,
            "diagnostic_codes": [d["code"] for d in report["diagnostics"]], "passed": True}


def preflight(folder, requested, expected_system):
    report = {"schema": SCHEMA, "ok": False, "status": "failed",
              "started_utc": datetime.now(timezone.utc).isoformat(),
              "system": platform.system(), "machine": platform.machine(),
              "requested_clang": requested, "identity_commands": [], "cases": [],
              "claims": {"native_component_qualified": False, "cross_host_results_inferred": False,
                         "original_type_guard_bypassed": False},
              "limits": "Existing bounded compiler/type-worker capture; this preflight grants no sandbox or process-ownership qualification. Actual capture process controls run separately.",
              "native_program_executions": 0, "rust_compiler_invocations": 0}
    try:
        require(report["system"] == expected_system, "actual host differs from requested system")
        chosen = select_clang(requested, report["system"],
                              lambda argv: observe(argv, folder, report["identity_commands"]))
        report["selected_clang"] = str(chosen)
        version = observe([str(chosen), "--version"], folder, report["identity_commands"])
        target = observe([str(chosen), "-dumpmachine"], folder, report["identity_commands"])
        identity = original_type_reader_identity(str(chosen))
        report["reader_identity"] = identity
        write(folder / "reader-identity.json", identity)
        check_identity(identity, chosen, version, target, report["system"])
        for name, source in CASES.items():
            work = folder / name
            work.mkdir()
            (work / "input.c").write_text(source, encoding="utf-8", newline="\n")
            database = work / "compile_commands.json"
            write(database, [{"directory": str(work), "file": "input.c",
                              "arguments": [str(chosen), "-std=c11", "-O0", "-c", "input.c", "-o", "input.o"]}])
            contracts = {"schema": "hepta.c-contracts.v1", "functions": {
                "probe": {"slices": {"data": {"length": "n", "access": "read"}}}}}
            result = migrate_c_project(database, work / "translated", contracts=contracts,
                                       clang=str(chosen), verify_native=False)
            write(work / "migration.json", result)
            row = {"name": name, "report": str(work / "migration.json"),
                   "report_sha256": sha(work / "migration.json")}
            report["cases"].append(row)
            row.update(check_case(name, result, identity, work))
        check_identity(identity, chosen, version, target, report["system"])
        report.update(ok=True, status="original_type_host_preflight_passed")
    except Exception as exc:
        report["error"] = {"type": type(exc).__name__, "code": getattr(exc, "code", None), "message": str(exc)}
    report["finished_utc"] = datetime.now(timezone.utc).isoformat()
    report["tool_sha256"] = sha(__file__)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--expected-system", required=True, choices=("Linux", "Darwin", "Windows"))
    parser.add_argument("--output-directory", required=True, type=Path)
    parser.add_argument("--github-env", type=Path)
    args = parser.parse_args(argv)
    if args.output_directory.exists():
        parser.error("use a new preflight evidence directory")
    folder = args.output_directory.resolve()
    folder.mkdir(parents=True)
    report = preflight(folder, args.clang, args.expected_system)
    write(folder / "qualification.json", report)
    if report["ok"] and args.github_env is not None:
        with args.github_env.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write("HEPTA_CAPTURE_CLANG=" + report["selected_clang"] + "\n")
    print(json.dumps({k: report[k] for k in ("schema", "ok", "status", "system", "cases")}, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
