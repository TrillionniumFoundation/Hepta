#!/usr/bin/env python3
"""Zero-generation startup and native-tool probes before a new Agent study.

Only initialize/initialized are sent to app-server: no thread, turn, model or
task request is issued. A successful handshake does not verify model access,
usage reporting, productivity or the eligibility of an existing frozen cohort.
"""
from __future__ import annotations

import argparse
from itertools import islice
import json
import os
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
sys.dont_write_bytecode = True

from tools.hia_agent_codex_transport import canonical, identity, run_owned, save, strict_json

MAX_RUNTIME_METADATA_ENTRIES = 128


def initialization_wire():
    """The complete outbound RPC set; this probe has no generation command."""
    return b"".join(canonical(message) + b"\n" for message in (
        {"id": 1, "method": "initialize", "params": {
            "clientInfo": {"name": "hepta_zero_generation_preflight", "version": "1"},
            # Codex 0.144.1 publishes this non-task status notification after
            # initialized. Opt out at the documented transport boundary so
            # startup_response can still require exactly one ACK and reject
            # every unexpected message, including all model/task events.
            "capabilities": {"experimentalApi": False,
                "optOutNotificationMethods": ["remoteControl/status/changed"]}}},
        {"method": "initialized", "params": {}},
    ))


def startup_response(raw):
    """Accept one initialization result, never task/turn/tool output."""
    lines = raw.splitlines()
    if len(lines) != 1 or not lines[0]:
        raise ValueError("exactly one app-server initialization response required")
    response = strict_json(lines[0])
    if (type(response) is not dict or set(response) != {"id", "result"}
            or type(response["id"]) is not int or response["id"] != 1
            or type(response["result"]) is not dict
            or type(response["result"].get("userAgent")) is not str
            or not response["result"]["userAgent"]):
        raise ValueError("app-server did not acknowledge the initialization request")
    return {"initialization_acknowledged": True,
            "response_keys": sorted(response["result"])}


def process_ok(record):
    return (record.get("status") == "exited"
            and type(record.get("returncode")) is int and record["returncode"] == 0
            and record.get("cleanup_confirmed") is True
            and record.get("leader_reaped") is True
            and record.get("streams_complete") is True)


def _owned(argv, cwd, output, seconds, *, input_bytes=b""):
    record = run_owned(argv, cwd, output, input_bytes=input_bytes, wall_seconds=seconds)
    if not process_ok(record):
        raise ValueError("probe process failed or its cleanup was not confirmed: " + str(output))
    return record


def _native_probe(language, compiler, folder, seconds):
    """Compile and execute known independent XOR cases, not benchmark tasks."""
    folder.mkdir()
    binary = folder / "probe"
    report = {"passed": False, "scope": "known-scalar-native-tool-smoke"}
    if language == "hia":
        from hepta.hia_program_source import lower_source
        from hepta.hia_program_llvm import emit_program_llvm
        program = lower_source('export "C" fn target(x:u32,y:u32)->u32 effects{}{return x^y;}')
        report["core_sha256"] = program.sha256
        llvm = folder / "program.ll"
        llvm.write_text(emit_program_llvm(program).text)
        report["llvm"] = identity(llvm)
        report["object_compile"] = _owned([compiler, "-O2", "-c", str(llvm), "-o", str(folder / "program.o")],
                                          folder, folder / "object-compile", seconds)
        report["object"] = identity(folder / "program.o")
        source = folder / "driver.c"
        source.write_text('#include <stdint.h>\n#include <stdio.h>\n'
            'extern uint32_t target(uint32_t,uint32_t);\n'
            'int main(void){printf("%u\\n%u\\n",target(3,6),target(UINT32_MAX,0));return 0;}\n')
        command = [compiler, "-O2", str(source), str(folder / "program.o"), "-o", str(binary)]
    else:
        source = folder / "main.rs"
        source.write_text('fn target(x:u32,y:u32)->u32{x^y}\n'
            'fn main(){println!("{}\\n{}",target(3,6),target(u32::MAX,0));}\n')
        command = [compiler, "--edition=2021", "-C", "opt-level=2", "-C", "overflow-checks=on",
                   "-C", "panic=abort", str(source), "-o", str(binary)]
    report["compile"] = _owned(command, folder, folder / "compile", seconds)
    before = identity(binary)
    report["execute"] = _owned([str(binary)], folder, folder / "execute", seconds)
    report["binary"] = before
    report["passed"] = ((folder / "execute/stdout.raw").read_bytes() == b"5\n4294967295\n"
                        and identity(binary) == before)
    if not report["passed"]:
        raise ValueError("known scalar native smoke output or artifact identity differs")
    return report


def preflight(output, *, codex, clang, rustc, campaign=None, registered_paths=None,
              freeze_path=None, isolate_sqlite=False, isolate_logs=False, wall_seconds=15):
    if type(wall_seconds) is not int or not 1 <= wall_seconds <= 60:
        raise ValueError("preflight per-process wall limit must be an integer in 1..60")
    if type(isolate_sqlite) is not bool or type(isolate_logs) is not bool:
        raise ValueError("preflight runtime isolation flags must be Boolean")
    folder = Path(output)
    if not folder.is_absolute() or folder.resolve().is_relative_to(ROOT.resolve()):
        raise ValueError("preflight output must be absolute and outside the source checkout")
    folder.mkdir(parents=True, exist_ok=False)
    started = time.monotonic_ns()
    report = {"schema": "hepta.hia.agent-preflight.v1", "campaign": campaign,
              "status": "starting", "passed": False, "probes": {}, "tools": {},
              "requested_tool_paths": {"codex": str(codex), "clang": str(clang), "rustc": str(rustc)},
              "model_requests_sent_by_probe": 0, "task_requests": 0,
              "model_access_verified": False, "model_usage": None,
              "registered_campaign_run_authorized": False, "new_registration_required": True,
              "prior_results_replaced": False, "model_successes": 0,
              "startup_overrides": {}, "runtime_directory_metadata": {},
              "runtime_database_payloads_read": False,
              "claims": {"productivity_advantage_proved": False,
                         "full_cost_advantage_proved": False,
                         "arbitrary_tool_or_process_attestation": False}}
    freeze = Path(freeze_path) if freeze_path is not None else None
    freeze_before = identity(freeze) if freeze is not None and freeze.is_file() else None
    report["existing_freeze"] = freeze_before
    sources = (Path(__file__), ROOT / "tools/hia_agent_codex_transport.py",
               ROOT / "tools/qualify_hia_agent_maintenance.py")
    report["probe_sources"] = {str(path.relative_to(ROOT)): identity(path) for path in sources}
    try:
        # A real create/fsync/read-back checks the receipt workspace before
        # starting any subprocess. No global HOME/CODEX_HOME is relocated.
        probe = folder / "workspace.probe"
        with probe.open("xb") as stream:
            stream.write(b"hepta-zero-generation-preflight\n")
            stream.flush()
            os.fsync(stream.fileno())
        if probe.read_bytes() != b"hepta-zero-generation-preflight\n":
            raise ValueError("preflight workspace write/read-back differs")
        probe.unlink()
        for name, requested in report["requested_tool_paths"].items():
            if not Path(requested).is_absolute() or not os.access(requested, os.X_OK):
                raise ValueError("missing absolute executable tool: " + name)
            report["tools"][name] = identity(requested)
        report["requested_paths_match_registered_protocol"] = (
            registered_paths == report["requested_tool_paths"] if registered_paths is not None else None)
        for name in ("codex", "clang", "rustc"):
            try:
                report["probes"][name + "_version"] = {
                    "passed": True, "process": _owned([report["tools"][name]["path"], "--version"],
                        folder, folder / (name + "-version"), wall_seconds)}
            except Exception as exc:
                report["probes"][name + "_version"] = {"passed": False, "error": str(exc)}
        command = [report["tools"]["codex"]["path"]]
        # Expose only these documented local path settings. Paths are always
        # fresh children of the admitted output; there is no arbitrary config,
        # home relocation, permission or thread-store selector in this API.
        for enabled, key, child in ((isolate_sqlite, "sqlite_home", "sqlite-state"),
                                    (isolate_logs, "log_dir", "codex-logs")):
            if enabled:
                runtime = folder / child
                runtime.mkdir()  # Existing files/symlinks refuse before startup.
                report["startup_overrides"][key] = str(runtime)
                command.extend(["-c", key + "=" + json.dumps(str(runtime))])
        command.extend(["app-server", "--stdio"])
        try:
            process = run_owned(command, folder, folder / "app-server", wall_seconds=wall_seconds,
                                input_bytes=initialization_wire())
            report["probes"]["startup"] = {"passed": False, "process": process}
            if not process_ok(process):
                raise ValueError("app-server initialization process failed or cleanup was not confirmed")
            response = startup_response((folder / "app-server/stdout.raw").read_bytes())
            report["probes"]["startup"] = {"passed": True, "process": process, **response}
        except Exception as exc:
            report["probes"].setdefault("startup", {"passed": False})["error"] = str(exc)
        for key, name in report["startup_overrides"].items():
            runtime = Path(name)
            entries = list(islice(runtime.iterdir(), MAX_RUNTIME_METADATA_ENTRIES + 1))
            if len(entries) > MAX_RUNTIME_METADATA_ENTRIES:
                raise ValueError("preflight runtime metadata entry budget exceeded")
            report["runtime_directory_metadata"][key] = {
                "directory": name, "payloads_read": False, "scope": "direct regular files only",
                "files": [{"relative_path": str(path.relative_to(runtime)), "bytes": path.stat().st_size}
                          for path in sorted(entries)
                          if not path.is_symlink() and path.is_file()]}
        for language, tool in (("hia", "clang"), ("rust", "rustc")):
            try:
                report["probes"][language + "_native"] = _native_probe(
                    language, report["tools"][tool]["path"], folder / (language + "-native"), wall_seconds)
            except Exception as exc:
                report["probes"][language + "_native"] = {"passed": False, "error": str(exc)}
        report["tools_unchanged"] = all(identity(path) == report["tools"][name]
            for name, path in report["requested_tool_paths"].items())
        report["existing_freeze_unchanged"] = (freeze_before is None if freeze is None or not freeze.is_file()
                                                else identity(freeze) == freeze_before)
        report["probe_sources_unchanged"] = all(identity(ROOT / name) == recorded
            for name, recorded in report["probe_sources"].items())
        report["passed"] = (all(row.get("passed") is True for row in report["probes"].values())
                            and report["tools_unchanged"] and report["existing_freeze_unchanged"]
                            and report["probe_sources_unchanged"])
        report["status"] = "startup_and_native_probes_passed" if report["passed"] else "blocked"
    except Exception as exc:
        report.update(status="blocked", error={"type": type(exc).__name__, "message": str(exc)})
    finally:
        report["wall_ns"] = time.monotonic_ns() - started
        save(folder / "RESULT.json", report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("output", "codex", "clang", "rustc"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--isolate-sqlite", action="store_true")
    parser.add_argument("--isolate-logs", action="store_true")
    parser.add_argument("--wall-seconds", type=int, default=15)
    args = parser.parse_args(argv)
    result = preflight(args.output, codex=args.codex, clang=args.clang, rustc=args.rustc,
                       isolate_sqlite=args.isolate_sqlite, isolate_logs=args.isolate_logs,
                       wall_seconds=args.wall_seconds)
    print(json.dumps({key: result[key] for key in ("status", "passed", "model_requests_sent_by_probe",
          "model_access_verified", "registered_campaign_run_authorized", "new_registration_required")}))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
