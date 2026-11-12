"""Execute only the separately frozen four source controls once."""
from __future__ import annotations
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parent))
import files


def main():
    if len(sys.argv) != 3:
        raise ValueError("expected request and request-sha256")
    request_raw, request_pin = files.read(sys.argv[1])
    files.require(hashlib.sha256(request_raw).hexdigest() == sys.argv[2], "request SHA differs")
    request = json.loads(request_raw)
    root = Path(request["actual_root"])
    final = {
        "schema": "hepta.hia.fixed-transport-source4-final.v1", "status": "HOLD",
        "request_sha256": request_pin["sha256"], "source83_executed": False,
        "native_executed": False, "assembler_oracle_executed": False,
        "owner_started": False,
    }
    closed = False
    root_created = False
    parent_pins = []
    try:
        files.require(request["qualification_seconds"] == 180 and request["cleanup_seconds"] == 3,
                      "fixed source owner budgets differ")
        files.require(request["expected_methods"] == 4 and len(request["expected_ids"]) == 4,
                      "four source methods required")
        for row in request["control_pins"]:
            files.read(row["path"], row)
        runtime = request["runtime"]
        files.require(str(Path(sys.executable).resolve(strict=True)) == runtime["path"],
                      "current interpreter path differs")
        files.read(runtime["path"], runtime)
        files.require(sys.version == request["runtime_version"], "runtime version differs")
        files.read(request["owner"]["path"], request["owner"])
        space = os.statvfs(root.parent)
        resource = {"available_bytes": space.f_bavail * space.f_frsize,
                    "available_inodes": space.f_favail,
                    "frsize": space.f_frsize, "f_bavail": space.f_bavail,
                    "minimum_available_bytes": request["minimum_available_bytes"],
                    "minimum_available_inodes": request["minimum_available_inodes"]}
        files.require(resource["available_bytes"] >= request["minimum_available_bytes"]
                      and resource["available_inodes"] >= request["minimum_available_inodes"],
                      "fresh source-control resource preflight refused")
        files.mkdir_new(root)
        root_created = True
        parent_pins.append(files.save(root / "RESOURCE-PREFLIGHT.json", resource))
        specification = importlib.util.spec_from_file_location("fixed_transport_process_owner",
                                                              request["owner"]["path"])
        owner = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(owner)
        command = [runtime["path"], "-I", "-S", "-B", request["worker"],
                   request["source_root"], str(root / "cases"), str(root / "SOURCE4.json"),
                   str(Path(sys.argv[1]).absolute()), request_pin["sha256"]]
        environment = {"PATH": "", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
        final["owner_started"] = True
        wrapper = owner.run_owned(
            command, cwd=request["source_root"], env=environment,
            stdout_path=root / "child.stdout.log", stderr_path=root / "child.stderr.log",
            receipt_path=root / "lifecycle.json", qualification_seconds=180, cleanup_seconds=3)
        parent_pins.append(files.save(root / "owner-wrapper.json", wrapper))
        provisional = wrapper.get("cleanup", {})
        files.require(type(wrapper.get("supervisor_returncode")) is int
                      and type(wrapper.get("receipt_sha256")) is str
                      and provisional.get("complete") is True
                      and provisional.get("observed_echild") is True
                      and provisional.get("leader_reaped") is True
                      and provisional.get("deadline_exceeded") is False
                      and provisional.get("errors") == []
                      and provisional.get("remaining_direct_children") == [],
                      "owner closure is unconfirmed; child originals must not be read")
        life, life_raw, life_pin = files.json_read(root / "lifecycle.json", owned=True)
        owner_request, owner_request_raw, owner_request_pin = files.json_read(root / "lifecycle.json.request.json", owned=True)
        files.require(wrapper.get("receipt_sha256") == life_pin["sha256"],
                      "wrapper raw owner receipt SHA differs")
        files.require({key: value for key, value in wrapper.items()
                       if key not in {"receipt_sha256", "supervisor_returncode"}} == life,
                      "wrapper-to-original owner projection differs")
        files.require(life["request_sha256"] == owner_request_pin["sha256"]
                      and owner_request["command"] == command
                      and owner_request["cwd"] == request["source_root"]
                      and owner_request["env"] == environment
                      and owner_request["qualification_seconds"] == 180
                      and owner_request["cleanup_seconds"] == 3
                      and owner_request["implementation_sha256"] == request["owner"]["sha256"],
                      "actual owned command or input identity differs")
        cleanup = life["cleanup"]
        files.require(life["schema"] == "hepta.hia.selfhost-process-owner.v1"
                      and life["qualification_seconds"] == 180 and life["cleanup_seconds"] == 3
                      and life["implementation_sha256"] == request["owner"]["sha256"]
                      and life["subreaper_enabled"] is True
                      and cleanup["complete"] is True and cleanup["observed_echild"] is True
                      and cleanup["leader_reaped"] is True and cleanup["deadline_exceeded"] is False
                      and cleanup["errors"] == [] and cleanup["remaining_direct_children"] == [],
                      "bound original owner does not confirm ECHILD closure")
        closed = True
        final.update(closed_owner_confirmed=True, lifecycle=life_pin,
                     owner_request=owner_request_pin)
        files.require(wrapper["supervisor_returncode"] == 0
                      and life["schema"] == "hepta.hia.selfhost-process-owner.v1"
                      and life["status"] == "OWNED_PROCESS_COMPLETED"
                      and life["returncode"] == 0 and life["timed_out"] is False
                      and life["exit_observed_before_deadline"] is True
                      and life["subreaper_enabled"] is True
                      and life.get("owner_error") is None
                      and life["interrupted_signals"] == [] and life["event_overflow"] is False
                      and cleanup["complete"] is True and cleanup["observed_echild"] is True
                      and cleanup["leader_reaped"] is True and cleanup["deadline_exceeded"] is False
                      and cleanup["errors"] == [] and cleanup["remaining_direct_children"] == []
                      and [row["kind"] for row in life["events"]] == [
                          "qualification_started", "owned_child_observed",
                          "qualification_exit_observed", "owned_child_reaped"],
                      "source owner did not close naturally")
        report, report_raw, report_pin = files.json_read(root / "SOURCE4.json", owned=True)
        files.require(report["status"] == "SOURCE_CONTROLS_PASS"
                      and report["expected_methods"] == 4
                      and report["expected_ids"] == request["expected_ids"]
                      and report["loaded_ids"] == request["expected_ids"]
                      and report["executed_ids"] == request["expected_ids"]
                      and all(report[key] == [] for key in (
                          "failures", "errors", "skipped", "expectedFailures", "unexpectedSuccesses",
                          "native_or_compiler_or_process_attempts"))
                      and report.get("error") is None and report.get("preservation_error") is None
                      and report["source_inputs_stable"] is True
                      and report["request_sha256"] == request_pin["sha256"],
                      "four complete source controls required")
        before, _, before_pin = files.json_read(root / "cases/INPUTS-BEFORE.json", owned=True)
        after, _, after_pin = files.json_read(root / "cases/INPUTS-AFTER.json", owned=True)
        files.require(before == after and len(before) == len(request["input_pins"]),
                      "original input snapshots differ")
        final.update(status="SOURCE4_PASS", source_report=report_pin,
                     inputs_before=before_pin, inputs_after=after_pin,
                     lifecycle=life_pin, owner_request=owner_request_pin,
                     source4_seconds=report["seconds"])
    except BaseException:
        final["status"] = "HOLD"
        final["error"] = traceback.format_exc()
    finally:
        final["closed_owner_confirmed"] = closed
        destination = root / "FINAL.json" if root_created else Path(request["prelaunch_hold"])
        parent_pins.append(files.save(destination, final))
        if root_created and closed:
            originals = []
            for path in sorted(root.rglob("*")):
                if path.is_file():
                    _, pin = files.read(path, owned=True)
                    originals.append(pin)
            files.save(root / "ORIGINALS.json", {"files": originals,
                       "closed_owner_confirmed": True, "child_originals_read": True})
        elif root_created:
            files.save(root / "PARENT-OBSERVATIONS.json", {
                "files": parent_pins, "closed_owner_confirmed": False,
                "child_originals_read": False,
                "scope": "Only files written by this parent; no traversal or child-body read."})
    print(json.dumps({"status": final["status"], "owner_started": final["owner_started"],
                      "source4_seconds": final.get("source4_seconds")}))
    return 0 if final["status"] == "SOURCE4_PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())

