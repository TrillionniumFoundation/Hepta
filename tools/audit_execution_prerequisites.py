#!/usr/bin/env python3
"""Record available execution prerequisites without issuing an API request.

Only the presence of the adapter's documented environment key is inspected.
No credential value, HTTP request, paid model call, device control, or remote
machine inference is part of this inventory.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys


def inspect(probe_dns=False):
    report = {"schema": "hepta.execution-prerequisites.v1", "status": "recorded",
              "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "host": {"system": platform.system(), "machine": platform.machine(),
                       "kernel": platform.release()},
              "tools_present": {name: shutil.which(name) is not None for name in ("gcc", "clang", "gdb", "bwrap", "nvcc", "nvidia-smi")},
              "model_access": {"documented_api_key_present": bool(os.environ.get("OPENAI_API_KEY")),
                               "credential_value_recorded": False, "dns": {"status": "not_attempted"},
                               "tls_attempted": False, "http_requests_issued": 0,
                               "model_calls_issued_by_this_audit": 0,
                               "model_revisions_and_budget_inspected": False},
              "devices": {},
              "claims": {"additional_native_hosts_executed": False, "physical_board_qualified": False,
                         "gpu_device_qualified": False, "actual_model_trial_completed": False}}
    for name, patterns in {"gpu": ["/dev/nvidia[0-9]*", "/dev/dri/renderD*"],
                           "serial_board_interfaces": ["/dev/ttyUSB*", "/dev/ttyACM*"]}.items():
        found = []
        for pattern in patterns:
            path = Path(pattern)
            found += [str(p) for p in path.parent.glob(path.name)]
        report["devices"][name] = {"matching_paths": sorted(set(found)),
                                    "device_opened_or_executed": False,
                                    "absence_is_only_this_process_namespace": True}
    if probe_dns:
        code = """import json,socket
try:
    results=socket.getaddrinfo('api.openai.com',443,type=socket.SOCK_STREAM)
    print(json.dumps({'status':'resolved','address_count':len(results)}))
except OSError as exc:
    print(json.dumps({'status':'failed','error_class':type(exc).__name__,'errno':exc.errno}))
"""
        try:
            proc = subprocess.run([sys.executable, "-c", code], text=True, capture_output=True, timeout=8)
            report["model_access"]["dns"] = json.loads(proc.stdout) if proc.returncode == 0 else {"status": "probe_process_failed", "returncode": proc.returncode}
        except subprocess.TimeoutExpired:
            report["model_access"]["dns"] = {"status": "timeout", "seconds": 8}
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe-api-dns", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = inspect(args.probe_api_dns)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps({"status": "recorded", "output": str(args.output),
                      "key_present": report["model_access"]["documented_api_key_present"],
                      "dns": report["model_access"]["dns"]}))


if __name__ == "__main__":
    main()
