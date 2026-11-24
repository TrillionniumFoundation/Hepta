"""Build the selected CPython Slot transport; never substitute for an HIA gate.

The caller supplies the external process supervisor/deadline. This operation
introduces no production retry, wall-time limit, compiler seed, or Native image.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
MECHANICAL_SOURCES = (
    "hepta/native/slot_mechanical.c", "hepta/hia_slot_continuations.py",
    "hepta/hia_slot_mechanical.py", "hepta/hia_slot_operations_native.py",
    "hepta/hia_slot_operations_selection.py", "hepta/hia_slot_operations_protocol.py",
    "hepta/hia_slot_operation_series.py", "hepta/hia_native_delivery.py",
    "hepta/hia_native_helpers.py", "hepta/hia_native_host_support.py",
    "hepta/hia_mechanical_worker_bundle.py", "hepta/native/slot_mechanical_build.py",
)
SOURCES = MECHANICAL_SOURCES + (
    "tools/build_hia_slot_mechanical.py", "setup.py", "pyproject.toml", "MANIFEST.in",
)

def pin(raw):
    return {"bytes": len(raw), "sha256": sha256(raw).hexdigest()}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--in-place", action="store_true",
                        help="explicitly install only the built binary/receipt beside source")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    before = {name: (ROOT / name).read_bytes() for name in SOURCES}
    command = [sys.executable, "-I", "-B", str(ROOT / "setup.py"), "build_ext",
               "--force", "--build-lib", str(output / "lib"),
               "--build-temp", str(output / "objects")]
    if args.in_place:
        command.append("--inplace")
    start = {"schema": "hepta.slot.mechanical.compiler-attempt.v1",
             "scope": "CPYTHON_MECHANICAL_EXTENSION_ONLY",
             "argv": command, "cwd": str(ROOT), "pid": os.getpid(),
             "ppid": os.getppid(), "pgid": os.getpgrp(),
             "started_ns": time.time_ns(),
             "source_before": {name: pin(raw) for name, raw in before.items()},
             "qualification_claimed": False,
             "compiler_selection": {name: os.environ.get(name) for name in
                                    ("CC", "CFLAGS", "CPPFLAGS", "LDFLAGS", "LDSHARED")}}
    (output / "started.json").write_text(json.dumps(start, indent=2, sort_keys=True) + "\n")
    # The actual parent workflow_process owns this process group and all
    # compiler descendants; this command does not create a detached group.
    result = subprocess.run(command, cwd=ROOT)
    stable = all((ROOT / name).read_bytes() == raw for name, raw in before.items())
    location = ROOT / "hepta" if args.in_place else output / "lib/hepta"
    identity = location / "_slot_mechanical_build.json"
    raw = identity.read_bytes() if result.returncode == 0 and identity.is_file() else None
    value = json.loads(raw) if raw is not None else None
    verified = False
    if value is not None:
        binary = location / value["binary"]["name"]
        binary_raw = binary.read_bytes()
        verified = (
            value["schema"] == "hepta.slot.mechanical.build.v2"
            and value["product_qualification_claimed"] is False
            and value["binary"] == {"name": binary.name, **pin(binary_raw)}
            and set(value["sources"]) == set(MECHANICAL_SOURCES)
            and all(value["sources"][name] == pin(before[name])
                    for name in MECHANICAL_SOURCES)
            and identity.read_bytes() == raw)
    report = {**start, "ended_ns": time.time_ns(), "returncode": result.returncode,
              "source_after_equal": stable, "extension_receipt_verified": verified,
              "identity_path": str(identity), "identity": None if raw is None else pin(raw),
              "status": "BUILT_NOT_QUALIFIED" if result.returncode == 0 and stable and verified else "HOLD"}
    (output / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return 0 if report["status"] == "BUILT_NOT_QUALIFIED" else 1

if __name__ == "__main__":
    raise SystemExit(main())
