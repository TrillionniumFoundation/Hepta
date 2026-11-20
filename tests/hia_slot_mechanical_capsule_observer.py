"""Explicit v5 candidate launcher around an unchanged complete observer."""
from __future__ import annotations
import argparse
from hashlib import sha256
import importlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
OBSERVERS = {
    "finite": ("tests.hia_slot_operations_observer", "tests/hia_slot_operations_observer.py"),
    "public": ("tests.hia_slot_operations_public_observer", "tests/hia_slot_operations_public_observer.py"),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--expected-bundle-sha256", required=True)
    parser.add_argument("--observer", choices=tuple(OBSERVERS), required=True)
    parser.add_argument("inner", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    outer = list(sys.argv)
    inner = args.inner[1:] if args.inner[:1] == ["--"] else args.inner
    module_name, relative = OBSERVERS[args.observer]
    if (not inner or Path(inner[0]).resolve(strict=True) != ROOT / relative
            or inner.count("--backend") != 1
            or inner[inner.index("--backend") + 1] != "native"
            or inner.count("--output") != 1):
        raise ValueError("mechanical launcher requires its exact native original observer")
    output = Path(inner[inner.index("--output") + 1]).resolve()
    bundle_path = args.bundle.resolve(strict=True)
    bundle_raw = bundle_path.read_bytes()
    if sha256(bundle_raw).hexdigest() != args.expected_bundle_sha256:
        raise ValueError("mechanical launcher administrator digest differs")
    observer_raw = (ROOT / relative).read_bytes()
    sys.path.insert(0, str(ROOT))
    from hepta.hia_native_helpers import native_helpers_scope, native_helpers_identity
    from hepta import hia_slot_mechanical as mechanical
    import fcntl
    import traceback
    marker = {
        "schema": "hepta.slot.mechanical.observer-launch.v1",
        "outer_argv": outer, "inner_argv": list(inner),
        "pid": os.getpid(), "ppid": os.getppid(), "pgid": os.getpgrp(),
        "bundle": {"path": str(bundle_path), "bytes": len(bundle_raw),
                   "sha256": args.expected_bundle_sha256},
        "observer": {"path": relative, "bytes": len(observer_raw),
                     "sha256": sha256(observer_raw).hexdigest()},
        "expected_observations_supplied": False,
    }
    status, error = None, None
    try:
        with native_helpers_scope(str(bundle_path), args.expected_bundle_sha256) as binding:
            from hepta.hia_native_helpers import selected_mechanical_bridge
            if selected_mechanical_bridge("slot-mechanical", mechanical.ABI) is not binding.bridge_owner:
                raise ValueError("candidate launcher did not select its actual v5 bridge")
            loaded = mechanical.extension()
            captured = mechanical._CAPTURED
            fd, seals = mechanical._SEALED
            marker["bridge"] = binding.bridge_owner.record
            marker["sealed_executable"] = {
                "bytes": len(captured["binary"]),
                "sha256": sha256(os.pread(fd, len(captured["binary"]) + 1, 0)).hexdigest(),
                "seals": fcntl.fcntl(fd, fcntl.F_GET_SEALS),
                "required_seals": seals, "actual_module_file": loaded.__file__,
                "abi": loaded.ABI, "modes": loaded.MODES, "ports": loaded.PORTS,
            }
            marker["counters_before"] = loaded.execution_counters()
            observer = importlib.import_module(module_name)
            sys.argv = list(inner)
            try:
                status = observer.main()
            finally:
                sys.argv = outer
            mechanical._check_exports(loaded)
            marker["counters_after"] = loaded.execution_counters()
            marker["terminal_identity"] = native_helpers_identity()
            if (bundle_path.read_bytes() != bundle_raw
                    or (ROOT / relative).read_bytes() != observer_raw):
                raise ValueError("mechanical launcher inputs changed")
    except BaseException as caught:
        error = {"type": type(caught).__module__ + "." + type(caught).__qualname__,
                 "message": str(caught), "traceback": traceback.format_exc()}
        raise
    finally:
        marker.update({"returned_code": status, "exception": error,
                       "scope": "actual v5 capsule plus unchanged complete native observer"})
        if output.is_dir():
            raw = json.dumps(marker, ensure_ascii=True, sort_keys=True,
                             separators=(",", ":"), allow_nan=False).encode("ascii") + b"\n"
            with (output / "mechanical-launch.json").open("xb") as stream:
                stream.write(raw)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
