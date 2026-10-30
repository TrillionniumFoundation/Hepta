#!/usr/bin/env python3
"""Measure the original finite NDU build from an absent target directory.

The outer measurement includes process startup and the builder's final manifest
write. It does not relabel toolchain acquisition, human work or all machine
caches as known cold costs. Failed attempts and original streams are retained.
"""
import argparse
from hashlib import sha256
import json
import os
import signal
from pathlib import Path
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[1]
PIN = "4b6391e116949af0c7e59776baead67271856bdb"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ndu-source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target-dir", type=Path, required=True)
    parser.add_argument("--cargo", type=Path, required=True)
    parser.add_argument("--rustc", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    if args.target_dir.exists():
        raise ValueError("the registered native target directory must not already exist")
    builder = ROOT / "tools/build_hia_recursive_ndu_bridge.py"
    builder_before = sha256(builder.read_bytes()).hexdigest()
    native = args.output / "original"
    command = [sys.executable, str(builder), "--ndu-source", str(args.ndu_source),
        "--expected-source", PIN, "--output", str(native), "--target-dir", str(args.target_dir),
        "--cargo", str(args.cargo), "--rustc", str(args.rustc)]
    report = {"schema": "hepta.hia.ndu.outer-build-cost.v1", "native_source_pin": PIN,
        "command": command, "builder_sha256": builder_before, "target_cache": "empty",
        "returncode": None, "identity_sha256": None, "binary_sha256": None,
        "source_unchanged": False, "authority": "DENY_ALL", "safety_certificate": False,
        "scope": "original subprocess, source/blob checks, compilation, original streams and final inner manifest write",
        "excluded_unknown": ["toolchain acquisition", "dependency-cache prior history", "human work",
            "persistent storage", "outer receipt write"], "fully_cold_machine_claim": False}
    start = time.monotonic_ns()
    try:
        with (args.output / "build.stdout").open("xb") as stdout, (args.output / "build.stderr").open("xb") as stderr:
            process = subprocess.Popen(command, cwd=ROOT, stdout=stdout, stderr=stderr,
                start_new_session=True,
                env={**os.environ, "CARGO_INCREMENTAL": "0", "CARGO_PROFILE_RELEASE_DEBUG": "0"})
            try:
                returncode = process.wait(timeout=1800)
            except BaseException:
                # The unreaped process retains its PID while its owned group is
                # stopped. A failed timeout is never successful build evidence.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=15)
                raise
        report["wall_ns"] = time.monotonic_ns() - start
        report["returncode"] = returncode
        if returncode:
            raise RuntimeError("original finite NDU build failed; retained build.stderr")
        identity = native / "identity.json"
        raw = identity.read_bytes()
        manifest = json.loads(raw)
        report["identity_sha256"] = sha256(raw).hexdigest()
        report["binary_sha256"] = sha256(Path(manifest["binary"]).read_bytes()).hexdigest()
        report["source_unchanged"] = (manifest["source_admission"]["before"] == manifest["source_admission"]["after"]
            and sha256(builder.read_bytes()).hexdigest() == builder_before)
        if (not report["source_unchanged"] or manifest["identity"]["source_commit"] != PIN
                or report["binary_sha256"] != manifest["binary_sha256"]
                or manifest["build_cost"]["target_cache"] != "empty"
                or manifest["build_cost"]["wall_ns"] > report["wall_ns"]):
            raise RuntimeError("original build does not meet the registered source/empty-target contract")
        report["status"] = "measured"
    except Exception as exc:
        report.setdefault("wall_ns", time.monotonic_ns() - start)
        report.update(status="failed", error={"type": type(exc).__name__, "message": str(exc)})
    report["streams"] = {name: {"sha256": sha256((args.output / name).read_bytes()).hexdigest(),
        "bytes": (args.output / name).stat().st_size} for name in ("build.stdout", "build.stderr")
        if (args.output / name).is_file()}
    (args.output / "OUTER.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": report["status"], "wall_ns": report["wall_ns"],
                      "output": str(args.output), "error": report.get("error")}))
    return 0 if report["status"] == "measured" else 1


if __name__ == "__main__":
    raise SystemExit(main())
