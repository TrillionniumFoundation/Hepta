#!/usr/bin/env python3
"""Retain a complete outer cost receipt for one real empty-target native build.

The existing builder's detailed source and command evidence is unchanged. This
wrapper adds its process startup and final identity write to the measured cost.
"""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ndu-source", type=Path, required=True)
    parser.add_argument("--target-dir", type=Path, required=True)
    parser.add_argument("--cargo", type=Path, required=True)
    parser.add_argument("--rustc", type=Path, required=True)
    parser.add_argument("--cargo-home", type=Path, required=True)
    parser.add_argument("--expected-source", required=True)
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    started = time.monotonic_ns()
    output, target = args.output.resolve(), args.target_dir.resolve()
    if output.is_relative_to(ROOT) or target.is_relative_to(ROOT):
        raise ValueError("build outputs must be outside source")
    if target.exists() and any(target.iterdir()):
        raise ValueError("full-cost build requires a new empty target directory")
    if subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT):
        raise RuntimeError("complete build envelope requires clean committed source")
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    scripts = [Path(__file__), ROOT / "tools/build_hia_recursive_ndu_bridge.py"]
    source = {}
    for path in scripts:
        name, raw = str(path.relative_to(ROOT)), path.read_bytes()
        if subprocess.check_output(["git", "cat-file", "blob", commit + ":" + name], cwd=ROOT) != raw:
            raise RuntimeError("build wrapper differs from registered source")
        source[name] = sha256(raw).hexdigest()
    output.mkdir(parents=True, exist_ok=False)
    command = [sys.executable, str(scripts[1]), "--output", str(output / "build"),
               "--ndu-source", str(args.ndu_source.resolve()), "--target-dir", str(target),
               "--cargo", str(args.cargo.resolve()), "--rustc", str(args.rustc.resolve()),
               "--cargo-home", str(args.cargo_home.resolve()), "--expected-source", args.expected_source]
    if args.offline:
        command.append("--offline")
    with (output / "builder.stdout").open("xb") as stdout, (output / "builder.stderr").open("xb") as stderr:
        result = subprocess.run(command, stdout=stdout, stderr=stderr, check=False)
    identity = output / "build/identity.json"
    raw = identity.read_bytes() if identity.exists() else b""
    manifest = json.loads(raw) if raw else {}
    unchanged = all(sha256((ROOT / name).read_bytes()).hexdigest() == expected for name, expected in source.items())
    receipt = {"schema": "hepta.hia.ndu.outer-build-cost.v1", "source_commit": commit,
        "source_sha256": source, "source_unchanged": unchanged, "command": command,
        "returncode": result.returncode, "identity_sha256": sha256(raw).hexdigest(),
        "binary_sha256": manifest.get("binary_sha256"),
        "native_source_pin": manifest.get("identity", {}).get("source_commit"),
        "inner_build_cost": manifest.get("build_cost"), "target_cache": "empty",
        "wall_ns": time.monotonic_ns() - started,
        "scope": "outer source admission, builder process startup, complete builder, final manifest read; final envelope serialization excluded",
        "authority": "DENY_ALL", "safety_certificate": False}
    with (output / "BUILD_ENVELOPE.json").open("x") as stream:
        json.dump(receipt, stream, sort_keys=True, indent=2)
        stream.write("\n")
    print(output / "BUILD_ENVELOPE.json")
    if result.returncode or not unchanged:
        raise SystemExit(result.returncode or 1)


if __name__ == "__main__":
    main()
