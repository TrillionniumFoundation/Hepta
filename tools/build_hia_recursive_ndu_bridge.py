#!/usr/bin/env python3
"""Build the original private-ci NDU crates and bind source/tool/binary identity.

This script never edits the native crates or downloads a replacement evaluator.
The standalone bridge lock is generated once; subsequent builds use --locked.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess
import time


def run(argv: list[str], *, cwd: Path, env: dict[str, str]) -> str:
    completed = subprocess.run(argv, cwd=cwd, env=env, text=True, capture_output=True)
    if completed.returncode:
        raise RuntimeError(f"{argv[0]} failed ({completed.returncode}):\n{completed.stderr}")
    return completed.stdout.strip()


def source_inventory(root: Path, paths: list[Path]) -> tuple[str, dict[str, str]]:
    inventory = {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
                 for path in sorted(set(paths))}
    digest = hashlib.sha256(json.dumps(inventory, sort_keys=True,
                                      separators=(",", ":")).encode()).hexdigest()
    return digest, inventory


def build(args: argparse.Namespace) -> Path:
    started, cpu = time.monotonic_ns(), time.process_time_ns()
    children = resource.getrusage(resource.RUSAGE_CHILDREN)
    root = args.ndu_source.resolve(strict=True)
    bridge = root / "tools/hia-ndu-bridge"
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    target_preexisting = (output / "target").exists()
    cargo = str(args.cargo.resolve(strict=True))
    rustc = str(args.rustc.resolve(strict=True))
    env = dict(os.environ)
    env["RUSTC"] = rustc
    env["CARGO_TARGET_DIR"] = str(output / "target")
    if args.cargo_home:
        env["CARGO_HOME"] = str(args.cargo_home.resolve())
    env["PATH"] = os.pathsep.join([str(Path(cargo).parent), str(Path(rustc).parent), env.get("PATH", "")])
    commit = run(["git", "rev-parse", "HEAD"], cwd=root, env=env)
    if args.expected_source and commit != args.expected_source:
        raise RuntimeError("source commit differs from the requested pin")
    compiler = run([rustc, "--version"], cwd=root, env=env)
    if not (bridge / "Cargo.lock").exists():
        command = [cargo, "generate-lockfile", "--manifest-path", str(bridge / "Cargo.toml")]
        if args.offline:
            command.append("--offline")
        run(command, cwd=bridge, env=env)
    native_paths = [root / "codex-rs/Cargo.toml"]
    for name in ("hepta-ndu", "hepta-types", "hepta-contracts"):
        crate = root / "codex-rs" / name
        native_paths.append(crate / "Cargo.toml")
        native_paths.extend((crate / "src").rglob("*.rs"))
    native_digest, native_inventory = source_inventory(root, native_paths)
    bridge_paths = [bridge / "Cargo.toml", bridge / "Cargo.lock", *(bridge / "src").rglob("*.rs")]
    bridge_digest, bridge_inventory = source_inventory(root, bridge_paths)
    env.update(HEPTA_NDU_SOURCE_COMMIT=commit, HEPTA_NDU_SOURCE_DIGEST=native_digest,
               HEPTA_NDU_BRIDGE_DIGEST=bridge_digest, HEPTA_NDU_RUSTC=compiler)
    command = [cargo, "build", "--release", "--locked", "--manifest-path", str(bridge / "Cargo.toml")]
    if args.offline:
        command.append("--offline")
    run(command, cwd=bridge, env=env)
    binary = output / "target/release" / ("hepta-hia-ndu-bridge.exe" if os.name == "nt" else "hepta-hia-ndu-bridge")
    identity = json.loads(run([str(binary), "--identity"], cwd=bridge, env=env))
    if identity.get("source_digest") != native_digest or identity.get("bridge_digest") != bridge_digest:
        raise RuntimeError("built executable has stale source identity")
    # Detect concurrent source changes while Cargo was compiling.
    if source_inventory(root, native_paths)[0] != native_digest or source_inventory(root, bridge_paths)[0] != bridge_digest:
        raise RuntimeError("source changed during compilation")
    manifest = {"schema": "hepta.hia.ndu.build.v1", "binary": str(binary),
                "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "identity": identity, "native_sources": native_inventory,
                "bridge_sources": bridge_inventory, "build_command": command,
                "build_tools": {"builder_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                                "cargo_sha256": hashlib.sha256(Path(cargo).read_bytes()).hexdigest(),
                                "rustc_sha256": hashlib.sha256(Path(rustc).read_bytes()).hexdigest()},
                "native_source_repository": "https://github.com/TrillionniumFoundation/hepta-private-ci",
                "authority": "DENY_ALL", "safety_certificate": False}
    after_children = resource.getrusage(resource.RUSAGE_CHILDREN)
    manifest["build_cost"] = {
        "wall_ns": time.monotonic_ns() - started,
        "parent_cpu_ns": time.process_time_ns() - cpu,
        "child_cpu_ns": round(1e9 * ((after_children.ru_utime - children.ru_utime) +
                                      (after_children.ru_stime - children.ru_stime))),
        "target_cache": "existing" if target_preexisting else "empty",
        "dependency_cache": "caller supplied; downloads charged if incurred",
        "scope": "source admission, inventory, cargo, binary admission; excludes this manifest write and process startup",
        "fully_cold_machine_claim": False,
    }
    target = output / "identity.json"
    target.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return target


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ndu-source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cargo", type=Path, required=True)
    parser.add_argument("--rustc", type=Path, required=True)
    parser.add_argument("--cargo-home", type=Path)
    parser.add_argument("--expected-source")
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    print(build(args))


if __name__ == "__main__":
    main()
