#!/usr/bin/env python3
"""Build an independent Rust ordinary control with the frozen NDU compiler profile."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import shutil
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATHS = [
    "rust/hia-kernel-ordinary-control/Cargo.toml",
    "rust/hia-kernel-ordinary-control/Cargo.lock",
    "rust/hia-kernel-ordinary-control/src/main.rs",
    "tools/build_hia_kernel_ordinary_control.py",
    "tests/test_hia_kernel_ordinary_control.py",
    "docs/HIA_KERNEL_ORDINARY_CONTROL.md",
]
ENV_KEYS = ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_TARGET")


def binding(path):
    path = Path(path).resolve(strict=True)
    data = path.read_bytes()
    return {"path": str(path), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def child_cpu_ns():
    r = resource.getrusage(resource.RUSAGE_CHILDREN)
    return int((r.ru_utime + r.ru_stime) * 1e9)


def build(output, cargo, ndu_receipt, source_commit):
    started, parent_cpu, children_cpu = time.monotonic_ns(), time.process_time_ns(), child_cpu_ns()
    output = Path(output).resolve()
    if output.exists():
        raise ValueError("ordinary build output must be a new directory")
    if len(source_commit) != 40 or any(c not in "0123456789abcdef" for c in source_commit):
        raise ValueError("exact source commit required")
    baseline_path = Path(ndu_receipt).resolve(strict=True)
    baseline_identity = binding(baseline_path)
    baseline = json.loads(baseline_path.read_text())
    if baseline["original_rust_sources_unchanged"] is not True:
        raise ValueError("reference NDU build is not qualified as unchanged")
    cargo = str(Path(cargo).resolve(strict=True))
    env = dict(os.environ)
    rustc = env.get("RUSTC", str(Path(cargo).parent / "rustc"))
    cargo_version = subprocess.check_output([cargo, "--version"], env=env, text=True).strip()
    rustc_version = subprocess.check_output([rustc, "-vV"], env=env, text=True).strip()
    if cargo_version != baseline["cargo_version"] or rustc_version != baseline["rustc_version"]:
        raise ValueError("ordinary and frozen NDU compiler identities differ")
    if not cargo_version.startswith("cargo 1.95.0 ") or not rustc_version.startswith("rustc 1.95.0 "):
        raise ValueError("registered Rust 1.95.0 required")
    if "--release" not in baseline["build_command"]:
        raise ValueError("frozen NDU build is not release")
    observed_env = {k: env.get(k, "") for k in ENV_KEYS}
    if observed_env != {k: baseline["build_environment"].get(k, "") for k in ENV_KEYS}:
        raise ValueError("ordinary and frozen NDU code-generation environments differ")
    source_bindings = {p: binding(ROOT / p) for p in SOURCE_PATHS}
    output.mkdir(parents=True)
    crate = output / "crate"
    shutil.copytree(ROOT / "rust/hia-kernel-ordinary-control", crate)
    copied = {str(p.relative_to(crate)): binding(p) for p in sorted(crate.rglob("*")) if p.is_file()}
    if set(copied) != {"Cargo.toml", "Cargo.lock", "src/main.rs"}:
        raise ValueError("ordinary crate source closure is not exact")
    env.update({"RUSTC": rustc, "CARGO_INCREMENTAL": "0", "CARGO_PROFILE_DEV_DEBUG": "0",
                "CARGO_BUILD_JOBS": "1", "CARGO_TARGET_DIR": str(output / "target")})
    report = {"schema": "hepta.hia.kernel-ordinary-control.build.v1", "status": "RUNNING",
        "source_commit": source_commit, "sources": source_bindings,
        "reference_ndu_build_receipt": baseline_identity, "compiler_profile_equal": True,
        "cargo_version": cargo_version, "rustc_version": rustc_version,
        "cargo_executable": binding(cargo), "rustc_executable": binding(rustc),
        "build_environment": observed_env, "build_profile": "release", "build_jobs": 1,
        "target_directory_preexisting": False, "commands": []}

    def run(label, argv):
        start = time.monotonic_ns()
        with (output / (label + ".stdout")).open("xb") as out, (output / (label + ".stderr")).open("xb") as err:
            proc = subprocess.run(argv, cwd=crate, env=env, stdout=out, stderr=err, timeout=300)
        command = {"argv": argv, "exit_code": proc.returncode, "wall_ns": time.monotonic_ns() - start,
                   "stdout": binding(output / (label + ".stdout")), "stderr": binding(output / (label + ".stderr"))}
        report["commands"].append(command)
        if proc.returncode:
            raise RuntimeError(f"{label} failed: {proc.returncode}; see {command['stderr']['path']}")
        return (output / (label + ".stdout")).read_bytes()

    try:
        metadata = json.loads(run("metadata", [cargo, "metadata", "--manifest-path", str(crate / "Cargo.toml"),
            "--offline", "--locked", "--format-version", "1"]))
        packages = metadata["packages"]
        if any("hepta" in p["name"].lower() or (p.get("source") or "").startswith("git+") for p in packages):
            raise ValueError("ordinary control must not depend on Hepta or a Git source")
        report["dependency_packages"] = [{"name": p["name"], "version": p["version"],
                                         "source": p.get("source")} for p in packages]
        report["no_hepta_dependencies"] = True
        command = [cargo, "build", "--manifest-path", str(crate / "Cargo.toml"),
                   "--release", "--offline", "--locked"]
        run("cargo", command)
        executable = output / "target/release/hia-kernel-ordinary-control"
        identity = json.loads(run("identity", [str(executable), "--identity"]))
        if identity["profile"] != "hepta.hia.kernel-ordinary-control.v1" or identity["native_ndu_linked_or_called"]:
            raise ValueError("ordinary binary identity mismatch")
        report["identity"] = identity
        report["executable"] = binding(executable)
        for path, expected in source_bindings.items():
            if binding(ROOT / path) != expected:
                raise ValueError("ordinary source changed during build: " + path)
        for path, expected in copied.items():
            if binding(crate / path) != expected:
                raise ValueError("ordinary copied input changed during build: " + path)
        if binding(baseline_path) != baseline_identity:
            raise ValueError("frozen NDU receipt changed")
        report["build_inputs_unchanged"] = True
        report["locked_dependencies"] = True
        report["status"] = "PASS"
    except Exception as error:
        report["status"] = "FAIL"
        report["error"] = str(error)
        raise
    finally:
        report["build_cost"] = {"wall_ns": time.monotonic_ns() - started,
            "parent_cpu_ns": time.process_time_ns() - parent_cpu,
            "children_cpu_ns": child_cpu_ns() - children_cpu,
            "completed": report["status"] == "PASS"}
        (output / "build-receipt.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--cargo", required=True)
    p.add_argument("--ndu-build-receipt", required=True, type=Path)
    p.add_argument("--source-commit", required=True)
    args = p.parse_args()
    report = build(args.output, args.cargo, args.ndu_build_receipt, args.source_commit)
    print(json.dumps({"status": report["status"], "executable": report["executable"],
                      "no_hepta_dependencies": report["no_hepta_dependencies"],
                      "build_cost": report["build_cost"]}))


if __name__ == "__main__":
    main()
