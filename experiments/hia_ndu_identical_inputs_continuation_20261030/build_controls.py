"""Exact-source, empty-target builds of separately identified native controls."""
from __future__ import annotations
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
CRATE = HERE / "native_control"
CRATE_FILES = ("Cargo.toml", "Cargo.lock", "src/main.rs")
EXPECTED_RUSTC = "rustc 1.90.0 (1159e78c4 2025-09-14)"
EXPECTED_CARGO = "cargo 1.90.0 (840b83a10 2025-07-30)"
TOOL_PINS = {
    "cargo": "51de284e8bb0d03dcee595a0fb1cb3a952fe9e7e4b953a8b1467b7f71725b561",
    "rustc": "e6abf55ab1859e7c990be77fd593f51661ea99fb2fde626ae9f4108aaa34e7fa",
}
ALGORITHMS = {"native-exact-dp": "exact-suffix-dp", "native-myopic": "myopic-first-batch"}


def file_sha(path):
    with Path(path).open("rb") as stream:
        from hashlib import file_digest
        return file_digest(stream, "sha256").hexdigest()


def write_json(path, value):
    with Path(path).open("x") as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n")


def crate_identity():
    files = {name: file_sha(CRATE / name) for name in CRATE_FILES}
    return files, sha256(json.dumps(files, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def admit_blob(commit, relative, expected):
    if not re.fullmatch("[0-9a-f]{40}", commit):
        raise ValueError("a complete source commit is required")
    raw = subprocess.check_output(["git", "cat-file", "blob", commit + ":" + relative], cwd=ROOT)
    if sha256(raw).hexdigest() != expected or file_sha(ROOT / relative) != expected:
        raise ValueError("source file differs from its committed blob: " + relative)


def run_bounded(argv, *, cwd, env, timeout):
    process = subprocess.Popen(argv, cwd=cwd, env=env, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True)
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        os.killpg(process.pid, signal.SIGTERM)
        try:
            stdout, stderr = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate(timeout=5)
    return subprocess.CompletedProcess(argv, process.returncode, stdout, stderr), timed_out


def build_control(arm, output, *, cargo, rustc, cargo_home, source_commit=None, timeout=300):
    if arm not in ALGORITHMS:
        raise ValueError("unknown control arm")
    output = Path(output).absolute()
    output.mkdir(parents=True, exist_ok=False)
    target = output / "empty-target"
    if target.exists():
        raise ValueError("control target must not preexist")
    before, source_digest = crate_identity()
    source_name = source_commit if source_commit else "uncommitted-development"
    if source_commit:
        for name, expected in before.items():
            admit_blob(source_commit, str((CRATE / name).relative_to(ROOT)), expected)
    cargo, rustc, cargo_home = map(lambda p: Path(p).resolve(strict=True), (cargo, rustc, cargo_home))
    for name, path in (("cargo", cargo), ("rustc", rustc)):
        if file_sha(path) != TOOL_PINS[name]:
            raise ValueError("pinned Rust tool mismatch: " + name)
    env = dict(os.environ)
    env.update(RUSTC=str(rustc), CARGO_HOME=str(cargo_home), CARGO_TARGET_DIR=str(target),
               CONTROL_SOURCE_COMMIT=source_name, CONTROL_SOURCE_DIGEST=source_digest,
               CONTROL_RUSTC=EXPECTED_RUSTC, CONTROL_ALGORITHM=ALGORITHMS[arm])
    env["PATH"] = str(cargo.parent) + os.pathsep + str(rustc.parent) + os.pathsep + env.get("PATH", "")
    # One compiler job bounds transient memory; the same setting is used for
    # the original NDU build by the study runner and is recorded explicitly.
    env["CARGO_BUILD_JOBS"] = "1"
    commands = []
    started = time.monotonic_ns()
    report = {"schema": "hepta.native-control.empty-build.v1", "ok": False,
              "arm": arm, "target_cache": "empty", "dependency_cache": str(cargo_home),
              "source_commit": source_name, "source_files": before, "source_digest": source_digest,
              "build_jobs": 1, "acquisition_cost_ns": None, "human_cost_ns": None,
              "fully_cold_machine_claim": False, "authority": "DENY_ALL", "safety_certificate": False}
    def command(argv):
        n = len(commands)
        begin = time.monotonic_ns()
        remaining = timeout - (time.monotonic_ns()-started)/1e9
        if remaining <= 0:
            raise TimeoutError("bounded control build deadline reached")
        run, timed_out = run_bounded(argv, cwd=CRATE, env=env, timeout=remaining)
        elapsed = time.monotonic_ns() - begin
        row = {"argv": argv, "returncode": run.returncode, "wall_ns": elapsed, "timed_out": timed_out}
        for label, raw in (("stdout", run.stdout), ("stderr", run.stderr)):
            path = output / f"command-{n:02d}.{label}"
            path.write_bytes(raw)
            row[label] = {"path": path.name, "bytes": len(raw), "sha256": sha256(raw).hexdigest()}
        commands.append(row)
        if run.returncode or timed_out:
            raise RuntimeError("control build command failed: " + repr(argv))
        return run.stdout.decode().strip()
    try:
        if command([str(rustc), "--version"]) != EXPECTED_RUSTC or command([str(cargo), "--version"]) != EXPECTED_CARGO:
            raise ValueError("pinned tool version mismatch")
        command([str(cargo), "build", "--release", "--locked", "--offline",
                 "--manifest-path", str(CRATE / "Cargo.toml")])
        binary = output / ("hepta-" + arm)
        shutil.copy2(target / "release/hepta-prospective-native-controls", binary)
        identity = json.loads(command([str(binary), "--identity"]))
        if (identity.get("source_commit") != source_name or identity.get("source_digest") != source_digest
                or identity.get("bridge_digest") != source_digest or identity.get("rustc") != EXPECTED_RUSTC
                or identity.get("algorithms") != ["hepta.control." + ALGORITHMS[arm]]
                or identity.get("schema") != "hepta.hia.native-control.identity.v1"
                or identity.get("authority") != "DENY_ALL" or identity.get("safety_certificate") is not False):
            raise ValueError("built control identity differs")
        if crate_identity() != (before, source_digest):
            raise ValueError("control source changed during build")
        if source_commit:
            for name, expected in before.items():
                admit_blob(source_commit, str((CRATE / name).relative_to(ROOT)), expected)
        report.update(ok=True, identity=identity, binary_sha256=file_sha(binary),
                      binary=str(binary), build_wall_ns=time.monotonic_ns()-started)
        manifest = {"schema": "hepta.hia.ndu.build.v1", "binary": str(binary),
                    "binary_sha256": report["binary_sha256"], "identity": identity,
                    "control_build": report, "original_ndu_claim": False}
        write_json(output / "identity.json", manifest)
        return output / "identity.json"
    except BaseException as error:
        report.update(ok=False, error=type(error).__name__ + ": " + str(error),
                      build_wall_ns=time.monotonic_ns()-started)
        raise
    finally:
        cleanup = time.monotonic_ns()
        if target.exists():
            # Only this invocation's newly-created reproducible target.
            shutil.rmtree(target)
        report["target_cleanup_ns"] = time.monotonic_ns() - cleanup
        report["total_build_and_cleanup_ns"] = time.monotonic_ns() - started
        report["commands"] = commands
        write_json(output / "BUILD.json", report)
