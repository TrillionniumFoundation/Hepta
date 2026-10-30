"""Exact-source, empty-target builds of separately identified native controls."""
from __future__ import annotations
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import signal
import selectors
import threading
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


def run_bounded(argv, *, cwd, env, timeout, receipt_prefix):
    """Own the process group until termination and preserve every observed byte.

    No poll/wait/communicate reaps the leader before group cleanup. WNOWAIT
    keeps its PID reserved even when the leader exits before descendants.
    This Linux runner requires sole child-reaping ownership. It does not claim
    containment of a child that deliberately escapes its original group.
    """
    prefix = Path(receipt_prefix)
    prefix.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic_ns()
    receipt = {"schema": "hepta.ndu.owned-process.v1", "argv": list(argv),
        "cwd": str(cwd), "timeout_seconds": timeout, "timed_out": False,
        "leader_reaped": False, "owned_group_terminated": False, "owned_group_kill_sent": False,
        "safe_target_cleanup": True, "raw_stream_scope": "all observed bytes; EOF completeness recorded",
        "escaped_process_group_containment_claim": False}
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    selector = selectors.DefaultSelector()
    process, failure = None, None
    cleanup_errors = []
    previous_mask = None

    def drain(wait):
        for key, _ in selector.select(wait):
            raw = os.read(key.fd, 65536)
            if raw:
                buffers[key.data].extend(raw)
            else:
                selector.unregister(key.fd)

    try:
        if threading.active_count() != 1 or signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
            raise RuntimeError("owned process runner requires sole child-reaping ownership")
        if timeout <= 0:
            raise TimeoutError("owned process deadline elapsed before launch")
        process = subprocess.Popen(argv, cwd=cwd, env=env, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True)
        receipt.update(pid=process.pid, safe_target_cleanup=False)
        for label in buffers:
            stream = getattr(process, label)
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, label)
        deadline = started/1_000_000_000 + timeout
        while True:
            # Observe without reaping. Until cleanup, process.pid cannot be reused.
            exited = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if exited is not None and not selector.get_map():
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                receipt["timed_out"] = True
                break
            drain(min(0.05, remaining))
    except BaseException as error:
        failure = error
        receipt["error"] = type(error).__name__ + ": " + str(error)
    finally:
        # A second SIGINT must not interrupt reaping or raw-evidence persistence.
        # Restore the prior mask only after the receipt has reached disk.
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT})
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
                receipt["owned_group_kill_sent"] = True
            except ProcessLookupError:
                receipt["owned_group_kill_sent"] = True
            except BaseException as error:
                cleanup_errors.append(type(error).__name__ + ": " + str(error))
            try:
                deadline = time.monotonic() + 5
                while selector.get_map() and time.monotonic() < deadline:
                    drain(min(0.05, max(0, deadline-time.monotonic())))
                receipt["streams_reached_eof"] = not bool(selector.get_map())
            except BaseException as error:
                cleanup_errors.append(type(error).__name__ + ": " + str(error))
                receipt["streams_reached_eof"] = False
            # SIGKILL delivery is not itself proof that descendants have
            # finished their last syscall. Keep the leader unreaped (and thus
            # the group id reserved) until /proc shows no live group member.
            try:
                deadline = time.monotonic() + 5
                while True:
                    live = []
                    for entry in Path("/proc").iterdir():
                        if not entry.name.isdigit():
                            continue
                        try:
                            fields = (entry / "stat").read_text().rsplit(") ", 1)[1].split()
                        except (FileNotFoundError, ProcessLookupError):
                            continue
                        if int(fields[2]) == process.pid and fields[0] not in ("Z", "X"):
                            live.append({"pid": int(entry.name), "state": fields[0]})
                    receipt["live_group_members_after_signal"] = live
                    if not live:
                        receipt["owned_group_terminated"] = True
                        break
                    if time.monotonic() >= deadline:
                        raise TimeoutError("owned process group did not reach quiescence")
                    os.killpg(process.pid, signal.SIGKILL)
                    time.sleep(0.01)
            except BaseException as error:
                cleanup_errors.append(type(error).__name__ + ": " + str(error))
            try:
                process.wait(timeout=5)
                receipt["leader_reaped"] = True
                receipt["returncode"] = process.returncode
            except BaseException as error:
                cleanup_errors.append(type(error).__name__ + ": " + str(error))
                receipt["returncode"] = None
            receipt["safe_target_cleanup"] = bool(receipt["owned_group_terminated"] and receipt["leader_reaped"])
            for label in buffers:
                getattr(process, label).close()
        else:
            receipt.update(returncode=None, streams_reached_eof=True)
        selector.close()
        if cleanup_errors or not receipt.get("streams_reached_eof", False):
            receipt["cleanup_errors"] = cleanup_errors
            if failure is None:
                failure = RuntimeError("owned process cleanup or complete pipe drain failed")
                receipt["error"] = type(failure).__name__ + ": " + str(failure)
        receipt["wall_ns"] = time.monotonic_ns()-started
        try:
            for label, raw in buffers.items():
                path = Path(str(prefix) + "." + label)
                with path.open("xb") as stream:
                    stream.write(raw)
                receipt[label] = {"path": path.name, "bytes": len(raw), "sha256": sha256(raw).hexdigest()}
            write_json(Path(str(prefix) + ".process.json"), receipt)
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
    if failure is not None:
        failure.owned_process_receipt = receipt
        raise failure
    completed = subprocess.CompletedProcess(argv, process.returncode, bytes(buffers["stdout"]), bytes(buffers["stderr"]))
    completed.owned_process_receipt = receipt
    return completed, receipt["timed_out"]


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
    cleanup_allowed = True
    def command(argv):
        nonlocal cleanup_allowed
        n = len(commands)
        remaining = timeout - (time.monotonic_ns()-started)/1e9
        if remaining <= 0:
            raise TimeoutError("bounded control build deadline reached")
        prefix = output / f"command-{n:02d}"
        receipt_path = Path(str(prefix) + ".process.json")
        cleanup_allowed = False
        try:
            run, timed_out = run_bounded(argv, cwd=CRATE, env=env, timeout=remaining, receipt_prefix=prefix)
        finally:
            if receipt_path.exists():
                row = json.loads(receipt_path.read_bytes())
                commands.append(row)
                cleanup_allowed = row.get("safe_target_cleanup") is True
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
        if target.exists() and cleanup_allowed:
            # Only this invocation's new target, after owned descendants stop.
            shutil.rmtree(target)
        elif target.exists():
            report.update(ok=False, target_retained_due_to_unconfirmed_process_cleanup=True)
        report["target_cleanup_ns"] = time.monotonic_ns() - cleanup
        report["total_build_and_cleanup_ns"] = time.monotonic_ns() - started
        report["commands"] = commands
        write_json(output / "BUILD.json", report)
