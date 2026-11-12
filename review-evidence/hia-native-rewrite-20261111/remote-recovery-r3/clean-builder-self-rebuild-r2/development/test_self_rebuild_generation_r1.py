"""One actual complete ELF build, retaining exact source, output and limits.

The original whole-build tests used 120 CPU / 150 wall / 1 GiB.  This new local
development gate is stricter at 90 aggregate CPU and the same 150 wall; each
native peer still has the unchanged executor's 10 CPU / 20 wall / 256 MiB.
"""
from pathlib import Path
import ctypes
import hashlib
import json
import os
import resource
import signal
import stat
import struct
import subprocess
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parent
ORIGINAL = ROOT / "original-r13"
OUT = ROOT / "development/self-rebuild-generation1-r1"
OUT.mkdir(parents=True, exist_ok=False)
HOME = OUT / "empty-home"
HOME.mkdir()
EXE = ROOT / "development/build-self-rebuild-r1/hia-build-self-rebuilding"
KIT = ROOT / "development/self-rebuild-kit-r1/source-kit.hiabuild"
OLD_PACKAGE = ORIGINAL / "development/native-whole-r2/package.raw"
OLD_SUMMARY = ORIGINAL / "development/native-whole-r2/summary.json"

def digest(raw): return hashlib.sha256(raw).hexdigest()
def identity(path):
    raw = path.read_bytes()
    return {"path": str(path), "bytes": len(raw), "sha256": digest(raw), "mode": stat.S_IMODE(path.stat().st_mode)}
def unpack(raw):
    assert len(raw) >= 24
    magic, count, reserved = struct.unpack_from("<3Q", raw)
    assert magic == int.from_bytes(b"HIAREL01", "little") and count == 6 and reserved == 0
    at = 24
    result = {}
    for _ in range(count):
        assert at <= len(raw) - 24
        namesz, mode, size = struct.unpack_from("<3Q", raw, at)
        at += 24
        assert namesz <= len(raw) - at
        name = raw[at:at + namesz].decode("ascii")
        at += namesz
        assert size <= len(raw) - at and name not in result
        payload = raw[at:at + size]
        at += size
        result[name] = (mode, payload)
    assert at == len(raw)
    assert set(result) == {"hia", "hia-release", "hia-build", "compiler.bin", "source-kit.hiabuild", "build.json"}
    return result

parent_pid = os.getpid()
def setup():
    resource.setrlimit(resource.RLIMIT_CPU, (90, 90))
    resource.setrlimit(resource.RLIMIT_AS, (1 << 30, 1 << 30))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    libc = ctypes.CDLL(None, use_errno=True)
    assert libc.prctl(1, signal.SIGKILL, 0, 0, 0) == 0
    assert os.getppid() == parent_pid
    assert libc.prctl(4, 0, 0, 0, 0) == 0 and libc.prctl(3, 0, 0, 0, 0) == 0

started = time.monotonic_ns()
self0 = resource.getrusage(resource.RUSAGE_SELF)
children0 = resource.getrusage(resource.RUSAGE_CHILDREN)
def usage():
    self1 = resource.getrusage(resource.RUSAGE_SELF)
    children1 = resource.getrusage(resource.RUSAGE_CHILDREN)
    return {"elapsed_ns": time.monotonic_ns() - started,
            "aggregate_cpu_seconds": (self1.ru_utime + self1.ru_stime - self0.ru_utime - self0.ru_stime +
                                      children1.ru_utime + children1.ru_stime - children0.ru_utime - children0.ru_stime),
            "self_maxrss_kib": self1.ru_maxrss, "children_maxrss_kib": children1.ru_maxrss}
inputs = [Path(__file__), EXE, KIT, OLD_PACKAGE, OLD_SUMMARY,
          ROOT / "development/self-rebuild-kit-r1/manifest.json", ROOT / "development/build-self-rebuild-r1/bundle.json"]
inputs += [Path(row["original_path"]) for row in json.loads(inputs[-2].read_bytes())["own_sources"]]
before = [identity(path) for path in sorted(set(inputs), key=str)]
(OUT / "source-before.json").write_text(json.dumps(before, indent=2, sort_keys=True) + "\n")
kit = KIT.read_bytes()
request = {"executable": identity(EXE), "argv": [digest(kit)], "stdin": identity(KIT),
           "environment": {"PATH": "", "HOME": str(HOME)},
           "limits": {"cpu_seconds_per_process": 90, "aggregate_cpu_seconds_strict": 90,
                      "wall_seconds_strict": 150, "address_bytes": 1 << 30},
           "scope": "LOCAL_COMPLETE_NATIVE_SELF_BUILD_NOT_COLD_NOT_ORIGINAL_UBUNTU_DOMAIN"}
(OUT / "request.json").write_text(json.dumps(request, indent=2, sort_keys=True) + "\n")
summary = {"schema": "hia-clean-builder-self-rebuild-generation-r1", "status": "INCOMPLETE", "request": request}
primary = None
secondary = []
proc = None
def alarm_handler(signum, frame): raise TimeoutError("complete native build exceeded original 150 wall seconds")
try:
    signal.signal(signal.SIGALRM, alarm_handler)
    signal.setitimer(signal.ITIMER_REAL, max(0.001, 150 - (time.monotonic_ns() - started) / 1e9))
    with KIT.open("rb") as src, (OUT / "package.raw").open("xb") as out, (OUT / "terminal.raw").open("xb") as err:
        proc = subprocess.Popen([str(EXE), digest(kit)], stdin=src, stdout=out, stderr=err,
                                env=request["environment"], preexec_fn=setup, start_new_session=True)
        pid, status, observed = os.wait4(proc.pid, 0)
        proc.returncode = os.waitstatus_to_exitcode(status)
    summary["process"] = {"returncode": proc.returncode, "wait4_status": status, "user_seconds": observed.ru_utime,
                          "system_seconds": observed.ru_stime, "maxrss_kib": observed.ru_maxrss}
    terminal = (OUT / "terminal.raw").read_bytes()
    package = (OUT / "package.raw").read_bytes()
    summary["stdout"] = identity(OUT / "package.raw")
    summary["stderr"] = identity(OUT / "terminal.raw")
    assert proc.returncode == 0, (proc.returncode, terminal.hex())
    assert len(terminal) == 128
    event = struct.unpack("<16Q", terminal)
    assert event[0] == int.from_bytes(b"HIABBE01", "little") and event[1] == 0 and event[4] == len(package)
    assert terminal[96:128] == hashlib.sha256(package).digest()
    files = unpack(package)
    old = unpack(OLD_PACKAGE.read_bytes())
    for name in ("hia", "hia-release", "compiler.bin"):
        assert files[name] == old[name], name
    assert files["source-kit.hiabuild"] == (0o400, kit)
    assert files["hia-build"] == (0o500, EXE.read_bytes())
    report = json.loads(files["build.json"][1])
    old_report = json.loads(OLD_SUMMARY.read_bytes())["native_receipt"]
    assert report["schema"] == "hepta.hia.native-clean-build.v2"
    assert report["status"] == "SELF_REBUILT_NATIVE_BUILD"
    assert report["kit_sha256"] == digest(kit) and report["builder_sha256"] == digest(files["hia-build"][1])
    assert report["compiler_sha256"] == digest(files["compiler.bin"][1])
    assert report["builder_recompiled_from_kit_source"] is True and report["builder_copy_used"] is False
    assert report["new_builder_matching_source_cold_qualified"] is False and report["whole_native_delivery_qualified"] is False
    assert len(report["images"]) == 13 and report["images"][:9] == old_report["images"]
    for index, label in [(9, "clean-build-driver"), (10, "agent-data-json"), (11, "clean-build-packer")]:
        manifest = json.loads((ROOT / "development/build-self-rebuild-r1" / (label + ".manifest.json")).read_bytes())
        image = Path(manifest["image_path"]).read_bytes()
        assert report["images"][index] == {"input_sha256": manifest["source_sha256"],
                                            "image_sha256": digest(image), "image_bytes": len(image)}
    assert report["images"][12]["image_sha256"] == digest(files["hia-build"][1])
    assert report["images"][12]["image_bytes"] == len(files["hia-build"][1])
    materialized = OUT / "package-files"
    materialized.mkdir()
    for name, (mode, raw) in files.items():
        path = materialized / name
        path.write_bytes(raw)
        path.chmod(mode)
    summary.update(status="PASS", terminal_words=list(event), native_receipt=report,
                   complete_original_seven_recipes_and_two_application_packers_equal=True,
                   new_self_builder_complete_bytes_equal_to_independently_compiled_seed=True,
                   files={name: {"mode": mode, "bytes": len(raw), "sha256": digest(raw)} for name, (mode, raw) in files.items()})
except BaseException as exc:
    primary = exc
    summary.update(status="FAIL", error_class=type(exc).__name__, error=str(exc))
    (OUT / "primary-traceback.txt").write_text(traceback.format_exc())
finally:
    if proc is not None and proc.returncode is None:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
            pid, status, observed = os.wait4(proc.pid, 0)
            proc.returncode = os.waitstatus_to_exitcode(status)
            summary["termination"] = {"returncode": proc.returncode, "wait4_status": status,
                                      "user_seconds": observed.ru_utime, "system_seconds": observed.ru_stime,
                                      "maxrss_kib": observed.ru_maxrss}
        except BaseException as exc:
            secondary.append({"phase": "cleanup", "class": type(exc).__name__, "error": str(exc)})
    for row in before:
        try: assert identity(Path(row["path"])) == row
        except BaseException as exc:
            secondary.append({"phase": "source-after", "path": row["path"], "class": type(exc).__name__, "error": str(exc)})
    measured = usage()
    if not (0 <= measured["aggregate_cpu_seconds"] < 90 and 0 <= measured["elapsed_ns"] < 150000000000):
        secondary.append({"phase": "budget", "usage": measured})
    summary["usage_before_output"] = measured
    summary["secondary_errors"] = secondary
    summary["all_pins_unchanged"] = not any(r["phase"] == "source-after" for r in secondary)
    if secondary: summary["status"] = "FAIL"
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps({k: v for k, v in summary.items() if k not in ("native_receipt", "request", "terminal_words")}, sort_keys=True), flush=True)
    final_usage = usage()
    (OUT / "post-output-budget.json").write_text(json.dumps(final_usage, indent=2, sort_keys=True) + "\n")
    signal.setitimer(signal.ITIMER_REAL, 0)
if primary is not None: raise primary
assert not secondary
assert 0 <= final_usage["aggregate_cpu_seconds"] < 90 and 0 <= final_usage["elapsed_ns"] < 150000000000
