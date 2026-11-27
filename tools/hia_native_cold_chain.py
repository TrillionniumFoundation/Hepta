"""Execute the current native cold, post-bootstrap, install and rebuild chain.

This is an external development observer. All product construction, source
admission, installation and rebuilding run through the actual native entries.
"""
from pathlib import Path
from hashlib import sha256
from datetime import datetime, timezone
import argparse
import json
import os
import re
import signal
import stat
import struct
import subprocess
import threading
import time
import traceback


def pin(raw):
    return {"bytes": len(raw), "sha256": sha256(raw).hexdigest()}


def read_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            assert key not in result, key
            result[key] = value
        return result
    def invalid_constant(value):
        raise ValueError("non-JSON numeric token: " + value)
    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid_constant)


def regular(path, maximum=67108864, *, single_link=True, mode=None):
    assert not any(p.is_symlink() for p in (path, *path.parents)), str(path)
    before = path.stat(follow_symlinks=False)
    assert stat.S_ISREG(before.st_mode), str(path)
    assert before.st_size <= maximum and before.st_uid == os.geteuid(), str(path)
    assert not single_link or before.st_nlink == 1, str(path)
    if mode is not None:
        assert stat.S_IMODE(before.st_mode) == mode, str(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_nlink,
                          s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    assert identity(before) == identity(opened) == identity(after) == identity(path.stat(follow_symlinks=False))
    assert len(raw) == before.st_size
    return raw


def manifest(raw):
    assert len(raw) >= 32 and raw[:8] == b"HIASXM01"
    count, version, reserved = struct.unpack_from("<3Q", raw, 8)
    assert 1 <= count <= 4096 and version == 1 and reserved == 0
    rows, cursor, previous = {}, 32, b""
    for _ in range(count):
        assert cursor + 48 <= len(raw)
        length, size = struct.unpack_from("<2Q", raw, cursor)
        digest = raw[cursor + 16:cursor + 48]
        cursor += 48
        assert 1 <= length <= 4095 and cursor + length <= len(raw) and size <= 67108864
        name = raw[cursor:cursor + length]
        assert re.fullmatch(rb"[A-Za-z0-9_./-]+", name) and name > previous
        assert all(p not in (b"", b".", b"..", b".git", b"__pycache__") for p in name.split(b"/"))
        assert digest != bytes(32)
        rows[name.decode("ascii")] = dict(bytes=size, sha256=digest.hex())
        previous, cursor = name, cursor + length
    assert cursor == len(raw)
    return rows


def retained_evidence_pin(path):
    """Hash the complete native evidence without an observer-side extent guess."""
    assert not any(p.is_symlink() for p in (path, *path.parents)), str(path)
    before = path.stat(follow_symlinks=False)
    assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.geteuid()
    digest, count = sha256(), 0
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        while raw := stream.read(1048576):
            digest.update(raw)
            count += len(raw)
        after = os.fstat(stream.fileno())
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_nlink,
                          s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    assert identity(before) == identity(opened) == identity(after) == identity(path.stat(follow_symlinks=False))
    assert count == before.st_size
    return dict(bytes=count, sha256=digest.hexdigest())


def package_members(raw):
    assert 24 <= len(raw) <= 268435456
    magic, count, reserved = struct.unpack_from("<8s2Q", raw)
    assert 1 <= count <= 384 and reserved == 0
    assert magic == (b"HIAREL01" if count <= 256 and len(raw) <= 134217728 else b"HIAREL02")
    rows, cursor, previous = {}, 24, b""
    for _ in range(count):
        assert cursor + 24 <= len(raw)
        length, mode, extent = struct.unpack_from("<3Q", raw, cursor)
        cursor += 24
        assert 1 <= length <= 127 and mode in (0o400, 0o500)
        assert cursor + length + extent <= len(raw)
        name = raw[cursor:cursor + length]
        assert re.fullmatch(rb"[A-Za-z0-9][A-Za-z0-9._-]*", name) and name > previous
        cursor += length
        rows[name.decode("ascii")] = dict(mode=mode, offset=cursor, **pin(raw[cursor:cursor + extent]))
        previous, cursor = name, cursor + extent
    assert cursor == len(raw)
    return rows


class ResourceObserver:
    """Read-only, out-of-process evidence; never participates in product admission."""
    def __init__(self, path, child_pid, storage_paths):
        self.path = path
        self.child_pid = child_pid
        self.storage_paths = storage_paths
        self.stop = threading.Event()
        self.error = None
        self.stream = path.open("x")
        self.thread = threading.Thread(target=self.observe_guarded, name="hia-resource-observer", daemon=True)

    def observe_guarded(self):
        try:
            self.observe()
        except BaseException as exc:
            self.error = repr(exc)

    def observe(self):
        while True:
            row = dict(monotonic_ns=time.monotonic_ns(), utc=datetime.now(timezone.utc).isoformat(),
                       observed_child_pid=self.child_pid, read_only=True)
            for name in ("cpu", "io", "memory"):
                try:
                    row[name + "_pressure"] = Path("/proc/pressure", name).read_text()
                except OSError as exc:
                    row[name + "_pressure_error"] = repr(exc)
            try:
                row["host_cpu_counters"] = Path("/proc/stat").read_text().splitlines()[0]
                row["loadavg"] = Path("/proc/loadavg").read_text().strip()
                row["disk_counters"] = [line for line in Path("/proc/diskstats").read_text().splitlines()
                                        if line.split()[2] in ("nvme0n1", "sda")]
                row["memory"] = {line.split(":", 1)[0]: line.split(":", 1)[1].strip()
                                 for line in Path("/proc/meminfo").read_text().splitlines()
                                 if line.split(":", 1)[0] in ("MemAvailable", "SwapFree", "Dirty", "Writeback")}
            except OSError as exc:
                row["host_read_error"] = repr(exc)
            try:
                row["child_cgroup"] = Path("/proc", str(self.child_pid), "cgroup").read_text()
                suffix = next(line[3:] for line in row["child_cgroup"].splitlines() if line.startswith("0::/"))
                group = Path("/sys/fs/cgroup") / suffix.lstrip("/")
                row["child_cgroup_counters"] = {name: (group / name).read_text()
                                                 for name in ("cpu.stat", "cpu.max", "cpu.pressure", "io.pressure", "memory.pressure")
                                                 if (group / name).is_file()}
            except (OSError, StopIteration) as exc:
                row["child_read_error"] = repr(exc)
            row["storage"] = {}
            for directory in self.storage_paths:
                try:
                    fs = os.statvfs(directory)
                    row["storage"][str(directory)] = dict(device=directory.stat().st_dev,
                                                          available_bytes=fs.f_bavail * fs.f_frsize,
                                                          block_size=fs.f_frsize)
                except OSError as exc:
                    row["storage"][str(directory)] = dict(error=repr(exc))
            self.stream.write(json.dumps(row, sort_keys=True) + "\n")
            self.stream.flush()
            if self.stop.is_set():
                break
            self.stop.wait(5)

    def start(self):
        self.thread.start()

    def close(self):
        self.stop.set()
        self.thread.join(timeout=10)
        if self.thread.is_alive():
            return dict(complete=False, reason="read-only resource observer did not terminate")
        self.stream.close()
        return dict(complete=self.error is None, error=self.error, path=str(self.path), **pin(self.path.read_bytes()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "preparation", "build", "export", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--stop-after-cold", action="store_true",
                        help="Qualify the full native cold compiler only; do not claim release, install or rebuild qualification.")
    parser.add_argument("--cold-storage", type=Path,
                        help="New private directory for native cold data and its external evidence; executables remain in --output.")
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    head = subprocess.check_output(["/usr/bin/git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
    assert head == args.head
    preparation = read_json((args.preparation / "report.json").read_bytes())
    build = read_json((args.build / "qualification.json").read_bytes())
    exported = read_json((args.export / "qualification.json").read_bytes())
    assert preparation["passed"] and build["passed"] and exported["passed"]
    assert build["source_head"] == exported["source_head"] == head
    assert build["target_or_successor_compiler_used"] is False
    assert build["preparation"]["sha256"] == sha256((args.preparation / "report.json").read_bytes()).hexdigest()
    assert exported["build"]["sha256"] == sha256((args.build / "qualification.json").read_bytes()).hexdigest()
    native_source = Path(exported["native_only_copy"])
    sources = read_json((args.preparation / "source-manifest.json").read_bytes())
    source_pins = read_json((args.preparation / "after-source-pins.json").read_bytes())
    contract = read_json((source / "docs/HIA_SELFHOST_CORE_SUPPORT.json").read_bytes())
    assert contract["source_identity"]["files"] == {n: h for n, h in sources.items() if n != "docs/HIA_SELFHOST_CORE_SUPPORT.json"}
    native = contract["native_cold_qualification"]
    assert native["schema"] == "hepta.hia.selfhost-cold-replay.v2"
    assert native["qualification_wall_limit_seconds"] == 180 and native["cleanup_wall_limit_seconds"] == 3
    toolchain = args.build / "toolchain"
    expected_source_manifest = (args.preparation / "source-manifest.hiasxm").read_bytes()
    assert pin(expected_source_manifest) == build["source_manifest"]
    post_plan = read_json((source / "examples/hia_bootstrap/cold_source_bootstrap_plans/build-plan.json").read_bytes())
    assert len(post_plan["stages"]) == 1 and post_plan["maximum_stage_imports"] <= 64
    output = args.output
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    cold_storage = None
    if args.cold_storage is not None:
        cold_storage = args.cold_storage
        assert cold_storage.is_absolute() and not cold_storage.exists()
        assert cold_storage.parent.is_dir() and not any(p.is_symlink() for p in (cold_storage, *cold_storage.parents))
        assert cold_storage.parent.stat().st_uid == os.geteuid()
        assert not stat.S_IMODE(cold_storage.parent.stat().st_mode) & 0o022
        assert not any(cold_storage.is_relative_to(root) for root in (source, native_source, toolchain))
        cold_storage.mkdir(mode=0o700, exist_ok=False)
        (cold_storage / "evidence").mkdir(mode=0o700)
    report = dict(schema="hepta.hia.current-native-production-chain.v1", passed=False,
                  source_head=head, source=str(source), native_source=str(native_source),
                  whole_cold_qualified=False, whole_native_delivery_qualified=False,
                  whole_stack_rewritten_in_hia=False, production_activated=False,
                  qualification_wall_limit_seconds=180, cleanup_wall_limit_seconds=3,
                  ordinary_release_timeout_seconds=1800,
                  commands=[], started_utc=datetime.now(timezone.utc).isoformat(),
                  driver=dict(path=__file__, **pin(Path(__file__).read_bytes())))
    report["cold_storage"] = str(cold_storage) if cold_storage is not None else str(output)
    report["resource_observation_affects_admission"] = False

    def save():
        (output / "qualification.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

    def check_sources():
        assert subprocess.check_output(["/usr/bin/git", "rev-parse", "HEAD"], cwd=source, text=True).strip() == head
        for name, expected in source_pins.items():
            assert pin(regular(source / name)) == expected, name
        for name, digest in sources.items():
            path = native_source / name
            raw = regular(path, mode=0o400)
            assert sha256(raw).hexdigest() == digest, name
            assert raw[:4] != b"\x7fELF" and path.suffix.lower() not in (".py", ".pyc", ".rs", ".flat", ".so", ".o", ".elf", ".whl")
        actual = {p.relative_to(native_source).as_posix() for p in native_source.rglob("*") if not p.is_dir()}
        assert actual == set(sources)

    def run(label, argv, *, timeout=360, packet=None, packet_path=None):
        assert packet is None or packet_path is None
        evidence = cold_storage / "evidence" if label == "full-cold" and cold_storage is not None else output
        stdout_path, stderr_path = evidence / (label + ".stdout"), evidence / (label + ".stderr")
        trace = evidence / (label + ".exec.trace")
        command = ["/usr/bin/strace", "-D", "-f", "--seccomp-bpf", "-e", "trace=execve,execveat", "-o", str(trace), "--", *map(str, argv)]
        row = dict(label=label, argv=list(map(str, argv)), trace_argv=command,
                   started_utc=datetime.now(timezone.utc).isoformat(), native_descendants_only=False)
        report["commands"].append(row)
        save()
        print("CURRENT_NATIVE_CHAIN_BEGIN", label, flush=True)
        start = time.monotonic_ns()
        with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
            input_stream = packet_path.open("rb") if packet_path is not None else None
            child = None
            resources = None
            try:
                child = subprocess.Popen(command, stdin=input_stream if input_stream is not None else (subprocess.PIPE if packet is not None else subprocess.DEVNULL),
                                         stdout=stdout, stderr=stderr, env={"PATH": "", "LANG": "C", "LC_ALL": "C", "TZ": "UTC"}, start_new_session=True)
                row["pid"] = child.pid
                resources = ResourceObserver(evidence / (label + ".resources.jsonl"), child.pid,
                                             [output, evidence])
                resources.start()
                save()
                try:
                    child.communicate(input=packet, timeout=timeout)
                except subprocess.TimeoutExpired:
                    row["observer_timeout"] = True
                    row["observer_termination_requests"] = ["SIGTERM"]
                    os.killpg(child.pid, signal.SIGTERM)
                    try:
                        child.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        row["observer_termination_requests"].append("SIGKILL")
                        os.killpg(child.pid, signal.SIGKILL)
                        child.wait()
                    raise
            except BaseException:
                row["error"] = traceback.format_exc()
                raise
            finally:
                if resources is not None:
                    row["read_only_resource_observation"] = resources.close()
                if input_stream is not None:
                    input_stream.close()
                stdout.flush()
                stderr.flush()
                row.update(returncode=None if child is None else child.poll(),
                           observed_entry_process_terminal=child is not None and child.returncode is not None,
                           elapsed_ns=time.monotonic_ns() - start,
                           stdout=pin(stdout_path.read_bytes()), stderr=pin(stderr_path.read_bytes()))
                save()
        stdout, stderr = stdout_path.read_bytes(), stderr_path.read_bytes()
        row.update(returncode=child.returncode, elapsed_ns=time.monotonic_ns() - start,
                   stdout=pin(stdout), stderr=pin(stderr))
        save()
        print("CURRENT_NATIVE_CHAIN_TERMINAL", label, child.returncode, row["elapsed_ns"], len(stdout), len(stderr), flush=True)
        assert child.returncode == 0 and not stderr, row
        trace_text = trace.read_text()
        execs = [line for line in trace_text.splitlines() if re.search(r"(?:^|\s)execve\(", line)]
        assert len(execs) == 1 and str(argv[0]) in execs[0], execs
        assert all("execveat(" not in line or "AT_EMPTY_PATH" in line or "<unfinished ...>" in line for line in trace_text.splitlines())
        row.update(native_descendants_only=True, execve=1, execveat=trace_text.count("execveat("), trace=pin(trace.read_bytes()))
        save()
        return stdout

    try:
        check_sources()
        for name, expected in build["installed"].items():
            assert pin(regular(toolchain / name)) == expected, name
        cold = (cold_storage if cold_storage is not None else output) / "cold"
        cold_raw = run("full-cold", [toolchain / "hia-cold", "--source", native_source,
                                    "--output", cold, "--toolchain", toolchain,
                                    "--bundle", toolchain / "cold-bundle.hiadat"])
        assert regular(cold / "final-cold.json") == cold_raw
        result = read_json(cold_raw)
        assert result["schema"] == "hepta.hia.selfhost-cold-replay.v2" and result["status"] == "NATIVE_COLD_SELFHOST_REPLAY_PASS"
        assert type(result["returncode"]) is int and result["returncode"] == 0
        assert result["profile"] == contract["profile"] and result["source_manifest"] == sources
        assert result["qualification_wall_limit_seconds"] == 180 and result["cleanup_wall_limit_seconds"] == 3
        assert 0 < result["nested_wall_elapsed_ns"] <= 180000000000
        assert 0 <= result["cleanup_wall_elapsed_ns"] <= 3000000000
        assert len(result["checks"]) == 14 and set(result["checks"]) == set(native["checks"])
        assert all(v is True for v in result["checks"].values())
        families = {"capacity", "cfg", "elf", "chain", "owned", "bulk", "loan", "resource", "tail", "select", "effects", "multi", "keyword", "signed", "scalar-casts", "explicit-traps", "cli", "names", "exports"}
        assert set(result["qualification_families"]) == families
        assert all(row == {"original": True, "modified": True} for row in result["qualification_families"].values())
        scheduler = result["scheduler"]
        assert {key: scheduler[key] for key in native["scheduler"]} == native["scheduler"]
        assert 1 <= scheduler["peak_phase_workers"] <= 2 and scheduler["peak_archive_workers"] == 1
        assert 0 <= scheduler["peak_pending_archives"] <= 2 and 1 <= scheduler["peak_unsealed_phases"] <= 4
        generations = {name: pin(regular(cold / "qualification/base" / (name + ".flat"), 1048576)) for name in ("B0", "B1", "B2", "B3", "M1", "M2", "M3")}
        assert result["seed_sha256"] == generations["B0"]["sha256"]
        assert result["generation_sha256"] == [generations[name]["sha256"] for name in ("B1", "B2", "B3")]
        assert result["modified_generation_sha256"] == [generations[name]["sha256"] for name in ("M1", "M2", "M3")]
        assert generations["B1"] == generations["B2"] == generations["B3"]
        assert generations["M1"] != generations["M2"] and generations["M2"] == generations["M3"] and generations["M3"] != generations["B3"]
        observer = regular(cold / "qualification/base/native-observer.elf", 1107)
        assert len(observer) == 1107 and observer.hex() == result["native_flat_observer_hex"]
        catalog = {row["id"]: row for row in native["phase_plan_catalog"]}
        assert len(catalog) == len(result["phases"]) == 60
        phases, seen, base_seen = [], set(), False
        for row in result["phases"]:
            identity = row["id"]
            assert identity in catalog and identity not in seen and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,126}", identity)
            seen.add(identity)
            expected = catalog[identity]
            assert all(row[key] == expected[key] for key in ("kind", "family", "label", "plan_sha256", "node_count"))
            assert row["returncode"] == 0 and row["nodes_retained"] == row["node_count"]
            assert row["cleanup_complete"] is True and row["sealed"] is True
            if row["kind"] == "reference":
                assert not base_seen
            elif row["kind"] == "base":
                assert not base_seen
                base_seen = True
            elif row["kind"] == "qualification":
                assert base_seen
            else:
                raise AssertionError(row["kind"])
            archive = cold / "qualification" / (identity + ".hiaqar")
            journal = cold / "qualification" / identity / "evidence.hiaqj"
            archive_pin = retained_evidence_pin(archive)
            journal_pin = retained_evidence_pin(journal)
            assert archive_pin["sha256"] == row["archive_sha256"]
            assert journal_pin["sha256"] == row["journal_sha256"]
            phases.append(dict(id=identity, archive=dict(path=str(archive), **archive_pin), journal=dict(path=str(journal), **journal_pin)))
        assert base_seen and seen == set(catalog)
        check_sources()
        report.update(whole_cold_qualified=True, cold=dict(path=str(cold / "final-cold.json"), **pin(cold_raw)),
                      cold_checks=result["checks"], scheduler=scheduler, generations=generations,
                      observer=pin(observer), phases=phases, source_count=len(sources),
                      qualification_nodes=sum(row["node_count"] for row in result["phases"]))
        save()
        print("CURRENT_NATIVE_60_PHASE_COLD_PASS", result["nested_wall_elapsed_ns"], flush=True)

        if args.stop_after_cold:
            report.update(passed=True, qualification_scope="NATIVE_COLD_COMPILER_ONLY",
                          installed_whole_source_rebuild_passed=False,
                          native_product_construction_installation_and_rebuild=False,
                          remaining_scope="Post-bootstrap, release, installation, installed rebuild, whole Worker and public facade remain separate gates.")
            save()
            return

        post = output / "source-bootstrap"
        post_receipt = run("post-bootstrap", [toolchain / "hia-source-bootstrap", "--source", native_source,
                                             "--cold", cold, "--bootstrap", args.build / "bootstrap", "--output", post])
        assert len(post_receipt) == 128 and post_receipt[:8] == b"HIASBOK1"
        assert regular(post / "build.receipt", 128) == post_receipt
        installed = {row["path"]: row for row in post_plan["publications"] if row["flags"] == 1}
        expected_tools = {"cold-inputs.receipt", "hia-source-build", "hia-release-owner", "hia-subprocess", "hia-source-capture", "hia-release-build", "hia-source-bootstrap", "hia-release"}
        assert set(installed) == expected_tools
        header = struct.unpack_from("<7Q", post_receipt, 8)
        assert header[:4] == (1, 1, len(sources), len(installed)) and header[-1] == 0
        source_manifest = regular(post / "source.manifest.hiasxm", 1048576)
        tool_manifest = regular(post / "toolchain.manifest.hiasxm", 1048576)
        assert (len(source_manifest), len(tool_manifest)) == header[4:6]
        assert source_manifest == expected_source_manifest
        assert post_receipt[64:96] == sha256(source_manifest).digest() and post_receipt[96:128] == sha256(tool_manifest).digest()
        tool_rows = manifest(tool_manifest)
        assert set(tool_rows) == expected_tools
        for name, expected in tool_rows.items():
            assert pin(regular(post / name, 67108864, mode=installed[name]["mode"])) == expected, name
        assert regular(post / "hia-source-bootstrap") == regular(toolchain / "hia-source-bootstrap")
        inputs = regular(post / "cold-inputs.receipt", 120)
        expected_inputs = b"HIASBIN1" + bytes.fromhex(generations["B3"]["sha256"]) + sha256(cold_raw).digest() + b"HIAADC01" + bytes.fromhex(generations["B3"]["sha256"]) + struct.pack("<Q", len(sources))
        assert inputs == expected_inputs
        owner = regular(post / "process-owner.receipt", 1048576)
        assert len(owner) >= 256 and owner[:8] == b"HIACOR01"
        words = struct.unpack_from("<32Q", owner)
        assert len(owner) == 256 + words[16] * 40 + words[18] * 48
        assert words[6:8] == (180, 3000000000) and words[8] >= 2
        assert words[1] == 0 and words[9] == 0 and words[11:14] == (1, 1, 1)
        assert words[10] == words[14] == words[15] == words[17] == 0
        assert words[21] == 0 and words[22] == 1 and words[24] == 0
        assert words[16] <= 16384 and words[18] <= 4096
        assert words[25:32] == (4096, 16384, 65536, 1, 0, 0, 0)
        assert words[5] == words[4] + 180000000000
        assert words[4] <= words[19] <= words[5] and words[20] == words[19] + 3000000000
        assert words[19] <= words[23] <= words[20]
        assert words[19] - words[4] <= 180000000000 and words[23] - words[19] <= 3000000000
        stages = []
        for stage in post_plan["stages"]:
            folder = post / "build-evidence" / ("s" + str(stage["id"]))
            receipt = regular(folder / "driver.receipt", 64)
            journal_pin = retained_evidence_pin(folder / "evidence.hiaqj")
            assert len(receipt) == 64 and struct.unpack("<4Q", receipt[:32]) == (int.from_bytes(b"HIAQOK01", "little"), stage["nodes"], stage["plan_bytes"], journal_pin["bytes"])
            assert receipt[32:].hex() == journal_pin["sha256"]
            stages.append(dict(id=stage["id"], nodes=stage["nodes"], receipt=pin(receipt), journal=journal_pin))
        check_sources()
        report["post_bootstrap"] = dict(path=str(post), receipt=pin(post_receipt), source_manifest=pin(source_manifest),
                                       tool_manifest=pin(tool_manifest), inputs=pin(inputs), owner=pin(owner), stages=stages,
                                       installed={name: dict(**row, nlink=(post / name).stat().st_nlink) for name, row in tool_rows.items()})
        save()
        print("CURRENT_NATIVE_POST_BOOTSTRAP_PASS", len(tool_rows), flush=True)

        release = output / "release"
        compiler = cold / "qualification/base/B3.flat"
        finalize_raw = run("ordinary-release", [post / "hia-release-build", "--output", release,
                                               "--compiler", compiler, "--cold-report", cold / "final-cold.json", "--source", native_source,
                                               "--timeout-seconds", "1800"], timeout=1830)
        finalize = read_json(finalize_raw)
        package = release / "store.hiapack"
        package_raw = regular(package, 268435456, single_link=False, mode=0o400)
        package_pin = pin(package_raw)
        members = package_members(package_raw)
        assert finalize == dict(schema="hepta.hia.release-finalize.v1", **package_pin, files=len(members), published=True, source_attested=True)
        report["ordinary_release"] = dict(path=str(package), **package_pin, files=len(members), nlink=package.stat().st_nlink,
                                          receipt=pin(finalize_raw), source_attested=True)
        save()
        depot = output / "depot"
        depot.mkdir(mode=0o700)
        installed_root = depot / package_pin["sha256"]
        receipts = {}
        for operation in ("install", "verify"):
            entry = post / "hia-release" if operation == "install" else installed_root / "hia-release"
            if operation == "verify":
                assert pin(regular(entry, mode=0o500)) == {k: members["hia-release"][k] for k in ("bytes", "sha256")}
            raw = run("depot-" + operation, [entry, operation, depot, package_pin["sha256"]], packet_path=package)
            receipt = read_json(raw)
            assert receipt == dict(schema="hepta.hia.release-install.v1", **package_pin, files=len(members), published=operation == "install")
            receipts[operation] = pin(raw)
        assert stat.S_IMODE(installed_root.stat().st_mode) == 0o500 and installed_root.stat().st_uid == os.geteuid()
        assert {p.name for p in installed_root.iterdir()} == set(members)
        for name, row in members.items():
            raw = regular(installed_root / name, 268435456, mode=row["mode"])
            assert raw == package_raw[row["offset"]:row["offset"] + row["bytes"]], name
        helper = read_json(regular(installed_root / "agent-identity-manifest.json", 4096))
        helper_image = regular(installed_root / "agent-identity.image.bin", 1048576)
        assert helper == dict(schema="hepta.hia.agent-identity-native.v1", source_sha256=sources["examples/hia_bootstrap/agent_identity.hepta"],
                             image_path="agent-identity.image.bin", image_sha256=sha256(helper_image).hexdigest(), compiler_sha256=generations["B3"]["sha256"])
        report["installation"] = dict(root=str(installed_root), receipts=receipts, member_count=len(members),
                                      all_member_bytes_modes_and_identities_match=True, helper=helper)
        save()
        rebuilt = output / "installed-rebuild"
        rebuilt_raw = run("installed-source-rebuild", [installed_root / "hia-release-build", "--output", rebuilt,
                                                       "--compiler", compiler, "--cold-report", cold / "final-cold.json", "--source", native_source,
                                                       "--timeout-seconds", "1800"], timeout=1830)
        assert read_json(rebuilt_raw) == finalize
        assert regular(rebuilt / "store.hiapack", 268435456, single_link=False, mode=0o400) == package_raw
        check_sources()
        assert regular(cold / "final-cold.json") == cold_raw
        for name, expected in tool_rows.items():
            assert pin(regular(post / name)) == expected, name
        report.update(passed=True, installed_whole_source_rebuild_passed=True,
                      installed_rebuild=dict(path=str(rebuilt / "store.hiapack"), **package_pin, receipt=pin(rebuilt_raw)),
                      source_pins_preserved=True, native_product_construction_installation_and_rebuild=True,
                      remaining_scope="Whole Worker, MCP/public facade and final legacy retirement remain separate gates.")
        save()
        print("CURRENT_NATIVE_COLD_INSTALL_REBUILD_CHAIN_PASS", head, len(sources), package_pin["sha256"], flush=True)
    except BaseException:
        report["error"] = traceback.format_exc()
        save()
        raise


if __name__ == "__main__":
    main()
