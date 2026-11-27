"""Run the complete current public seven-stage native construction."""
from pathlib import Path
from hashlib import sha256
from datetime import datetime, timezone
import argparse
import json
import os
import signal
import struct
import subprocess
import time
import traceback

def pin(raw):
    return {"bytes": len(raw), "sha256": sha256(raw).hexdigest()}

def manifest(raw):
    assert raw[:8] == b"HIASXM01"
    count, version, reserved = struct.unpack_from("<3Q", raw, 8)
    assert version == 1 and reserved == 0
    rows = {}
    at = 32
    for _ in range(count):
        size, extent = struct.unpack_from("<2Q", raw, at)
        digest = raw[at + 16:at + 48]
        name = raw[at + 48:at + 48 + size].decode("ascii")
        assert name not in rows
        rows[name] = (extent, digest)
        at += 48 + size
    assert at == len(raw) and list(rows) == sorted(rows)
    return rows

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--preparation", type=Path, required=True)
    parser.add_argument("--preseed", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    head = subprocess.check_output(["/usr/bin/git", "rev-parse", "HEAD"], cwd=source, text=True, timeout=20).strip()
    assert head == args.head
    prep = json.loads((args.preparation / "report.json").read_bytes())
    seeds = json.loads((args.preseed / "report.json").read_bytes())
    assert prep["passed"] and seeds["passed"]
    assert seeds["target_or_successor_compiler_used"] is False
    files = json.loads((args.preparation / "source-manifest.json").read_bytes())
    source_pins = json.loads((args.preparation / "after-source-pins.json").read_bytes())
    for name, expected in source_pins.items():
        assert pin((source / name).read_bytes()) == expected, name
    for name, expected in seeds["sources"].items():
        assert pin((source / name).read_bytes()) == expected, ("preseed role changed", name)
    plan = json.loads((source / "examples/hia_bootstrap/cold_build_plans/build-plan.json").read_bytes())
    assert len(plan["stages"]) == 7 and plan["maximum_stage_imports"] <= 64
    output = args.output
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    report = {
        "schema": "hepta.hia.public-native-production-construction.v1",
        "passed": False, "source": str(source), "source_head": head,
        "scope": "Actual current seven-stage construction and source/root custody; cold qualification is separate.",
        "whole_cold_qualified": False, "whole_native_delivery_qualified": False,
        "target_or_successor_compiler_used": False, "bootstrap": [], "packers": {},
        "preparation": {"path": str(args.preparation / "report.json"), **pin((args.preparation / "report.json").read_bytes())},
        "preseed": {"path": str(args.preseed / "report.json"), **pin((args.preseed / "report.json").read_bytes())},
        "driver": {"path": __file__, **pin(Path(__file__).read_bytes())},
    }
    def save():
        (output / "qualification.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    def product(name):
        row = seeds["products"][name]
        raw = Path(row["path"]).read_bytes()
        assert pin(raw) == {k: row[k] for k in ("bytes", "sha256")}
        return raw
    try:
        bootstrap = output / "bootstrap"
        bootstrap.mkdir(mode=0o700)
        for row in seeds["initial_roots"]:
            raw = Path(row["path"]).read_bytes()
            assert pin(raw) == {k: row[k] for k in ("bytes", "sha256")}
            target = bootstrap / row["name"]
            target.write_bytes(raw)
            target.chmod(0o500)
            report["bootstrap"].append({"name": row["name"], "path": str(target), **pin(raw)})
        sha = product("tmp-cold-sha256-flat")
        authority = (source / "examples/hia_bootstrap/cold_build_sources.hiadat").read_bytes()
        assert authority[:8] == b"HIATBS01" and struct.unpack_from("<Q", authority, 16)[0] == len(files)
        entries = [
            ("hia-cold-build", "tmp-build-entry-policy", "tmp-build-entry-packer", "cold_build_recipe.hiadat", b"HIAQBE01"),
            ("hia-source-bootstrap", "tmp-source-bootstrap-entry-policy", "tmp-source-bootstrap-entry-packer", "cold_source_bootstrap_recipe.hiadat", b"HIASBP01"),
        ]
        for target_name, role, packer_name, recipe, magic in entries:
            policy = product(role)
            packer = product(packer_name)
            tool = output / packer_name
            tool.write_bytes(packer)
            tool.chmod(0o500)
            pins = [sha256(authority).digest(), sha256((source / "examples/hia_bootstrap" / recipe).read_bytes()).digest(),
                    *(bytes.fromhex(r["sha256"]) for r in report["bootstrap"])]
            packet = magic + struct.pack("<2Q", len(policy), len(sha)) + b"".join(pins) + policy + sha
            (output / (target_name + ".packet")).write_bytes(packet)
            process = subprocess.run([str(tool)], input=packet, capture_output=True, env={"PATH": ""}, timeout=30)
            (output / (target_name + ".packer.stderr")).write_bytes(process.stderr)
            assert process.returncode == 0 and not process.stderr and process.stdout[:4] == b"\x7fELF"
            target = output / target_name
            target.write_bytes(process.stdout)
            target.chmod(0o500)
            report["packers"][target_name] = {
                "entry": {"path": str(target), **pin(process.stdout)}, "policy": pin(policy),
                "sha": pin(sha), "packer": pin(packer), "packet": pin(packet),
                "bound_pins": [p.hex() for p in pins],
            }
            save()
        entry = output / "hia-cold-build"
        toolchain = output / "toolchain"
        argv = [str(entry), "--source", str(source), "--bootstrap", str(bootstrap), "--output", str(toolchain)]
        trace = output / "execution.trace"
        command = ["/usr/bin/strace", "-D", "-f", "--seccomp-bpf", "-qq", "-e", "trace=execve,execveat", "-o", str(trace), *argv]
        started = time.monotonic_ns()
        report.update(started_utc=datetime.now(timezone.utc).isoformat(), argv=argv,
                      native_qualification_limit_seconds=180, native_cleanup_limit_seconds=3)
        save()
        with (output / "stdout.bin").open("xb") as stdout, (output / "stderr.bin").open("xb") as stderr:
            child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                     env={"PATH": "", "LANG": "C"}, start_new_session=True)
            report["pid"] = child.pid
            save()
            print("START_CURRENT_PUBLIC_NATIVE_BUILD", child.pid, flush=True)
            try:
                returncode = child.wait(timeout=360)
            except subprocess.TimeoutExpired:
                report["outer_observer_timeout"] = True
                report["termination_requested"] = "SIGTERM"
                try:
                    os.killpg(child.pid, signal.SIGTERM)
                except ProcessLookupError:
                    report["process_group_absent_at_sigterm"] = True
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    report["termination_requested"] = "SIGKILL"
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        report["process_group_absent_at_sigkill"] = True
                    child.wait()
                report.update(returncode=child.returncode, wall_elapsed_ns=time.monotonic_ns()-started,
                              stdout=pin((output/"stdout.bin").read_bytes()),
                              stderr=pin((output/"stderr.bin").read_bytes()))
                save()
                raise
        elapsed = time.monotonic_ns() - started
        stdout = (output / "stdout.bin").read_bytes()
        stderr = (output / "stderr.bin").read_bytes()
        report.update(returncode=returncode, wall_elapsed_ns=elapsed,
                      stdout=pin(stdout), stdout_hex=stdout.hex(), stderr=pin(stderr))
        save()
        print("CURRENT_NATIVE_PUBLIC_TERMINAL", returncode, elapsed, len(stdout), len(stderr), flush=True)
        assert returncode == 0 and not stderr and len(stdout) == 128 and stdout[:8] == b"HIATBOK1"
        assert (toolchain / "build.receipt").read_bytes() == stdout
        header = struct.unpack_from("<7Q", stdout, 8)
        installed = {r["path"]: r for r in plan["publications"] if r["flags"] == 1}
        assert header[:4] == (1, 7, len(files), len(installed)) and header[-1] == 0
        sm = (toolchain / "source.manifest.hiasxm").read_bytes()
        tm = (toolchain / "toolchain.manifest.hiasxm").read_bytes()
        assert (len(sm), len(tm)) == header[4:6]
        assert stdout[64:96] == sha256(sm).digest() and stdout[96:128] == sha256(tm).digest()
        assert sm == (args.preparation / "source-manifest.hiasxm").read_bytes()
        assert manifest(sm) == {n: ((source / n).stat().st_size, bytes.fromhex(h)) for n, h in sorted(files.items())}
        tools = manifest(tm)
        assert set(tools) == set(installed)
        for name, (size, digest) in tools.items():
            target = toolchain / name
            assert target.is_file() and not target.is_symlink() and target.stat().st_nlink == 1
            raw = target.read_bytes()
            assert len(raw) == size and sha256(raw).digest() == digest
            assert target.stat().st_mode & 0o777 == installed[name]["mode"]
        assert (toolchain / "hia-cold-build").read_bytes() == entry.read_bytes()
        assert (toolchain / "hia-source-bootstrap").read_bytes() == (output / "hia-source-bootstrap").read_bytes()
        owner_path = toolchain / "process-owner.receipt"
        owner_stat = owner_path.stat()
        assert owner_path.is_file() and not owner_path.is_symlink()
        assert owner_stat.st_nlink == 1 and owner_stat.st_uid == os.getuid()
        assert 256 <= owner_stat.st_size <= 1048576
        owner = owner_path.read_bytes()
        assert len(owner) == owner_stat.st_size and owner[:8] == b"HIACOR01"
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
        for stage in plan["stages"]:
            folder = toolchain / "build-evidence" / ("s" + str(stage["id"]))
            receipt = (folder / "driver.receipt").read_bytes()
            journal = (folder / "evidence.hiaqj").read_bytes()
            assert len(receipt) == 64 and struct.unpack("<4Q", receipt[:32]) == (
                int.from_bytes(b"HIAQOK01", "little"), stage["nodes"], stage["plan_bytes"], len(journal))
            assert receipt[32:] == sha256(journal).digest()
            stages.append({"id": stage["id"], "name": stage["name"], "nodes": stage["nodes"],
                           "plan_sha256": stage["plan_sha256"], "receipt": pin(receipt), "journal": pin(journal)})
        for name, expected in source_pins.items():
            assert pin((source / name).read_bytes()) == expected, name
        trace_text = trace.read_text()
        execs = [line for line in trace_text.splitlines() if " execve(" in line]
        assert len(execs) == 1 and str(entry) in execs[0]
        assert all("execveat(" not in line or "AT_EMPTY_PATH" in line or "<unfinished ...>" in line for line in trace_text.splitlines())
        report.update(
            passed=True, source_count=len(files), installed_count=len(installed),
            source_manifest=pin(sm), tool_manifest=pin(tm),
            installed={n: {"bytes": size, "sha256": digest.hex()} for n, (size, digest) in tools.items()},
            owner_receipt=pin(owner), native_nested_ns=words[19] - words[4],
            native_cleanup_ns=words[23] - words[19], stages=stages, total_nodes=sum(s["nodes"] for s in stages),
            execve=1, execveat=trace_text.count("execveat("), no_python_or_host_compiler_descendant=True,
            current_source_hashes_preserved=True, execution_trace=pin(trace.read_bytes()),
        )
        save()
        print("CURRENT_PUBLIC_SEVEN_STAGE_CONSTRUCTION_PASS", len(stages), len(installed), elapsed, flush=True)
    except BaseException:
        report["error"] = traceback.format_exc()
        save()
        raise

if __name__ == "__main__":
    main()
