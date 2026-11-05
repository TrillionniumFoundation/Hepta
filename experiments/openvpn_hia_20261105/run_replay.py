#!/usr/bin/env python3
"""Build the real upstream replay oracle against a frozen HIA packet object.

All business implementations are compiled from unmodified OpenVPN source.
The standalone C harness supplies diagnostic-only logging/assert/OOM functions.
This is a codec/replay state integration check, without a VPN or authentication.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(args):
    own = Path(__file__).resolve().parent
    upstream = args.upstream.resolve()
    config = args.config.resolve()
    output = args.output.resolve()
    if output.exists():
        raise ValueError("output must be a new directory; previous runs are preserved")
    output.mkdir(parents=True)
    sources = output / "sources"
    sources.mkdir()
    manifests = {}
    for name in ("packet_replay_differential.c", "openvpn_hia_adapter.c", "openvpn_hia_adapter.h"):
        original = own/name
        copied = sources/name
        data = original.read_bytes()
        copied.write_bytes(data)
        manifests[str(original)] = hashlib.sha256(data).hexdigest()
    source_names = ("packet_id.c", "buffer.c", "otime.c")
    for name in source_names:
        src = upstream/"src/openvpn"/name
        manifests[str(src)] = digest(src)
    for src in (config/"config.h", upstream/"src/openvpn/packet_id.h", upstream/"src/openvpn/circ_list.h"):
        manifests[str(src)] = digest(src)
    object_bytes = args.hia_object.read_bytes()
    receipt = json.loads(args.hia_receipt.read_text())
    object_hash = hashlib.sha256(object_bytes).hexdigest()
    if receipt.get("artifact_sha256") != object_hash or receipt.get("kind") != "object":
        raise ValueError("HIA object differs from its supplied native compilation receipt")
    (output/"packet.o").write_bytes(object_bytes)
    (output/"hia-receipt.json").write_text(json.dumps(receipt, indent=2)+"\n")
    clang = Path(shutil.which(args.clang) or args.clang).resolve()
    commands = []

    def command(argv, name, limit=60):
        start = time.monotonic()
        try:
            result = subprocess.run(argv, capture_output=True, timeout=limit)
            stdout, stderr, code = result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired as exc:
            stdout, stderr, code = exc.stdout or b"", exc.stderr or b"", 124
        (output/(name+".stdout")).write_bytes(stdout)
        (output/(name+".stderr")).write_bytes(stderr)
        commands.append({"command": argv, "exit_code": code,
                         "elapsed_seconds": time.monotonic()-start,
                         "stdout": name+".stdout", "stderr": name+".stderr",
                         "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
                         "stderr_sha256": hashlib.sha256(stderr).hexdigest()})
        return code

    flags = ["-O3", "-fPIC", "-ffunction-sections", "-fdata-sections", "-DHAVE_CONFIG_H",
             "-I"+str(config), "-I"+str(upstream/"src/openvpn"),
             "-I"+str(upstream/"src/compat"), "-I"+str(upstream/"include"), "-I"+str(sources)]
    compiler_hash = digest(clang)
    code = command([str(clang), "--version"], "compiler")
    compile_sources = [(upstream/"src/openvpn"/name, "upstream-"+Path(name).stem+".o") for name in source_names]
    compile_sources += [(sources/"openvpn_hia_adapter.c", "adapter.o"),
                        (sources/"packet_replay_differential.c", "replay.o")]
    for src, name in compile_sources:
        if code:
            break
        code = command([str(clang), *flags, "-MMD", "-MF", str(output/(name+".d")),
                        "-c", str(src), "-o", str(output/name)], "compile-"+name)
    if not code:
        argv = [str(clang), "-Wl,--gc-sections", *[str(output/name) for _, name in compile_sources],
                str(output/"packet.o"), "-o", str(output/"replay")]
        code = command(argv, "link")
    if not code:
        code = command([str(output/"replay")], "replay")
    summary = None
    if (output/"replay.stdout").exists():
        for line in (output/"replay.stdout").read_text().splitlines():
            item = json.loads(line)
            if item.get("kind") == "replay_summary":
                summary = item
    current = {name: digest(Path(name)) for name in manifests}
    changed = [name for name in manifests if manifests[name] != current[name]]
    if digest(clang) != compiler_hash:
        changed.append(str(clang))
    # Each actual translation unit's system-independent include dependencies are
    # included in the reproducibility record. System headers remain toolchain/OS.
    dependencies = {}
    for path in output.glob("*.o.d"):
        raw = path.read_text().replace("\\\n", " ")
        for name in raw.split(":", 1)[1].split():
            path = Path(name)
            if path.is_file():
                dependencies[str(path)] = digest(path)
    result = {"schema": "hepta.openvpn.replay-differential.v1",
              "status": "PASS" if not code and not changed and summary and not summary["failures"] else "FAIL",
              "exit_code": code, "inputs_sha256": manifests, "source_changes_during_run": changed,
              "compiler_sha256": compiler_hash, "dependencies_sha256": dependencies,
              "hia_object_sha256": object_hash, "hia_core_sha256": receipt.get("core_sha256"),
              "hia_implementation_sha256": receipt.get("implementation_sha256"),
              "commands": commands, "result": summary,
              "claims": {"hia_replay_implementation": False, "authentication_tested": False,
                         "crypto_epoch_key_management_tested": False, "tunnel_qualified": False}}
    if (output/"replay").exists():
        result["binary_sha256"] = digest(output/"replay")
    (output/"validation.json").write_text(json.dumps(result, indent=2)+"\n")
    print(json.dumps({"status": result["status"], "result": summary, "source_changes": changed}, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path, required=True, help="unmodified extracted OpenVPN source root")
    parser.add_argument("--config", type=Path, required=True, help="configured OpenVPN build root with config.h")
    parser.add_argument("--hia-object", type=Path, required=True)
    parser.add_argument("--hia-receipt", type=Path, required=True)
    parser.add_argument("--clang", required=True)
    parser.add_argument("--output", type=Path, required=True)
    sys.exit(run(parser.parse_args()))
