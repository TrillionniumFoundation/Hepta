"""Rebuild Selfhost-Core from a fresh, source-only export with no seed caches.

This is process/source/cache isolation on the current Linux host, not a fresh
virtual machine or a security sandbox. The seed toolchain remains explicitly
trusted and its actual identities are retained by the nested qualification.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
import stat
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))
from tools.hia_selfhost_contract import CONTRACT_PATH, validate_contract
from tools.hia_selfhost_process_owner import run_owned


def exported_observer(path, nested, packer_sha256):
    """Capture the HIA-emitted ELF admitted by both cold observer witnesses."""
    from tools.generate_hia_native_observer import reference_image

    expected = reference_image()
    reference = nested['native_observer_reference']
    build = nested['native_observer_build']
    identity = sha256(expected).hexdigest()
    if (reference['before_B0'] is not True or reference['every_output_byte_compared'] is not True
            or reference['expected_image_bytes'] != len(expected)
            or reference['expected_image_sha256'] != identity or build['executable_sha256'] != identity
            or build['independent_reference_before_B0'] is not True
            or reference['packer_source_sha256'] != packer_sha256 or build['source_sha256'] != packer_sha256):
        raise ValueError('cold observer does not match its HIA source and independent reference')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != len(expected):
            raise ValueError('cold observer has an invalid extent')
        executable = source.read(len(expected) + 1)
    if executable != expected:
        raise ValueError('cold observer differs from its checked HIA image')
    return executable


def cold_compiler_observer(cold_bytes):
    """Select immutable HIA observer bytes even when a portable report predates the embedded ELF."""
    from tools.generate_hia_native_observer import reference_image

    report = json.loads(cold_bytes)
    expected = reference_image()
    if 'native_flat_observer_hex' in report:
        encoded = report['native_flat_observer_hex']
        if encoded != expected.hex():
            raise ValueError('cold compiler observer differs from the admitted syscall ABI')
        return bytes.fromhex(encoded)
    from tools.hia_selfhost_native_observer import independent_reference
    reference = independent_reference()
    image = b''.join(bytes(row['result']['values'][1:]) for row in reference['vm_windows'])
    if image != expected:
        raise ValueError('HIA observer reconstruction differs from its admitted image')
    return image


def cold_replay(output, *, native_transport=False):
    if type(native_transport) is not bool:
        raise ValueError("native transport selection must be explicit boolean")
    contract = validate_contract()
    requested = Path(output)
    if not requested.is_absolute():
        requested = Path.cwd() / requested
    # Inspect the spelling supplied by the caller before resolve() erases a
    # dangling leaf link or traverses a link in an existing ancestor.
    if any(path.is_symlink() for path in (requested, *requested.parents)):
        raise ValueError("cold replay output cannot use symbolic links")
    if requested.exists():
        raise ValueError("cold replay requires a new report path")
    output = requested.resolve()
    directory = output.with_suffix(".cold")
    directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    source_root = directory / "source"
    source_root.mkdir(mode=0o700)
    files = {**contract["source_identity"]["files"],
             CONTRACT_PATH: sha256((ROOT / CONTRACT_PATH).read_bytes()).hexdigest()}
    for name, expected in files.items():
        source = ROOT / name
        data = source.read_bytes()
        if sha256(data).hexdigest() != expected:
            raise ValueError("source changed while preparing cold export: " + name)
        target = source_root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        target.chmod(0o400)
    validate_contract(source_root)
    home = directory / "home"
    home.mkdir(mode=0o700)
    temp = directory / "tmp"
    temp.mkdir(mode=0o700)
    nested_output = directory / "qualification.json"
    command = [sys.executable, "-I", "-S", "-B",
               str(source_root / "tools/qualify_hia_selfhost.py"),
               "--output", str(nested_output)]
    if native_transport:
        command.append("--native-transport")
    environment = {"PATH": "/usr/bin:/bin", "HOME": str(home), "TMPDIR": str(temp),
                   "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC"}
    request = {"schema": "hepta.hia.selfhost-cold-request.v1", "command": command,
               "source_root": str(source_root), "source_manifest": files,
               "environment_keys": sorted(environment), "new_home": str(home),
               "preexisting_generated_artifacts": []}
    (directory / "request.json").write_text(json.dumps(request, indent=2, sort_keys=True) + "\n")
    started = time.monotonic_ns()
    owner = run_owned(command, cwd=home, env=environment,
                      stdout_path=directory / "stdout.log", stderr_path=directory / "stderr.log",
                      receipt_path=directory / "process-owner.json",
                      qualification_seconds=180, cleanup_seconds=3)
    returncode = owner.get("returncode")
    owner_complete = (owner.get("status") == "OWNED_PROCESS_COMPLETED"
                      and owner.get("exit_observed_before_deadline") is True
                      and owner.get("timed_out") is False
                      and owner.get("cleanup", {}).get("complete") is True)
    # Do not inspect a report while a remaining descendant could still write it,
    # or admit a late successful report after the unchanged 180-second budget.
    nested = json.loads(nested_output.read_text()) if owner_complete and nested_output.exists() else None
    preserved = all(sha256((source_root / path).read_bytes()).hexdigest() == digest
                    for path, digest in files.items())
    untouched_origin = all(sha256((ROOT / path).read_bytes()).hexdigest() == digest
                           for path, digest in files.items())
    observer = None
    observer_error = None
    if nested and nested.get("status") == "SELF_HOSTED_FIXED_CORE_PASS":
        try:
            observer = exported_observer(nested_output.with_suffix(".evidence") / "native-observer.elf",
                                         nested, files["examples/hia_bootstrap/native_observer_packer.hepta"])
        except (OSError, KeyError, TypeError, ValueError) as error:
            observer_error = str(error)
    checks = {"nested_process_exit_zero": owner_complete and returncode == 0,
              "owned_process_tree_cleanup_confirmed": owner.get("cleanup", {}).get("complete") is True,
              "nested_full_qualification_pass": observer is not None,
              "source_export_hashes_preserved": preserved,
              "origin_hashes_preserved": untouched_origin,
              "export_manifest_matches_qualification": bool(nested and nested.get("source_manifest") == files),
              "isolated_python_without_site": bool(nested and nested["seed"]["python"]["isolated"]
                                                    and nested["seed"]["python"]["no_site"]),
              "no_inherited_seed_or_successor_images": True,
              "no_inherited_home_or_python_cache": True,
              "no_bytecode_cache_created": not any(source_root.rglob("__pycache__")),
              "no_ancestor_git_identity": bool(nested and nested.get("checkout", {}).get("kind") == "source_export")}
    result = {"schema": "hepta.hia.selfhost-cold-replay.v1",
              "status": "COLD_SELFHOST_REPLAY_PASS" if all(checks.values()) else "FAIL",
              "profile": contract["profile"], "checks": checks, "returncode": returncode,
              "process_owner": owner, "qualification_wall_limit_seconds": 180,
              "cleanup_wall_limit_seconds": 3,
              "wall_elapsed_ns": time.monotonic_ns() - started,
              "source_manifest": files, "nested_report": str(nested_output),
              "nested_report_sha256": sha256(nested_output.read_bytes()).hexdigest() if nested else None,
              "seed_sha256": nested["seed"]["artifact_sha256"] if nested else None,
              "generation_sha256": [x["produced_sha256"] for x in nested["generations"]] if nested else [],
              "modified_generation_sha256": [x["produced_sha256"] for x in nested["modified_generations"]] if nested else [],
              "isolation": {"source_only_copy": True, "fresh_home": True,
                            "fresh_processes": True, "python_site_disabled": True,
                            "virtual_machine": False, "security_sandbox": False,
                            "shared_host_dependencies": ["CPython executable and standard library",
                                                         "GNU ld", "libc", "kernel", "hardware"]}}
    if observer is not None:
        result["native_flat_observer_hex"] = observer.hex()
    elif observer_error is not None:
        result["native_flat_observer_error"] = observer_error
    if native_transport:
        result["isolation"]["shared_host_dependencies"].extend([
            "current CPython headers and shared library", "current source-bound C compiler for the explicit R3 bridge"])
        result["native_transport_selection"] = {
            "mode": "fresh-source-export-build-after-B3", "inherited_native_images": False,
            "whole_native": False}
    # The report is an externally visible result, not a scratch file. A rival
    # process may have claimed the initially absent path while we ran the cold
    # compiler; never overwrite its file or follow its newly created symlink.
    with output.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--native-transport", action="store_true")
    args = parser.parse_args()
    result = cold_replay(args.output, native_transport=args.native_transport)
    print(json.dumps({"status": result["status"], "output": str(args.output),
                      "checks_passed": sum(result["checks"].values()),
                      "checks_total": len(result["checks"]),
                      "generation_sha256": result["generation_sha256"],
                      "modified_generation_sha256": result["modified_generation_sha256"]}, sort_keys=True))
    raise SystemExit(0 if result["status"] == "COLD_SELFHOST_REPLAY_PASS" else 1)


if __name__ == "__main__":
    main()
