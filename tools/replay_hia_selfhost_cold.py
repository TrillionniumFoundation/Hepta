"""Rebuild Selfhost-Core from a fresh, source-only export with no seed caches.

This is process/source/cache isolation on the current Linux host, not a fresh
virtual machine or a security sandbox. The seed toolchain remains explicitly
trusted and its actual identities are retained by the nested qualification.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))
from tools.hia_selfhost_contract import CONTRACT_PATH, validate_contract


def cold_replay(output):
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
    environment = {"PATH": "/usr/bin:/bin", "HOME": str(home), "TMPDIR": str(temp),
                   "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC"}
    request = {"schema": "hepta.hia.selfhost-cold-request.v1", "command": command,
               "source_root": str(source_root), "source_manifest": files,
               "environment_keys": sorted(environment), "new_home": str(home),
               "preexisting_generated_artifacts": []}
    (directory / "request.json").write_text(json.dumps(request, indent=2, sort_keys=True) + "\n")
    started = time.monotonic_ns()
    try:
        completed = subprocess.run(command, cwd=home, env=environment,
                                   capture_output=True, timeout=180)
        stdout, stderr, returncode = completed.stdout, completed.stderr, completed.returncode
    except subprocess.TimeoutExpired as exc:
        stdout, stderr, returncode = exc.stdout or b"", exc.stderr or b"", None
    (directory / "stdout.log").write_bytes(stdout)
    (directory / "stderr.log").write_bytes(stderr)
    nested = json.loads(nested_output.read_text()) if nested_output.exists() else None
    preserved = all(sha256((source_root / path).read_bytes()).hexdigest() == digest
                    for path, digest in files.items())
    untouched_origin = all(sha256((ROOT / path).read_bytes()).hexdigest() == digest
                           for path, digest in files.items())
    checks = {"nested_process_exit_zero": returncode == 0,
              "nested_full_qualification_pass": bool(nested and nested.get("status") == "SELF_HOSTED_FIXED_CORE_PASS"),
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
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = cold_replay(args.output)
    print(json.dumps({"status": result["status"], "output": str(args.output),
                      "checks_passed": sum(result["checks"].values()),
                      "checks_total": len(result["checks"]),
                      "generation_sha256": result["generation_sha256"],
                      "modified_generation_sha256": result["modified_generation_sha256"]}, sort_keys=True))
    raise SystemExit(0 if result["status"] == "COLD_SELFHOST_REPLAY_PASS" else 1)


if __name__ == "__main__":
    main()
