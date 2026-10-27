"""Independent Clang object-format capability probe, not a Hepta ABI proof.

Uses a fixed pure LLVM IR fixture and checks real ELF/COFF/Mach-O object bytes.
Cross-object compilation is distinct from native execution and foreign ABI.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hepta.llvm_ssa_target import _TARGETS, _qualified_header

_FIXTURE = b"""define i32 @hepta_scalar(i32 %x) {
entry:
 %out = add i32 %x, 2
 ret i32 %out
}
"""


def probe(clang: str = "clang") -> dict:
    found = shutil.which(clang)
    if found is None:
        raise RuntimeError("Clang is not present in the requested toolchain")
    compiler = Path(found).resolve()
    version = subprocess.run([str(compiler), "--version"],
                             capture_output=True, text=True, timeout=15)
    if version.returncode or not version.stdout.strip():
        raise RuntimeError("Could not identify Clang")
    report = {
        "schema": "hepta.native-object-probe.v1",
        "scope": "independent_compiler_object_only_not_hepta_or_ffi_abi_qualification",
        "status": "rejected",
        "compiler": {"path": str(compiler),
                     "version": version.stdout.splitlines()[0],
                     "sha256": sha256(compiler.read_bytes()).hexdigest()},
        "fixture_sha256": sha256(_FIXTURE).hexdigest(),
        "targets": [],
        "claims": {
            "compiler_object_format_probe_completed": False,
            "hepta_native_backend_qualified": False,
            "foreign_c_abi_qualified": False,
            "target_program_executed": False,
            "physical_hardware_tested": False,
        },
    }
    with tempfile.TemporaryDirectory(prefix="hepta-target-object-") as td:
        root = Path(td)
        source = root / "source.ll"
        source.write_bytes(_FIXTURE)
        for target, (fmt, machine) in sorted(_TARGETS.items()):
            output = root / (target + ".o")
            cmd = [str(compiler), "--target=" + target, "-x", "ir",
                   "-O3", "-c", str(source), "-o", str(output)]
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=45, check=False)
            observed = output.read_bytes() if output.is_file() else b""
            accepted = proc.returncode == 0 and _qualified_header(observed, target)
            report["targets"].append({
                "target": target, "format": fmt, "machine": machine,
                "status": "passed" if accepted else "rejected",
                "compiler_exit_code": proc.returncode,
                "object_bytes": len(observed),
                "object_sha256": sha256(observed).hexdigest() if observed else None,
                "stderr": proc.stderr[-2000:],
                "command_profile": ["--target=" + target, "-x", "ir", "-O3", "-c"],
            })
    accepted = bool(report["targets"]) and all(t["status"] == "passed" for t in report["targets"])
    report["status"] = "passed_object_only" if accepted else "rejected"
    report["claims"]["compiler_object_format_probe_completed"] = accepted
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = probe(args.clang)
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        result = {"schema": "hepta.native-object-probe.v1", "status": "environment_blocked",
                  "error": str(exc), "claims": {"compiler_object_format_probe_completed": False}}
    dest = Path(os.path.abspath(args.output))
    if dest.exists() or dest.is_symlink() or not dest.parent.is_dir():
        raise SystemExit("E_PROBE_OUTPUT: output must be a fresh regular file path in an existing directory")
    stage = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=dest.parent,
                                         prefix=".native-formats-", delete=False) as stream:
            stage = Path(stream.name)
            stream.write(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.link(stage, dest)
    finally:
        if stage is not None:
            stage.unlink(missing_ok=True)
    print(json.dumps({"output": str(dest), "status": result["status"],
                      "tested_targets": len(result.get("targets", []))}, sort_keys=True))
    return 0 if result["status"] == "passed_object_only" else 1


if __name__ == "__main__":
    raise SystemExit(main())
