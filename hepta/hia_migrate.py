"""Strict C/C++ L1 -> checked Hepta -> source-qualified HIA SSA -> native LLVM.

This composes the ONE existing migration authority and HIA LLVM pipeline. It
accepts only their common finite scalar profile. No second parser, semantics,
C++ mangled ABI preservation, source-equivalence proof, or safety certification.
The three-file output bundle uses Linux renameat2 no-replace atomic directory publication.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import tempfile

from .c_migrate import migrate_c
from .cpp2hepta import migrate_cpp
from .hia_source_bridge import build_checked_hepta_hia_native
from .hia_bundle_atomic import (AtomicBundleRejected, AtomicBundleUncertain,
                                publish_hia_bundle)


class HIAMigrationRejected(ValueError):
    """Candidate cannot be represented by the strict source-checked HIA path."""


def _sha(data: bytes) -> str:
    return sha256(data).hexdigest()


def _reject(message: str) -> None:
    raise HIAMigrationRejected("E_HIA_MIGRATE: " + message)


def migrate_scalar_to_hia(source: str | Path, output_directory: str | Path, *,
                          language: str, rustc: str | None = None,
                          clang: str = "clang", clangxx: str = "clang++",
                          target: str | None = None) -> dict:
    """Emit a closed L1 bundle if all original migration/native gates succeed.

    Source and target bytes are rechecked before publication. The native pipeline
    independently checks the Hepta project against the pinned Rust toolchain,
    seals and replays executable HIA Core v1, and validates native LLVM publication.
    This wrapper never turns a source translator's claimed equivalence into proof.
    """
    src = Path(source).resolve(strict=False)
    out = Path(os.path.abspath(output_directory))
    result = {
        "schema": "hepta.hia-l1-migration.v1", "ok": False,
        "status": "rejected", "language": language,
        "source": str(src), "output_directory": str(out),
        "publication": "linux_renameat2_noreplace_fsync_v1",
        "migration": None, "hia_build": None, "artifacts": {},
        "diagnostics": [],
        "claims": {
            "bounded_l1_profile_only": True,
            "rust_reference_required": True,
            "hia_source_replay_required": True,
            "executable_hia_core_v1_required": True,
            "original_c_or_cpp_semantics_proved": False,
            "foreign_pointer_contracts_proved": False,
            "cpp_mangled_abi_preserved": False,
            "whole_language_memory_safety_proved": False,
            "native_backend_refinement_proved": False,
            "physical_target_executed": False,
        },
    }
    try:
        if language not in {"c", "cpp"}:
            _reject("language must be c or cpp")
        if target is not None and target not in {
                "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"}:
            _reject("target is outside explicitly admitted native HIA profiles")
        valid_ext = {".c"} if language == "c" else {".cc", ".cpp", ".cxx"}
        if (not src.is_file() or src.suffix not in valid_ext
                or out.exists() or out.is_symlink() or not out.parent.is_dir()
                or src == out):
            _reject("source/output paths outside the strict new-directory profile")
        before = src.read_bytes()
        if not before or len(before) > 256_000:
            _reject("source byte budget exceeded")
        result["source_sha256"] = _sha(before)
        with tempfile.TemporaryDirectory(prefix=".hia-l1-", dir=out.parent) as directory:
            stage = Path(directory)
            hepta = stage / "candidate.hepta"
            native = stage / ("candidate.o" if target is not None else "candidate.so")
            candidate_report = (migrate_c(src, hepta, clang=clang) if language == "c"
                                else migrate_cpp(src, hepta, clangxx=clangxx))
            result["migration"] = candidate_report
            if (type(candidate_report) is not dict or candidate_report.get("ok") is not True
                    or candidate_report.get("status") != "frontend_checked_not_native_qualified"
                    or candidate_report.get("native_validation") != "not_run"
                    or candidate_report.get("source_sha256") != result["source_sha256"]
                    or (language == "c" and candidate_report.get("source_equivalence_proved") is not False)
                    or (language == "cpp" and (candidate_report.get("behavioral_equivalence_proved") is not False
                                                  or candidate_report.get("cpp_abi_preserved") is not False))):
                _reject("underlying migration did not qualify the exact source")
            if not hepta.is_file() or hepta.is_symlink():
                _reject("migrator did not publish an ordinary Hepta candidate")
            code = hepta.read_bytes()
            if (not code or len(code) > 1_000_000
                    or candidate_report.get("output_sha256") != _sha(code)):
                _reject("candidate bytes disagree with source migration receipt")
            result["artifacts"]["candidate.hepta"] = {"sha256": _sha(code), "bytes": len(code)}
            # P0/P2: one native executable HIA Core consumer. Never return to
            # the older scalar-core.v0 -> independent SSA LLVM publisher.
            native_target = target or "x86_64-unknown-linux-gnu"
            native_kind = "object" if target is not None else "shared"
            build = build_checked_hepta_hia_native(
                hepta, native, rustc=rustc, clang=clang,
                target=native_target, kind=native_kind, profile="scalar")
            result["hia_build"] = build
            claims = build.get("claims") if type(build) is dict else None
            ids = build.get("identities") if type(build) is dict else None
            native_report = build.get("native_backend") if type(build) is dict else None
            reference = build.get("rust_reference") if type(build) is dict else None
            reference_checks = reference.get("checks") if type(reference) is dict else None
            expected_status = "native_compiled_not_executed"
            expected_claims = {
                "pinned_rust_reference_validated": True,
                "source_bound_resource_ir_checked": True,
                "native_codegen_consumed_verified_hia_core": True,
                "native_executed": False,
                "source_to_core_refinement_proved": False,
                "whole_language_soundness_proved": False,
            }

            def digest(value):
                return (type(value) is str and len(value) == 64
                        and all(c in "0123456789abcdef" for c in value))

            if (type(build) is not dict or build.get("ok") is not True
                    or build.get("schema") != "hepta.build-checked-hia-source.v1"
                    or build.get("status") != expected_status
                    or build.get("output") != str(native)
                    or build.get("target") != native_target
                    or type(reference) is not dict or reference.get("ok") is not True
                    or reference.get("source_sha256") != _sha(code)
                    or type(reference_checks) is not dict
                    or reference_checks.get("rust_borrows_types") != "rustc_checked"
                    or type(claims) is not dict
                    or set(claims) != set(expected_claims)
                    or any(claims[key] is not value for key, value in expected_claims.items())
                    or type(ids) is not dict
                    or not all(digest(ids.get(key)) for key in (
                        "project_sha256", "compiler_sha256", "source_semantic_sha256",
                        "resource_ir_sha256", "hia_program_sha256", "llvm_ir_sha256",
                        "scalar_ssa_sha256", "ssa_verification_sha256"))
                    or reference.get("compiler_sha256") != ids["compiler_sha256"]
                    or type(native_report) is not dict
                    or native_report.get("status") != expected_status
                    or native_report.get("target") != native_target
                    or native_report.get("kind") != native_kind
                    or native_report.get("core_sha256") != ids["hia_program_sha256"]
                    or native_report.get("llvm_ir_sha256") != ids["llvm_ir_sha256"]
                    or type(native_report.get("claims")) is not dict
                    or native_report["claims"].get("backend_refinement_proved") is not False
                    or native_report["claims"].get("native_execution_qualified") is not False):
                _reject("source-bound executable HIA Core and LLVM qualification incomplete")
            if not native.is_file() or native.is_symlink():
                _reject("native pipeline did not publish a real staged object")
            binary = native.read_bytes()
            publication = build.get("publication")
            if (not binary or native_report.get("artifact_sha256") != _sha(binary)
                    or native_report.get("artifact_bytes") != len(binary)
                    or type(publication) is not dict
                    or publication != {"sha256": _sha(binary), "bytes": len(binary)}):
                _reject("native artifact or publication changed after HIA Core build")
            binary_name = "candidate.o" if target else "candidate.so"
            result["artifacts"][binary_name] = {"sha256": _sha(binary), "bytes": len(binary)}
            if src.read_bytes() != before or hepta.read_bytes() != code or native.read_bytes() != binary:
                _reject("source/candidate/native snapshot changed before publication")
            result["status"] = "native_emitted_L1_not_equivalence_proved"
            result["ok"] = True
            result["target"] = target
            manifest_bytes = (json.dumps(result, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("utf-8")
            if len(manifest_bytes) > 2_000_000:
                _reject("evidence manifest exceeds bounded report budget")
            manifest = stage / "migration-hia.json"
            with manifest.open("xb") as stream:
                stream.write(manifest_bytes)
                stream.flush()
                os.fsync(stream.fileno())
            if out.exists() or out.is_symlink() or src.read_bytes() != before:
                _reject("destination appeared or source changed before publication")
            # All three files are already verified. Only one kernel-level
            # rename makes the entire directory visible; never create an
            # empty destination followed by per-file hardlinks.
            receipt = publish_hia_bundle(
                stage, out,
                {"candidate.hepta": code, binary_name: binary,
                 "migration-hia.json": manifest_bytes},
                lambda: src.read_bytes() == before)
            if (receipt.get("method") != "linux_renameat2_noreplace_fsync_v1"
                    or receipt.get("atomic_directory_visible") is not True
                    or receipt.get("parent_directory_fsynced") is not True):
                # Once the atomic rename succeeds, it must not be rolled
                # back by blindly deleting a bundle visible to readers.
                raise AtomicBundleUncertain(
                    "E_HIA_BUNDLE: incomplete durable publication receipt")
        return result
    except AtomicBundleUncertain as exc:
        result["ok"] = False
        result["status"] = "recovery_required"
        result["diagnostics"].append({
            "code": "E_HIA_BUNDLE_UNCERTAIN", "message": str(exc)})
        return result
    except (HIAMigrationRejected, AtomicBundleRejected, OSError, ValueError,
            UnicodeError, TypeError, KeyError) as exc:
        result["ok"] = False
        result["status"] = "rejected"
        result["diagnostics"].append({"code": "E_HIA_MIGRATE", "message": str(exc)})
        return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--language", choices=("c", "cpp"), required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--rustc")
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--clangxx", default="clang++")
    parser.add_argument("--target")
    args = parser.parse_args(argv)
    report = migrate_scalar_to_hia(args.source, args.output_dir, language=args.language,
                                   rustc=args.rustc, clang=args.clang,
                                   clangxx=args.clangxx, target=args.target)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
