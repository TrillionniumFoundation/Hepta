#!/usr/bin/env python3
"""Inventory Linux and run the existing C migration intake on every Kbuild TU.

This is an admission campaign, not a new GNU C translator. Original commands
are data: none is executed, normalized, or stripped to make admission succeed.
An early rejected flag means declaration/semantic analysis was NOT reached.
The original bounded full-project gate and the complete per-command gate have
separate results. Passing a per-command gate never claims whole-project capture.
"""
from __future__ import annotations

import argparse
from collections import Counter
import gzip
import hashlib
import json
import os
from pathlib import Path
import shlex
import stat
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.c_migrate import MigrationRejected
from hepta import c_project


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode()


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")


def source_inventory(source: Path, receipt: dict, output: Path) -> dict:
    """Hash all regular files and symlink targets without following symlinks.

    The all-files denominator includes tests, tools, docs and unused platforms.
    A .c count is a source-file count, not an active TU or function count.
    """
    started = time.monotonic_ns()
    collector_sha256 = sha256(Path(__file__))
    source = source.resolve(strict=True)
    output.mkdir(parents=True, exist_ok=False)
    counts, byte_counts, line_counts = Counter(), Counter(), Counter()
    total_bytes = regular_files = symlinks = 0
    manifest = output / "source-manifest.jsonl.gz"
    manifest_digest = hashlib.sha256()
    code_kinds = {"c", "header", "asm_cpp", "asm", "rust"}
    with manifest.open("xb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as stream:
            for directory, dirs, files in os.walk(source, followlinks=False):
                dirs.sort()
                # Symlinked directories are entries, not traversed directories.
                names = sorted(files + [d for d in dirs if (Path(directory) / d).is_symlink()])
                for name in names:
                    path = Path(directory) / name
                    relative = path.relative_to(source).as_posix()
                    info = path.lstat()
                    if stat.S_ISLNK(info.st_mode):
                        target = os.readlink(path)
                        item = {"path": relative, "type": "symlink", "target": target}
                        symlinks += 1
                    elif stat.S_ISREG(info.st_mode):
                        suffix = path.suffix
                        kind = {".c": "c", ".h": "header", ".S": "asm_cpp",
                                ".s": "asm", ".rs": "rust"}.get(suffix, "other")
                        data = path.read_bytes()
                        if len(data) != info.st_size or path.stat().st_mtime_ns != info.st_mtime_ns:
                            raise ValueError("source changed while inventorying: " + relative)
                        lines = data.count(b"\n") + bool(data and not data.endswith(b"\n"))
                        item = {"path": relative, "type": "file", "kind": kind,
                                "bytes": len(data), "lines": lines,
                                "sha256": hashlib.sha256(data).hexdigest()}
                        counts[kind] += 1
                        byte_counts[kind] += len(data)
                        line_counts[kind] += lines
                        regular_files += 1
                        total_bytes += len(data)
                    else:
                        raise ValueError("unexpected non-regular upstream input: " + relative)
                    line = canonical(item) + b"\n"
                    stream.write(line)
                    manifest_digest.update(line)
    result = {
        "schema": "hepta.linux-source-inventory.v1",
        "collector_sha256": collector_sha256,
        "kernel_version": receipt["version"],
        "source_archive_sha256": receipt["sha256"],
        "source_receipt": receipt,
        "source_directory": str(source),
        "scope": "complete_upstream_archive_all_architectures_and_files",
        "regular_files": regular_files,
        "symlinks": symlinks,
        "total_files": regular_files + symlinks,
        "total_bytes": total_bytes,
        "files_by_kind": dict(sorted(counts.items())),
        "bytes_by_kind": dict(sorted(byte_counts.items())),
        "lines_by_kind": dict(sorted(line_counts.items())),
        "source_files_total": sum(counts[k] for k in code_kinds),
        "source_files_total_scope": "suffix_classification_only_not_all_semantic_units",
        "source_file_suffixes": [".c", ".h", ".S", ".s", ".rs"],
        "c_source_files_total": counts["c"],
        "manifest": {"path": str(manifest), "sha256": sha256(manifest),
                     "uncompressed_jsonl_sha256": manifest_digest.hexdigest()},
        "function_denominator": None,
        "function_denominator_status": "not_parsed",
        "all_configurations_compiled": False,
        "wall_ns": time.monotonic_ns() - started,
    }
    if sha256(Path(__file__)) != collector_sha256:
        raise ValueError("inventory collector changed during execution")
    write_json(output / "inventory.json", result)
    return result


def _safe_database(path: Path) -> tuple[bytes, list[dict]]:
    """Campaign parser only; the compiler's stricter parser is still exercised."""
    with path.open("rb") as stream:
        raw = stream.read(256 * 1024 * 1024 + 1)
    if len(raw) > 256 * 1024 * 1024:
        raise ValueError("campaign compilation database exceeds 256 MiB")
    entries = json.loads(raw, object_pairs_hook=c_project._reject_duplicate_keys,
                         parse_constant=c_project._reject_nonfinite_constant)
    if type(entries) is not list or not entries or len(entries) > 200_000:
        raise ValueError("campaign requires 1..200000 original commands")
    return raw, entries


def _error(exc: Exception) -> dict:
    return {"code": getattr(exc, "code", type(exc).__name__), "message": str(exc)}


def kernel_flag_probes() -> list[dict]:
    """Exercise individual admission failures; these are not kernel TU results."""
    directory = Path.cwd().resolve()
    source = directory / "capability_probe.c"
    result = []
    for flag in ("-std=gnu11", "-ffreestanding", "-fno-strict-aliasing",
                 "-fno-pie", "-mno-red-zone", "-mcmodel=kernel",
                 "-fno-stack-protector", "-mno-sse", "-mno-mmx"):
        argv = ["clang", "-std=c11", flag, "-c", str(source)]
        try:
            c_project._command_arguments(argv, source, directory)
            result.append({"flag": flag, "status": "intake_admitted"})
        except MigrationRejected as exc:
            result.append({"flag": flag, "status": "intake_rejected", **_error(exc)})
    return result


def audit_translation(database: Path, config: Path, source: Path, output: Path,
                      clang: str) -> dict:
    started = time.monotonic_ns()
    from hepta.pipeline import compiler_hash
    compiler_sha256 = compiler_hash()
    collector_sha256 = sha256(Path(__file__))
    database, config, source = (p.resolve(strict=True) for p in (database, config, source))
    raw, entries = _safe_database(database)
    output.mkdir(parents=True, exist_ok=False)
    (output / "compile_commands.original.json").write_bytes(raw)
    (output / "config.original").write_bytes(config.read_bytes())
    try:
        # This intentionally preserves the current 2 MB/32-command gate.
        full_capture = c_project.capture_project(database, clang=clang)
        full_result = {"status": "captured", "capture": full_capture}
    except (MigrationRejected, OSError, ValueError) as exc:
        full_result = {"status": "rejected", **_error(exc)}

    counts, rejection_codes, first_errors = Counter(), Counter(), Counter()
    sources = set()
    ledger = output / "translation-units.jsonl.gz"
    declarations_complete = 0
    with ledger.open("xb") as raw_ledger:
        with gzip.GzipFile(filename="", fileobj=raw_ledger, mode="wb", mtime=0) as stream:
            # A relative `directory` in a compilation database is relative to
            # that database. Keep the shard in the SAME directory so a move
            # cannot silently change include/source resolution. We never run
            # database-provided commands or overwrite the original database.
            with tempfile.NamedTemporaryFile(prefix="hia-linux-tu-", suffix=".json",
                                             dir=database.parent) as temporary:
                single = Path(temporary.name)
                for index, entry in enumerate(entries):
                    row = {
                        "index": index, "original_entry": entry,
                        "entry_sha256": hashlib.sha256(canonical(entry)).hexdigest(),
                        "intake_status": "not_run", "declaration_analysis": "not_reached",
                        "hepta_translation": "not_run", "rust_bridge_build": "not_run",
                        "hia_native_build": "not_run", "kernel_object": "not_built",
                        "whole_translation_unit_rewritten": False,
                    }
                    try:
                        # Sharding is explicit campaign bookkeeping, never a claim
                        # that the original whole-project parser accepted the DB.
                        single.write_bytes(canonical([entry]))
                        _, selected = c_project._load_compdb(single)
                        record = selected[0]
                        directory = c_project._path(record["directory"], database.parent)
                        path = c_project._path(record["file"], directory)
                        row["source"] = str(path)
                        sources.add(str(path))
                        row["source_in_upstream_tree"] = path.is_relative_to(source)
                        if not path.is_file() or path.suffix != ".c":
                            raise MigrationRejected("E_C_BUILD_SOURCE", "Not a present C source")
                        row["source_sha256"] = sha256(path)
                        argv = record.get("arguments")
                        if argv is None:
                            argv = shlex.split(record["command"], posix=True)
                        flags, omitted, original_source = c_project._command_arguments(argv, path, directory)
                        row.update(intake_status="admitted", frontend_arguments=flags,
                                   omitted_arguments=omitted, original_source_argument=original_source)
                        # Only actually admitted commands advance to real capture
                        # and translation. This endpoint emits Hepta and optional
                        # Rust, not a source-qualified HIA kernel object.
                        from hepta.c_migration_project import migrate_project
                        migration = migrate_project(single, output / f"admitted-{index:06d}",
                                                    clang=clang, verify_native=False)
                        row["migration"] = migration
                        row["hepta_translation"] = "passed" if migration.get("ok") else "rejected"
                        complete = migration.get("declaration_inventory_complete") is True
                        row["declaration_analysis"] = "complete" if complete else "incomplete_or_not_reached"
                        declarations_complete += complete
                    except (MigrationRejected, ValueError, OSError, TypeError) as exc:
                        row.update(intake_status="rejected", rejection=_error(exc))
                        rejection_codes[row["rejection"]["code"]] += 1
                        first_errors[row["rejection"]["message"]] += 1
                    counts[row["intake_status"]] += 1
                    stream.write(canonical(row) + b"\n")
    if database.read_bytes() != raw:
        raise ValueError("original compilation database changed during campaign")
    if compiler_hash() != compiler_sha256 or sha256(Path(__file__)) != collector_sha256:
        raise ValueError("migration implementation changed during campaign")
    result = {
        "schema": "hepta.linux-translation-intake.v1",
        "collector_sha256": collector_sha256,
        "compiler_sha256": compiler_sha256,
        "status": "blocked" if counts["rejected"] else "intake_completed_not_kernel_built",
        "scope": "all_commands_in_one_frozen_configuration_not_all_linux_configurations",
        "config_sha256": sha256(config), "compile_commands_sha256": hashlib.sha256(raw).hexdigest(),
        "active_compile_units": len(entries), "unique_source_files": len(sources),
        "attempted_compile_units": len(entries), "not_run_compile_units": 0,
        "intake_status_counts": dict(sorted(counts.items())),
        "declaration_inventory_complete_units": declarations_complete,
        "whole_translation_units_hia_native": 0,
        "hia_compiled_units": 0,
        "all_configurations_translated": False,
        "source_files_rewritten": 0,
        "function_denominator": None,
        "function_denominator_status": "unavailable_after_early_intake_rejection",
        "fallback_c_units": len(entries),
        "fallback_policy": "retained_stock_baseline_not_counted_as_hia",
        "full_project_capture": full_result,
        "per_command_intake_is_full_project_capture": False,
        "rejection_codes": dict(sorted(rejection_codes.items())),
        "first_rejection_messages": dict(sorted(first_errors.items())),
        "kernel_flag_probes": kernel_flag_probes(),
        "kernel_image": None,
        "hia_kernel_status": "not_built",
        "ndu_calls": 0,
        "ledger": {"path": str(ledger), "sha256": sha256(ledger)},
        "wall_ns": time.monotonic_ns() - started,
    }
    write_json(output / "translation.json", result)
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    inventory = commands.add_parser("inventory")
    inventory.add_argument("--source", type=Path, required=True)
    inventory.add_argument("--source-receipt", type=Path, required=True)
    inventory.add_argument("--output", type=Path, required=True)
    intake = commands.add_parser("intake")
    intake.add_argument("--database", type=Path, required=True)
    intake.add_argument("--config", type=Path, required=True)
    intake.add_argument("--source", type=Path, required=True)
    intake.add_argument("--output", type=Path, required=True)
    intake.add_argument("--clang", default="clang")
    args = parser.parse_args(argv)
    if args.action == "inventory":
        result = source_inventory(args.source, json.loads(args.source_receipt.read_text()), args.output)
    else:
        result = audit_translation(args.database, args.config, args.source, args.output, args.clang)
    print(json.dumps(result, indent=2, sort_keys=True))
    # A measured rejection is a successfully completed intake audit, never a
    # successfully translated or qualified kernel. Consumers inspect status.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
