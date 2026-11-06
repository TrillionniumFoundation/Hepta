"""Close a full configured Linux build against actual compiler invocations.

The denominator is every saved Kbuild command plus every compiler invocation,
not just compile_commands.json or entries bearing -D__KERNEL__.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import gzip
import hashlib
import json
from pathlib import Path
import re
import shlex

from tools import qualify_hia_linux_baseline as baseline

SCHEMA = "hepta.hia.linux.full-build-inventory.v1"
TARGET_KINDS = frozenset(("target_c", "target_assembly"))
TRUSTED_KINDS = frozenset(("preprocess", "dependency_scan", "compiler_query", "object_link", "compiler_capability_probe", "host_tool"))
COMPILER_NAME = re.compile(r"(?:.+-)?(?:clang(?:\+\+)?(?:-[0-9]+)?|gcc(?:-[0-9]+)?|g\+\+(?:-[0-9]+)?|cc|c\+\+)$")
DERIVATION_NAME = re.compile(r"(?:.+-)?(?:ld(?:\.lld|\.bfd|\.gold)?|lld|llvm-ar|ar|llvm-objcopy|objcopy)$")


def require(condition, message):
    baseline.require(condition, message)


def resolve_argument(value, cwd):
    path = Path(value)
    return (path if path.is_absolute() else cwd / path).resolve()


def command_records(build):
    result = []
    for path in sorted(build.rglob("*.cmd")):
        text = path.read_text(errors="strict")
        saved = []
        for match in re.finditer(r"(?m)^(?:saved)?cmd_([^ \n]+)\s*:=\s*(.*(?:\\\n.*)*)", text):
            target, command = match.groups()
            command = command.replace("\\\n", " ").replace("$(pound)", "#").replace("$$", "$")
            saved.append({"target": target, "command": command})
        result.append({"file": baseline.identity(path), "relative_path": path.relative_to(build).as_posix(),
                       "commands": saved})
    return result


def compiler_tokens(command):
    # We inspect executable-looking words anywhere in the saved recipe so an
    # unregistered compiler hidden after a shell conditional is not overlooked.
    lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|()")
    lexer.whitespace_split = True
    lexer.commenters = ""
    return list(lexer)


def output_arguments(tokens, cwd):
    outputs = []
    for index, word in enumerate(tokens):
        if word == "-o" and index + 1 < len(tokens):
            outputs.append(resolve_argument(tokens[index + 1], cwd))
        elif word.startswith("-o") and len(word) > 2 and not word.startswith("-object"):
            outputs.append(resolve_argument(word[2:], cwd))
    return outputs


def compiler_receipts(ledger, manifest_binding):
    records = []
    for directory in sorted(ledger.iterdir()):
        if not directory.is_dir():
            continue
        intent, terminal = directory / "INTENT.json", directory / "RESULT.json"
        require(intent.is_file(), "compiler invocation lacks intent: " + str(directory))
        require(terminal.is_file(), "compiler invocation has no terminal receipt: " + str(directory))
        record = json.loads(terminal.read_bytes())
        require(record.get("schema") == "hepta.hia.system-compiler-invocation.v1",
                "unknown compiler receipt schema")
        require(record.get("id") == directory.name, "compiler receipt ID/path mismatch")
        require(record.get("manifest") == manifest_binding, "compiler receipt used a different manifest")
        kind = record.get("classification", {}).get("kind")
        require(kind in TARGET_KINDS | TRUSTED_KINDS, "unclassified compiler operation")
        if kind in TARGET_KINDS:
            require(record.get("status") == "PASS", "failed target compile remains in the accepted build")
            require(record.get("canonical_roundtrip_equal") is True, "target has no exact semantic roundtrip")
            require(record.get("fallback_c_compilation") is False, "target compiler fallback")
            stages = [command.get("name") for command in record.get("commands", [])]
            require("hia-native-codegen" in stages, "target has no HIA backend invocation")
            if kind == "target_c":
                require("decode-hia-fresh-module" in stages, "target C was not reconstructed from HIA")
            if record.get("mode") == "replay":
                require("clang-c-frontend-only" not in stages and "clang-assembly-preprocess" not in stages,
                        "HIA replay executed the original source frontend")
            program = record.get("retained_program")
            require(isinstance(program, dict) and baseline.identity(program["path"]) == program,
                    "retained HIA program no longer matches receipt")
        elif record.get("status") != "PASS":
            require(record.get("status") == "COMPILER_REJECTED" and record.get("payload_failure") is False,
                    "incomplete or failed trusted build operation")
            require(any(type(item.get("exit_code")) is int and item["exit_code"] != 0
                        for item in record.get("commands", [])),
                    "compiler rejection lacks an observed nonzero exit")
        records.append({"receipt": baseline.identity(terminal), "value": record})
    require(records, "no actual compiler invocation ledger")
    return records


def collect(build, source, ledger, manifest_path, wrappers, output):
    build, source, ledger, output = map(lambda p: Path(p).resolve(), (build, source, ledger, output))
    manifest_binding = baseline.identity(manifest_path)
    records = compiler_receipts(ledger, manifest_binding)
    targets, hosts, trusted_outputs = defaultdict(list), defaultdict(list), defaultdict(list)
    target_ids, kind_counts = set(), Counter()
    for entry in records:
        record = entry["value"]
        kind = record["classification"]["kind"]
        kind_counts[kind] += 1
        native = record.get("compiler_output")
        if native is not None:
            path = Path(native["path"]).resolve()
            if kind in TARGET_KINDS:
                targets[path].append(record)
                target_ids.add(record["id"])
            elif kind == "host_tool":
                hosts[path].append(record)
            else:
                trusted_outputs[path].append(record)
        if kind in TARGET_KINDS:
            require(native is not None and Path(native["path"]).is_relative_to(build),
                    "target has no output inside the registered build root")
    require(kind_counts["target_c"] and kind_counts["target_assembly"],
            "complete configured image requires both C and machine assembly")
    commands = command_records(build)
    require(commands, "no saved Kbuild commands")
    wrappers = {key: str(Path(value).resolve()) for key, value in wrappers.items()}
    rows, referenced_ids = [], set()
    derivations = set()
    for entry in commands:
        for command in entry["commands"]:
            tokens = compiler_tokens(command["command"])
            outputs = output_arguments(tokens, build)
            saved_target = resolve_argument(command["target"], build)
            uses_target = wrappers["target"] in tokens
            uses_host = any(wrappers[key] in tokens for key in ("host_c", "host_cxx"))
            raw_compilers = [token for token in tokens if COMPILER_NAME.fullmatch(Path(token).name)]
            require(not raw_compilers, "unregistered compiler in saved Kbuild command: " + entry["relative_path"])
            row = {"command_file": entry["relative_path"], **command}
            if uses_target:
                matched = [record for path in set(outputs + [saved_target]) for record in targets.get(path, [])]
                other = [record for path in set(outputs + [saved_target]) for record in trusted_outputs.get(path, [])]
                require(matched or other, "saved target compiler command has no actual invocation: " + command["target"])
                row["role"] = "hia_payload" if matched else "trusted_target_build_operation"
                row["compiler_invocations"] = sorted(record["id"] for record in matched + other)
                referenced_ids.update(record["id"] for record in matched)
            elif uses_host:
                matched = [record for path in set(outputs + [saved_target]) for record in hosts.get(path, [])]
                require(matched, "saved host compiler command has no actual invocation: " + command["target"])
                row["role"], row["compiler_invocations"] = "host_tool", sorted(record["id"] for record in matched)
            else:
                row["role"] = "registered_build_derivation"
                # A native object without an actual CC receipt can only be a
                # derived link/objcopy output whose command is retained here.
                if any(DERIVATION_NAME.fullmatch(Path(token).name) for token in tokens):
                    derivations.add(saved_target)
                    derivations.update(outputs)
            rows.append(row)
    objects = []
    for path in sorted(build.rglob("*.o")):
        if not path.is_file():
            continue
        actual = path.resolve()
        if actual in targets:
            role = "hia_payload_after_kbuild_postprocessing"
            invocations = [record["id"] for record in targets[actual]]
        elif actual in hosts:
            role, invocations = "host_tool", [record["id"] for record in hosts[actual]]
        elif actual in derivations:
            role, invocations = "linked_or_objcopy_derivative", []
        else:
            raise ValueError("native object has no compiler or derivation provenance: " + str(actual))
        objects.append({**baseline.identity(path), "relative_path": path.relative_to(build).as_posix(),
                        "role": role, "compiler_invocations": invocations})
    require(objects, "no native objects")
    orphan = []
    for path, items in targets.items():
        for record in items:
            if record["id"] not in referenced_ids:
                # Kallsyms/link-version and compiler-generated intermediates can
                # be removed by Kbuild; the actual invocation is still retained.
                orphan.append({"id": record["id"], "output": str(path), "exists_at_final_inventory": path.exists(),
                               "reason": "not referenced by a retained saved command; actual invocation retained"})
    program_ids = set()
    source_ids = set()
    for entry in records:
        record = entry["value"]
        if record["classification"]["kind"] in TARGET_KINDS:
            program_ids.add(record["program_key"])
            source_ids.add(record["source"]["path"])
    value = {
        "schema": SCHEMA, "scope": "complete_frozen_x86_64_configuration",
        "all_target_payloads_reconstructed_from_hia": True, "fallback_c_units": 0,
        "safe_core_memory_proof": False, "all_linux_configurations": False,
        "counts": {"compiler_invocations": len(records), **dict(sorted(kind_counts.items())),
                   "unique_hia_programs": len(program_ids), "unique_active_sources": len(source_ids),
                   "saved_command_files": len(commands), "saved_commands": len(rows), "objects": len(objects)},
        "compiler_invocations": records, "saved_commands": rows, "command_files": commands,
        "objects": objects, "intermediate_invocations_without_retained_saved_command": orphan,
        "final_cc_object_hash_is_not_assumed_equal_after_objtool_or_record_mcount": True,
    }
    metadata = baseline.write_gzip_json(output / "full-build-inventory.json.gz", value)
    return metadata, value
