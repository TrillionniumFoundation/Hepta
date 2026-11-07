#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""One source-pinned HIA release entry, reusing the existing runtime preflight.

A release lock names source and capability identities, not deployment authority.
The default lock is reviewed repository metadata. Freeze is an explicit release
engineering operation; ordinary users describe, materialize, check or prepare it.
No command merges a branch, changes a live configuration or restarts a service.
"""
from __future__ import annotations

import argparse
import ast
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

# The supported entry is this source file, not ``python -m``.  -B only
# disables cache writes; it does not prevent a timestamp-valid .pyc from
# replacing an imported helper. Execute the helper's actual source bytes.
_preflight_path = Path(__file__).resolve().with_name("hia_candidate_preflight.py")
_preflight_spec = importlib.util.spec_from_file_location("_hia_release_preflight", _preflight_path)
preflight = importlib.util.module_from_spec(_preflight_spec)
sys.modules[_preflight_spec.name] = preflight
exec(compile(_preflight_path.read_bytes(), str(_preflight_path), "exec"), preflight.__dict__)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOCK = ROOT / "releases/hia-current.json"
SCHEMA = "hepta.hia.release-lock.v1"
TARGET = "x86_64-unknown-linux-gnu"
SUPPORT = "docs/HIA_SELFHOST_CORE_SUPPORT.json"
HIA_TOOLS = tuple("hia_" + name for name in (
    "describe", "read", "artifact", "context", "inspect", "candidate",
    "verify", "emit", "evaluate", "adopt", "rollback"))
BOOTSTRAP_FILES = (
    SUPPORT, "docs/HIA_SELF_HOSTING_CORE.md", "examples/hia_bootstrap/selfhost.hiaasm",
    "examples/hia_bootstrap/bytesum.hiaasm", "tools/hia_selfhost_child.py",
    "tools/qualify_hia_selfhost.py", "tools/generate_hia_selfhost.py",
    "tools/hia_selfhost_cases.py", "tools/hia_selfhost_contract.py",
    "tools/hia_selfhost_resources.py",
    "tools/hia_selfhost_limits.py", "tools/hia_selfhost_capacity.py",
    "tools/replay_hia_selfhost_upgrade.py",
    "tools/generate_hia_selfhost_contract.py", "tools/replay_hia_selfhost_cold.py",
    "tests/test_hia_selfhost.py", "tests/test_hia_selfhost_contract.py",
)
ENTRY_FILES = ("README.md", "tools/hia_release.py", "tools/hia_candidate_preflight.py",
               "tools/hia_agent_native_transport.py")
CANDIDATE_FILES = (
    "tools/hia_original_reconcile.py", "tests/test_hia_original_reconcile.py",
    "tools/build_hia_safe_core.py", "tools/qualify_hia_safe_core.py",
    "tests/test_hia_safe_core.py", "docs/HIA_SAFE_CORE_MACHINE_VALIDATION.md",
    "examples/hia_safe_core/scalar_add.hia.json",
    "examples/hia_safe_core/guarded_update.hia.json",
    "examples/hia_safe_core/read_byte.hia.json",
    "tools/hia_agent_macro_policy.py", "tools/qualify_hia_macro_campaign.py",
    "docs/HIA_PRODUCT_CLOSURE_20261107.md", "docs/HIA_NDU_STRONG_CONTROL_20261107.md",
    "docs/HIA_PRODUCT_FOLLOWTHROUGH_20261107.md",
    "experiments/hia_product_closure_20261107/http-client/http_lifecycle.py",
    "experiments/hia_product_closure_20261107/http-client/test_http_lifecycle.py",
    "experiments/hia_product_closure_20261107/http-client/tools/hia_original_reconcile.py",
)
RUNTIME_FILES = ("Cargo.toml", "Cargo.lock",
    "src/mcp/hia_tool_catalog.json", "src/mcp/hia_contract.rs", "src/mcp/hia_provider.rs",
    "deploy/mcp_tool_contract.py", "deploy/stage_dc_successor.py", "deploy/hia_mcp_catalog.py",
    "deploy/contracts/hepta-hia-agent-native-v1.json")
REPOSITORIES = {"hepta": "https://github.com/TrillionniumFoundation/Hepta.git",
                "runtime": "https://github.com/TrillionniumFoundation/hepta-runtime.git"}
SOURCE_DIRECTORIES = ("hepta", "docs", "tools", "tests", "examples", "benchmarks", "formal",
                      "native", "rust", "spec", "specs", ".github", "releases",
                      "experiments/hia_agent_assembly_v4_20261030",
                      "experiments/hia_initialization_frontiers_20261103",
                      "experiments/hia_round4_20261105",
                      "experiments/hia_agent_first_use_20261107",
                      "experiments/hia_release_20261107",
                      "experiments/hia_product_closure_20261107")
MATERIALIZATION = {"hepta_sparse_directories": list(SOURCE_DIRECTORIES),
    "runtime_sparse_directories": None,
    "omitted_scope": "Historical campaigns and artifact/report archives outside this release's qualified source closure"}
QUALIFICATION = {"source_lock_only": True, "production_deployed": False,
                 "default_branch_updated": False, "agent_first_use_passed": False,
                 "native_ndu_value_passed": False,
                 "runtime_source_only_loading_enforced": False}
MCP_CONTRACT = {"hia_tools": list(HIA_TOOLS), "catalog_scope": "HIA family only",
                "whole_server_contract_required": True, "current_agent_discovery_required": True}
TARGET_ABI = {"target": TARGET, "machine": "ELF64 / AMD64 / little-endian / LP64",
    "scalar_profile": "hepta.hia.program.direct-linux-x86_64.v1",
    "borrowed_bytes_profile": "hepta.hia.program.direct-linux-x86_64-borrowed-bytes.v1",
    "calling_convention": "System V AMD64; explicit borrowed-byte wrapper",
    "primary_codegen": "hia-direct", "llvm_or_assembler_fallback": False,
    "external_linker_scope": "B0/shared-library linking and explicit ELF object qualification; the flat successor chain needs no linker"}
SELFHOST_STATIC = {"support_matrix": SUPPORT, "source": "examples/hia_bootstrap/selfhost.hiaasm",
    "loader": "tools/hia_selfhost_child.py", "seed": "Python assembler + Core checker + hia-direct + GNU ld",
    "seed_binary": "Measured per cold build in B0.receipt.json; not an unbuilt binary pin",
    "required_replay": ["B0->B1->B2->B3", "B1=B2=B3", "M2=M3", "M2!=B2"],
    "whole_language_selfhost": False}


def digest(raw):
    return sha256(raw).hexdigest()


def read_bytes(path):
    return preflight.bootstrap_read(Path(path).absolute(), 16 * 1024 * 1024)


def committed_files(root, revision, names):
    result = {}
    for name in sorted(set(names)):
        path = Path(root) / name
        raw = read_bytes(path)
        blob = preflight.git(root, "rev-parse", revision + ":" + name).strip()
        if preflight.blob_sha(raw) != blob:
            raise ValueError("release file differs from committed bytes: " + name)
        result[name] = digest(raw)
    return result


def literal_constant(path, name):
    values = []
    for node in ast.parse(read_bytes(path)).body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            values.append(ast.literal_eval(node.value))
    if len(values) != 1:
        raise ValueError("one literal native profile constant required: " + name)
    return values[0]


def build_lock(hepta_root, hepta_revision, runtime_root, runtime_revision, python, release_id):
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", release_id):
        raise ValueError("release id must be a bounded plain identifier")
    identities = {"hepta": preflight.source_identity(hepta_root, hepta_revision),
                  "runtime": preflight.source_identity(runtime_root, runtime_revision)}
    preflight.configure_runtime(runtime_root, runtime_revision)
    worker = preflight.worker_inventory(hepta_root)
    if not preflight.worker_matches_commit(hepta_root, hepta_revision, worker):
        raise ValueError("actual worker inventory differs from committed source")
    pins = preflight.installed_pins(hepta_root, python)
    if pins["worker_sha256"] != digest(preflight.canonical(worker)):
        raise ValueError("worker inventory and installation manifest disagree")
    language_files = committed_files(hepta_root, hepta_revision,
                                    (*worker, *BOOTSTRAP_FILES, *ENTRY_FILES, *CANDIDATE_FILES))
    if (digest(read_bytes(Path(__file__))) != language_files["tools/hia_release.py"]
            or digest(read_bytes(Path(preflight.__file__))) != language_files["tools/hia_candidate_preflight.py"]):
        raise ValueError("executing entry/preflight differs from the selected release source")
    runtime_files = committed_files(runtime_root, runtime_revision, RUNTIME_FILES)
    if (language_files["docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json"] != pins["catalog_sha256"]
            or runtime_files["src/mcp/hia_tool_catalog.json"] != pins["catalog_sha256"]):
        raise ValueError("runtime and worker catalog bytes differ")
    catalog = preflight.decode(read_bytes(Path(hepta_root) / "docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json"))
    if sorted(tool["name"] for tool in catalog["tools"]) != sorted(HIA_TOOLS):
        raise ValueError("release requires the exact eleven-tool HIA family")
    matrix = preflight.decode(read_bytes(Path(hepta_root) / SUPPORT))
    if (type(matrix) is not dict or matrix.get("schema") != "hepta.hia.selfhost-core-support.v1"
            or matrix.get("target", {}).get("triple") != TARGET
            or not isinstance(matrix.get("profile"), str)
            or type(matrix.get("abi")) is not dict or type(matrix.get("limits")) is not dict):
        raise ValueError("versioned Selfhost-Core support matrix required")
    declared = matrix.get("source_identity", {}).get("files")
    if (type(declared) is not dict or not declared
            or any(language_files.get(name) != value for name, value in declared.items())
            or not (set(BOOTSTRAP_FILES) - {SUPPORT}) <= set(declared)
            or not {name for name in worker if name.startswith("hepta/")} <= set(declared)):
        raise ValueError("Selfhost-Core source/seed/loader closure differs from actual committed files")
    if (literal_constant(Path(hepta_root) / "hepta/hia_program_native.py", "TARGET") != TARGET
            or literal_constant(Path(hepta_root) / "hepta/hia_program_native.py", "PROFILE")
            != "hepta.hia.program.direct-linux-x86_64.v1"
            or literal_constant(Path(hepta_root) / "hepta/hia_native_byte_abi.py", "PROFILE")
            != "hepta.hia.program.direct-linux-x86_64-borrowed-bytes.v1"):
        raise ValueError("native source target/ABI differs from this reviewed release profile")
    versions = {"hepta": hepta_revision, "runtime": runtime_revision}
    roots = {"hepta": hepta_root, "runtime": runtime_root}
    lock = {
        "schema": SCHEMA, "release_id": release_id,
        "entrypoint": "python3 -B tools/hia_release.py",
        "materialization": dict(MATERIALIZATION),
        "sources": {name: {"repository": REPOSITORIES[name], "commit": revision,
                           "tree": preflight.git(roots[name], "rev-parse", revision + "^{tree}").strip()}
                    for name, revision in versions.items()},
        "installation": pins,
        "target_abi": dict(TARGET_ABI),
        "selfhost": {"profile": matrix["profile"], "abi": matrix["abi"], "limits": matrix["limits"],
            "support_matrix": SUPPORT, "support_matrix_sha256": language_files[SUPPORT],
            "source": "examples/hia_bootstrap/selfhost.hiaasm",
            "source_sha256": language_files["examples/hia_bootstrap/selfhost.hiaasm"],
            "loader": "tools/hia_selfhost_child.py",
            "loader_sha256": language_files["tools/hia_selfhost_child.py"], **SELFHOST_STATIC},
        "files": {"hepta": language_files, "runtime": runtime_files},
        "mcp": dict(MCP_CONTRACT),
        "qualification": dict(QUALIFICATION),
    }
    # The subprocess and inventory are not a lock against independent writers.
    # Re-observe exact bytes and cleanliness before returning a frozen record.
    if committed_files(hepta_root, hepta_revision, language_files) != language_files:
        raise ValueError("Hepta source changed during release measurement")
    if committed_files(runtime_root, runtime_revision, runtime_files) != runtime_files:
        raise ValueError("runtime source changed during release measurement")
    for name, revision in versions.items():
        if identities[name] != preflight.source_identity(roots[name], revision):
            raise ValueError("source identity changed during release measurement")
    return lock


def load_lock(path, expected=None):
    raw = read_bytes(path)
    if expected is not None and digest(raw) != expected:
        raise ValueError("release lock digest differs from supplied pin")
    lock = preflight.decode(raw)
    if type(lock) is not dict or lock.get("schema") != SCHEMA:
        raise ValueError("unsupported HIA release lock")
    if set(lock) != {"schema", "release_id", "entrypoint", "materialization", "sources", "installation", "target_abi",
                     "selfhost", "files", "mcp", "qualification"}:
        raise ValueError("release lock has missing or unknown fields")
    if (preflight.canonical(lock["qualification"]) != preflight.canonical(QUALIFICATION)
            or lock["entrypoint"] != "python3 -B tools/hia_release.py"
            or preflight.canonical(lock["target_abi"]) != preflight.canonical(TARGET_ABI)):
        raise ValueError("source lock cannot grant deployment/Agent/benefit qualification")
    if (not isinstance(lock["release_id"], str)
            or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", lock["release_id"])
            or preflight.canonical(lock["mcp"]) != preflight.canonical(MCP_CONTRACT)):
        raise ValueError("release id or eleven-tool contract is malformed")
    if preflight.canonical(lock["materialization"]) != preflight.canonical(MATERIALIZATION):
        raise ValueError("release source materialization scope is unsupported")
    if set(lock.get("sources", {})) != set(REPOSITORIES):
        raise ValueError("release must bind both repositories")
    for name, repo in REPOSITORIES.items():
        source = lock["sources"][name]
        if (type(source) is not dict or set(source) != {"repository", "commit", "tree"}
                or source["repository"] != repo
                or any(not isinstance(source[key], str) or not re.fullmatch(r"[0-9a-f]{40}", source[key])
                       for key in ("commit", "tree"))):
            raise ValueError("release source identity is malformed")
    preflight.validate_pins(lock.get("installation"))
    files = lock["files"]
    if type(files) is not dict or set(files) != set(REPOSITORIES):
        raise ValueError("both source file inventories are required")
    for name, required in (("hepta", (*BOOTSTRAP_FILES, *ENTRY_FILES, *CANDIDATE_FILES)), ("runtime", RUNTIME_FILES)):
        inventory = files[name]
        if type(inventory) is not dict or not set(required) <= set(inventory):
            raise ValueError("release file inventory is incomplete")
        for filename, value in inventory.items():
            if (type(filename) is not str or not re.fullmatch(r"[A-Za-z0-9_./-]+", filename)
                    or filename.startswith("/") or any(p in ("", ".", "..") for p in filename.split("/"))
                    or type(value) is not str or not re.fullmatch(r"[0-9a-f]{64}", value)):
                raise ValueError("release file identity is malformed")
    selfhost = lock["selfhost"]
    dynamic = {"profile", "abi", "limits", "support_matrix_sha256", "source_sha256", "loader_sha256"}
    if (type(selfhost) is not dict or set(selfhost) != set(SELFHOST_STATIC) | dynamic
            or any(preflight.canonical(selfhost.get(name)) != preflight.canonical(value)
                   for name, value in SELFHOST_STATIC.items())
            or type(selfhost["profile"]) is not str or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", selfhost["profile"])
            or type(selfhost["abi"]) is not dict or not selfhost["abi"]
            or type(selfhost["limits"]) is not dict or not selfhost["limits"]
            or any(selfhost[name + "_sha256"] != files["hepta"][selfhost[name]]
                   for name in ("support_matrix", "source", "loader"))):
        raise ValueError("selfhost support/source/loader declaration is inconsistent")
    return lock, digest(raw)


def check_lock(lock, hepta_root, runtime_root, python):
    observed = build_lock(hepta_root, lock["sources"]["hepta"]["commit"],
        runtime_root, lock["sources"]["runtime"]["commit"], python, lock["release_id"])
    if preflight.canonical(observed) != preflight.canonical(lock):
        raise ValueError("release capability/source contract differs from measured installation")
    return observed


def write_new(path, value):
    path = preflight.absolute_path(path)
    # Reuse the runtime's descriptor-relative publication policy after selection.
    parent, name = preflight.open_parent(path)
    try:
        preflight.require_trusted_publication_parent(parent)
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent)
        with os.fdopen(fd, "wb") as stream:
            raw = preflight.json_bytes(value)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(parent)
        return digest(raw)
    finally:
        os.close(parent)


def materialize(lock, destination, repositories, python):
    """Create fresh exact-source checkouts; no dependency or service install."""
    destination = preflight.absolute_path(destination)
    if destination.exists() or destination.is_symlink():
        raise ValueError("materialization destination already exists")
    if not destination.parent.is_dir() or destination.parent.resolve() != destination.parent:
        raise ValueError("materialization parent must be an existing nonsymlink directory")
    destination.mkdir(mode=0o700)
    for name in REPOSITORIES:
        source = repositories.get(name) or lock["sources"][name]["repository"]
        target = destination / name
        # A local cache changes transport only. Checkout identities still have
        # to match the immutable release, including actual ignored source bytes.
        subprocess.run(["git", "clone", "--no-checkout", "--no-hardlinks", "--", str(source), str(target)],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
        if name == "hepta":
            # The repository's historical evidence blobs can be absent from a
            # valid local partial cache. Declare the complete source closure
            # explicitly rather than inheriting an unrelated checkout's sparse
            # index or treating omitted archives as deleted source.
            subprocess.run(["git", "-C", str(target), "sparse-checkout", "set", "--cone", *SOURCE_DIRECTORIES],
                           check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
        subprocess.run(["git", "-C", str(target), "checkout", "--detach", lock["sources"][name]["commit"]],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    check_lock(lock, destination / "hepta", destination / "runtime", python)
    return {"hepta_root": str(destination / "hepta"), "runtime_checkout": str(destination / "runtime"),
            "status": "exact_sources_materialized", "dependencies_installed": False,
            "production_deployed": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    parser.add_argument("--lock-sha256")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("describe", help="show the selected source, ABI and selfhost contract")
    freeze = sub.add_parser("freeze", help="release engineer: measure one clean source pair")
    freeze.add_argument("--hepta-revision", required=True)
    freeze.add_argument("--runtime-revision", required=True)
    freeze.add_argument("--release-id", required=True)
    freeze.add_argument("--output", required=True, type=Path)
    for name in ("check", "prepare", "probe"):
        sub.add_parser(name)
    for name in ("freeze", "check", "prepare", "probe"):
        command = sub.choices[name]
        command.add_argument("--hepta-root", type=Path, required=True)
        command.add_argument("--runtime-checkout", type=Path, required=True)
        command.add_argument("--worker-python", type=Path, default=Path(sys.executable))
    for name in ("prepare", "probe"):
        command = sub.choices[name]
        command.add_argument("--config", type=Path, required=True)
        command.add_argument("--output-directory", type=Path, required=True)
    probe = sub.choices["probe"]
    for name in ("candidate", "runtime-binary", "full-contract"):
        probe.add_argument("--" + name, type=Path, required=True)
        probe.add_argument("--" + name + "-sha256", required=True)
    probe.add_argument("--timeout-seconds", type=int, default=60, choices=range(1, 3601), metavar="1..3600")
    checkout = sub.add_parser("materialize", help="create cold exact-source checkouts from remote or local repositories")
    checkout.add_argument("--directory", type=Path, required=True)
    checkout.add_argument("--hepta-repository")
    checkout.add_argument("--runtime-repository")
    checkout.add_argument("--worker-python", type=Path, default=Path(sys.executable))
    args = parser.parse_args(argv)
    try:
        if args.command == "freeze":
            lock = build_lock(args.hepta_root, args.hepta_revision, args.runtime_checkout,
                              args.runtime_revision, args.worker_python, args.release_id)
            lock_hash = write_new(args.output, lock)
            result = {"status": "source_contract_frozen", "release_lock_sha256": lock_hash,
                      "production_deployed": False}
        else:
            lock, lock_hash = load_lock(args.lock, args.lock_sha256)
            if args.command == "describe":
                result = {"status": "source_contract_declared", "installed_source_checked": False,
                          "release_lock_sha256": lock_hash, "contract": lock}
            elif args.command == "materialize":
                result = materialize(lock, args.directory,
                    {"hepta": args.hepta_repository, "runtime": args.runtime_repository}, args.worker_python)
                result["release_lock_sha256"] = lock_hash
            else:
                check_lock(lock, args.hepta_root, args.runtime_checkout, args.worker_python)
                result = {"status": "source_contract_verified", "release_lock_sha256": lock_hash,
                          "production_deployed": False}
                if args.command == "prepare":
                    candidate, configuration = preflight.prepare(args.hepta_root,
                        lock["sources"]["hepta"]["commit"], lock["sources"]["runtime"]["commit"],
                        args.config, args.worker_python)
                    files = {"candidate.json": preflight.json_bytes(candidate),
                             "runtime-config.json": configuration,
                             "release-binding.json": preflight.json_bytes(result)}
                    preflight.publish(args.output_directory, files)
                    result.update(status="source_pinned", candidate_sha256=digest(files["candidate.json"]),
                                  configuration_sha256=digest(configuration))
                elif args.command == "probe":
                    candidate, metadata, config_metadata = preflight.load_candidate(
                        args.candidate, args.candidate_sha256, args.config)
                    if candidate["source_pair"] != {
                            "hepta_commit": lock["sources"]["hepta"]["commit"],
                            "runtime_commit": lock["sources"]["runtime"]["commit"],
                            "installation": lock["installation"]}:
                        raise ValueError("probe candidate differs from the selected release")
                    contract = preflight.ToolContract.load(args.full_contract, args.full_contract_sha256)
                    checks, files, binary = preflight.probe(candidate, args.config, args.runtime_binary,
                        args.runtime_binary_sha256, contract, timeout=args.timeout_seconds)
                    check_lock(lock, args.hepta_root, args.runtime_checkout, args.worker_python)
                    preflight.load_candidate(args.candidate, args.candidate_sha256, args.config)
                    result.update(status="entrypoint_observed", checks=checks,
                        evidence={"origin": "actual_configured_stdio_mcp", "runtime_binary": binary,
                                  "captures": {name: digest(raw) for name, raw in files.items()}},
                        entrypoint_observed=True, current_agent_discovery_established=False,
                        candidate_sha256=metadata["sha256"], configuration_sha256=config_metadata["sha256"],
                        full_contract_file_sha256=args.full_contract_sha256,
                        binary_build_provenance_attested=False)
                    files["release-preflight.json"] = preflight.json_bytes(result)
                    preflight.publish(args.output_directory, files)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, RecursionError, AssertionError,
            RuntimeError, SyntaxError, subprocess.SubprocessError) as exc:
        # Do not echo subprocess argv, which may carry an administrator's private
        # repository transport. Preserve the failed stage without leaking it.
        message = "source checkout command failed" if isinstance(exc, subprocess.SubprocessError) else str(exc)
        error = {"status": "rejected", "error": message[:4096], "production_deployed": False}
        if isinstance(exc, preflight.IncompleteProbe):
            error["recovery"] = exc.recovery
        print(json.dumps(error, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
