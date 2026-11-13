#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Bind a Hepta/runtime candidate, then check its configured MCP entry point.

Preparation writes a new private configuration copy; it never edits the supplied
configuration, restarts a service, or changes a gateway allowlist. Source pins
come from the selected worker's manifest command and a separate inventory of its
actual bytes. Verification requires a separately reviewed whole-server contract.
Offline captures remain captures. The optional stdio probe uses only discovery
and HIA reads through the existing runtime owner, without emitting or adopting code.
"""
from __future__ import annotations

import argparse
import ast
import copy
from contextlib import closing
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "hepta.hia.unified-candidate.v1"
PINS = frozenset({"worker_sha256", "backend_sha256", "catalog_sha256"})
NATIVE_HELPER_PIN = "native_helpers_sha256"
SUPPORT_CONTRACT = "docs/HIA_SELFHOST_CORE_SUPPORT.json"
EVIDENCE_SCHEMA = "hepta.hia.unified-candidate-evidence.v1"
EVIDENCE_FILES = frozenset({"cold", "language", "language_assertions", "native_image", "native_build"})
REQUIRED_WORKER_DOCS = frozenset({"HIA_AGENT_NATIVE_TOOL_CATALOG.json", "HIA_AGENT_ASSEMBLY.md", "HIA_PROGRAM.md"})
TRANSPORT = "tools/hia_agent_native_transport.py"
OWNER_TOOLS = frozenset({"host_list", "effective_config", "process_start", "process_status",
                         "process_read", "process_wait", "process_cancel"})
MAX_JSON_BYTES = 8 * 1024 * 1024
_runtime_root = None
# Loaded only after the explicitly selected runtime commit is checked. The
# runtime's contract/snapshot policy is reused, not copied into the language.
hia_mcp_catalog = ToolContract = snapshot = read_pinned = None
open_parent = remove_owned_directory = require_trusted_publication_parent = None


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def absolute_path(value):
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or any(ord(c) < 32 for c in str(path)):
        raise ValueError("explicit absolute path without traversal/control characters required")
    return path


def git(root, *arguments):
    result = subprocess.run(["git", "--no-replace-objects", "-C", str(root), *arguments],
                            capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise ValueError("source Git identity unavailable")
    return result.stdout


def bootstrap_read(path, limit=MAX_JSON_BYTES):
    """Bounded no-follow read before the runtime's snapshot module is loaded."""
    fd = os.open(absolute_path(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit
                or before.st_uid not in (0, os.getuid()) or before.st_mode & 0o022):
            raise ValueError("trusted bounded ordinary input file required")
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if len(raw) != before.st_size or any(getattr(before, key) != getattr(after, key) for key in fields):
            raise ValueError("input changed during snapshot")
    return raw


def blob_sha(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def json_bytes(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2,
                      allow_nan=False).encode("utf-8") + b"\n"


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON member")
            result[key] = value
        return result

    def invalid_constant(_value):
        raise ValueError("nonfinite JSON number")

    if len(raw) > MAX_JSON_BYTES:
        raise ValueError("JSON input exceeds the preflight bound")
    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid_constant)
    canonical(value)  # Reject overflow-to-infinity and invalid UTF-8 as well.
    return value


def read_json(path, label, expected=None):
    raw, metadata = (read_pinned(path, expected, label, MAX_JSON_BYTES) if expected else
                     snapshot(path, label, MAX_JSON_BYTES))
    return decode(raw), metadata


def validate_pins(value):
    if (type(value) is not dict or set(value) not in (PINS, PINS | {NATIVE_HELPER_PIN})
            or any(type(item) is not str or not re.fullmatch(r"[0-9a-f]{64}", item)
                   for item in value.values())):
        raise ValueError("complete worker/backend/catalog and optional native-helper SHA256 identities required")
    return value


def source_identity(root, revision, *, allow_dirty=False):
    root = absolute_path(root)
    if type(revision) is not str or not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("an exact 40-character source commit is required")
    if git(root, "rev-parse", "--show-toplevel").strip() != str(root):
        raise ValueError("source root must be the Git checkout root")
    if git(root, "rev-parse", "HEAD").strip() != revision:
        raise ValueError("checkout HEAD differs from the selected source commit")
    changes = git(root, "status", "--porcelain=v1", "--untracked-files=all").splitlines()
    if changes and not allow_dirty:
        raise ValueError("candidate source is dirty; commit it or use explicit development mode")
    return {"root": str(root), "commit": revision, "clean": not changes,
            "changes": changes}


def configure_runtime(root, revision):
    """Load the existing contract helpers from one exact clean runtime checkout."""
    global _runtime_root, hia_mcp_catalog, ToolContract, snapshot, read_pinned
    global open_parent, remove_owned_directory, require_trusted_publication_parent
    root = absolute_path(root)
    source_identity(root, revision)
    deploy = root / "deploy"
    if deploy.is_symlink():
        raise ValueError("runtime helper directory cannot be a symbolic link")
    for name in ("mcp_tool_contract", "stage_dc_successor", "hia_mcp_catalog"):
        path = deploy / (name + ".py")
        raw = bootstrap_read(path)
        if blob_sha(raw) != git(root, "rev-parse", revision + ":deploy/" + name + ".py").strip():
            raise ValueError("runtime helper bytes differ from the selected commit")
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            raise ValueError("runtime contract helper cannot be loaded")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        # Execute the bytes just compared with Git, without a timestamp-based
        # .pyc cache and without writing into the selected checkout.
        exec(compile(raw, str(path), "exec"), module.__dict__)
    contract = sys.modules["mcp_tool_contract"]
    stage = sys.modules["stage_dc_successor"]
    hia_mcp_catalog = sys.modules["hia_mcp_catalog"]
    ToolContract = contract.ToolContract
    snapshot, read_pinned = stage.snapshot, stage.read_pinned
    open_parent, remove_owned_directory = stage.open_parent, stage.remove_owned_directory
    require_trusted_publication_parent = stage.require_trusted_publication_parent
    _runtime_root = root


def worker_inventory(root):
    root = absolute_path(root)
    require_uncached_worker_source(root)
    # rglob does not traverse directory symlinks. Refuse them explicitly instead
    # of silently omitting an importable subtree from the independently measured pin.
    entries = {}
    for path in sorted((root / "hepta").rglob("*")):
        if path.is_symlink():
            raise ValueError("worker source cannot contain symbolic links")
        if path.suffix == ".py":
            raw, _ = snapshot(path, "worker source", 16 * 1024 * 1024)
            entries[path.relative_to(root).as_posix()] = sha256(raw)
    contract, _ = snapshot(root / "hepta/hia_agent_contract.py", "worker identity contract")
    data_files = tuple("docs/" + name for name in discovery_documents(contract)) + native_source_files(contract)
    for filename in data_files:
        path = root / filename
        if any(part.is_symlink() for part in (path, *path.parents)):
            raise ValueError("worker asset cannot use symbolic links")
        package_source = filename.startswith("hepta/") and filename.endswith(".py")
        if package_source and filename not in entries:
            raise ValueError("worker source resource has no package module: " + filename)
        raw, _ = snapshot(path, "worker language contract")
        digest = sha256(raw)
        if package_source and entries[filename] != digest:
            raise ValueError("worker package module and source resource differ: " + filename)
        entries[filename] = digest
    if "hepta/hia_agent_worker.py" not in entries or "hepta/hia_agent_store.py" not in entries:
        raise ValueError("selected source lacks the actual HIA worker")
    return entries


def literal_inventory(source, name, *, required=True):
    """Read exactly one literal assignment without importing the selected code."""
    values = []
    for node in ast.parse(source).body:
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == name
                                                for target in node.targets):
            values.append(node.value)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == name:
            values.append(node.value)
    if not values and not required:
        return ()
    if len(values) != 1:
        raise ValueError("one literal " + name + " inventory is required")
    value = ast.literal_eval(values[0])
    if type(value) not in (tuple, list) or any(type(item) is not str for item in value):
        raise ValueError(name + " must be a literal list of paths")
    return tuple(value)


def discovery_documents(source):
    """Read the pinned source's literal inventory without importing its code."""
    documents = literal_inventory(source, "DISCOVERY_FILES")
    if (not 3 <= len(documents) <= 64
            or any(not re.fullmatch(r"[A-Za-z0-9_-]+\.(md|json)", name) for name in documents)
            or len(set(documents)) != len(documents)
            or not REQUIRED_WORKER_DOCS <= set(documents)):
        raise ValueError("discovery inventory must contain unique bounded contract filenames")
    return documents


def native_source_files(source):
    """Match the worker's declared native/build assets, including old empty domains.

    Optional absence supports pre-native historical workers. A present malformed
    declaration always refuses; it never silently shrinks the identity domain.
    These files are build inputs, not evidence that a native image was selected.
    The notes module is the one declared dual-role Python source; its ordinary
    module observation must also exist and agree in worker_inventory.
    """
    native = literal_inventory(source, "NATIVE_SOURCE_FILES", required=False)
    source_build = literal_inventory(source, "SOURCE_BUILD_FILES", required=False)
    compiler_build = literal_inventory(source, "COMPILER_BUILD_FILES", required=False)
    publication = literal_inventory(source, "PUBLICATION_BUILD_FILES", required=False)
    source_build_paths = frozenset({
        "examples/hia_bootstrap/source_build_policy.hepta",
        "examples/hia_bootstrap/selfhost.hepta",
        "examples/hia_bootstrap/source_build_packer.hepta",
    })
    compiler_build_paths = frozenset({"examples/hia_bootstrap/core_json_cli_packer.hepta"})
    files = native + source_build + compiler_build + publication
    if (len(files) > 256 or len(files) != len(set(files))
            or any(name != "hepta/hia_program_normalization_notes.py"
                   and not re.fullmatch(r"examples/hia_bootstrap/[A-Za-z0-9_-]+\.hepta", name)
                   for name in native)
            or any(name not in source_build_paths for name in source_build)
            or any(name not in compiler_build_paths for name in compiler_build)
            or any(not re.fullmatch(r"(?:examples/hia_bootstrap/[A-Za-z0-9_-]+\.hepta|tools/[A-Za-z0-9_-]+\.(?:py|S))", name)
                   for name in publication)):
        raise ValueError("native/build inventory must contain unique bounded repository asset paths")

    # Preserve the four original inventory reads and their rejection order.
    # Main's six explicit bundle roles follow them; each is a closed role and
    # all roles share the original 256-asset limit and cross-role uniqueness.
    bundle_roles = (
        ("BACKEND_BUILD_FILES", frozenset({
            "docs/HIA_CORE_LOWERING_ABI.json",
            "examples/hia_bootstrap/core_lowering_pool.hepta",
            "examples/hia_bootstrap/core_lowering_000.hepta",
            "examples/hia_bootstrap/core_lowering_001.hepta",
            "examples/hia_bootstrap/core_lowering_002.hepta",
            "examples/hia_bootstrap/core_lowering_003.hepta",
            "examples/hia_bootstrap/core_lowering_004.hepta",
            "examples/hia_bootstrap/core_lowering_005.hepta",
            "examples/hia_bootstrap/core_lowering_006.hepta",
            "examples/hia_bootstrap/core_lowering_007.hepta",
            "examples/hia_bootstrap/core_lowering_008.hepta",
            "examples/hia_bootstrap/core_lowering_009.hepta",
            "examples/hia_bootstrap/core_lowering_010.hepta",
            "examples/hia_bootstrap/core_lowering_011.hepta",
            "examples/hia_bootstrap/core_lowering_012.hepta",
            "examples/hia_bootstrap/core_lowering_013.hepta",
            "examples/hia_bootstrap/core_lowering_014.hepta",
            "examples/hia_bootstrap/core_lowering_015.hepta",
            "examples/hia_bootstrap/core_lowering_016.hepta",
            "examples/hia_bootstrap/core_lowering_017.hepta",
            "examples/hia_bootstrap/core_lowering_018.hepta",
            "examples/hia_bootstrap/core_lowering_019.hepta",
            "examples/hia_bootstrap/core_lowering_020.hepta",
            "examples/hia_bootstrap/core_lowering_021.hepta",
            "examples/hia_bootstrap/core_lowering_022.hepta",
            "examples/hia_bootstrap/core_lowering_023.hepta",
            "examples/hia_bootstrap/core_lowering_024.hepta",
            "examples/hia_bootstrap/core_lowering_025.hepta",
            "examples/hia_bootstrap/core_lowering_026.hepta",
            "examples/hia_bootstrap/core_lowering_027.hepta",
            "examples/hia_bootstrap/core_lowering_028.hepta",
            "examples/hia_bootstrap/core_lowering_029.hepta",
            "examples/hia_bootstrap/core_lowering_030.hepta",
        })),
        ("EMITTER_BUILD_FILES", frozenset({
            "docs/HIA_CORE_EMITTER_ABI.json",
            "examples/hia_bootstrap/core_emitter_pool.hepta",
            "examples/hia_bootstrap/core_emitter_000.hepta",
            "examples/hia_bootstrap/core_emitter_001.hepta",
            "examples/hia_bootstrap/core_emitter_002.hepta",
            "examples/hia_bootstrap/core_emitter_003.hepta",
            "examples/hia_bootstrap/core_emitter_004.hepta",
            "examples/hia_bootstrap/core_emitter_005.hepta",
            "examples/hia_bootstrap/core_emitter_006.hepta",
            "examples/hia_bootstrap/core_emitter_007.hepta",
        })),
        ("BYTE_WRAPPER_BUILD_FILES", frozenset({
            "docs/HIA_BYTE_WRAPPER_ABI.json",
            "examples/hia_bootstrap/byte_wrapper_pool.hepta",
            "examples/hia_bootstrap/byte_wrapper_000.hepta",
            "examples/hia_bootstrap/byte_wrapper_001.hepta",
            "examples/hia_bootstrap/byte_wrapper_002.hepta",
            "examples/hia_bootstrap/byte_wrapper_003.hepta",
            "examples/hia_bootstrap/byte_wrapper_004.hepta",
            "examples/hia_bootstrap/byte_wrapper_005.hepta",
            "examples/hia_bootstrap/byte_wrapper_006.hepta",
            "examples/hia_bootstrap/byte_wrapper_007.hepta",
        })),
        ("MACHINE_OBJECT_BUILD_FILES", frozenset({
            "docs/HIA_MACHINE_OBJECT_ABI.json",
            "examples/hia_bootstrap/machine_object_pool.hepta",
            "examples/hia_bootstrap/machine_object_000.hepta",
            "examples/hia_bootstrap/machine_object_001.hepta",
            "examples/hia_bootstrap/machine_object_002.hepta",
            "examples/hia_bootstrap/machine_object_003.hepta",
            "examples/hia_bootstrap/machine_object_004.hepta",
            "examples/hia_bootstrap/machine_object_005.hepta",
            "examples/hia_bootstrap/machine_object_006.hepta",
            "examples/hia_bootstrap/machine_object_007.hepta",
            "examples/hia_bootstrap/machine_object_008.hepta",
            "examples/hia_bootstrap/machine_object_009.hepta",
            "examples/hia_bootstrap/machine_object_010.hepta",
            "examples/hia_bootstrap/machine_object_011.hepta",
        })),
        ("EXECUTION_OBSERVATION_BUILD_FILES", frozenset({
            "docs/HIA_EXECUTION_OBSERVATION_ABI.json",
            "examples/hia_bootstrap/execution_observation_pool.hepta",
            "examples/hia_bootstrap/execution_observation_000.hepta",
            "examples/hia_bootstrap/execution_observation_001.hepta",
            "examples/hia_bootstrap/execution_observation_002.hepta",
            "examples/hia_bootstrap/execution_observation_003.hepta",
            "examples/hia_bootstrap/execution_observation_004.hepta",
            "examples/hia_bootstrap/execution_observation_005.hepta",
            "examples/hia_bootstrap/execution_observation_006.hepta",
        })),
        ("CONTINUATION_BUILD_FILES", frozenset({
            "docs/HIA_NATIVE_CONTINUATION_ABI.json",
            "examples/hia_bootstrap/continuation_policy.hepta",
            "examples/hia_bootstrap/continuation_packer.hepta",
            "examples/hia_bootstrap/continuation_inprocess_packer.hepta",
        })),
    )
    for role, allowed in bundle_roles:
        values = literal_inventory(source, role, required=False)
        combined = files + values
        if (any(name not in allowed for name in values)
                or len(combined) > 256 or len(combined) != len(set(combined))):
            raise ValueError("native/build inventory must contain unique bounded repository asset paths")
        files = combined
    entry = literal_inventory(source, "ENTRY_BUILD_FILES", required=False)
    entry_paths = frozenset({
        'examples/hia_bootstrap/candidate_build_policy.hepta',
        'examples/hia_bootstrap/candidate_build_packer.hepta',
        "examples/hia_bootstrap/release_launch_policy.hepta",
        "examples/hia_bootstrap/release_launch_packer.hepta",
    })
    combined = files + entry
    if (any(name not in entry_paths for name in entry)
            or len(combined) > 256 or len(combined) != len(set(combined))):
        raise ValueError("native/build inventory must contain unique bounded repository asset paths")
    return combined

def worker_matches_commit(root, revision, entries):
    """Do not let assume-unchanged/ignored source masquerade as an exact revision."""
    rows = git(root, "ls-tree", "-r", "-z", revision, "--", "hepta",
               *(path for path in entries if not path.startswith("hepta/"))).split("\0")
    blobs = {}
    for row in rows:
        if not row:
            continue
        metadata, path = row.split("\t", 1)
        mode, kind, value = metadata.split()
        if path.startswith("hepta/") and not path.endswith(".py"):
            continue
        if kind != "blob" or mode not in ("100644", "100755"):
            return False
        blobs[path] = value
    if set(blobs) != set(entries):
        return False
    return all(blob_sha(snapshot(root / path, "source/commit comparison", 16 * 1024 * 1024)[0]) == value
               for path, value in blobs.items())


def require_uncached_worker_source(root):
    """A Git-clean source tree can still contain executable ignored caches.

    This is an admission check of a trusted local checkout, not protection
    against a concurrent privileged writer or a source-only runtime loader.
    """
    root = absolute_path(root)
    for path in (root / "hepta").rglob("*"):
        if path.name == "__pycache__" or path.suffix.lower() in {".pyc", ".pyo", ".so", ".pyd"}:
            raise ValueError("worker source contains a bytecode cache or binary shadow module; use a fresh source checkout")


def installed_pins(root, python, *, native_helpers=None):
    """Run only the installed worker's non-mutating manifest entry point."""
    require_uncached_worker_source(root)
    arguments = [str(absolute_path(python)), "-B", "-E", "-s", "-m", "hepta.hia_agent_worker",
                 "--installation-manifest"]
    if native_helpers is not None:
        path, expected = native_helpers
        arguments += ["--native-helpers-manifest", str(absolute_path(path)),
                      "--expected-native-helpers-sha256", expected]
    result = subprocess.run(arguments, cwd=root, capture_output=True, timeout=60)
    if result.returncode:
        # Worker stderr is deliberately not copied into a public qualification.
        raise ValueError("selected worker installation-manifest command failed")
    return validate_pins(decode(result.stdout))


def normal_path(value):
    return (type(value) is str and value.startswith("/") and len(value.encode("utf-8")) <= 4096
            and not any(c in value for c in "\0\n\r")
            and not any(part in (".", "..") for part in value.split("/")))


def inside(path, roots):
    if type(roots) is not list or any(not normal_path(root) for root in roots):
        raise ValueError("host policy roots must be normal absolute Linux paths")
    return any(PurePosixPath(path).is_relative_to(PurePosixPath(root)) for root in roots)


def validate_config(config, pins):
    """Check HIA's profile boundary; Rust still validates the complete policy."""
    if type(config) is not dict or type(config.get("hia_worker")) is not dict:
        raise ValueError("existing runtime configuration with hia_worker is required")
    profile = copy.deepcopy(config["hia_worker"])
    profile.setdefault("artifact_roots", [])
    profile.setdefault("timeout_seconds", 120)
    profile.setdefault("memory_max_bytes", 1024**3)
    expected = PINS | {"host", "python_executable", "working_directory", "state_root",
                       "artifact_roots", "timeout_seconds", "memory_max_bytes"}
    if NATIVE_HELPER_PIN in pins:
        expected |= {"native_helpers_manifest", NATIVE_HELPER_PIN}
    if set(profile) != expected:
        raise ValueError("HIA worker profile has missing or unknown fields")
    validate_pins({key: profile[key] for key in pins})
    if any(profile[key] != pins[key] for key in pins):
        raise ValueError("configured source pin differs from the selected worker")
    host_name = profile["host"]
    if type(host_name) is not str or not re.fullmatch(r"[A-Za-z0-9._@-]{1,128}", host_name):
        raise ValueError("configured worker host alias is invalid")
    hosts = config.get("hosts")
    host = hosts.get(host_name) if type(hosts) is dict else None
    if (type(host) is not dict or host.get("platform", "linux") != "linux"
            or host.get("allow_execute") is not True or host.get("allow_write") is not True):
        raise ValueError("HIA requires an already configured executing, writable Linux host")
    timeout, memory = profile["timeout_seconds"], profile["memory_max_bytes"]
    roots = profile["artifact_roots"]
    if (type(timeout) is not int or not 1 <= timeout <= 3600 or type(memory) is not int
            or not 64 * 1024**2 <= memory <= 16 * 1024**3
            or type(roots) is not list or len(roots) > 32):
        raise ValueError("HIA worker resource limits exceed the admitted profile bounds")
    paths = [profile["python_executable"], profile["working_directory"], profile["state_root"], *roots]
    if NATIVE_HELPER_PIN in pins:
        paths.append(profile["native_helpers_manifest"])
    for path in paths:
        if (not normal_path(path) or not inside(path, host.get("allowed_read_path_prefixes", []))
                or inside(path, host.get("protected_path_prefixes", []))):
            raise ValueError("HIA profile path exceeds the configured host read policy")
    state, source = profile["state_root"], profile["working_directory"]
    if NATIVE_HELPER_PIN in pins and inside(profile["native_helpers_manifest"], [state]):
        raise ValueError("native helper manifest must be outside mutable state")
    if (state == "/" or not inside(state, host.get("allowed_write_path_prefixes", []))
            or inside(state, [source]) or inside(source, [state])):
        raise ValueError("HIA state requires a writable private root disjoint from source")
    cwd_roots = host.get("allowed_cwd_prefixes", [])
    if cwd_roots and not inside(source, cwd_roots):
        raise ValueError("HIA installation exceeds its host execution roots")
    return profile


def native_support_identity(root, entries):
    """Expose the exact declared Selfhost domain without promoting its claims."""
    if SUPPORT_CONTRACT not in entries:
        return {"available": False, "native_execution_attested": False}
    contract, metadata = read_json(root / SUPPORT_CONTRACT, "native support contract", entries[SUPPORT_CONTRACT])
    if (type(contract) is not dict or contract.get("schema") != "hepta.hia.selfhost-core-support.v1"
            or type(contract.get("profile")) is not str or type(contract.get("target")) is not dict
            or type(contract.get("abi")) is not dict or type(contract.get("support")) is not list
            or type(contract.get("syntax")) is not dict or type(contract.get("limits")) is not dict
            or type(contract.get("source_identity")) is not dict
            or type(contract["source_identity"].get("files")) is not dict):
        raise ValueError("native support contract is incomplete")
    sources = {**contract["source_identity"]["files"], SUPPORT_CONTRACT: metadata["sha256"]}
    return {"available": True, "contract_sha256": metadata["sha256"], "profile": contract["profile"],
            "target": contract["target"], "abi": contract["abi"],
            "support_sha256": sha256(canonical(contract["support"])),
            "syntax_sha256": sha256(canonical(contract["syntax"])),
            "limits_sha256": sha256(canonical(contract["limits"])),
            "source_manifest_sha256": sha256(canonical(sources)),
            "scope": "Declared bounded Selfhost-Core domain; direct and standalone profiles keep their own contracts",
            "native_execution_attested": False}


def native_image_metadata(raw):
    """Inspect only the existing canonical syscall-only ELF profile, without exec."""
    if len(raw) <= 176 or raw[:16] != b"\x7fELF\x02\x01\x01" + bytes(9):
        raise ValueError("native candidate is not a canonical ELF64 executable")
    header = struct.unpack_from("<HHIQQQIHHHHHH", raw, 16)
    if header != (2, 62, 1, 0x4000b0, 64, 0, 0, 64, 56, 2, 0, 0, 0):
        raise ValueError("native candidate ELF entry or ABI header differs")
    load = struct.unpack_from("<IIQQQQQQ", raw, 64)
    stack = struct.unpack_from("<IIQQQQQQ", raw, 120)
    if (load != (1, 5, 0, 0x400000, 0x400000, len(raw), len(raw), 4096)
            or stack != (0x6474e551, 6, 0, 0, 0, 0, 0, 16)):
        raise ValueError("native candidate ELF segment profile differs")
    return {"elf_type": "ET_EXEC", "machine": "EM_X86_64", "entry": header[3],
            "program_headers": ["PT_LOAD_RX", "PT_GNU_STACK_RW"], "interpreter": None,
            "dynamic_loader": False, "libc": False, "bytes": len(raw), "sha256": sha256(raw)}


def qualification_evidence(root, revision, support, bundle=None):
    """Bind retained original component reports; missing/failing work stays HOLD.

    Report integrity and finite observations are checked here. The existing
    native-stdio build receipt has no durable MCP lifecycle evidence, so it can
    never close the native-worker gate or authorize installation on its own.
    """
    gates = {name: {"status": "missing"} for name in ("cold", "language", "native_image_build")}
    gates["native_worker"] = {"status": "not_established",
        "reason": "native image construction and discovery do not establish the durable MCP lifecycle"}
    result = {"status": "HOLD", "whole_candidate_qualified": False, "gates": gates,
              "bundle": bundle, "artifacts": {}, "new_execution_performed": False,
              "scope": "Original local artifact integrity and finite component evidence; no independent execution attestation"}
    if bundle is None:
        return result
    if (type(bundle) is not dict or set(bundle) != {"path", "sha256"}
            or type(bundle["sha256"]) is not str or not re.fullmatch(r"[0-9a-f]{64}", bundle["sha256"])):
        raise ValueError("qualification bundle requires an exact path and SHA256")
    evidence, _ = read_json(absolute_path(bundle["path"]), "qualification evidence bundle", bundle["sha256"])
    if (type(evidence) is not dict or set(evidence) != {"schema", "artifacts"}
            or evidence["schema"] != EVIDENCE_SCHEMA or type(evidence["artifacts"]) is not dict
            or set(evidence["artifacts"]) - EVIDENCE_FILES):
        raise ValueError("unsupported qualification evidence inventory")
    if support.get("available") is not True:
        raise ValueError("native evidence requires the selected source's support contract")
    contract, _ = read_json(root / SUPPORT_CONTRACT, "native support contract", support["contract_sha256"])
    sources = {**contract["source_identity"]["files"], SUPPORT_CONTRACT: support["contract_sha256"]}
    # Git status can hide assume-unchanged bytes. Compare every actual source,
    # including compiler and all qualification code, with the selected commit.
    for name, expected in sources.items():
        if (type(name) is not str or not re.fullmatch(r"[A-Za-z0-9_./-]+", name)
                or name.startswith("/") or any(part in ("", ".", "..") for part in name.split("/"))
                or type(expected) is not str or not re.fullmatch(r"[0-9a-f]{64}", expected)):
            raise ValueError("invalid source path or digest in native support contract")
        raw, _ = read_pinned(root / name, expected, "native qualification source", 16 * 1024 * 1024)
        if blob_sha(raw) != git(root, "rev-parse", revision + ":" + name).strip():
            raise ValueError("native qualification source differs from the selected commit")
    documents, metadata = {}, {}
    for name, reference in evidence["artifacts"].items():
        if (type(reference) is not dict or set(reference) != {"path", "sha256"}
                or type(reference["sha256"]) is not str or not re.fullmatch(r"[0-9a-f]{64}", reference["sha256"])):
            raise ValueError("qualification artifact requires an exact path and SHA256")
        raw, observed = read_pinned(absolute_path(reference["path"]), reference["sha256"],
                                    "original " + name + " evidence", 16 * 1024 * 1024)
        documents[name] = raw if name == "native_image" else decode(raw)
        metadata[name] = {"path": reference["path"], "sha256": observed["sha256"], "bytes": len(raw)}
    result["artifacts"] = metadata

    def bound_report(name, schema):
        report = documents[name]
        if (type(report) is not dict or report.get("schema") != schema
                or report.get("profile") != support["profile"] or report.get("source_manifest") != sources):
            raise ValueError(name + " report belongs to a different source or support domain")
        return report

    def checks_pass(report):
        checks = report.get("checks")
        return type(checks) is dict and bool(checks) and all(value is True for value in checks.values())

    def mapping(value):
        return value if type(value) is dict else {}

    compiler = None
    if "cold" in documents:
        report = bound_report("cold", "hepta.hia.selfhost-cold-replay.v1")
        required = {"export_manifest_matches_qualification", "isolated_python_without_site",
                    "nested_full_qualification_pass", "nested_process_exit_zero", "no_ancestor_git_identity",
                    "no_bytecode_cache_created", "no_inherited_home_or_python_cache",
                    "no_inherited_seed_or_successor_images", "origin_hashes_preserved",
                    "owned_process_tree_cleanup_confirmed", "source_export_hashes_preserved"}
        hashes = report.get("generation_sha256")
        fixed = (type(hashes) is list and len(hashes) == 3
                 and all(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) for value in hashes)
                 and len(set(hashes)) == 1)
        owner = mapping(report.get("process_owner"))
        passed = (report.get("status") == "COLD_SELFHOST_REPLAY_PASS" and checks_pass(report)
                  and set(report["checks"]) == required and type(report.get("returncode")) is int
                  and report["returncode"] == 0 and report.get("qualification_wall_limit_seconds") == 180
                  and report.get("cleanup_wall_limit_seconds") == 3 and fixed
                  and owner.get("status") == "OWNED_PROCESS_COMPLETED"
                  and owner.get("exit_observed_before_deadline") is True and owner.get("timed_out") is False
                  and mapping(owner.get("cleanup")).get("complete") is True)
        if passed:
            compiler = hashes[0]
        gates["cold"] = {"status": "passed" if passed else "failed", "original_status": report.get("status")}
    if "language" in documents:
        report = bound_report("language", "hepta.hia.selfhost-language-qualification.v1")
        counts, checks = mapping(report.get("counts")), mapping(report.get("checks"))
        base = {"reference_vm_matches_all_scalar_oracles", "inventory_matches_actual_compiler_source",
                "original_fixed_point", "modified_fixed_point", "source_bound_before_execution", "source_closure_unchanged"}
        passed = (report.get("status") == "SELFHOST_LANGUAGE_COVERAGE_PASS" and checks_pass(report)
                  and base <= set(checks) and counts.get("checks_total") == len(checks)
                  and counts.get("checks_passed") == len(checks) and counts.get("compilers") == 2)
        assertions = documents.get("language_assertions")
        asserted = (type(assertions) is dict
                    and assertions.get("schema") == "hepta.hia.selfhost-language-native-assertions.v1"
                    and assertions.get("report_sha256") == metadata["language"]["sha256"]
                    and assertions.get("passed") is True and type(assertions.get("tests_run")) is int
                    and assertions["tests_run"] == 10
                    and all(assertions.get(key) == [] for key in ("errors", "failures", "skipped")))
        original = report.get("generations", [])
        linked = (compiler is not None and type(original) is list and len(original) == 3
                  and all(type(row) is dict and row.get("produced_sha256") == compiler for row in original))
        gates["language"] = {"status": "passed" if passed and asserted and linked else "failed",
                             "original_status": report.get("status"), "native_assertions_bound": asserted,
                             "same_compiler_as_cold": linked}
    elif "language_assertions" in documents:
        raise ValueError("language assertions require their exact original report")
    if "native_image" in documents or "native_build" in documents:
        if not {"native_image", "native_build"} <= set(documents):
            gates["native_image_build"] = {"status": "incomplete"}
        else:
            build = documents["native_build"]
            if type(build) is not dict or build.get("schema") != "hepta.hia.agent-stdio-build.v1":
                raise ValueError("unsupported native image build receipt")
            declared = build.get("source_sha256")
            expected_sources = {"examples/hia_bootstrap/agent_stdio_dispatch.hepta",
                                "examples/hia_bootstrap/agent_stdio_packer.hepta",
                                "examples/hia_bootstrap/core_json_frontend.hepta"}
            if (type(declared) is not dict or set(declared) != expected_sources
                    or any(sources.get(name) != digest for name, digest in declared.items())):
                raise ValueError("native image build source differs from the selected contract")
            image = documents["native_image"]
            executable = mapping(build.get("executable"))
            try:
                inspected = native_image_metadata(image)
            except ValueError:
                inspected = None
            passed = (build.get("status") == "NATIVE_AGENT_STDIO_BUILT" and compiler is not None
                      and build.get("compiler_sha256") == compiler
                      and build.get("cold_report_sha256") == metadata.get("cold", {}).get("sha256")
                      and build.get("output_profile") in ("flat", "elf", "exec")
                      and inspected is not None and executable == inspected
                      and executable.get("sha256") == metadata["native_image"]["sha256"]
                      and support["target"].get("triple") == "x86_64-unknown-linux-gnu")
            gates["native_image_build"] = {"status": "passed" if passed else "failed",
                                           "original_status": build.get("status"),
                                           "native_worker_execution_qualified": False}
    result["component_gates_passed"] = sum(gate["status"] == "passed" for gate in gates.values())
    return result


def prepare(hepta_root, hepta_revision, runtime_revision, config_path, python,
            *, allow_dirty=False, evidence_bundle=None):
    if _runtime_root is None:
        raise ValueError("select an exact runtime checkout first")
    runtime_root = _runtime_root
    identities = {
        "hepta": source_identity(hepta_root, hepta_revision, allow_dirty=allow_dirty),
        "runtime": source_identity(runtime_root, runtime_revision),
    }
    entries = worker_inventory(hepta_root)
    config, config_input = read_json(config_path, "input runtime configuration")
    if type(config) is not dict or type(config.get("hia_worker")) is not dict:
        raise ValueError("configuration must explicitly select the existing HIA worker host and roots")
    selected = config["hia_worker"]
    has_native = {"native_helpers_manifest", NATIVE_HELPER_PIN} & set(selected)
    native_helpers = None
    if has_native:
        if (has_native != {"native_helpers_manifest", NATIVE_HELPER_PIN}
                or not normal_path(selected["native_helpers_manifest"])
                or type(selected[NATIVE_HELPER_PIN]) is not str
                or not re.fullmatch(r"[0-9a-f]{64}", selected[NATIVE_HELPER_PIN])):
            raise ValueError("native helper selection requires a complete path and SHA256 pair")
        native_helpers = (selected["native_helpers_manifest"], selected[NATIVE_HELPER_PIN])
    pins = installed_pins(hepta_root, python, native_helpers=native_helpers)
    exact_worker = worker_matches_commit(hepta_root, hepta_revision, entries)
    if not exact_worker and not allow_dirty:
        raise ValueError("actual worker files differ from the selected commit")
    if pins["worker_sha256"] != sha256(canonical(entries)):
        raise ValueError("worker manifest differs from the independently measured source inventory")
    runtime_catalog, _ = snapshot(runtime_root / "src/mcp/hia_tool_catalog.json", "runtime HIA catalog")
    if blob_sha(runtime_catalog) != git(runtime_root, "rev-parse", runtime_revision + ":src/mcp/hia_tool_catalog.json").strip():
        raise ValueError("runtime catalog bytes differ from the selected commit")
    if (sha256(runtime_catalog) != pins["catalog_sha256"]
            or entries["docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json"] != pins["catalog_sha256"]):
        raise ValueError("runtime and worker catalogs do not have identical bytes")
    transport, _ = snapshot(hepta_root / TRANSPORT, "HIA qualification transport")
    transport_matches = blob_sha(transport) == git(hepta_root, "rev-parse", hepta_revision + ":" + TRANSPORT).strip()
    if not transport_matches and not allow_dirty:
        raise ValueError("HIA transport differs from the selected source commit")
    config = copy.deepcopy(config)
    config["hia_worker"].update(pins)
    profile = validate_config(config, pins)
    config["hia_worker"] = profile
    configuration = json_bytes(config)
    pair = {"hepta_commit": hepta_revision, "runtime_commit": runtime_revision, "installation": pins}
    support = native_support_identity(hepta_root, entries)
    qualification = qualification_evidence(hepta_root, hepta_revision, support, evidence_bundle)
    if (entries != worker_inventory(hepta_root)
            or identities["hepta"] != source_identity(hepta_root, hepta_revision, allow_dirty=allow_dirty)
            or identities["runtime"] != source_identity(runtime_root, runtime_revision)):
        raise ValueError("source changed during candidate preparation")
    if native_helpers is not None:
        read_pinned(Path(native_helpers[0]), native_helpers[1], "selected native helper bundle")
    candidate = {
        "schema": SCHEMA, "source_pair": pair, "source_pair_sha256": sha256(canonical(pair)),
        "source": identities,
        "source_qualified": exact_worker and transport_matches and all(item["clean"] for item in identities.values()),
        "worker_matches_commit": exact_worker,
        "worker_source_files": entries, "transport_sha256": sha256(transport),
        "native_support_identity": support, "qualification": qualification,
        "preflight_tool_sha256": snapshot(Path(__file__), "preflight tool")[1]["sha256"],
        "configuration_sha256": sha256(configuration),
        "input_configuration_sha256": config_input["sha256"],
        "worker_profile_sha256": sha256(canonical(profile)),
        "catalog_verified_against_actual_server": False, "production_deployed": False,
        "pin_scope": "Installed Python, language-contract and declared native/build asset bytes; interpreter, OS and selected binary build provenance are not attested",
    }
    return candidate, configuration


def load_candidate(path, expected, config_path):
    candidate, metadata = read_json(path, "unified candidate", expected)
    if type(candidate) is not dict or candidate.get("schema") != SCHEMA:
        raise ValueError("unsupported unified candidate schema")
    if candidate.get("source_qualified") is not True:
        raise ValueError("development candidate cannot qualify an installation")
    pair = candidate.get("source_pair")
    if (type(pair) is not dict or set(pair) != {"hepta_commit", "runtime_commit", "installation"}
            or sha256(canonical(pair)) != candidate.get("source_pair_sha256")):
        raise ValueError("source-pair identity is inconsistent")
    pins = validate_pins(pair["installation"])
    for name in ("hepta", "runtime"):
        identity = candidate["source"][name]
        if identity != source_identity(Path(identity["root"]), pair[name + "_commit"]):
            raise ValueError("selected source pair changed after preparation")
    hepta_root = Path(candidate["source"]["hepta"]["root"])
    runtime_root = Path(candidate["source"]["runtime"]["root"])
    if runtime_root != _runtime_root:
        raise ValueError("runtime checkout differs from the selected candidate")
    read_pinned(Path(__file__), candidate["preflight_tool_sha256"], "preflight tool")
    entries = worker_inventory(hepta_root)
    if entries != candidate["worker_source_files"] or sha256(canonical(entries)) != pins["worker_sha256"]:
        raise ValueError("installed worker bytes changed after preparation")
    if not worker_matches_commit(hepta_root, pair["hepta_commit"], entries):
        raise ValueError("worker files differ from the selected source commit")
    catalog, _ = snapshot(runtime_root / "src/mcp/hia_tool_catalog.json", "runtime HIA catalog")
    if sha256(catalog) != pins["catalog_sha256"]:
        raise ValueError("runtime catalog changed after preparation")
    if blob_sha(catalog) != git(runtime_root, "rev-parse", pair["runtime_commit"] + ":src/mcp/hia_tool_catalog.json").strip():
        raise ValueError("runtime catalog bytes differ from the selected commit")
    transport, _ = read_pinned(hepta_root / TRANSPORT, candidate["transport_sha256"], "HIA qualification transport")
    if blob_sha(transport) != git(hepta_root, "rev-parse", pair["hepta_commit"] + ":" + TRANSPORT).strip():
        raise ValueError("HIA transport differs from the selected source commit")
    config, config_metadata = read_json(config_path, "pinned runtime configuration",
                                      candidate["configuration_sha256"])
    profile = validate_config(config, pins)
    if sha256(canonical(profile)) != candidate["worker_profile_sha256"]:
        raise ValueError("worker profile identity is inconsistent")
    if "native_support_identity" in candidate:
        support = native_support_identity(hepta_root, entries)
        if support != candidate["native_support_identity"]:
            raise ValueError("native support or ABI identity changed after preparation")
        qualification = candidate.get("qualification")
        if (type(qualification) is not dict
                or qualification_evidence(hepta_root, pair["hepta_commit"], support,
                                          qualification.get("bundle")) != qualification):
            raise ValueError("original qualification evidence changed after preparation")
    if NATIVE_HELPER_PIN in pins:
        # The worker loader validates and maps each selected image. Preflight
        # rechecks the exact selected bundle without activating native mappings.
        read_pinned(Path(profile["native_helpers_manifest"]), pins[NATIVE_HELPER_PIN],
                    "selected native helper bundle")
    return candidate, metadata, config_metadata


def complete_tools(value):
    if type(value) is not dict or "error" in value:
        raise ValueError("complete actual tools/list response required")
    if "result" in value:
        if value.get("jsonrpc") != "2.0" or "error" in value:
            raise ValueError("successful JSON-RPC tools/list response required")
        value = value["result"]
    if type(value) is not dict or value.get("nextCursor") is not None:
        raise ValueError("tools/list capture is incomplete; collect every page first")
    tools = value.get("tools")
    contract = ToolContract(hia_mcp_catalog.make_contract(tools))
    if not OWNER_TOOLS <= set(contract.by_name):
        raise ValueError("HIA-only catalog cannot replace the whole runtime-owner catalog")
    hia_mcp_catalog.verify_native(value)
    return tools


def verify_captures(candidate, tools_value, worker_manifest, full_contract):
    pins = candidate["source_pair"]["installation"]
    if validate_pins(worker_manifest) != pins:
        raise ValueError("observed worker installation differs from the selected source pair")
    tools = complete_tools(tools_value)
    full_contract.verify(tools)
    return {"tool_count": len(tools), "hia_tool_count": len(hia_mcp_catalog.TOOL_NAMES),
            "whole_server_catalog_sha256": full_contract.catalog_sha256,
            "hia_catalog_sha256": pins["catalog_sha256"]}


class IncompleteProbe(ValueError):
    def __init__(self, tool, arguments, response):
        super().__init__("MCP probe has no completed HIA result; observe the original request")
        self.recovery = {"tool": tool, "arguments": copy.deepcopy(arguments), "response": copy.deepcopy(response),
                         "retry_action": "observe_original"}


def probe(candidate, config_path, binary, binary_sha256, full_contract, *, timeout=60):
    """Discover through one configured stdio server and its existing owner."""
    hepta_root = Path(candidate["source"]["hepta"]["root"])
    # Reuse the already-qualified HIA client instead of introducing another
    # scheduler, process owner, HTTP endpoint or arbitrary-command interface.
    transport_bytes, _ = read_pinned(hepta_root / TRANSPORT, candidate["transport_sha256"], "HIA qualification transport")
    _, binary_metadata = read_pinned(binary, binary_sha256, "runtime binary", 512 * 1024 * 1024)
    spec = importlib.util.spec_from_file_location("hia_candidate_transport", hepta_root / TRANSPORT)
    if spec is None or spec.loader is None:
        raise ValueError("selected HIA transport is unavailable")
    transport = importlib.util.module_from_spec(spec)
    exec(compile(transport_bytes, str(hepta_root / TRANSPORT), "exec"), transport.__dict__)
    pins = candidate["source_pair"]["installation"]
    client = transport.MCPStdio([str(binary), "mcp", "--runtime-config", str(config_path)],
                                cwd=_runtime_root, timeout=timeout)
    with closing(client.process.stdout), client:
        tools = {"tools": client.list_tools()}
        full_contract.verify(complete_tools(tools))
        args = {"section": "manifest"}
        described = client.call("hia_describe", args)
        if described.get("status") != "completed":
            raise IncompleteProbe("hia_describe", args, described)
        result = described["result"]
        if result.get("catalog_sha256") != pins["catalog_sha256"]:
            raise ValueError("live HIA discovery changed the catalog pin")
        ref = result["manifest"]
        args = {"catalog_sha256": pins["catalog_sha256"], "artifact": ref, "max_bytes": 65536}
        read = client.call("hia_read", args)
        if read.get("status") != "completed":
            raise IncompleteProbe("hia_read", args, read)
        page = read["result"]
        if (page.get("artifact") != ref or page.get("encoding") != "utf8"
                or page.get("next_cursor") is not None or type(page.get("content")) is not str):
            raise ValueError("live HIA manifest read is incomplete or bound to another artifact")
        raw = page["content"].encode("utf-8")
        if sha256(raw) != ref["sha256"]:
            raise ValueError("live HIA manifest bytes differ from their retained identity")
        manifest = decode(raw)
        if manifest.get("schema") != "hepta.hia.agent.manifest.v1":
            raise ValueError("live HIA manifest schema is unsupported")
        worker_manifest = validate_pins(manifest.get("installation"))
        checks = verify_captures(candidate, tools, worker_manifest, full_contract)
        transcript = client.protocol_records
    read_pinned(binary, binary_sha256, "runtime binary after probe", 512 * 1024 * 1024)
    return checks, {"native-tools.json": json_bytes(tools),
                    "worker-manifest.json": json_bytes(worker_manifest),
                    "stdio-transcript.json": json_bytes(transcript)}, binary_metadata


def publish(directory, files):
    """Create-only private output; refuse symlink ancestors and existing state."""
    directory = absolute_path(directory)
    parent, name = open_parent(directory)
    descriptor = None
    identity = None
    created = []
    try:
        require_trusted_publication_parent(parent)
        os.mkdir(name, 0o700, dir_fd=parent)
        descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                             dir_fd=parent)
        identity = os.fstat(descriptor)
        for filename, raw in files.items():
            if not re.fullmatch(r"[A-Za-z0-9_-]+\.json", filename):
                raise ValueError("invalid preflight output filename")
            fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=descriptor)
            created.append(filename)
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        os.fsync(descriptor)
        linked = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (linked.st_dev, linked.st_ino) != (identity.st_dev, identity.st_ino):
            raise ValueError("preflight output directory changed during publication")
        os.fsync(parent)
    except BaseException:
        if descriptor is not None:
            for filename in reversed(created):
                os.unlink(filename, dir_fd=descriptor)
        remove_owned_directory(parent, name, identity)
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    prepare_parser = sub.add_parser("prepare", help="create a source-pinned private config copy")
    prepare_parser.add_argument("--hepta-root", type=Path, default=ROOT)
    prepare_parser.add_argument("--runtime-checkout", required=True, type=Path)
    prepare_parser.add_argument("--hepta-revision", required=True)
    prepare_parser.add_argument("--runtime-revision", required=True)
    prepare_parser.add_argument("--config", required=True, type=Path)
    prepare_parser.add_argument("--worker-python", type=Path, default=Path(sys.executable))
    prepare_parser.add_argument("--allow-dirty", action="store_true",
                                help="development inventory only; cannot qualify an installation")
    prepare_parser.add_argument("--qualification-evidence", type=Path,
                                help="optional original cold/language/native build artifact inventory; missing work stays HOLD")
    prepare_parser.add_argument("--qualification-evidence-sha256")
    prepare_parser.add_argument("--output-directory", required=True, type=Path)
    for command in ("verify", "probe"):
        item = sub.add_parser(command, help="check supplied captures" if command == "verify" else
                            "check actual stdio MCP discovery through the configured owner")
        item.add_argument("--candidate", required=True, type=Path)
        item.add_argument("--runtime-checkout", required=True, type=Path)
        item.add_argument("--candidate-sha256", required=True)
        item.add_argument("--config", required=True, type=Path)
        item.add_argument("--full-contract", required=True, type=Path)
        item.add_argument("--full-contract-sha256", required=True)
        item.add_argument("--output-directory", required=True, type=Path)
        if command == "verify":
            item.add_argument("--native-tools", required=True, type=Path)
            item.add_argument("--worker-manifest", required=True, type=Path)
        else:
            item.add_argument("--runtime-binary", required=True, type=Path)
            item.add_argument("--runtime-binary-sha256", required=True)
            item.add_argument("--timeout-seconds", type=int, default=60, choices=range(1, 3601),
                              metavar="1..3600")
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare":
            configure_runtime(args.runtime_checkout, args.runtime_revision)
            if bool(args.qualification_evidence) != bool(args.qualification_evidence_sha256):
                raise ValueError("qualification evidence path and SHA256 must be supplied together")
            evidence_bundle = ({"path": str(args.qualification_evidence),
                                "sha256": args.qualification_evidence_sha256}
                               if args.qualification_evidence else None)
            candidate, configuration = prepare(
                args.hepta_root, args.hepta_revision, args.runtime_revision, args.config,
                args.worker_python, allow_dirty=args.allow_dirty, evidence_bundle=evidence_bundle)
            files = {"candidate.json": json_bytes(candidate), "runtime-config.json": configuration}
            publish(args.output_directory, files)
            result = {"status": "source_pinned" if candidate["source_qualified"] else "development_only",
                      "candidate_sha256": sha256(files["candidate.json"]),
                      "source_pair_sha256": candidate["source_pair_sha256"],
                      "configuration_sha256": sha256(configuration),
                      "qualification_status": candidate["qualification"]["status"],
                      "whole_candidate_qualified": False, "production_deployed": False}
        else:
            # Only the bounded, explicitly pinned candidate is read before the
            # runtime's own descriptor-relative snapshot helpers become available.
            raw = bootstrap_read(args.candidate)
            if sha256(raw) != args.candidate_sha256:
                raise ValueError("candidate SHA256 differs from the supplied pin")
            initial = decode(raw)
            configure_runtime(args.runtime_checkout, initial["source_pair"]["runtime_commit"])
            candidate, metadata, config_metadata = load_candidate(
                args.candidate, args.candidate_sha256, args.config)
            contract = ToolContract.load(args.full_contract, args.full_contract_sha256)
            if args.command == "verify":
                tools, tools_metadata = read_json(args.native_tools, "actual tools/list capture")
                worker, worker_metadata = read_json(args.worker_manifest, "worker manifest capture")
                checks = verify_captures(candidate, tools, worker, contract)
                files = {}
                evidence = {"native_tools_sha256": tools_metadata["sha256"],
                            "worker_manifest_sha256": worker_metadata["sha256"],
                            "origin": "operator_supplied_captures"}
            else:
                checks, files, binary_metadata = probe(candidate, args.config, args.runtime_binary,
                    args.runtime_binary_sha256, contract, timeout=args.timeout_seconds)
                evidence = {"origin": "actual_configured_stdio_mcp", "runtime_binary": binary_metadata,
                            "captures": {path: sha256(raw) for path, raw in files.items()}}
            load_candidate(args.candidate, args.candidate_sha256, args.config)
            result = {"schema": "hepta.hia.candidate-preflight.v1", "status": "passed",
                      "source_pair_sha256": candidate["source_pair_sha256"],
                      "candidate_sha256": metadata["sha256"],
                      "configuration_sha256": config_metadata["sha256"],
                      "full_contract_file_sha256": args.full_contract_sha256,
                      "checks": checks, "evidence": evidence,
                      "entrypoint_observed": args.command == "probe",
                      "qualification_status": candidate.get("qualification", {}).get("status", "HOLD"),
                      "whole_candidate_qualified": False,
                      "binary_build_provenance_attested": False, "production_deployed": False}
            files["preflight.json"] = json_bytes(result)
            publish(args.output_directory, files)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, RecursionError, AssertionError,
            RuntimeError, SyntaxError, subprocess.SubprocessError) as exc:
        error = {"status": "rejected", "error": str(exc)[:4096], "production_deployed": False}
        if isinstance(exc, IncompleteProbe):
            error["recovery"] = exc.recovery
        print(json.dumps(error, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
