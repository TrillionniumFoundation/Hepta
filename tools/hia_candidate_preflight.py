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
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "hepta.hia.unified-candidate.v1"
PINS = frozenset({"worker_sha256", "backend_sha256", "catalog_sha256"})
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
    if (type(value) is not dict or set(value) != PINS
            or any(type(item) is not str or not re.fullmatch(r"[0-9a-f]{64}", item)
                   for item in value.values())):
        raise ValueError("complete worker/backend/catalog SHA256 identities required")
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
    for filename in discovery_documents(contract):
        path = root / "docs" / filename
        raw, _ = snapshot(path, "worker language contract")
        entries[path.relative_to(root).as_posix()] = sha256(raw)
    if "hepta/hia_agent_worker.py" not in entries or "hepta/hia_agent_store.py" not in entries:
        raise ValueError("selected source lacks the actual HIA worker")
    return entries


def discovery_documents(source):
    """Read the pinned source's literal inventory without importing its code."""
    values = []
    for node in ast.parse(source).body:
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "DISCOVERY_FILES"
                                                 for target in node.targets):
            values.append(node.value)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == "DISCOVERY_FILES":
            values.append(node.value)
    if len(values) != 1:
        raise ValueError("one literal DISCOVERY_FILES inventory is required")
    documents = ast.literal_eval(values[0])
    if (type(documents) not in (tuple, list) or not 3 <= len(documents) <= 64
            or any(type(name) is not str or not re.fullmatch(r"[A-Za-z0-9_-]+\.(md|json)", name)
                   for name in documents)
            or len(set(documents)) != len(documents)
            or not REQUIRED_WORKER_DOCS <= set(documents)):
        raise ValueError("discovery inventory must contain unique bounded contract filenames")
    return tuple(documents)


def worker_matches_commit(root, revision, entries):
    """Do not let assume-unchanged/ignored source masquerade as an exact revision."""
    rows = git(root, "ls-tree", "-r", "-z", revision, "--", "hepta",
               *(path for path in entries if path.startswith("docs/"))).split("\0")
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


def installed_pins(root, python):
    """Run only the installed worker's non-mutating manifest entry point."""
    result = subprocess.run(
        [str(absolute_path(python)), "-B", "-E", "-s", "-m", "hepta.hia_agent_worker",
         "--installation-manifest"], cwd=root, capture_output=True, timeout=60,
    )
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
    if set(profile) != expected:
        raise ValueError("HIA worker profile has missing or unknown fields")
    validate_pins({key: profile[key] for key in PINS})
    if any(profile[key] != pins[key] for key in PINS):
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
    for path in [profile["python_executable"], profile["working_directory"],
                 profile["state_root"], *roots]:
        if (not normal_path(path) or not inside(path, host.get("allowed_read_path_prefixes", []))
                or inside(path, host.get("protected_path_prefixes", []))):
            raise ValueError("HIA profile path exceeds the configured host read policy")
    state, source = profile["state_root"], profile["working_directory"]
    if (state == "/" or not inside(state, host.get("allowed_write_path_prefixes", []))
            or inside(state, [source]) or inside(source, [state])):
        raise ValueError("HIA state requires a writable private root disjoint from source")
    cwd_roots = host.get("allowed_cwd_prefixes", [])
    if cwd_roots and not inside(source, cwd_roots):
        raise ValueError("HIA installation exceeds its host execution roots")
    return profile


def prepare(hepta_root, hepta_revision, runtime_revision, config_path, python,
            *, allow_dirty=False):
    if _runtime_root is None:
        raise ValueError("select an exact runtime checkout first")
    runtime_root = _runtime_root
    identities = {
        "hepta": source_identity(hepta_root, hepta_revision, allow_dirty=allow_dirty),
        "runtime": source_identity(runtime_root, runtime_revision),
    }
    entries = worker_inventory(hepta_root)
    pins = installed_pins(hepta_root, python)
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
    config, config_input = read_json(config_path, "input runtime configuration")
    if type(config) is not dict or type(config.get("hia_worker")) is not dict:
        raise ValueError("configuration must explicitly select the existing HIA worker host and roots")
    config = copy.deepcopy(config)
    config["hia_worker"].update(pins)
    profile = validate_config(config, pins)
    config["hia_worker"] = profile
    if (entries != worker_inventory(hepta_root)
            or identities["hepta"] != source_identity(hepta_root, hepta_revision, allow_dirty=allow_dirty)
            or identities["runtime"] != source_identity(runtime_root, runtime_revision)):
        raise ValueError("source changed during candidate preparation")
    configuration = json_bytes(config)
    pair = {"hepta_commit": hepta_revision, "runtime_commit": runtime_revision, "installation": pins}
    candidate = {
        "schema": SCHEMA, "source_pair": pair, "source_pair_sha256": sha256(canonical(pair)),
        "source": identities,
        "source_qualified": exact_worker and transport_matches and all(item["clean"] for item in identities.values()),
        "worker_matches_commit": exact_worker,
        "worker_source_files": entries, "transport_sha256": sha256(transport),
        "preflight_tool_sha256": snapshot(Path(__file__), "preflight tool")[1]["sha256"],
        "configuration_sha256": sha256(configuration),
        "input_configuration_sha256": config_input["sha256"],
        "worker_profile_sha256": sha256(canonical(profile)),
        "catalog_verified_against_actual_server": False, "production_deployed": False,
        "pin_scope": "Installed Python and language-contract bytes; interpreter, OS and binary build provenance are not attested",
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
            candidate, configuration = prepare(
                args.hepta_root, args.hepta_revision, args.runtime_revision, args.config,
                args.worker_python, allow_dirty=args.allow_dirty)
            files = {"candidate.json": json_bytes(candidate), "runtime-config.json": configuration}
            publish(args.output_directory, files)
            result = {"status": "source_pinned" if candidate["source_qualified"] else "development_only",
                      "candidate_sha256": sha256(files["candidate.json"]),
                      "source_pair_sha256": candidate["source_pair_sha256"],
                      "configuration_sha256": sha256(configuration), "production_deployed": False}
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
