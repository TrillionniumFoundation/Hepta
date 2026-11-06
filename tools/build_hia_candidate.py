#!/usr/bin/env python3
"""Build a deterministic, offline-installable HIA candidate from one source snapshot.

This creates an ordinary PEP 427 pure-Python wheel, not a new compiler or a
qualification shortcut. Every installed module and declared package data file
is included. Native toolchains and optional proof solvers remain external.
"""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import tomllib
import zipfile

ROOT = Path(__file__).resolve().parents[1]
MAX_FILE_BYTES = 16 * 1024 * 1024
DATA_SUFFIXES = {".py", ".json", ".hia", ".hiaasm"}
FIXTURES = ("counter.hia", "parameter_loan_return_v8.hia")
SCHEMA = "hepta.hia.candidate.v1"


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def read_regular(path):
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_FILE_BYTES:
        raise ValueError(f"not a bounded regular source file: {path}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        opened = os.fstat(stream.fileno())
        data = stream.read(MAX_FILE_BYTES + 1)
        after = os.fstat(stream.fileno())
    identity = lambda x: (x.st_dev, x.st_ino, x.st_size, x.st_mtime_ns, x.st_ctime_ns)
    if (len(data) > MAX_FILE_BYTES or identity(before) != identity(opened)
            or identity(opened) != identity(after) or identity(after) != identity(path.lstat())):
        raise ValueError(f"source changed while reading: {path}")
    return data


def git(root, *arguments):
    result = subprocess.run(["git", "-C", str(root), *arguments], check=True,
                            capture_output=True, text=True, timeout=30)
    return result.stdout.strip()


def collect_source(root):
    paths = []
    for path in sorted((root / "hepta").rglob("*")):
        if "__pycache__" in path.parts or path.suffix not in DATA_SUFFIXES:
            continue
        if path.is_symlink():
            raise ValueError(f"symlink is not candidate source: {path}")
        if path.is_file():
            paths.append(path)
    for relative in ("pyproject.toml", "tools/build_hia_candidate.py", "tools/verify_hia_candidate.py"):
        paths.append(root / relative)
    paths.extend(root / "examples/hia_program" / name for name in FIXTURES)
    return {path.relative_to(root).as_posix(): read_regular(path) for path in sorted(set(paths))}


def identity_inventory(root):
    # The isolated child imports the exact selected checkout, without user-site
    # or ambient PYTHONPATH imports. The source bytes are checked again below.
    code = '''import json, sys
sys.path.insert(0, sys.argv[1])
from hepta.pipeline import compiler_hash
from hepta.hia_routes import route_inventory
from hepta.hia_schema import schema_registry
from hepta.hia_program_llvm import _implementation_hash, TARGET, TARGET_AARCH64, TARGET_RISCV64
print(json.dumps({"compiler_sha256":compiler_hash(), "llvm_implementation_sha256":_implementation_hash(),
 "schemas":schema_registry(), "routes":route_inventory(),
 "abi":{"targets":[TARGET,TARGET_AARCH64,TARGET_RISCV64], "data_model":"LP64",
 "exports":"public scalar parameters; zero or one scalar return; resource returns remain internal",
 "cross_target_native_execution_qualified":False}}, sort_keys=True))'''
    # -B prevents writes but still reads valid .pyc files. A new empty prefix
    # forces source imports without deleting or altering developer caches.
    with tempfile.TemporaryDirectory(prefix="hia-candidate-pycache-") as cache:
        result = subprocess.run([sys.executable, "-I", "-B", "-X", "pycache_prefix=" + cache,
                                 "-c", code, str(root)],
                                check=True, capture_output=True, text=True, timeout=60)
    return json.loads(result.stdout)


def wheel_bytes(source, candidate, project):
    distribution = project["name"].replace("-", "_")
    version = candidate["distribution"]["version"]
    dist_info = f"{distribution}-{version}.dist-info"
    files = {name: data for name, data in source.items() if name.startswith("hepta/")}
    metadata = (f"Metadata-Version: 2.1\nName: {project['name']}\nVersion: {version}\n"
                f"Summary: {project['description']}\nRequires-Python: {project['requires-python']}\n")
    for dependency in project.get("dependencies", []):
        metadata += f"Requires-Dist: {dependency}\n"
    for extra, requirements in sorted(project.get("optional-dependencies", {}).items()):
        metadata += f"Provides-Extra: {extra}\n"
        for requirement in requirements:
            metadata += f"Requires-Dist: {requirement}; extra == '{extra}'\n"
    files[dist_info + "/METADATA"] = (metadata + "\n").encode()
    files[dist_info + "/WHEEL"] = b"Wheel-Version: 1.0\nGenerator: hepta-candidate-v1\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    scripts = project.get("scripts", {})
    files[dist_info + "/entry_points.txt"] = ("[console_scripts]\n" + "".join(
        f"{name} = {value}\n" for name, value in sorted(scripts.items()))).encode()
    files[dist_info + "/top_level.txt"] = b"hepta\n"
    files[dist_info + "/hia-candidate.json"] = encoded(candidate)
    record = io.StringIO(newline="")
    writer = csv.writer(record, lineterminator="\n")
    for name, data in sorted(files.items()):
        hash_value = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        writer.writerow((name, "sha256=" + hash_value, len(data)))
    writer.writerow((dist_info + "/RECORD", "", ""))
    files[dist_info + "/RECORD"] = record.getvalue().encode()
    archive = io.BytesIO()
    # ZIP_STORED avoids dependence on a platform's compression implementation.
    # Sorted names, fixed epoch, permissions and creator make bytes reproducible.
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as wheel:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            wheel.writestr(info, data)
    return f"{distribution}-{version}-py3-none-any.whl", archive.getvalue()


def build_candidate(output, *, root=ROOT, allow_dirty=False):
    root = Path(root).resolve()
    output = Path(output).absolute()
    if output.exists() or output.is_symlink():
        raise ValueError("candidate output must be absent; existing artifacts are never replaced")
    output = output.resolve()
    if output.is_relative_to(root):
        raise ValueError("candidate output must be outside the source checkout")
    dirty = bool(git(root, "status", "--porcelain", "--untracked-files=all"))
    if dirty and not allow_dirty:
        raise ValueError("candidate source is dirty; commit the snapshot or use --allow-dirty for development only")
    commit = git(root, "rev-parse", "HEAD")
    tree = git(root, "rev-parse", "HEAD^{tree}")
    source = collect_source(root)
    project = tomllib.loads(source["pyproject.toml"].decode())["project"]
    inventory = identity_inventory(root)
    source_files = [{"path": name, "sha256": digest(data), "size_bytes": len(data)}
                    for name, data in sorted(source.items())]
    source_seal = digest(encoded(source_files))
    candidate_version = project["version"] + "+hia.g" + commit[:12] + ".s" + source_seal[:12]
    candidate = {"schema": SCHEMA, "scope": "standalone-hia-installable-candidate",
                 "source_commit": commit, "source_tree": tree, "worktree_dirty": dirty,
                 "source_files": source_files, "source_manifest_sha256": source_seal,
                 "distribution": {"name": project["name"], "version": candidate_version,
                                  "base_version": project["version"]},
                 "compatibility": inventory,
                 "claims": {"production_release_qualified": False,
                            "whole_project_blockers_closed": False,
                            "performance_advantage_established": False,
                            "agent_productivity_advantage_established": False}}
    filename, wheel = wheel_bytes(source, candidate, project)
    payload = {filename: wheel, "verify_hia_candidate.py": source["tools/verify_hia_candidate.py"],
               "pyproject.toml": source["pyproject.toml"]}
    payload.update({name: source["examples/hia_program/" + name] for name in FIXTURES})
    manifest = {**candidate, "wheel": filename, "files": [
        {"path": name, "sha256": digest(data), "size_bytes": len(data)} for name, data in sorted(payload.items())]}
    payload["candidate-manifest.json"] = encoded(manifest)
    payload["SHA256SUMS"] = "".join(f"{digest(data)}  {name}\n" for name, data in sorted(payload.items())).encode()
    # Reject concurrent code edits, including subpackage/data changes, before
    # creating the output. No prior report is borrowed for this snapshot.
    if source != collect_source(root) or commit != git(root, "rev-parse", "HEAD"):
        raise ValueError("source snapshot changed during candidate construction")
    if dirty != bool(git(root, "status", "--porcelain", "--untracked-files=all")):
        raise ValueError("source worktree state changed during candidate construction")
    output.mkdir(parents=True, exist_ok=False)
    for name, data in sorted(payload.items(), key=lambda item: item[0] == "candidate-manifest.json"):
        with (output / name).open("xb") as stream:
            stream.write(data)
    return {"schema": "hepta.hia.candidate-build.v1", "status": "candidate_built_not_qualified",
            "output": str(output), "source_commit": commit,
            "source_manifest_sha256": candidate["source_manifest_sha256"],
            "manifest_sha256": digest(payload["candidate-manifest.json"]),
            "wheel_sha256": digest(wheel), "worktree_dirty": dirty,
            "reproducible_archive_format": "sorted-stored-zip-fixed-epoch-v1"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--allow-dirty", action="store_true", help="Development builds only; recorded permanently in manifest")
    args = parser.parse_args(argv)
    try:
        print(json.dumps(build_candidate(args.output_directory, allow_dirty=args.allow_dirty), indent=2, sort_keys=True))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(json.dumps({"status": "rejected", "error": str(error)}))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
