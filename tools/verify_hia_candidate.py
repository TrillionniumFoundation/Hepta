#!/usr/bin/env python3
"""Check a HIA bundle and execute its installed wheel outside the source checkout."""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tempfile
import tomllib
import venv
import zipfile

MAX_BUNDLE_FILE_BYTES = 64 * 1024 * 1024


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def regular_bytes(path):
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_BUNDLE_FILE_BYTES:
        raise ValueError("bundle entries must be bounded regular files")
    with os.fdopen(os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)), "rb") as stream:
        opened = os.fstat(stream.fileno())
        data = stream.read(MAX_BUNDLE_FILE_BYTES + 1)
        after = os.fstat(stream.fileno())
    same = lambda x: (x.st_dev, x.st_ino, x.st_size, x.st_mtime_ns, x.st_ctime_ns)
    if len(data) > MAX_BUNDLE_FILE_BYTES or not same(before) == same(opened) == same(after) == same(path.lstat()):
        raise ValueError("bundle file changed while reading")
    return data


def safe_name(value, *, basename=False):
    if (not isinstance(value, str) or not value or "\\" in value or "\x00" in value
            or PurePosixPath(value).is_absolute() or str(PurePosixPath(value)) != value
            or ".." in PurePosixPath(value).parts or (basename and "/" in value)):
        raise ValueError("invalid bundle path")
    return value


def exact_fields(value, fields, label):
    if type(value) is not dict or set(value) != set(fields):
        raise ValueError(f"invalid {label} fields")


def sha256_field(value, label):
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError(f"invalid {label} SHA256")


def validate_manifest_fields(manifest):
    exact_fields(manifest, {"schema", "scope", "source_commit", "source_tree", "worktree_dirty",
                           "source_files", "source_manifest_sha256", "distribution", "compatibility",
                           "claims", "wheel", "files"}, "candidate manifest")
    if (manifest["schema"] != "hepta.hia.candidate.v1"
            or manifest["scope"] != "standalone-hia-installable-candidate"):
        raise ValueError("unsupported candidate manifest schema or scope")
    if type(manifest["worktree_dirty"]) is not bool:
        raise ValueError("candidate must record worktree identity")
    for key in ("source_commit", "source_tree"):
        value = manifest[key]
        if type(value) is not str or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", value) is None:
            raise ValueError(f"invalid candidate {key}")
    sha256_field(manifest["source_manifest_sha256"], "source manifest")
    distribution = manifest["distribution"]
    exact_fields(distribution, {"name", "version", "base_version"}, "distribution")
    if (distribution["name"] != "hepta-language" or type(distribution["base_version"]) is not str
            or not distribution["base_version"]):
        raise ValueError("unsupported candidate distribution")
    version = (distribution["base_version"] + "+hia.g" + manifest["source_commit"][:12]
               + ".s" + manifest["source_manifest_sha256"][:12])
    if distribution["version"] != version:
        raise ValueError("candidate version does not bind the recorded source identity")
    claims = manifest["claims"]
    exact_fields(claims, {"production_release_qualified", "whole_project_blockers_closed",
                         "performance_advantage_established", "agent_productivity_advantage_established"},
                 "candidate claims")
    if any(value is not False for value in claims.values()):
        raise ValueError("candidate cannot grant production, completeness or advantage claims")
    inventory = manifest["compatibility"]
    exact_fields(inventory, {"compiler_sha256", "llvm_implementation_sha256", "schemas", "routes", "abi"},
                 "compatibility inventory")
    for key in ("compiler_sha256", "llvm_implementation_sha256"):
        sha256_field(inventory[key], key)
    if type(inventory["schemas"]) is not dict or type(inventory["routes"]) is not dict:
        raise ValueError("invalid schema or route inventory")
    exact_fields(inventory["abi"], {"targets", "data_model", "exports", "cross_target_native_execution_qualified"},
                 "ABI inventory")
    if (inventory["abi"]["cross_target_native_execution_qualified"] is not False
            or inventory["abi"]["data_model"] != "LP64"
            or type(inventory["abi"]["exports"]) is not str
            or type(inventory["abi"]["targets"]) is not list
            or not inventory["abi"]["targets"]
            or any(type(target) is not str for target in inventory["abi"]["targets"])
            or len(set(inventory["abi"]["targets"])) != len(inventory["abi"]["targets"])):
        raise ValueError("invalid candidate ABI inventory")
    for key in ("source_files", "files"):
        rows = manifest[key]
        if type(rows) is not list or not rows:
            raise ValueError(f"invalid {key} roster")
        names = []
        for entry in rows:
            exact_fields(entry, {"path", "sha256", "size_bytes"}, key + " entry")
            names.append(safe_name(entry["path"], basename=key == "files"))
            sha256_field(entry["sha256"], key + " entry")
            if type(entry["size_bytes"]) is not int or not 0 <= entry["size_bytes"] <= MAX_BUNDLE_FILE_BYTES:
                raise ValueError(f"invalid {key} entry size")
        if names != sorted(names) or len(names) != len(set(names)):
            raise ValueError(f"noncanonical or duplicate {key} roster")


def expected_metadata(project_bytes, distribution):
    """Bind wheel metadata and scripts to the exact packaged source config."""
    project = tomllib.loads(project_bytes.decode())["project"]
    if project["name"] != distribution["name"] or project["version"] != distribution["base_version"]:
        raise ValueError("packaging configuration/distribution mismatch")
    metadata = (f"Metadata-Version: 2.1\nName: {project['name']}\nVersion: {distribution['version']}\n"
                f"Summary: {project['description']}\nRequires-Python: {project['requires-python']}\n")
    for dependency in project.get("dependencies", []):
        metadata += f"Requires-Dist: {dependency}\n"
    for extra, requirements in sorted(project.get("optional-dependencies", {}).items()):
        metadata += f"Provides-Extra: {extra}\n"
        for requirement in requirements:
            metadata += f"Requires-Dist: {requirement}; extra == '{extra}'\n"
    scripts = project.get("scripts", {})
    return {"METADATA": (metadata + "\n").encode(),
            "WHEEL": b"Wheel-Version: 1.0\nGenerator: hepta-candidate-v1\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
            "entry_points.txt": ("[console_scripts]\n" + "".join(
                f"{name} = {value}\n" for name, value in sorted(scripts.items()))).encode(),
            "top_level.txt": b"hepta\n"}


def validate_bundle(directory, *, expected_manifest_sha256=None, allow_dirty=False):
    directory = Path(directory).resolve()
    manifest_bytes = regular_bytes(directory / "candidate-manifest.json")
    if expected_manifest_sha256 is not None:
        sha256_field(expected_manifest_sha256, "pinned manifest")
        if digest(manifest_bytes) != expected_manifest_sha256:
            raise ValueError("candidate manifest does not match the pinned SHA256")
    manifest = json.loads(manifest_bytes)
    if encoded(manifest) != manifest_bytes:
        raise ValueError("candidate manifest must use canonical JSON without duplicate keys")
    validate_manifest_fields(manifest)
    if manifest["worktree_dirty"] and not allow_dirty:
        raise ValueError("development candidate has uncommitted source; --allow-dirty is required")
    source_files = manifest["source_files"]
    if digest(encoded(source_files)) != manifest["source_manifest_sha256"]:
        raise ValueError("source manifest identity mismatch")
    source_index = {}
    for entry in source_files:
        name = safe_name(entry["path"])
        if name in source_index:
            raise ValueError("duplicate source identity")
        source_index[name] = entry
    payload = {}
    for entry in manifest["files"]:
        name = safe_name(entry["path"], basename=True)
        if name in payload or name in {"candidate-manifest.json", "SHA256SUMS"}:
            raise ValueError("duplicate or recursive bundle entry")
        data = regular_bytes(directory / name)
        if type(entry["size_bytes"]) is not int or len(data) != entry["size_bytes"] or digest(data) != entry["sha256"]:
            raise ValueError(f"bundle file identity mismatch: {name}")
        payload[name] = data
    if set(path.name for path in directory.iterdir()) != set(payload) | {"candidate-manifest.json", "SHA256SUMS"}:
        raise ValueError("bundle contains missing or unexpected files")
    sums = "".join(f"{digest(data)}  {name}\n" for name, data in sorted(
        {**payload, "candidate-manifest.json": manifest_bytes}.items())).encode()
    if regular_bytes(directory / "SHA256SUMS") != sums:
        raise ValueError("checksum roster mismatch")
    wheel_name = safe_name(manifest["wheel"], basename=True)
    expected_dist = manifest["distribution"]["name"].replace("-", "_") + "-" + manifest["distribution"]["version"]
    if wheel_name != expected_dist + "-py3-none-any.whl":
        raise ValueError("wheel filename/distribution mismatch")
    external_sources = {"verify_hia_candidate.py": "tools/verify_hia_candidate.py", "pyproject.toml": "pyproject.toml",
                        "counter.hia": "examples/hia_program/counter.hia",
                        "parameter_loan_return_v8.hia": "examples/hia_program/parameter_loan_return_v8.hia"}
    if set(payload) != {wheel_name, *external_sources}:
        raise ValueError("unexpected candidate payload roster")
    for filename, source_name in external_sources.items():
        entry, data = source_index[source_name], payload[filename]
        if len(data) != entry["size_bytes"] or digest(data) != entry["sha256"]:
            raise ValueError(f"bundle/source bytes differ: {filename}")
    with zipfile.ZipFile(io.BytesIO(payload[wheel_name])) as archive:
        infos = archive.infolist()
        if sum(info.file_size for info in infos) > MAX_BUNDLE_FILE_BYTES:
            raise ValueError("wheel expands beyond the candidate limit")
        names = [safe_name(info.filename) for info in infos]
        if len(set(names)) != len(names):
            raise ValueError("duplicate wheel member")
        if any(info.is_dir() or stat.S_ISLNK(info.external_attr >> 16) or info.flag_bits & 1 for info in infos):
            raise ValueError("unsupported wheel member")
        wheel_files = {name: archive.read(name) for name in names}
    dist_info = expected_dist + ".dist-info/"
    expected_members = {name for name in source_index if name.startswith("hepta/")} | {
        dist_info + name for name in ("METADATA", "WHEEL", "entry_points.txt", "top_level.txt", "hia-candidate.json", "RECORD")}
    if set(wheel_files) != expected_members:
        raise ValueError("wheel/source file roster differs")
    for name, entry in source_index.items():
        if name.startswith("hepta/") and (len(wheel_files[name]) != entry["size_bytes"] or digest(wheel_files[name]) != entry["sha256"]):
            raise ValueError(f"wheel/source bytes differ: {name}")
    for name, expected in expected_metadata(payload["pyproject.toml"], manifest["distribution"]).items():
        if wheel_files[dist_info + name] != expected:
            raise ValueError("wheel metadata/source configuration differs: " + name)
    embedded_bytes = wheel_files[dist_info + "hia-candidate.json"]
    embedded = json.loads(embedded_bytes)
    if encoded(embedded) != embedded_bytes:
        raise ValueError("embedded candidate identity must use canonical JSON without duplicate keys")
    if embedded != {key: value for key, value in manifest.items() if key not in {"wheel", "files"}}:
        raise ValueError("wheel embeds a different candidate identity")
    rows = list(csv.reader(io.StringIO(wheel_files[dist_info + "RECORD"].decode())))
    if len(rows) != len(wheel_files) or any(len(row) != 3 for row in rows):
        raise ValueError("invalid wheel RECORD roster")
    seen = set()
    for name, hash_value, size in rows:
        if name in seen or name not in wheel_files:
            raise ValueError("duplicate or missing wheel RECORD member")
        seen.add(name)
        if name == dist_info + "RECORD":
            if hash_value or size:
                raise ValueError("wheel RECORD must not hash itself")
            continue
        data = wheel_files[name]
        expected = "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        if hash_value != expected or size != str(len(data)):
            raise ValueError("wheel RECORD hash mismatch")
    return manifest, payload


def verify_installed_files(site_packages, source_files):
    """Independently check the complete installed package, including subpackages/data."""
    expected = {entry["path"]: entry for entry in source_files if entry["path"].startswith("hepta/")}
    package = site_packages / "hepta"
    if package.is_symlink() or not package.is_dir():
        raise ValueError("installed package must be an ordinary directory")
    observed = {}
    for path in sorted(package.rglob("*")):
        if path.is_symlink():
            raise ValueError("installed package contains a symlink")
        if path.is_dir():
            continue
        name = path.relative_to(site_packages).as_posix()
        data = regular_bytes(path)
        observed[name] = {"path": name, "sha256": digest(data), "size_bytes": len(data)}
    if set(observed) != set(expected):
        raise ValueError("installed package/source file roster differs")
    for name, entry in observed.items():
        if entry != expected[name]:
            raise ValueError("installed package/source bytes differ: " + name)
    return {"returncode": 0, "file_count": len(observed),
            "package_manifest_sha256": digest(encoded([observed[name] for name in sorted(observed)]))}


def verify_installed(directory, *, expected_manifest_sha256=None, allow_dirty=False, clang=None):
    directory = Path(directory).resolve()
    manifest, payload = validate_bundle(directory, expected_manifest_sha256=expected_manifest_sha256, allow_dirty=allow_dirty)
    observations = []
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(("PYTHON", "PIP_"))}
    environment.update(PYTHONDONTWRITEBYTECODE="1", PIP_CONFIG_FILE=os.devnull,
                       PIP_DISABLE_PIP_VERSION_CHECK="1", PIP_NO_INDEX="1")
    with tempfile.TemporaryDirectory(prefix="hia-installed-candidate-") as temporary:
        work = Path(temporary)
        venv.EnvBuilder(with_pip=True, clear=False).create(work / "venv")
        python = work / "venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        cache = work / "empty-pycache"
        cache.mkdir()
        environment["PYTHONPYCACHEPREFIX"] = str(cache)

        def run(label, arguments, *, timeout=90):
            command = [str(python), "-I", "-B", "-X", "pycache_prefix=" + str(cache), *map(str, arguments)]
            result = subprocess.run(command, cwd=work, env=environment,
                                    capture_output=True, text=True, timeout=timeout)
            observations.append({"name": label, "arguments": list(map(str, arguments)),
                                 "returncode": result.returncode,
                                 "stdout_sha256": digest(result.stdout.encode()),
                                 "stderr_sha256": digest(result.stderr.encode())})
            if result.returncode:
                raise ValueError(f"installed {label} failed ({result.returncode}): {result.stderr[-2000:]} {result.stdout[-2000:]}")
            return result.stdout

        # Install the already checked bytes into an isolated venv. Copying from
        # the captured payload prevents a changed bundle path from being used.
        wheel = work / manifest["wheel"]
        wheel.write_bytes(payload[manifest["wheel"]])
        run("offline_wheel_install", ["-m", "pip", "install", "--no-index", "--no-deps", "--no-compile", str(wheel)])
        layout = json.loads(run("installed_layout", ["-c", '''import json, sys, sysconfig
print(json.dumps({"prefix":sys.prefix,"purelib":sysconfig.get_path("purelib")}))''']))
        prefix, site_packages = Path(layout["prefix"]).resolve(), Path(layout["purelib"]).resolve()
        if prefix != (work / "venv").resolve() or not site_packages.is_relative_to(prefix):
            raise ValueError("installed Python/package layout is outside the fresh venv")
        observations.append({"name": "installed_package_before",
                             **verify_installed_files(site_packages, manifest["source_files"])})
        identity = json.loads(run("installed_identity", ["-c", '''import json, pathlib, sys
import hepta
from importlib.metadata import version
from hepta.pipeline import compiler_hash
from hepta.hia_program_llvm import _implementation_hash, TARGET, TARGET_AARCH64, TARGET_RISCV64
from hepta.hia_routes import route_inventory
from hepta.hia_schema import schema_registry
print(json.dumps({"location":str(pathlib.Path(hepta.__file__).resolve()),
 "compiler_sha256":compiler_hash(),"llvm_implementation_sha256":_implementation_hash(),"routes":route_inventory(),
 "schemas":schema_registry(),
 "abi":{"targets":[TARGET,TARGET_AARCH64,TARGET_RISCV64],"data_model":"LP64",
 "exports":"public scalar parameters; zero or one scalar return; resource returns remain internal",
 "cross_target_native_execution_qualified":False},
 "distribution_version":version("hepta-language")}))''']))
        if Path(identity["location"]) != site_packages / "hepta/__init__.py":
            raise ValueError("smoke test imported source checkout instead of installed wheel")
        inventory = manifest["compatibility"]
        if identity["distribution_version"] != manifest["distribution"]["version"]:
            raise ValueError("installed distribution version differs")
        for key in ("compiler_sha256", "llvm_implementation_sha256", "routes", "schemas", "abi"):
            if encoded(identity[key]) != encoded(inventory[key]):
                raise ValueError("installed compiler or compatibility identity differs")
        for filename in ("counter.hia", "parameter_loan_return_v8.hia"):
            (work / filename).write_bytes(payload[filename])
            result = json.loads(run("verify_" + filename, ["-m", "hepta", "hia", "verify", filename]))
            if result.get("ok") is not True:
                raise ValueError("installed verifier did not accept the bundled fixture")
        result = json.loads(run("interpret", ["-m", "hepta", "hia", "run", "counter.hia", "--function", "increment", "--arguments", "[40]"]))
        if result.get("status") != "returned" or result.get("result") != 41:
            raise ValueError("installed interpreter result mismatch")
        for target in inventory["abi"]["targets"]:
            ir = run("emit_" + target, ["-m", "hepta", "hia", "emit", "parameter_loan_return_v8.hia", "--target", target])
            if 'target triple = "' + target + '"' not in ir:
                raise ValueError("installed emitter target mismatch")
        console = python.parent / ("hepta.exe" if os.name == "nt" else "hepta")
        command = subprocess.run([str(console), "hia", "routes"], cwd=work, env=environment,
                                 check=True, capture_output=True, text=True, timeout=60)
        if json.loads(command.stdout) != inventory["routes"]:
            raise ValueError("installed console script compatibility mismatch")
        observations.append({"name": "installed_console_script", "returncode": command.returncode})
        if any(entry["path"] == "hepta/apps/quota.py" for entry in manifest["source_files"]):
            app = ["-m", "hepta.apps.quota", "--ledger", "installed-quota"]
            initial = json.loads(run("installed_quota_init", app + ["init", "--initial", "100"]))
            reserved = json.loads(run("installed_quota_reserve", app + ["apply", "reserve-1", "reserve", "40"]))
            upgraded = json.loads(run("installed_quota_upgrade", app + ["upgrade", "upgrade-1"]))
            recovered = json.loads(run("installed_quota_recover", app + ["status"]))
            if (initial.get("state") != {"available": 100, "held": 0}
                    or reserved.get("status") != "applied" or reserved.get("state") != {"available": 60, "held": 40}
                    or upgraded.get("status") != "upgraded" or recovered.get("version") != "v2"
                    or recovered.get("state") != reserved.get("state")):
                raise ValueError("installed quota data or application result mismatch")
        native = {"status": "not_requested", "execution_qualified": False}
        if clang:
            native_build = json.loads(run("native_build", ["-m", "hepta", "hia", "build", "counter.hia", "--clang", str(Path(clang).resolve()), "-o", "counter.so"]))
            if native_build.get("ok") is not True:
                raise ValueError("installed native build was not accepted")
            actual = run("native_execute", ["-c", '''import ctypes
lib=ctypes.CDLL('./counter.so')
lib.increment.argtypes=[ctypes.c_uint32]
lib.increment.restype=ctypes.c_uint32
assert lib.increment(40)==41
print(41)'''])
            if actual.strip() != "41":
                raise ValueError("installed native result mismatch")
            native = {"status": "counter_executed", "execution_qualified": True,
                      "scope": "one bundled u32 counter on the actual host", "build_receipt": native_build}
        observations.append({"name": "installed_package_after",
                             **verify_installed_files(site_packages, manifest["source_files"])})
    return {"schema": "hepta.hia.candidate-installed-verification.v1", "status": "passed",
            "source_commit": manifest["source_commit"], "source_manifest_sha256": manifest["source_manifest_sha256"],
            "manifest_sha256": digest(encoded(manifest)),
            "wheel_sha256": digest(payload[manifest["wheel"]]), "worktree_dirty": manifest["worktree_dirty"],
            "observations": observations, "native": native,
            "claims": {"installed_verify_run_emit": True, "production_release_qualified": False,
                       "cross_target_execution_qualified": False, "performance_advantage_established": False}}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-directory", type=Path, required=True)
    parser.add_argument("--expected-manifest-sha256")
    parser.add_argument("--allow-dirty", action="store_true")
    parser.add_argument("--clang", help="Explicit actual Clang 20+ executable for the native counter smoke")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        report = verify_installed(args.candidate_directory, expected_manifest_sha256=args.expected_manifest_sha256,
                                  allow_dirty=args.allow_dirty, clang=args.clang)
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile, subprocess.SubprocessError) as error:
        report = {"schema": "hepta.hia.candidate-installed-verification.v1", "status": "rejected", "error": str(error)}
    if args.output:
        with args.output.open("xb") as stream:
            stream.write(encoded(report))
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
