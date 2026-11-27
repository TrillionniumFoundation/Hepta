"""Real development component wheels with independent Git and install custody.

This fixture never invokes the public HIA wheel backend and never qualifies a
default native distribution. The old ordinary_wheel fixture is unchanged.
"""
from __future__ import annotations

import ast
import base64
import csv
from email.parser import BytesParser
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys
import sysconfig
import tempfile
import threading
import tomllib
import zipfile

from tools.hia_component_input_custody import (
    _git_inputs, _head, _head_tree, _name, _regular_bytes, _tree_entries,
)
from tools.hia_native_worker_source_authority import checked_paths

ROOT = Path(__file__).resolve().parents[1]
AUTHORITY = "docs/HIA_NATIVE_SOURCE_AUTHORITY.json"
SCHEMA = "hepta.hia.development-component-wheel-custody.v1"
SCOPE = "DEVELOPMENT_COMPONENT_INSTALL_ONLY"
_SLOT_RECEIPT = "hepta/_slot_mechanical_build.json"
_lock = threading.Lock()
_built = {}
_cache = {}


def _require(condition, message):
    if not condition:
        raise ValueError("component wheel: " + message)


def _encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


def _pairs(items):
    value = {}
    for key, item in items:
        _require(key not in value, "duplicate JSON key: " + key)
        value[key] = item
    return value


def _json(raw):
    return json.loads(raw, object_pairs_hook=_pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(
                          ValueError("component wheel: invalid JSON constant " + value)))


def _pin(raw):
    return {"bytes": len(raw), "sha256": sha256(raw).hexdigest()}


def _read(root, name):
    """Return actual descriptor-bound bytes without following any input link."""
    _name(name)
    descriptor = None
    parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parts = name.split("/")
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=parent)
            os.close(parent)
            parent = child
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=parent)
        before = os.fstat(descriptor)
        _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                 and not before.st_mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX),
                 "input is not an ordinary single-link file: " + name)
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            raw = stream.read(before.st_size + 1)
            after = os.fstat(stream.fileno())
        identity = lambda value: (value.st_dev, value.st_ino, value.st_size,
                                  value.st_mtime_ns, value.st_ctime_ns, value.st_mode,
                                  value.st_nlink)
        _require(len(raw) == before.st_size and identity(before) == identity(after),
                 "input changed during its physical read: " + name)
        return raw
    except OSError as exc:
        raise ValueError("component wheel: unreadable or redirected input: " + name) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)


def _inventory(directory):
    """Enumerate the complete physical regular-file set, rejecting redirects."""
    root = Path(directory)
    _require(root.is_dir() and not root.is_symlink(), "input root is not an ordinary directory")
    names = set()
    for current, dirs, files in os.walk(root, followlinks=False):
        for name in dirs:
            path = Path(current) / name
            _require(stat.S_ISDIR(path.lstat().st_mode) and not path.is_symlink(),
                     "directory is redirected: " + str(path))
        for name in files:
            relative = (Path(current) / name).relative_to(root).as_posix()
            _name(relative)
            _require(relative not in names, "duplicate physical member")
            names.add(relative)
    return names


def _literal(tree, name):
    values = [node.value for node in tree.body if isinstance(node, ast.Assign)
              and any(isinstance(target, ast.Name) and target.id == name
                      for target in node.targets)]
    _require(len(values) == 1, "one explicit declaration required: " + name)
    return ast.literal_eval(values[0])


def _tuple(value, label):
    _require(type(value) is tuple and all(type(item) is str for item in value),
             "resource tuple differs: " + label)
    for item in value:
        _name(item)
    _require(len(value) == len(set(value)), "duplicate resource: " + label)
    return value


def _resource_paths(captured):
    """Follow the actual setup resource expression, including every new group."""
    setup = ast.parse(captured["setup.py"])
    functions = {node.name: node for node in setup.body if isinstance(node, ast.FunctionDef)}
    agent = functions["agent_resources"]
    declarations = [node for node in ast.walk(agent) if isinstance(node, ast.For)
                    and isinstance(node.target, ast.Name) and node.target.id == "symbol"]
    _require(len(declarations) == 1, "Agent resource selector is not explicit")
    symbols = _tuple(ast.literal_eval(declarations[0].iter), "Agent symbols")
    contract = ast.parse(captured["hepta/hia_agent_contract.py"])
    values = {name: _tuple(_literal(contract, name), name) for name in symbols}
    discovery = values["DISCOVERY_FILES"]
    _require(all("/" not in name for name in discovery), "invalid discovery filename")
    names_assignments = [node.value for node in ast.walk(agent) if isinstance(node, ast.Assign)
                         and any(isinstance(target, ast.Name) and target.id == "names"
                                 for target in node.targets)
                         and not isinstance(node.value, ast.Call)]
    _require(len(names_assignments) == 1, "Agent resource concatenation is not explicit")

    def agent_value(node):
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return agent_value(node.left) + agent_value(node.right)
        if (isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name)
                and node.value.id == "values"):
            key = ast.literal_eval(node.slice)
            _require(key in values, "unknown Agent resource group")
            return values[key]
        expected = ast.parse("tuple('docs/'+n for n in values['DISCOVERY_FILES'])",
                             mode="eval").body
        _require(ast.dump(node, include_attributes=False)
                 == ast.dump(expected, include_attributes=False),
                 "unknown Agent resource expression")
        return tuple("docs/" + name for name in discovery)

    agent_names = _tuple(agent_value(names_assignments[0]), "Agent resources")
    modules = {
        "executable_capture_resources": "hepta/hia_executable_capture.py",
        "nominal_program_resources": "hepta/hia_nominal_program_native.py",
    }
    extras = {function: _tuple(_literal(ast.parse(captured[path]), "PACKAGE_RESOURCES"), path)
              for function, path in modules.items()}
    builders = [node for node in setup.body if isinstance(node, ast.ClassDef)
                and node.name == "AgentResourceBuild"]
    _require(len(builders) == 1, "one actual AgentResourceBuild is required")
    runs = [node for node in builders[0].body if isinstance(node, ast.FunctionDef)
            and node.name == "run"]
    _require(len(runs) == 1, "one actual resource build run is required")
    loops = [node for node in ast.walk(runs[0]) if isinstance(node, ast.For)
             and isinstance(node.target, ast.Name) and node.target.id == "name"]
    _require(len(loops) == 1, "one explicit packaging resource loop is required")

    def resource_value(node):
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return resource_value(node.left) + resource_value(node.right)
        if isinstance(node, ast.Name):
            return agent_names if node.id == "names" else _tuple(
                _literal(setup, node.id), node.id)
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id in extras and len(node.args) == 1 and not node.keywords
                and isinstance(node.args[0], ast.Name) and node.args[0].id == "names"):
            return extras[node.func.id]
        raise ValueError("component wheel: unknown setup resource expression")

    resources = _tuple(resource_value(loops[0].iter), "all setup resources")
    calls = [node for node in setup.body if isinstance(node, ast.Expr)
             and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name)
             and node.value.func.id == "setup"]
    _require(len(calls) == 1, "one actual setup call is required")
    package = [item.value for item in calls[0].value.keywords if item.arg == "package_data"]
    _require(len(package) == 1, "explicit package_data is required")
    data = ast.literal_eval(package[0])
    _require(type(data) is dict and set(data) == {"hepta"}
             and type(data["hepta"]) is list, "unsupported package_data domain")
    package_paths = _tuple(tuple(data["hepta"]), "package_data")
    return resources, tuple("hepta/" + name for name in package_paths)


def _package_tree(root, tree):
    entries = _tree_entries(root, tree)
    _require(b"hepta" in entries and entries[b"hepta"][0] == "40000",
             "the Git root has no regular hepta package tree")
    result = {}
    pending = [("hepta", entries[b"hepta"][1])]
    while pending:
        prefix, identity = pending.pop()
        for raw_name, (mode, blob) in _tree_entries(root, identity).items():
            name = prefix + "/" + raw_name.decode("ascii")
            _name(name)
            if mode == "40000":
                pending.append((name, blob))
            else:
                _require(mode in ("100644", "100755"), "non-regular Git package input")
                result[name] = (mode, blob)
    return entries, result


def _snapshot(root, additional=()):
    root = Path(root).absolute()
    head = _head(root)
    tree = _head_tree(root, head)
    root_entries, package = _package_tree(root, tree)
    captured = {}
    def take(name):
        if name not in captured:
            captured[name] = _read(root, name)
        return captured[name]
    initial = (
        "setup.py", "pyproject.toml", "MANIFEST.in", AUTHORITY,
        "hepta/hia_agent_contract.py", "hepta/hia_executable_capture.py",
        "hepta/hia_nominal_program_native.py",
        "tests/hia_component_install_fixture.py",
        "tools/hia_component_input_custody.py",
        "tools/hia_native_worker_source_authority.py",
        "tools/build_hia_default_release.py",
    )
    for name in initial:
        take(name)
    authority = _json(captured[AUTHORITY])
    _require(type(authority) is dict and set(authority) == {"schema", "paths"}
             and authority["schema"] == "hepta.hia.native-source-authority.v1",
             "native source authority schema differs")
    native = checked_paths(authority["paths"])
    additional = tuple(sorted(set(additional)))
    for name in additional:
        _name(name)
    names = set(initial) | set(package) | set(native) | set(additional)
    for line in captured["MANIFEST.in"].decode("utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        _require(line.startswith("include "), "packaging manifest is not explicit")
        name = line[len("include "):]
        _name(name)
        _require(not any(character in name for character in "*?[]"),
                 "packaging manifest contains a glob")
        names.add(name)
    resources, package_data = _resource_paths(captured)
    names.update(resources)
    names.update(package_data)
    licenses = {}
    for name, (mode, identity) in root_entries.items():
        label = name.decode("ascii")
        if mode in ("100644", "100755") and label.upper().startswith(
                ("LICENSE", "LICENCE", "COPYING", "NOTICE", "AUTHORS", "README")):
            names.add(label)
            if not label.upper().startswith("README"):
                licenses[label] = label
    for name in sorted(names):
        take(name)
    actual_head, actual_tree, pins = _git_inputs(root, captured)
    _require((actual_head, actual_tree) == (head, tree),
             "source identity changed during packaging input capture")
    project = tomllib.loads(captured["pyproject.toml"].decode("utf-8"))
    _require(project["tool"]["setuptools"]["packages"] == ["hepta"]
             and not project["project"].get("dynamic"),
             "component packaging requires the explicit hepta package and metadata")
    expected = {name: name for name in package
                if name.startswith("hepta/") and name.count("/") == 1 and name.endswith(".py")}
    expected.update({name: name for name in package_data})
    for name in resources:
        target = "hepta/_data/" + name
        _require(target not in expected, "duplicate packaged source member")
        expected[target] = name
    custody = {
        "schema": SCHEMA, "scope": SCOPE, "source_head": head, "source_tree": tree,
        "native_authority": {name: pins[name] for name in native},
        "packaging_inputs": pins, "partial_staging_inputs": list(additional),
        "native_cold_qualified": False, "host_authoring_is_native_qualified": False,
        "whole_native_delivery_qualified": False,
        "resource_paths": list(resources), "package_members": expected,
    }
    return {"root": root, "captured": captured, "custody": custody,
            "expected": expected, "licenses": licenses, "project": project["project"],
            "additional": additional}


def _verify_snapshot(snapshot):
    current = _snapshot(snapshot["root"], snapshot["additional"])
    _require(_encoded(current["custody"]) == _encoded(snapshot["custody"]),
             "Git/native/packaging source custody changed")
    _require(current["captured"] == snapshot["captured"], "source bytes changed")
    return current


def _staged_inputs(source, snapshot):
    source = Path(source).absolute()
    _require(not source.is_symlink(), "partial staging root is redirected")
    source = source.resolve(strict=True)
    if source == snapshot["root"]:
        return
    names = _inventory(source)
    _require({"setup.py", "pyproject.toml", "MANIFEST.in"} <= names,
             "partial staging lacks its original package configuration")
    _require(names == set(snapshot["additional"]), "partial staging membership changed")
    _require(names <= set(snapshot["captured"]), "partial staging has an unbound extra file")
    for name in sorted(names):
        _require(_read(source, name) == snapshot["captured"][name],
                 "partial staging differs from current Git bytes: " + name)


def _record(files, record):
    _require(record in files, "RECORD is missing")
    try:
        rows = list(csv.reader(io.StringIO(files[record].decode("utf-8"), newline=""),
                               strict=True))
    except (UnicodeError, csv.Error) as exc:
        raise ValueError("component wheel: invalid RECORD encoding") from exc
    observed = {}
    for row in rows:
        _require(len(row) == 3, "RECORD row must have exactly three fields")
        name, digest, size = row
        _name(name)
        _require(name not in observed and name in files, "duplicate or unknown RECORD member")
        if name == record:
            _require(digest == size == "", "RECORD must leave its own hash and size empty")
        else:
            raw = files[name]
            expected = "sha256=" + base64.urlsafe_b64encode(sha256(raw).digest()).rstrip(b"=").decode()
            _require(digest == expected and size == str(len(raw)),
                     "RECORD bytes/hash/size differ: " + name)
        observed[name] = True
    _require(set(observed) == set(files), "RECORD is not the complete physical member set")


def _zip(raw):
    files, modes = {}, {}
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            for item in archive.infolist():
                name = _name(item.filename)
                mode = item.external_attr >> 16
                _require(name not in files and not item.is_dir()
                         and not item.flag_bits & 1
                         and stat.S_IFMT(mode) in (0, stat.S_IFREG)
                         and not mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX),
                         "duplicate, encrypted or non-regular wheel member: " + name)
                data = archive.read(item)
                _require(len(data) == item.file_size, "wheel member extent differs")
                files[name] = data
                modes[name] = bool(mode & stat.S_IXUSR)
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        raise ValueError("component wheel: invalid physical wheel") from exc
    _require(files, "empty wheel")
    return files, modes


def _slot_supported():
    return (sys.implementation.name == "cpython" and sys.platform == "linux"
            and (3, 11) <= sys.version_info[:2] <= (3, 14)
            and not bool(sysconfig.get_config_var("Py_GIL_DISABLED"))
            and platform.machine() == "x86_64" and sysconfig.get_config_var("SIZEOF_VOID_P") == 8)


def _checked_wheel(path, raw, snapshot):
    files, modes = _zip(raw)
    records = [name for name in files if name.endswith(".dist-info/RECORD")]
    _require(len(records) == 1, "one wheel distribution RECORD is required")
    record = records[0]
    prefix = record[:-len("RECORD")]
    project = snapshot["project"]
    normalized = re.sub(r"[-_.]+", "_", project["name"])
    _require(prefix == normalized + "-" + project["version"] + ".dist-info/",
             "wheel distribution identity differs from pyproject")
    _record(files, record)
    metadata = BytesParser().parsebytes(files[prefix + "METADATA"])
    _require(metadata.get_all("Name") == [project["name"]]
             and metadata.get_all("Version") == [project["version"]]
             and metadata.get_all("Requires-Python") == [project["requires-python"]],
             "wheel metadata differs from package source")
    wheel = BytesParser().parsebytes(files[prefix + "WHEEL"])
    tag = "-".join(Path(path).stem.rsplit("-", 3)[-3:])
    _require(wheel.get_all("Tag") == [tag] and wheel.get_all("Wheel-Version") == ["1.0"],
             "wheel filename and metadata ABI differ")
    from tools.build_hia_default_release import _slot_wheel_members
    mechanical, unused_native_tag = _slot_wheel_members(files, snapshot["captured"], tag)
    _require(bool(mechanical) == _slot_supported(),
             "mechanical extension does not match this actual build profile")
    if mechanical:
        receipt = _json(files[_SLOT_RECEIPT])
        from hepta.hia_slot_mechanical import SOURCES, _profile
        _require(_encoded(receipt["profile"]) == _encoded(_profile())
                 and _encoded(receipt["sources"]) == _encoded({
                     name: _pin(snapshot["captured"][name]) for name in sorted(SOURCES)})
                 and receipt["product_qualification_claimed"] is False,
                 "mechanical receipt types or source identity differ")
        binary_name = "hepta/" + receipt["binary"]["name"]
        _require(binary_name in files and _encoded(receipt["binary"]) == _encoded({
            "name": binary_name[len("hepta/"):], **_pin(files[binary_name])}),
            "mechanical binary receipt has incorrect bytes or numeric types")
        _require(type(receipt["compiler_commands"]) is list
                 and receipt["compiler_commands"]
                 and all(type(argv) is list and argv
                         and all(type(arg) is str and arg for arg in argv)
                         for argv in receipt["compiler_commands"]),
                 "mechanical receipt lacks actual compiler commands")
        _require(type(receipt["compiler_executables"]) is dict
                 and receipt["compiler_executables"], "mechanical compiler identities missing")
        for name, pin in receipt["compiler_executables"].items():
            executable = Path(name)
            _require(executable.is_absolute() and str(executable.resolve(strict=True)) == name,
                     "mechanical compiler path changed")
            actual = _pin(_read(executable.parent, executable.name))
            _require(_encoded(pin) == _encoded({"path": name, **actual}),
                     "mechanical compiler bytes or exact numeric types differ")
    expected = snapshot["expected"]
    for member, source in expected.items():
        _require(files.get(member) == snapshot["captured"][source],
                 "packaged source differs or is absent: " + member)
        wanted_exec = (not member.startswith("hepta/_data/")
                       and snapshot["custody"]["packaging_inputs"][source]["git_mode"] == "100755")
        _require(modes[member] is wanted_exec, "packaged source executable mode differs: " + member)
    generated = {prefix + name for name in ("METADATA", "WHEEL", "top_level.txt", "RECORD")}
    _require(files.get(prefix + "top_level.txt") == b"hepta\n", "unexpected installed package domain")
    for name in snapshot["licenses"]:
        for member in (prefix + name, prefix + "licenses/" + name):
            if member in files:
                _require(files[member] == snapshot["captured"][name], "license bytes differ")
                generated.add(member)
    _require(set(files) == set(expected) | mechanical | generated,
             "wheel contains an unknown or missing member")
    _require(wheel.get_all("Root-Is-Purelib") == [str(not bool(mechanical)).lower()],
             "wheel purelib profile differs")
    return files, modes, record


def _build(source, snapshot):
    work = Path(tempfile.mkdtemp(prefix="hia-component-wheel-")).resolve()
    work.chmod(0o700)
    stage, output = work / "source", work / "wheel"
    stage.mkdir(mode=0o700)
    output.mkdir(mode=0o700)
    for name, raw in snapshot["captured"].items():
        path = stage / name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(raw)
        path.chmod(0o755 if snapshot["custody"]["packaging_inputs"][name]["git_mode"] == "100755" else 0o644)
    environment = {name: value for name, value in os.environ.items()
                   if name not in ("PYTHONPATH", "PYTHONHOME")
                   and not name.startswith("HEPTA_HIA_")}
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    command = [sys.executable, "-B", "-c",
               "from setuptools.build_meta import build_wheel; import sys; print(build_wheel(sys.argv[1]))",
               str(output)]
    (work / "intent.json").write_bytes(_encoded({
        "scope": SCOPE, "source_head": snapshot["custody"]["source_head"],
        "command": command, "timeout_seconds": 60,
        "native_cold_qualified": False, "whole_native_delivery_qualified": False}))
    try:
        result = subprocess.run(command, cwd=stage, env=environment, capture_output=True, timeout=60)
    except subprocess.TimeoutExpired as exc:
        (work / "build.stdout").write_bytes(exc.stdout or b"")
        (work / "build.stderr").write_bytes(exc.stderr or b"")
        (work / "result.json").write_bytes(_encoded({"terminal": "timeout", "passed": False}))
        raise ValueError("component wheel: actual setuptools build exceeded original 60s budget: " + str(work)) from exc
    (work / "build.stdout").write_bytes(result.stdout)
    (work / "build.stderr").write_bytes(result.stderr)
    (work / "result.json").write_bytes(_encoded({"returncode": result.returncode,
        "setuptools_process_succeeded": result.returncode == 0,
        "component_install_verified": False, "whole_native_delivery_qualified": False}))
    _require(result.returncode == 0, "actual setuptools build failed; evidence: " + str(work))
    wheels = list(output.glob("*.whl"))
    _require(len(wheels) == 1, "actual build did not create exactly one wheel")
    path = wheels[0]
    raw = _read(output, path.name)
    files, modes, record = _checked_wheel(path, raw, snapshot)
    for name, original in snapshot["captured"].items():
        _require(_read(stage, name) == original, "backend changed a captured input")
    _staged_inputs(source, snapshot)
    _verify_snapshot(snapshot)
    custody = {**snapshot["custody"], "wheel": {"name": path.name, **_pin(raw)},
               "wheel_members": {name: {**_pin(data), "executable": modes[name]}
                                 for name, data in sorted(files.items())}}
    custody_raw = _encoded(custody)
    receipt_path = work / "custody.json"
    receipt_path.write_bytes(custody_raw)
    receipt_path.chmod(0o400)
    path.chmod(0o400)
    _built[str(path)] = {"snapshot": snapshot, "wheel_bytes": raw, "files": files,
                        "modes": modes, "record": record,
                        "custody_path": receipt_path, "custody_bytes": custody_raw}
    return path


def component_wheel(source):
    """Build the actual source-owned package for an explicit component test."""
    with _lock:
        staging = Path(source).absolute()
        _require(not staging.is_symlink(), "partial staging root is redirected")
        staging = staging.resolve(strict=True)
        additional = () if staging == ROOT else tuple(sorted(_inventory(staging)))
        snapshot = _snapshot(ROOT, additional)
        _staged_inputs(source, snapshot)
        key = sha256(_encoded(snapshot["custody"]) + sys.executable.encode()
                     + sys.version.encode()).hexdigest()
        if key not in _cache:
            _cache[key] = _build(source, snapshot)
        path = _cache[key]
        item = _built[str(path)]
        _require(_read(path.parent, path.name) == item["wheel_bytes"],
                 "the previously built component wheel changed")
        _require(_read(item["custody_path"].parent, item["custody_path"].name)
                 == item["custody_bytes"], "the built component custody changed")
        _checked_wheel(path, item["wheel_bytes"], snapshot)
        return path


def _installed_files(installed):
    installed = Path(installed).absolute()
    _require(not installed.is_symlink(), "installed root is redirected")
    root = installed.resolve(strict=True)
    files = {name: _read(root, name) for name in sorted(_inventory(root))}
    modes = {name: bool((root / name).lstat().st_mode & stat.S_IXUSR) for name in files}
    return root, files, modes


def _verify_installed(files, modes, item, installed_from):
    record = item["record"]
    original = item["files"]
    prefix = record[:-len("RECORD")]
    extras = {prefix + name for name in ("INSTALLER", "REQUESTED", "direct_url.json")}
    _require(set(files) == set(original) | extras,
             "installed physical files differ from complete wheel and pip metadata")
    for name, data in original.items():
        if name != record:
            _require(files[name] == data and modes[name] is item["modes"][name],
                     "installed bytes or executable mode differ: " + name)
    _require(files[prefix + "INSTALLER"] == b"pip\n"
             and files[prefix + "REQUESTED"] == b"", "unexpected actual pip install metadata")
    direct = _json(files[prefix + "direct_url.json"])
    _require(type(direct) is dict and set(direct) == {"url", "archive_info"}
             and direct["url"] == Path(installed_from).resolve(strict=True).as_uri(),
             "installed direct URL differs from the actual copied wheel")
    info = direct["archive_info"]
    digest = sha256(item["wheel_bytes"]).hexdigest()
    _require(type(info) is dict and set(info) in ({"hashes"}, {"hash", "hashes"})
             and info.get("hashes") == {"sha256": digest}
             and ("hash" not in info or info["hash"] == "sha256=" + digest),
             "installed archive identity differs from actual wheel bytes")
    _require(not any(modes[name] for name in extras | {record}),
             "installed metadata unexpectedly executable")
    _record(files, record)


def verify_component_install(component, installed, *, installed_from):
    """Read the real built wheel, pip copy, every installed member and RECORD."""
    path = Path(component).absolute()
    with _lock:
        _require(str(path) in _built, "no actual component build custody exists for this wheel")
        item = _built[str(path)]
        _require(_read(path.parent, path.name) == item["wheel_bytes"],
                 "original component wheel changed")
        copied = Path(installed_from).absolute()
        _require(copied.name == path.name
                 and _read(copied.parent, copied.name) == item["wheel_bytes"],
                 "pip wheel copy differs from original component bytes")
        _require(_read(item["custody_path"].parent, item["custody_path"].name)
                 == item["custody_bytes"], "component custody sidecar changed")
        _verify_snapshot(item["snapshot"])
        _checked_wheel(path, item["wheel_bytes"], item["snapshot"])
        root, files, modes = _installed_files(installed)
        _verify_installed(files, modes, item, copied)
        for name, raw in files.items():
            _require(_regular_bytes(root, name, raw) is modes[name],
                     "installed executable mode changed during readback: " + name)
        _require(_inventory(root) == set(files), "installed membership changed during readback")
        _require(_read(path.parent, path.name) == item["wheel_bytes"]
                 and _read(copied.parent, copied.name) == item["wheel_bytes"],
                 "wheel changed during installed readback")
        _verify_snapshot(item["snapshot"])
        return {"schema": SCHEMA, "scope": SCOPE, "source_head": item["snapshot"]["custody"]["source_head"],
                "wheel_sha256": sha256(item["wheel_bytes"]).hexdigest(),
                "native_authority_input_count": len(item["snapshot"]["custody"]["native_authority"]),
                "packaging_input_count": len(item["snapshot"]["captured"]),
                "installed_file_count": len(files), "component_install_verified": True,
                "native_cold_qualified": False, "whole_native_delivery_qualified": False}
