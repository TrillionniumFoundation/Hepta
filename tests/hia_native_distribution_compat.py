"""Captured compatibility wheels for retained installed Python API controls.

The production native release remains the separately qualified native tar.
This fixture invokes the existing development setup hook explicitly. It never
uses the ordinary native wheel backend or grants its release provenance.
"""
from __future__ import annotations
import ast
import atexit
import base64
import csv
from email.parser import BytesParser
from hashlib import sha256
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
from tempfile import TemporaryDirectory, mkdtemp
from threading import Lock
import tomllib
import zipfile

SCOPE = "RETAINED_PYTHON_API_COMPATIBILITY_WHEEL"
SOURCE = "tests/hia_native_distribution_compat.py"
FIXTURE = "tests/hia_distribution_fixture.py"
HOSTED_INVENTORY = 'tests/fixtures/hia_installed_compatibility_source_inventory_v1.json'
HOSTED_INVENTORY_PIN = {'bytes': 160750, 'sha256': '27d67d1600c1e0507cf749df65332d102b2126987008c6f2054cf9d3c7f86158'}
SETUP_PIN = {"bytes": 6500, "sha256": "26fed560e8d03b7f2e93693ae3fec05e0f7eb485feabf1b6b9a69df1ecc1b0d5"}
PROJECT_PIN = {"bytes": 403, "sha256": "9119869ebe8102e3eca929fa876a62043e4dc7b6a70d59cd67da7cab83fcdc7d"}
MECHANICAL_PIN = {"bytes": 6975, "sha256": "f773008d5e3e4f3a7f9bd3922b1243a9d54359ccbdb80a70e3325c719418b87d"}
MECHANICAL = "hepta/native/slot_mechanical_build.py"
_cache = {}
_lock = Lock()


def pin(raw):
    return {"bytes": len(raw), "sha256": sha256(raw).hexdigest()}


def regular(path):
    path = Path(path).absolute()
    if path.resolve(strict=True) != path:
        raise ValueError("compatibility source must not traverse symlinks: " + str(path))
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise ValueError("compatibility source requires one regular file: " + str(path))
    raw = path.read_bytes()
    after = path.lstat()
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode", "st_nlink")
    if len(raw) != before.st_size or any(getattr(before, k) != getattr(after, k) for k in fields):
        raise ValueError("compatibility source changed while being captured: " + str(path))
    return raw


def source_names(root, native, hosted):
    authority_raw = regular(Path(root) / HOSTED_INVENTORY)
    if pin(authority_raw) != HOSTED_INVENTORY_PIN:
        raise ValueError("fixed complete hosted compatibility inventory differs")
    authority = json.loads(authority_raw)
    if (authority["schema"] != "hepta.hia.retained-python-compatibility-source-inventory.v1"
            or authority["native_qualification_claimed"] is not False
            or sorted(hosted["source_identity"]["files"]) != authority["files"]):
        raise ValueError("complete hosted compatibility source inventory differs")
    names = set(native["source_identity"]["files"]) | set(hosted["source_identity"]["files"])
    from tools.hia_selfhost_contract import CONTRACT_PATH
    names.update((CONTRACT_PATH, SOURCE, FIXTURE, HOSTED_INVENTORY))
    # The executed reader bytes must match this root's captured copies.
    # Identical readers may serve a complete foreign root; all data reads use root.
    names.update(("tools/hia_release_contract.py", "tools/hia_selfhost_contract.py",
                  "tools/hia_native_worker_source_authority.py",
                  "tools/generate_hia_source_release_cold_admit.py"))
    for name in names:
        p = PurePosixPath(name)
        if p.is_absolute() or str(p) != name or any(v in ("", ".", "..") for v in p.parts):
            raise ValueError("invalid compatibility source member")
    return names


def capture_sources(root):
    from tools.hia_release_contract import source_domain, validate_release_contract
    from tools.hia_selfhost_contract import CONTRACT_PATH, support_contract
    root = Path(root).absolute()
    if root.resolve(strict=True) != root:
        raise ValueError("compatibility root must not traverse symlinks")
    declared_raw = regular(root / CONTRACT_PATH)
    native = validate_release_contract(root)
    if source_domain(native) != "native":
        raise ValueError("compatibility fixture requires the declared native release domain")
    hosted = support_contract(root)
    names = source_names(root, native, hosted)
    captured = {name: regular(root / name) for name in sorted(names)}
    if captured[CONTRACT_PATH] != declared_raw:
        raise ValueError("native contract changed during compatibility capture")
    for domain in (native, hosted):
        if any(sha256(captured[name]).hexdigest() != digest
               for name, digest in domain["source_identity"]["files"].items()):
            raise ValueError("compatibility inputs differ from their complete source domain")
    if (pin(captured["setup.py"]) != SETUP_PIN or pin(captured["pyproject.toml"]) != PROJECT_PIN
            or pin(captured[MECHANICAL]) != MECHANICAL_PIN):
        raise ValueError("compatibility packaging implementation changed")
    from tools.generate_hia_source_release_cold_admit import native_authority_contract
    from tools.hia_native_worker_source_authority import load_native_source_authority
    loaded = {SOURCE: Path(__file__), "tools/hia_release_contract.py": Path(validate_release_contract.__code__.co_filename),
              "tools/hia_selfhost_contract.py": Path(support_contract.__code__.co_filename),
              "tools/generate_hia_source_release_cold_admit.py": Path(native_authority_contract.__code__.co_filename),
              "tools/hia_native_worker_source_authority.py": Path(load_native_source_authority.__code__.co_filename)}
    if any(regular(path) != captured[name] for name, path in loaded.items()):
        raise ValueError("compatibility reader differs from the captured source root")
    snapshot = {"root": root, "native": native, "hosted": hosted, "raw": captured,
                "pins": {name: pin(raw) for name, raw in captured.items()}, "loaded": loaded}
    terminal_sources(snapshot)
    return snapshot


def terminal_sources(snapshot, stage=None):
    from tools.hia_release_contract import validate_release_contract
    from tools.hia_selfhost_contract import support_contract
    root, captured = snapshot["root"], snapshot["raw"]
    for name, raw in captured.items():
        if regular(root / name) != raw or (stage is not None and regular(stage / name) != raw):
            raise ValueError("compatibility source changed at terminal readback: " + name)
    if any(regular(path) != captured[name] for name, path in snapshot["loaded"].items()):
        raise ValueError("loaded compatibility reader changed")
    native, hosted = validate_release_contract(root), support_contract(root)
    if native != snapshot["native"] or hosted != snapshot["hosted"]:
        raise ValueError("compatibility source domain changed at terminal readback")
    if source_names(root, native, hosted) != set(captured):
        raise ValueError("compatibility complete source inventory changed")
    if stage is not None:
        if validate_release_contract(stage) != native or support_contract(stage) != hosted:
            raise ValueError("staged compatibility source closure differs")


def compatibility_sources(root):
    snapshot = capture_sources(root)
    return {name: item["sha256"] for name, item in snapshot["pins"].items()}


def literal(raw, symbol):
    rows = [node.value for node in ast.parse(raw).body if isinstance(node, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == symbol for t in node.targets)]
    if len(rows) != 1:
        raise ValueError("compatibility resource has no unique literal: " + symbol)
    value = ast.literal_eval(rows[0])
    if type(value) is not tuple or any(type(v) is not str or not v for v in value):
        raise ValueError("compatibility resource literal differs: " + symbol)
    return value


def copied_members(snapshot):
    raw = snapshot["raw"]
    agent = raw["hepta/hia_agent_contract.py"]
    symbols = ("NATIVE_SOURCE_FILES", "SOURCE_BUILD_FILES", "COMPILER_BUILD_FILES",
               "PUBLICATION_BUILD_FILES", "BACKEND_BUILD_FILES", "EMITTER_BUILD_FILES",
               "BYTE_WRAPPER_BUILD_FILES", "MACHINE_OBJECT_BUILD_FILES",
               "EXECUTION_OBSERVATION_BUILD_FILES", "CONTINUATION_BUILD_FILES")
    resources = tuple("docs/" + n for n in literal(agent, "DISCOVERY_FILES"))
    resources += tuple(n for symbol in symbols for n in literal(agent, symbol))
    resources += literal(raw["hepta/hia_executable_capture.py"], "PACKAGE_RESOURCES")
    resources += literal(raw["hepta/hia_nominal_program_native.py"], "PACKAGE_RESOURCES")
    resources += tuple(n for symbol in ("VM_INTEGER_DIVREM_RESOURCES", "VM_INTEGER_ARITHMETIC_RESOURCES",
                                       "VM_INTEGER_SCALAR_RESOURCES", "NOMINAL_BYTE_BOUNDARY_RESOURCES")
                       for n in literal(raw["setup.py"], symbol))
    if len(resources) != len(set(resources)):
        raise ValueError("compatibility package resource inventory has duplicates")
    members = {name: value for name, value in raw.items()
               if name.startswith("hepta/") and name.count("/") == 1 and name.endswith(".py")}
    members.update({"hepta/_data/" + name: raw[name] for name in resources})
    members.update({name: raw[name] for name in ("hepta/native/slot_mechanical.c", MECHANICAL)})
    return members


def check_wheel(path, snapshot, profile, mechanical_outputs):
    path = Path(path)
    wheel_raw = regular(path)
    copied = copied_members(snapshot)
    project = tomllib.loads(snapshot["raw"]["pyproject.toml"].decode())["project"]
    for role in ("binary", "receipt"):
        if regular(mechanical_outputs[role]["path"]) != mechanical_outputs[role]["raw"]:
            raise ValueError("actual compatibility build output changed")
    distribution = project["name"].replace("-", "_") + "-" + project["version"] + ".dist-info"
    metadata = {distribution + "/" + name for name in ("METADATA", "WHEEL", "top_level.txt", "RECORD")}
    binary = "hepta/_hia_slot_mechanical" + profile["extension_suffix"]
    mechanical = "hepta/_slot_mechanical_build.json"
    expected = set(copied) | metadata | {binary, mechanical}
    tag = ("cp" + "".join(str(v) for v in profile["python"][:2]) + "-cp"
           + profile["soabi"].split("-")[1] + "-linux_x86_64")
    expected_name = project["name"].replace("-", "_") + "-" + project["version"] + "-" + tag + ".whl"
    if path.name != expected_name:
        raise ValueError("compatibility wheel ABI filename differs")
    with zipfile.ZipFile(io.BytesIO(wheel_raw)) as archive:
        rows = archive.infolist()
        names = [row.filename for row in rows]
        if len(names) != len(set(names)) or set(names) != expected:
            raise ValueError("compatibility wheel member set differs: " + repr(
                {"missing": sorted(expected - set(names)), "extra": sorted(set(names) - expected)}))
        if any(row.is_dir() or stat.S_ISLNK(row.external_attr >> 16) for row in rows):
            raise ValueError("compatibility wheel requires regular members")
        files = {name: archive.read(name) for name in names}
    for name, raw in copied.items():
        if files[name] != raw:
            raise ValueError("compatibility wheel changed captured source: " + name)
    record_name = distribution + "/RECORD"
    record_rows = list(csv.reader(io.StringIO(files[record_name].decode("utf-8"))))
    if any(len(row) != 3 for row in record_rows):
        raise ValueError("compatibility RECORD row shape differs")
    if len(record_rows) != len(expected) or len({row[0] for row in record_rows}) != len(expected):
        raise ValueError("compatibility RECORD member inventory differs")
    for name, digest, size in record_rows:
        if name not in files:
            raise ValueError("compatibility RECORD contains a foreign member")
        if name == record_name:
            if digest or size:
                raise ValueError("compatibility RECORD self row differs")
        else:
            wanted = "sha256=" + base64.urlsafe_b64encode(sha256(files[name]).digest()).rstrip(b"=").decode()
            if digest != wanted or size != str(len(files[name])):
                raise ValueError("compatibility RECORD identity differs: " + name)
    meta = BytesParser().parsebytes(files[distribution + "/METADATA"])
    wheel = BytesParser().parsebytes(files[distribution + "/WHEEL"])
    if (meta.get_all("Name") != [project["name"]] or meta.get_all("Version") != [project["version"]]
            or wheel.get_all("Wheel-Version") != ["1.0"] or wheel.get_all("Root-Is-Purelib") != ["false"]
            or files[distribution + "/top_level.txt"] != b"hepta\n"):
        raise ValueError("compatibility package metadata differs")
    if (wheel.get_all("Tag") != [tag] or files[binary] != mechanical_outputs["binary"]["raw"]
            or files[mechanical] != mechanical_outputs["receipt"]["raw"]):
        raise ValueError("wheel differs from the actual isolated mechanical build")
    def pairs(rows):
        value = {}
        for key, item in rows:
            if key in value:
                raise ValueError("duplicate mechanical receipt field")
            value[key] = item
        return value
    build = json.loads(files[mechanical], object_pairs_hook=pairs)
    mechanical_sources = literal(snapshot["raw"][MECHANICAL], "SOURCES")
    if (build.get("schema") != "hepta.slot.mechanical.build.v2"
            or build.get("abi") != "hepta.slot.mechanical.cpython-gil-linux.v1"
            or build.get("build_scope") != "CPYTHON_MECHANICAL_EXTENSION_ONLY"
            or build.get("product_qualification_claimed") is not False
            or build.get("profile") != profile
            or build.get("binary") != {"name": Path(binary).name, **pin(files[binary])}
            or not files[binary].startswith(b"\x7fELF")
            or build.get("sources") != {name: snapshot["pins"][name] for name in mechanical_sources}
            or not build.get("compiler_commands") or not build.get("compiler_executables")):
        raise ValueError("compatibility mechanical build receipt differs")
    for name, record in build["compiler_executables"].items():
        if record != {"path": name, **pin(regular(Path(name)))}:
            raise ValueError("compatibility mechanical compiler changed")
    if regular(path) != wheel_raw:
        raise ValueError("compatibility wheel changed during verification")
    return {"wheel": pin(wheel_raw), "members": {name: pin(raw) for name, raw in files.items()},
            "copied_members": sorted(copied), "mechanical_build": build,
            "complete_record_verified": True, "complete_member_set_verified": True}


PROFILE_CHILD = """import json,platform,sys,sysconfig
if sys.flags.optimize or not sys.flags.isolated or sysconfig.get_config_var('SIZEOF_VOID_P') != 8:
    raise ValueError('compatibility interpreter must be unoptimized isolated LP64')
print(json.dumps({'implementation':sys.implementation.name,'python':list(sys.version_info[:3]),
'platform':sys.platform,'machine':platform.machine(),'soabi':sysconfig.get_config_var('SOABI'),
'extension_suffix':sysconfig.get_config_var('EXT_SUFFIX'),
'gil_disabled':bool(sysconfig.get_config_var('Py_GIL_DISABLED'))}))
"""
BUILD_CHILD = """import sys
if sys.flags.optimize or not sys.flags.isolated:
    raise ValueError('compatibility build must be unoptimized and isolated')
from setuptools.build_meta import build_wheel
print(build_wheel(sys.argv[1]))
"""


def compatibility_wheel(root, requested_source, python):
    if any(key in os.environ for key in ("HEPTA_HIA_TEST_DISTRIBUTION_WHEEL", "HEPTA_HIA_TEST_DISTRIBUTION_SHA256")):
        raise ValueError("ordinary native wheel provenance cannot select a compatibility fixture")
    snapshot = capture_sources(root)
    requested = Path(requested_source).absolute()
    if requested.resolve(strict=True) != requested:
        raise ValueError("compatibility caller source must not traverse symlinks")
    for name, raw in snapshot["raw"].items():
        p = requested / name
        if (p.exists() or p.is_symlink()) and regular(p) != raw:
            raise ValueError("compatibility caller staged different source: " + name)
    for p in (requested / "hepta").rglob("*.py"):
        if p.relative_to(requested).as_posix() not in snapshot["raw"]:
            raise ValueError("compatibility caller has an undeclared Python source")
    executable = Path(shutil.which(str(python)) or python).resolve(strict=True)
    interpreter = regular(executable)
    identity = sha256(json.dumps(snapshot["pins"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    key = (str(snapshot["root"]), str(executable), sha256(interpreter).hexdigest(), identity)
    environment = {k: v for k, v in os.environ.items() if not k.startswith(("PYTHON", "HEPTA_HIA_"))}
    with _lock:
        if key in _cache:
            path, expected, profile, receipt, receipt_raw, mechanical_outputs = _cache[key]
            if regular(receipt) != receipt_raw or pin(regular(path)) != expected:
                raise ValueError("verified compatibility fixture changed")
            check_wheel(path, snapshot, profile, mechanical_outputs)
            terminal_sources(snapshot)
            return path
        profile_run = subprocess.run([str(executable), "-I", "-B", "-c", PROFILE_CHILD],
                                     env=environment, capture_output=True, timeout=30)
        if profile_run.returncode or profile_run.stderr:
            raise RuntimeError("compatibility interpreter profile did not complete")
        profile = json.loads(profile_run.stdout)
        if (profile["implementation"] != "cpython" or profile["platform"] != "linux"
                or profile["machine"] != "x86_64" or profile["gil_disabled"] is not False
                or not (3, 11) <= tuple(profile["python"][:2]) <= (3, 14)
                or type(profile["extension_suffix"]) is not str):
            raise ValueError("compatibility fixture requires the retained mechanical ABI")
        evidence = os.environ.get("HEPTA_HIA_TEST_COMPATIBILITY_EVIDENCE_DIRECTORY")
        if evidence is None:
            owner = TemporaryDirectory(prefix="hia-compatibility-wheel-")
            atexit.register(owner.cleanup)
            work = Path(owner.name)
        else:
            parent = Path(evidence).absolute()
            parent.mkdir(parents=True, exist_ok=True)
            if parent.resolve(strict=True) != parent:
                raise ValueError("compatibility evidence root must not traverse symlinks")
            work = Path(mkdtemp(prefix="wheel-", dir=parent))
        stage, wheels = work / "source", work / "wheels"
        stage.mkdir(); wheels.mkdir()
        for name, raw in snapshot["raw"].items():
            destination = stage / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(raw)
        terminal_sources(snapshot, stage)
        argv = [str(executable), "-I", "-B", "-c", BUILD_CHILD, str(wheels)]
        with (work / "build.stdout").open("xb") as out, (work / "build.stderr").open("xb") as err:
            done = subprocess.run(argv, cwd=stage, env=environment, stdout=out, stderr=err, timeout=120)
        if done.returncode:
            raise RuntimeError("explicit compatibility setup build failed: " + (work / "build.stderr").read_text()[-6000:])
        path, = wheels.glob("*.whl")
        binary_name = "_hia_slot_mechanical" + profile["extension_suffix"]
        binaries = list((stage / "build").glob("lib.*/hepta/" + binary_name))
        if len(binaries) != 1:
            raise ValueError("compatibility build has no one physical mechanical output")
        binary_path = binaries[0]
        receipt_path = binary_path.parent / "_slot_mechanical_build.json"
        mechanical_outputs = {
            "binary": {"path": binary_path, "raw": regular(binary_path)},
            "receipt": {"path": receipt_path, "raw": regular(receipt_path)},
        }
        checked = check_wheel(path, snapshot, profile, mechanical_outputs)
        terminal_sources(snapshot, stage)
        if regular(executable) != interpreter:
            raise ValueError("compatibility interpreter changed during build")
        report = {"schema": "hepta.hia.installed-python-compatibility-fixture.v1", "scope": SCOPE,
                  "source_root": str(snapshot["root"]), "source_identity_sha256": identity,
                  "sources": snapshot["pins"], "native_contract": pin(snapshot["raw"]["docs/HIA_SELFHOST_CORE_SUPPORT.json"]),
                  "hosted_source_files": snapshot["hosted"]["source_identity"]["files"],
                  "native_source_files": snapshot["native"]["source_identity"]["files"],
                  "packaging_argv": argv, "packaging_returncode": done.returncode, "profile": profile,
                  "actual_mechanical_outputs": {role: {"path": str(item["path"]), **pin(item["raw"])}
                                               for role, item in mechanical_outputs.items()},
                  "python": {"path": str(executable), **pin(interpreter)}, "validation": checked,
                  "terminal_complete_source_inventory_unchanged": True, "terminal_sources_unchanged": True,
                  "ordinary_native_wheel_qualified": False, "native_tar_qualified": False,
                  "whole_native_delivery_qualified": False, "production_fallback": False}
        receipt = work / "compatibility.json"
        receipt_raw = (json.dumps(report, sort_keys=True, indent=2) + "\n").encode()
        receipt.write_bytes(receipt_raw)
        path.chmod(0o400); receipt.chmod(0o400)
        _cache[key] = (path, checked["wheel"], profile, receipt, receipt_raw, mechanical_outputs)
        return path
