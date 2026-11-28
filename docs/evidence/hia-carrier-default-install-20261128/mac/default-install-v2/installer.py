"""Install the explicit current HIA carriers into one target-bound Python wheel.

The native release supplies the two policy images and their HIACPUB1 record.
This host compatibility operation compiles only the closed CPython resource ABI,
checks its embedded HIA bytes against that publication, and runs real pip.
It does not claim that a C compiler or CPython is part of the pure HIA product.
"""
from __future__ import annotations

import argparse
import base64
import csv
from hashlib import sha256
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1]
if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))
PIN_RESOURCE = "hepta/_data/native/carriers/install-pin.json"
BUNDLE_RESOURCE = "hepta/_data/native/carriers/current.json"
MAX_WHEEL = 256 << 20
MAX_MEMBER = 16 << 20
_EXECUTED_SOURCE = Path(__file__).resolve().read_bytes()


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(value):
    return type(value) is str and re.fullmatch("[0-9a-f]{64}", value) is not None


def pin(raw):
    return {"bytes": len(raw), "sha256": sha256(raw).hexdigest()}


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False, allow_nan=False) + "\n").encode()


def record_digest(raw):
    return "sha256=" + base64.urlsafe_b64encode(sha256(raw).digest()).rstrip(b"=").decode()


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate installation data field")
            result[key] = value
        return result
    def nonfinite(_value):
        raise ValueError("nonfinite installation data")
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=nonfinite)


def capture(path, maximum, *, empty=False):
    path = Path(path)
    require(path == path.resolve(strict=True), "installation input must have a canonical path")
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        a = os.fstat(stream.fileno())
        require(stat.S_ISREG(a.st_mode) and a.st_nlink == 1
                and a.st_uid in (0, os.getuid()) and not a.st_mode & 0o022
                and (0 if empty else 1) <= a.st_size <= maximum,
                "installation input must be an owned bounded single ordinary file")
        raw = stream.read(maximum + 1)
        b = os.fstat(stream.fileno())
    fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_uid",
              "st_size", "st_mtime_ns", "st_ctime_ns")
    identity = tuple(getattr(a, name) for name in fields)
    require(len(raw) == a.st_size and identity == tuple(getattr(b, n) for n in fields)
            and identity == tuple(getattr(path.lstat(), n) for n in fields)
            and path == path.resolve(strict=True), "installation input changed during capture")
    return path, raw, identity, maximum, empty


def unchanged(item):
    require(capture(item[0], item[3], empty=item[4]) == item,
            "installation input changed after its initial capture")


def owned_directory(path):
    path = Path(path)
    require(path == path.resolve(strict=True), "installation directory must be canonical")
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
            and not info.st_mode & 0o022, "installation directory must be owner-controlled")
    return path


def member_name(name):
    require(type(name) is str and name and "\\" not in name and "\x00" not in name
            and not name.endswith("/") and not any(ord(c) < 32 for c in name),
            "wheel member must be an explicit ordinary path")
    parts = PurePosixPath(name)
    require(not parts.is_absolute() and ".." not in parts.parts and "." not in parts.parts
            and str(parts) == name, "wheel member traverses its installation")
    return parts


def wheel_members(raw):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_WHEEL, "wheel extent differs")
    members, modes = {}, {}
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        require(archive.testzip() is None, "wheel CRC differs")
        total = 0
        for item in archive.infolist():
            member_name(item.filename)
            mode = item.external_attr >> 16
            # wheel 0.46 writes the newly generated RECORD as 0664 regardless
            # of umask. It is data metadata, not an installed permission grant.
            # Admit only that exact standard case and extract it without any
            # group/world write bit; all other unsafe member modes still refuse.
            record_metadata = (re.fullmatch(r"hia_core-[^/]+\.dist-info/RECORD",
                                           item.filename) is not None
                               and stat.S_IMODE(mode) == 0o664)
            require(item.filename not in members and not item.flag_bits & 1
                    and stat.S_IFMT(mode) in (0, stat.S_IFREG)
                    and not mode & 0o7000 and (not mode & 0o022 or record_metadata)
                    and 0 <= item.file_size <= MAX_MEMBER,
                    "wheel has duplicate, special, unsafe or oversized members: " + item.filename)
            total += item.file_size
            require(total <= MAX_WHEEL, "wheel expanded extent differs")
            members[item.filename] = archive.read(item)
            modes[item.filename] = (mode & 0o755) or 0o600
    records = [n for n in members if re.fullmatch(r"hia_core-[^/]+\.dist-info/RECORD", n)]
    require(len(records) == 1, "wheel must contain one hia-core distribution RECORD")
    record = records[0]
    dist = record.rsplit("/", 1)[0]
    require(all(n.startswith("hepta/") or n.startswith(dist + "/") for n in members),
            "wheel contains an undeclared top-level package or data scheme")
    rows = {}
    for row in csv.reader(io.StringIO(members[record].decode("utf-8"))):
        require(len(row) == 3 and row[0] not in rows, "wheel RECORD is not unique")
        member_name(row[0])
        rows[row[0]] = row[1:]
    require(set(rows) == set(members) and rows[record] == ["", ""],
            "wheel RECORD does not exactly cover its members")
    for name, data in members.items():
        if name != record:
            require(rows[name] == [record_digest(data), str(len(data))],
                    "wheel member differs from RECORD: " + name)
    require(dist + "/WHEEL" in members and dist + "/METADATA" in members,
            "wheel distribution metadata is incomplete")
    require(PIN_RESOURCE not in members and BUNDLE_RESOURCE not in members
            and not any(n.startswith("hepta/_data/native/carriers/") for n in members),
            "a base wheel must not carry another target-bound installation")
    return members, modes, dist


def write_new(path, raw, mode=0o600):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    require(capture(path, max(len(raw), 1), empty=True)[1] == raw, "new installation data differs")


def rewrite_package_paths(value, old_package, new_package):
    """Only the known bridge path fields relocate; child/native records do not."""
    result = decode(canonical(value))
    require(type(result) is dict and type(result.get("bridges")) is list,
            "current capsule lacks explicit bridges")
    def move(path):
        require(type(path) is str, "bridge path is not text")
        relative = Path(path).relative_to(old_package)
        require(relative.parts and ".." not in relative.parts, "bridge leaves its package")
        return str(new_package / relative)
    for bridge in result["bridges"]:
        require(bridge["package_path"] == str(old_package), "bridge package source differs")
        bridge["package_path"] = str(new_package)
        for key in ("build_receipt", "binary"):
            bridge[key]["path"] = move(bridge[key]["path"])
        for entry in bridge["sources"].values():
            entry["path"] = move(entry["path"])
    return result


def make_wheel(members, modes, dist, target, capsule, receipts, profile):
    require(type(profile["python"]) is list and profile["python"][0] == 3
            and all(type(v) is int for v in profile["python"]), "wheel Python profile differs")
    python_tag = "cp" + "".join(str(v) for v in profile["python"][:2])
    tag = python_tag + "-" + python_tag + "-linux_x86_64"
    result = dict(members)
    result[BUNDLE_RESOURCE] = canonical(capsule)
    pin_data = {
        "schema": "hepta.hia.carrier-default-install.v1", "target": "linux-x86_64-lp64",
        "scope": "TARGET_BOUND_CPYTHON_COMPATIBILITY", "package_path": str(target / "hepta"),
        "bundle_resource": BUNDLE_RESOURCE[len("hepta/"):],
        "bundle_sha256": sha256(result[BUNDLE_RESOURCE]).hexdigest(),
        "policy_release_sha256": capsule["policy_release_sha256"], "receipts": receipts,
    }
    result[PIN_RESOURCE] = canonical(pin_data)
    result[dist + "/WHEEL"] = (
        "Wheel-Version: 1.0\nGenerator: hepta-current-carrier-installer\n"
        "Root-Is-Purelib: false\nTag: " + tag + "\n").encode()
    record = dist + "/RECORD"
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    for name, data in sorted(result.items()):
        if name != record:
            writer.writerow((name, record_digest(data), str(len(data))))
    writer.writerow((record, "", ""))
    result[record] = output.getvalue().encode()
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as wheel:
        for name, data in sorted(result.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | modes.get(name, 0o600)) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            wheel.writestr(info, data)
    name = dist[:-len(".dist-info")] + "-" + tag + ".whl"
    return name, archive.getvalue(), result, pin_data


def verify_installed(target, members, dist):
    """Read every installed file and every actual pip RECORD row independently."""
    target = owned_directory(target)
    actual = {}
    for path in target.rglob("*"):
        require(not path.is_symlink(), "installed target contains a symlink")
        if path.is_dir():
            owned_directory(path)
        else:
            actual[path.relative_to(target).as_posix()] = capture(path, MAX_MEMBER, empty=True)
    record = dist + "/RECORD"
    require(record in actual, "installed wheel RECORD is missing")
    rows = {}
    for row in csv.reader(io.StringIO(actual[record][1].decode("utf-8"))):
        require(len(row) == 3 and row[0] not in rows, "installed RECORD is not unique")
        member_name(row[0])
        rows[row[0]] = row[1:]
    require(set(rows) == set(actual) and rows[record] == ["", ""],
            "installed RECORD does not exactly cover the actual target")
    extras = set(actual) - set(members)
    require(extras <= {dist + "/INSTALLER", dist + "/REQUESTED", dist + "/direct_url.json"},
            "pip produced an unexpected installed member")
    require(set(members) <= set(actual), "an original wheel member is missing after pip")
    for name, item in actual.items():
        if name != record:
            require(rows[name] == [record_digest(item[1]), str(len(item[1]))],
                    "installed member differs from actual RECORD: " + name)
        if name in members and name != record:
            require(item[1] == members[name], "installed member differs from wheel: " + name)
    require(actual.get(dist + "/INSTALLER", (None, None))[1] == b"pip\n",
            "installed RECORD lacks the actual pip installer")
    for item in actual.values():
        unchanged(item)
    return actual


# Fresh interpreters load all product modules from the selected physical package.
# The first branch builds; the second performs full typed admission, not a data
# parser substitute. Both commands preserve their original finite wall budgets.
_STAGE_PROGRAM = r"""
import json, os, sys
from pathlib import Path
from hashlib import sha256
root=Path(sys.argv[2]); sys.path.insert(0,str(root))
if sys.argv[1]=='build':
 from hepta.native.native_carrier_build import build
 report=build(root/'hepta',Path(sys.argv[3]),sys.argv[4],
              cc=Path(sys.argv[5]),output=Path(sys.argv[6]))
 print(json.dumps(report,sort_keys=True))
elif sys.argv[1]=='admit':
 from hepta import hia_native_helpers as h
 from hepta.hia_current_carrier_worker_bundle import NativeCurrentCarrierWorkerBinding
 from hepta.hia_carrier_default import capture_default_bundle
 native=Path(sys.argv[5])
 explicit=sys.argv[3]!='DEFAULT'
 selected=(sys.argv[3],sys.argv[4]) if explicit else ()
 with h.native_helpers_scope(*selected) as binding:
  if type(binding) is not NativeCurrentCarrierWorkerBinding:
   raise ValueError('the installed default did not select current HIA carriers')
  observed={}
  for owner in (binding,*binding._ordinary):
   for snapshot,limit in owner.snapshots:
    path=snapshot.path
    if not path.is_relative_to(root/'hepta') and not path.is_relative_to(native):
     raise ValueError('typed runtime capture leaves the package/native installation: '+str(path))
    key=str(path)
    value={'bytes':len(snapshot.raw),'sha256':sha256(snapshot.raw).hexdigest()}
    if key in observed and observed[key]!=value:
     raise ValueError('typed runtime capture changed')
    observed[key]=value
  binding.check()
  if not explicit:
   captured=capture_default_bundle()
   if captured is None or captured[1]!=binding.sha256:
    raise ValueError('installed default input changed')
  print(json.dumps({'status':'PASS','default_selected':not explicit,
                    'schema':'hepta.hia.current-carrier-worker-bundle.v1',
                    'sha256':binding.sha256,'selections':binding.selections,
                    'physical_inputs':observed},sort_keys=True))
else: raise ValueError('unknown fixed installer phase')
"""


def install(*, wheel, expected_wheel_sha256, compiler, expected_compiler_sha256,
            cc, native_root, base_bundle, expected_base_sha256, policy_release,
            expected_publication_sha256, target, output):
    from tools.capture_hia_current_carrier_bundle import create, _selectors
    from hepta.hia_carrier_build_identity import SPECS
    from hepta.hia_carrier_policy_release import capture as capture_release

    require(sys.platform == "linux" and sys.implementation.name == "cpython",
            "carrier installation requires its explicit CPython/Linux host")
    for value in (expected_wheel_sha256, expected_compiler_sha256,
                  expected_base_sha256, expected_publication_sha256):
        require(digest(value), "all installation inputs require exact SHA256")
    wheel, compiler, cc, base_bundle, policy_release, target, output = map(
        Path, (wheel, compiler, cc, base_bundle, policy_release, target, output))
    native_root = owned_directory(native_root)
    owned_directory(target.parent)
    owned_directory(output.parent)
    require(target.is_absolute() and output.is_absolute() and target != output
            and not target.exists() and not target.is_symlink()
            and not output.exists() and not output.is_symlink(),
            "installation target and evidence directory must be fresh")
    require(base_bundle.is_relative_to(native_root) and policy_release.is_relative_to(native_root),
            "typed bundle/publication must belong to the native installation")
    initial = [capture(wheel, MAX_WHEEL), capture(compiler, MAX_MEMBER), capture(cc, MAX_MEMBER),
               capture(Path(__file__).resolve(), MAX_MEMBER)]
    require(initial[-1][1] == _EXECUTED_SOURCE, "executing installer source changed")
    require(pin(initial[0][1])["sha256"] == expected_wheel_sha256
            and pin(initial[1][1])["sha256"] == expected_compiler_sha256,
            "wheel or compiler identity differs")
    members, modes, dist = wheel_members(initial[0][1])
    required = {name for spec in SPECS.values() for name in spec["inputs"]
                if name.startswith("hepta/")}
    required |= {"hepta/hia_carrier_default.py", "hepta/hia_current_carrier_worker_bundle.py",
                 "hepta/hia_carrier_policy_release.py"}
    for name in sorted(required):
        source = capture(ROOT / name, MAX_MEMBER)
        initial.append(source)
        require(members.get(name) == source[1], "base wheel differs from current installer source: " + name)
    # Validate publication source/image custody before any compiler invocation.
    output.mkdir(mode=0o700)
    stage = output / "stage"
    stage.mkdir(mode=0o700)
    for name, raw in members.items():
        write_new(stage / name, raw, modes[name])
    report = {"schema": "hepta.hia.carrier-compatibility-install.v1", "status": "HOLD",
              "scope": "TARGET_BOUND_CPYTHON_COMPATIBILITY",
              "pure_hia_host_or_full_worker_qualification_claimed": False,
              "commands": [], "terminals": []}
    native_inputs = {}
    def native_read(path):
        item = capture(path, MAX_MEMBER)
        require(item[0].is_relative_to(native_root) or item[0].is_relative_to(stage / "hepta"),
                "native publication input leaves its physical installation")
        if item[0] in native_inputs:
            require(native_inputs[item[0]] == item, "native publication changed during capture")
        native_inputs[item[0]] = item
        return item[1]
    def stable():
        for item in (*initial, *native_inputs.values()):
            unchanged(item)
    def run(label, argv, timeout):
        stable()
        argv = list(map(str, argv))
        report["commands"].append(argv)
        write_new(output / (label + ".intent.json"),
                  canonical({"argv": argv, "timeout_seconds": timeout}))
        env = {k: v for k, v in os.environ.items() if not k.startswith("HEPTA_HIA_")}
        env.update(PYTHONDONTWRITEBYTECODE="1", PYTHONNOUSERSITE="1",
                   PIP_DISABLE_PIP_VERSION_CHECK="1", PIP_NO_INDEX="1", TMPDIR=str(output))
        start = time.monotonic()
        result = subprocess.run(argv, capture_output=True, env=env, cwd=output, timeout=timeout)
        write_new(output / (label + ".stdout"), result.stdout)
        write_new(output / (label + ".stderr"), result.stderr)
        terminal = {"name": label, "returncode": result.returncode,
                    "seconds": time.monotonic() - start,
                    "stdout": pin(result.stdout), "stderr": pin(result.stderr)}
        report["terminals"].append(terminal)
        write_new(output / (label + ".terminal.json"), canonical(terminal))
        stable()
        require(result.returncode == 0, "actual carrier installation phase failed: " + label)
        return result
    try:
        publication, _ = capture_release(policy_release, expected_publication_sha256,
                                         stage / "hepta", native_read)
        require(publication["seed"] == pin(initial[1][1]),
                "host compatibility compiler differs from native publication")
        selector_inputs = []
        selectors = _selectors(base_bundle, expected_base_sha256, selector_inputs)
        for path, raw, maximum in selector_inputs:
            item = capture(path, maximum)
            require(path.is_relative_to(native_root) and item[1] == raw,
                    "typed child leaves its native installation")
            native_inputs[path] = item
        build = run("build-closed-abi", [sys.executable, "-I", "-B", "-c", _STAGE_PROGRAM,
                                       "build", stage, compiler, expected_compiler_sha256,
                                       cc, output / "closed-abi"], 180)
        built = decode(build.stdout)
        require(built["status"] == "PASS"
                and built["default_native_or_worker_qualification_claimed"] is False,
                "closed ABI build did not return its original component result")
        receipts = {"native-image": built["receipts"]["image"]["sha256"],
                    "cell-frame": built["receipts"]["cell"]["sha256"]}
        if "HEPTA_HIA_SLOT_OPERATIONS_MANIFEST" in selectors:
            slot = capture(stage / "hepta/_slot_mechanical_build.json", MAX_MEMBER)
            receipts["slot-mechanical"] = sha256(slot[1]).hexdigest()
        capsule_path = output / "staged-current.json"
        captured = create(stage / "hepta", base_bundle, expected_base_sha256,
                          policy_release, expected_publication_sha256, receipts, capsule_path)
        # Admission uses the real typed graph before installing anything.
        admitted = run("admit-staged-typed-graph",
                       [sys.executable, "-I", "-B", "-c", _STAGE_PROGRAM, "admit", stage,
                        capsule_path, captured["sha256"], native_root], 60)
        staged_admission = decode(admitted.stdout)
        require(staged_admission["status"] == "PASS"
                and staged_admission["default_selected"] is False, "staged typed admission differs")
        for text in staged_admission["physical_inputs"]:
            path = Path(text)
            if path.is_relative_to(native_root):
                item = capture(path, MAX_MEMBER)
                require(pin(item[1]) == staged_admission["physical_inputs"][text],
                        "admitted native child changed before installation")
                native_inputs[path] = item
        capsule = rewrite_package_paths(decode(capture(capsule_path, 65536)[1]),
                                        stage / "hepta", target / "hepta")
        final_members = dict(members)
        for path in sorted((stage / "hepta").rglob("*")):
            require(not path.is_symlink(), "staged package contains a symlink")
            if path.is_file():
                name = path.relative_to(stage).as_posix()
                item = capture(path, MAX_MEMBER, empty=True)
                if name in members:
                    require(item[1] == members[name], "ABI build changed an original wheel member")
                final_members[name] = item[1]
        profile = decode(capture(stage / "hepta/_native_image_build.json", MAX_MEMBER)[1])["profile"]
        filename, raw, installed_members, pin_data = make_wheel(
            final_members, modes, dist, target, capsule, receipts, profile)
        final_wheel = output / filename
        write_new(final_wheel, raw)
        final_wheel_capture = capture(final_wheel, MAX_WHEEL)
        initial.append(final_wheel_capture)
        run("pip-install-target-wheel",
            [sys.executable, "-I", "-B", "-m", "pip", "install", "--no-index",
             "--no-deps", "--no-compile", "--target", target,
             "--report", output / "pip-install-report.json", final_wheel], 60)
        installed = verify_installed(target, installed_members, dist)
        observation = run("installed-default-admission",
                          [sys.executable, "-I", "-B", "-c", _STAGE_PROGRAM, "admit", target,
                           "DEFAULT", pin_data["bundle_sha256"], native_root], 60)
        selected = decode(observation.stdout)
        require(selected["status"] == "PASS" and selected["default_selected"] is True
                and selected["sha256"] == pin_data["bundle_sha256"],
                "installed package did not activate the exact current default")
        second = verify_installed(target, installed_members, dist)
        require(second == installed, "installed files changed across default execution")
        stable()
        report.update(status="PASS", wheel={"path": str(final_wheel), **pin(raw)},
                      original_wheel={"path": str(wheel), **pin(initial[0][1])},
                      target=str(target), native_root=str(native_root),
                      package_default=pin_data, installed_file_count=len(installed),
                      installed_files={name: pin(item[1]) for name, item in sorted(installed.items())},
                      staged_admission=staged_admission, default_admission=selected,
                      native_inputs={str(path): pin(item[1])
                                     for path, item in sorted(native_inputs.items())})
        return report
    finally:
        write_new(output / "result.json", canonical(report))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("wheel", "compiler", "cc", "native-root", "base-bundle",
                 "policy-release", "target", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("wheel", "compiler", "base", "publication"):
        parser.add_argument("--expected-" + name + "-sha256", required=True)
    args = parser.parse_args()
    os.umask(0o077)
    report = install(wheel=args.wheel, expected_wheel_sha256=args.expected_wheel_sha256,
                     compiler=args.compiler, expected_compiler_sha256=args.expected_compiler_sha256,
                     cc=args.cc, native_root=args.native_root, base_bundle=args.base_bundle,
                     expected_base_sha256=args.expected_base_sha256,
                     policy_release=args.policy_release,
                     expected_publication_sha256=args.expected_publication_sha256,
                     target=args.target, output=args.output)
    print(json.dumps({"status": report["status"], "target": report["target"],
                      "wheel": report["wheel"], "scope": report["scope"]}, sort_keys=True))


if __name__ == "__main__":
    main()
