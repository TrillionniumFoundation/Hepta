"""Create pure-DATA v6 administrator input from explicitly pinned build receipts.

No extension or HIA image is loaded. The operator must independently verify the
complete output digest before passing it to the existing worker scope option.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import stat

SCHEMA = "hepta.hia.native-helpers.v6"
ABI = "hia-worker-native-carriers-v1"
BRIDGES = {'cell-frame': ('HEPTA_HIA_SERVICE_VERIFICATION_MANIFEST',
                'hepta.cell-frame.real-cells.v1',
                'hepta.cell-frame.build.v1',
                '_cell_frame_build.json',
                '_hia_cell_frame',
                ('hepta/native/cell_frame.c',
                 'hepta/native/native_carrier_build.py',
                 'hepta/hia_cell_frame.py',
                 'hepta/hia_native_helpers.py',
                 'hepta/hia_native_carrier_worker_bundle.py',
                 'hepta/hia_service_verification_native.py')),
 'native-image': ('HEPTA_HIA_SERVICE_ARTIFACT_MANIFEST',
                  'hepta.native-image.three-writable-buffers.v1',
                  'hepta.native-image.build.v1',
                  '_native_image_build.json',
                  '_hia_native_image',
                  ('hepta/native/native_image.c',
                   'hepta/native/native_carrier_build.py',
                   'hepta/hia_native_image.py',
                   'hepta/hia_native_helpers.py',
                   'hepta/hia_native_carrier_worker_bundle.py',
                   'hepta/hia_service_artifact_native.py',
                   'hepta/hia_service_artifact_bridge.py')),
 'slot-mechanical': ('HEPTA_HIA_SLOT_OPERATIONS_MANIFEST',
                     'hepta.slot.mechanical.cpython-gil-linux.v1',
                     'hepta.slot.mechanical.build.v2',
                     '_slot_mechanical_build.json',
                     '_hia_slot_mechanical',
                     ('hepta/native/slot_mechanical.c',
                      'hepta/hia_slot_continuations.py',
                      'hepta/hia_slot_mechanical.py',
                      'hepta/hia_slot_operations_native.py',
                      'hepta/hia_slot_operations_selection.py',
                      'hepta/hia_slot_operations_protocol.py',
                      'hepta/hia_slot_operation_series.py',
                      'hepta/hia_native_delivery.py',
                      'hepta/hia_native_helpers.py',
                      'hepta/hia_mechanical_worker_bundle.py',
                      'hepta/native/slot_mechanical_build.py'))}

def pin(raw):
    return {"bytes": len(raw), "sha256": sha256(raw).hexdigest()}


def digest(value):
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def read(path, maximum):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        a = os.fstat(stream.fileno())
        if (not stat.S_ISREG(a.st_mode) or a.st_nlink != 1 or a.st_mode & 0o022
                or a.st_uid not in (0, os.getuid()) or not 0 < a.st_size <= maximum):
            raise ValueError("capsule input is not an owned bounded ordinary file")
        raw = stream.read(maximum + 1)
        b = os.fstat(stream.fileno())
    fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_uid", "st_size", "st_mtime_ns", "st_ctime_ns")
    if len(raw) != a.st_size or any(getattr(a, name) != getattr(b, name) for name in fields):
        raise ValueError("capsule input changed during capture")
    return raw


def decode(raw):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError("duplicate capsule field")
            result[key] = value
        return result
    def constant(value):
        raise ValueError("nonfinite capsule value")
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("ascii")



def create(package, base_path, expected_base, expected_receipts, output):
    package, base_path, output = Path(package), Path(base_path), Path(output)
    if (not digest(expected_base) or type(expected_receipts) is not dict
            or any(type(k) is not str or k not in BRIDGES or not digest(v)
                   for k, v in expected_receipts.items())):
        raise ValueError("explicit preexisting administrator input pins are required")
    if package != package.resolve(strict=True) or base_path != base_path.resolve(strict=True):
        raise ValueError("administrator input paths must be exact canonical paths")
    base = read(base_path, 65536)
    if sha256(base).hexdigest() != expected_base:
        raise ValueError("base bundle differs from the supplied digest")
    value = decode(base)
    if (type(value) is not dict or set(value) != {"schema", "target", "abi", "helpers"}
            or value["schema"] != "hepta.hia.native-helpers.v1"
            or value["target"] != "linux-x86_64-lp64" or value["abi"] != "hia-byte-six-argument-v1"
            or type(value["helpers"]) is not list or not value["helpers"]):
        raise ValueError("v6 requires one explicit original closed v1 helper bundle")
    selectors = []
    for row in value["helpers"]:
        if (type(row) is not dict or set(row) != {"selector", "manifest_path", "manifest_sha256"}
                or type(row["selector"]) is not str or row["selector"] in selectors
                or type(row["manifest_path"]) is not str or not row["manifest_path"]
                or not digest(row["manifest_sha256"])):
            raise ValueError("invalid original v1 helper declaration")
        selectors.append(row["selector"])
    required = sorted(name for name, spec in BRIDGES.items() if spec[0] in selectors)
    if (sorted(expected_receipts) != required
            or not ({"native-image", "cell-frame"} & expected_receipts.keys())):
        raise ValueError("receipt pins must exactly cover the selected v6 carrier owners")
    captures = [(base_path, base, 65536)]
    bridges = []
    for bridge_name in required:
        _selector, abi, schema, receipt_name, basename, sources = BRIDGES[bridge_name]
        receipt_path = package / receipt_name
        receipt = read(receipt_path, 8 << 20)
        if sha256(receipt).hexdigest() != expected_receipts[bridge_name]:
            raise ValueError("build receipt differs from the supplied digest")
        record = decode(receipt)
        if (type(record) is not dict or set(record) != {
                "schema", "abi", "profile", "binary", "sources", "compiler_commands",
                "compiler_executables", "build_scope", "product_qualification_claimed"}
                or record["schema"] != schema or record["abi"] != abi
                or record["build_scope"] != "CPYTHON_MECHANICAL_EXTENSION_ONLY"
                or record["product_qualification_claimed"] is not False
                or type(record["sources"]) is not dict or set(record["sources"]) != set(sources)
                or type(record["compiler_commands"]) is not list or not record["compiler_commands"]
                or any(type(row) is not list or not row or any(type(v) is not str for v in row)
                       for row in record["compiler_commands"])
                or type(record["compiler_executables"]) is not dict or not record["compiler_executables"]):
            raise ValueError("mechanical compile receipt schema or source closure differs")
        profile = record["profile"]
        if (type(profile) is not dict or set(profile) != {"implementation", "python", "platform",
                "machine", "soabi", "extension_suffix", "gil_disabled"}
                or profile["implementation"] != "cpython" or profile["platform"] != "linux"
                or profile["machine"] != "x86_64" or profile["gil_disabled"] is not False
                or type(profile["python"]) is not list or len(profile["python"]) != 3
                or any(type(v) is not int for v in profile["python"])
                or profile["python"][0] != 3 or not 11 <= profile["python"][1] <= 14
                or type(profile["soabi"]) is not str or not profile["soabi"]
                or type(profile["extension_suffix"]) is not str
                or not profile["extension_suffix"].startswith(".")
                or "/" in profile["extension_suffix"] or "\\" in profile["extension_suffix"]):
            raise ValueError("mechanical compile receipt profile differs")
        name = basename + profile["extension_suffix"]
        executable = read(package / name, 1 << 20)
        if canonical(record["binary"]) != canonical({"name": name, **pin(executable)}):
            raise ValueError("mechanical binary differs from the pinned receipt")
        captured = {}
        for source in sources:
            raw = read(package / source.removeprefix("hepta/"), 8 << 20)
            if canonical(record["sources"][source]) != canonical(pin(raw)):
                raise ValueError("mechanical source differs from the pinned receipt")
            captured[source] = raw
            captures.append((package / source.removeprefix("hepta/"), raw, 8 << 20))
        captures.extend(((receipt_path, receipt, 8 << 20), (package / name, executable, 1 << 20)))
        bridges.append({"name": bridge_name, "abi": abi, "package_path": str(package), "profile": profile,
            "build_receipt": {"path": str(receipt_path), **pin(receipt)},
            "binary": {"name": name, "path": str(package / name), **pin(executable)},
            "sources": {source: {"path": str(package / source.removeprefix("hepta/")), **pin(raw)}
                        for source, raw in sorted(captured.items())}})
    capsule = {"schema": SCHEMA, "target": "linux-x86_64-lp64", "abi": ABI,
               "helpers_bundle": str(base_path), "helpers_bundle_sha256": expected_base, "bridges": bridges}
    raw = canonical(capsule) + b"\n"
    if len(raw) > 65536:
        raise ValueError("mechanical capsule exceeds the unchanged bundle limit")
    if any(read(path, limit) != captured for path, captured, limit in captures):
        raise ValueError("mechanical capsule inputs changed before output")
    with output.open("xb") as stream:
        stream.write(raw)
    if read(output, 65536) != raw:
        raise ValueError("mechanical capsule output changed")
    return {"path": str(output.resolve()), **pin(raw), "authority": "OPERATOR_MUST_PIN_THIS_DIGEST",
            "product_qualification_claimed": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--helpers-bundle", type=Path, required=True)
    parser.add_argument("--expected-helpers-sha256", required=True)
    for name in BRIDGES:
        parser.add_argument("--" + name + "-receipt-sha256")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    receipts = {name: getattr(args, name.replace("-", "_") + "_receipt_sha256") for name in BRIDGES}
    receipts = {name: value for name, value in receipts.items() if value is not None}
    result = create(args.package.resolve(strict=True), args.helpers_bundle.resolve(strict=True),
                    args.expected_helpers_sha256, receipts, args.output)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
