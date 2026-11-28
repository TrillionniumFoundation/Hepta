"""Pure data and exact source/binary checks for the closed CPython HIA carriers.

This receipt does not qualify a default Worker or execute a foreign policy.
The HIA image is independently compiled and embedded without transformation.
"""
from __future__ import annotations
from hashlib import sha256
from pathlib import Path
from types import MappingProxyType
import json

SPECS = MappingProxyType({'image': {'abi': 'hepta.native-image.three-writable-buffers.v1', 'schema': 'hepta.native-image.build.v2', 'basename': '_hia_native_image', 'receipt': '_native_image_build.json', 'loader': 'hia_native_image', 'inputs': ('hepta/native/carrier_image_abi.c', 'hepta/native/carrier_image_dispatch.inc', 'hepta/native/native_carrier_build.py', 'hepta/hia_carrier_build_identity.py', 'hepta/hia_carrier_image_abi.json', 'examples/hia_bootstrap/carrier_image_policy.hepta', 'hepta/hia_native_image.py', 'hepta/hia_native_helpers.py', 'hepta/hia_native_carrier_worker_bundle.py', 'hepta/hia_service_artifact_native.py', 'hepta/hia_loaded_source.py', 'hepta/hia_service_artifact_bridge.py', 'hepta/hia_native_host_support.py'), 'generated': ('hepta/native/carrier_image_policy.flat', 'hepta/native/carrier_image_policy.inc')}, 'cell': {'abi': 'hepta.cell-frame.real-cells.v1', 'schema': 'hepta.cell-frame.build.v2', 'basename': '_hia_cell_frame', 'receipt': '_cell_frame_build.json', 'loader': 'hia_cell_frame', 'inputs': ('hepta/native/carrier_cell_abi.c', 'hepta/native/carrier_cell_dispatch.inc', 'hepta/native/native_carrier_build.py', 'hepta/hia_carrier_build_identity.py', 'hepta/hia_carrier_cell_abi.json', 'examples/hia_bootstrap/carrier_cell_policy.hepta', 'hepta/hia_cell_frame.py', 'hepta/hia_native_helpers.py', 'hepta/hia_native_carrier_worker_bundle.py', 'hepta/hia_service_verification_native.py', 'hepta/hia_loaded_source.py'), 'generated': ('hepta/native/carrier_cell_policy.flat', 'hepta/native/carrier_cell_policy.inc')}})

def pin(raw):
    return {"bytes": len(raw), "sha256": sha256(raw).hexdigest()}

def same(left, right):
    return json.dumps(left, sort_keys=True, separators=(",", ":"), allow_nan=False) == json.dumps(right, sort_keys=True, separators=(",", ":"), allow_nan=False)

def source_path(package, name):
    package = Path(package)
    if name.startswith("hepta/"):
        return package / name[len("hepta/"):]
    if name not in (SPECS["image"]["inputs"][5], SPECS["cell"]["inputs"][5]):
        raise ValueError("undeclared HIA carrier resource")
    source = package.parent / name
    if (package.parent / "pyproject.toml").is_file():
        return source
    return package / "_data" / name

def policy_header(kind, image):
    if kind not in SPECS or type(image) is not bytes or not 0 < len(image) <= 1048576:
        raise ValueError("HIA carrier policy image extent differs")
    return ("static const unsigned char hia_carrier_" + kind + "_policy[] = {\n" +
            "".join("  " + ",".join("0x%02x" % x for x in image[i:i+20]) + ",\n"
                    for i in range(0, len(image), 20)) + "};\n").encode("ascii")

def verify_policy(kind, record, sources, executable):
    spec = SPECS[kind]
    source = sources[spec["inputs"][5]]
    image = sources[spec["generated"][0]]
    header = sources[spec["generated"][1]]
    if (type(record) is not dict or set(record) != {
            "schema", "source", "image", "header", "compiler", "returncode",
            "stdout", "stderr", "abi"}
            or record["schema"] != "hepta.hia.carrier-policy-build.v1"
            or record["abi"] != spec["abi"]
            or type(record["returncode"]) is not int or record["returncode"] != 0
            or not same(record["source"], pin(source))
            or not same(record["image"], pin(image))
            or not same(record["stdout"], pin(image))
            or not same(record["stderr"], pin(b""))
            or not same(record["header"], pin(header))
            or type(record["compiler"]) is not dict
            or set(record["compiler"]) != {"bytes", "sha256"}
            or type(record["compiler"]["bytes"]) is not int
            or not 0 < record["compiler"]["bytes"] <= 16777216
            or type(record["compiler"]["sha256"]) is not str
            or len(record["compiler"]["sha256"]) != 64
            or any(c not in "0123456789abcdef" for c in record["compiler"]["sha256"])
            or header != policy_header(kind, image)
            or executable.count(image) != 1):
        raise ValueError("HIA carrier policy source/image/embedded byte custody differs")

from .hia_loaded_source import register_loaded_module as _register_loaded_source
_register_loaded_source(__name__)
