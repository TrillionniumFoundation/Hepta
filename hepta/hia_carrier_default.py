"""Package-owned activation of the explicit current carrier installation.

The installer derives this data after an actual native policy publication and
closed CPython ABI build. A source checkout has no default. The existing
full-cost default remains a separate domain and an explicit operator selection
is never supplemented.
"""
from __future__ import annotations

import base64
import csv
from hashlib import sha256
import io
import json
from pathlib import Path

PIN_RESOURCE = "_data/native/carriers/install-pin.json"
BUNDLE_RESOURCE = "_data/native/carriers/current.json"
SCHEMA = "hepta.hia.carrier-default-install.v1"
TARGET = "linux-x86_64-lp64"
SCOPE = "TARGET_BOUND_CPYTHON_COMPATIBILITY"
_EXECUTED_SOURCE = Path(__file__).resolve().read_bytes()


def _row_digest(raw):
    return "sha256=" + base64.urlsafe_b64encode(sha256(raw).digest()).rstrip(b"=").decode("ascii")


def capture_default_bundle():
    from . import __version__
    from .hia_native_helpers import _decode, _digest, _read

    def unchanged(captured, limit):
        if _read(captured.path, limit) != captured:
            raise ValueError("carrier default input changed during admission")

    package = Path(__file__).resolve().parent
    pin_path = package / PIN_RESOURCE
    bundle_path = package / BUNDLE_RESOURCE
    record_path = package.parent / ("hia_core-" + __version__ + ".dist-info/RECORD")
    snapshots = []
    try:
        record = _read(record_path, 1 << 20)
    except FileNotFoundError:
        record = None
    rows = {}
    if record is not None:
        snapshots.append((record, 1 << 20))
        for row in csv.reader(io.StringIO(record.raw.decode("utf-8"))):
            if (len(row) != 3 or not row[0] or row[0] in rows
                    or Path(row[0]).is_absolute() or "\\" in row[0]):
                raise ValueError("carrier installed RECORD is not a unique file inventory")
            # pip script entries may traverse to its scripts directory. This
            # reader never follows those rows; every carrier row is exact below.
            rows[row[0]] = row[1:]
    try:
        pin = _read(pin_path, 16384)
    except FileNotFoundError:
        if ("hepta/" + PIN_RESOURCE in rows or "hepta/" + BUNDLE_RESOURCE in rows
                or pin_path.parent.exists()):
            raise ValueError("installed carrier default data is missing")
        if record is not None:
            unchanged(record, 1 << 20)
        return None
    if record is None:
        raise ValueError("carrier default lacks its actual installed wheel RECORD")
    snapshots.append((pin, 16384))
    raw = pin.raw
    value = _decode(raw)
    fields = {"schema", "target", "scope", "package_path", "bundle_resource",
              "bundle_sha256", "policy_release_sha256", "receipts"}
    if (type(value) is not dict or set(value) != fields or value["schema"] != SCHEMA
            or value["target"] != TARGET or value["scope"] != SCOPE
            or value["package_path"] != str(package)
            or value["bundle_resource"] != BUNDLE_RESOURCE
            or not _digest(value["bundle_sha256"])
            or not _digest(value["policy_release_sha256"])
            or type(value["receipts"]) is not dict
            or set(value["receipts"]) not in (
                {"native-image", "cell-frame"}, {"native-image", "cell-frame", "slot-mechanical"})
            or any(not _digest(digest) for digest in value["receipts"].values())):
        raise ValueError("carrier package default is outside its exact installation domain")
    canonical = (json.dumps(value, sort_keys=True, separators=(",", ":"),
                            ensure_ascii=False, allow_nan=False) + "\n").encode()
    if raw != canonical:
        raise ValueError("carrier package default is not canonical")
    own = _read(Path(__file__).resolve(), 1 << 20)
    if own.raw != _EXECUTED_SOURCE:
        raise ValueError("executing carrier default reader changed")
    bundle = _read(bundle_path, 65536)
    if sha256(bundle.raw).hexdigest() != value["bundle_sha256"]:
        raise ValueError("installed carrier capsule identity differs")
    declaration = _decode(bundle.raw)
    if (type(declaration) is not dict
            or declaration.get("schema") != "hepta.hia.current-carrier-worker-bundle.v1"
            or declaration.get("abi") != "hia-worker-current-native-carriers-v1"
            or declaration.get("policy_release_sha256") != value["policy_release_sha256"]
            or type(declaration.get("bridges")) is not list):
        raise ValueError("installed carrier capsule changed its explicit current domain")
    receipt_pins = {}
    for bridge in declaration["bridges"]:
        if (type(bridge) is not dict or type(bridge.get("name")) is not str
                or bridge["name"] in receipt_pins
                or type(bridge.get("build_receipt")) is not dict):
            raise ValueError("installed carrier receipt declarations differ")
        receipt_pins[bridge["name"]] = bridge["build_receipt"].get("sha256")
    if receipt_pins != value["receipts"]:
        raise ValueError("installed carrier receipt pins differ")
    snapshots.extend(((own, 1 << 20), (bundle, 65536)))
    for name, captured in (
        ("hepta/" + PIN_RESOURCE, pin), ("hepta/" + BUNDLE_RESOURCE, bundle),
        ("hepta/hia_carrier_default.py", own),
    ):
        if rows.get(name) != [_row_digest(captured.raw), str(len(captured.raw))]:
            raise ValueError("carrier default differs from its installed RECORD: " + name)
    for captured, maximum in snapshots:
        unchanged(captured, maximum)
    return bundle_path, value["bundle_sha256"], tuple(snapshots)
