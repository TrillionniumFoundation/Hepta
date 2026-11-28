"""Capture explicit current Worker carrier data without loading any extension.

This output is operator input, not a native qualification receipt. The runtime
still performs its original complete typed Store/Core/Page/scheduler admission.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path

from hepta.hia_carrier_policy_release import capture as capture_release
from tools.capture_hia_native_carrier_bundle import (
    BRIDGES, canonical, capture_bridge_records, decode, digest, pin, read,
)

SCHEMA = "hepta.hia.current-carrier-worker-bundle.v1"
ABI = "hia-worker-current-native-carriers-v1"
TARGET = "linux-x86_64-lp64"
BYTE_ABI = "hia-byte-six-argument-v1"
CURRENT = (
    "hepta.hia.native-helpers.v24",
    "hepta.hia.core-companion-worker-bundle.v1",
    "hepta.hia.artifact-page-worker-bundle.v1",
    "hepta.hia.native-helpers.v3",
)


def _path(value, parent):
    if type(value) is not str or not value or "\\" in value:
        raise ValueError("current carrier input path must be explicit")
    path = Path(value)
    if ".." in path.parts:
        raise ValueError("current carrier input path traverses a parent")
    path = path if path.is_absolute() else parent / path
    if path != path.resolve(strict=True):
        raise ValueError("current carrier input path is not canonical")
    return path


def _selectors(path, expected, captures, *, top=True, seen=()):
    if not digest(expected) or path in seen or len(seen) >= 7:
        raise ValueError("current carrier child graph is cyclic, unpinned or too deep")
    raw = read(path, 65536)
    if sha256(raw).hexdigest() != expected:
        raise ValueError("current carrier child capsule identity differs")
    captures.append((path, raw, 65536))
    value = decode(raw)
    if (type(value) is not dict or value.get("target") != TARGET
            or value.get("abi") != BYTE_ABI
            or (top and value.get("schema") not in CURRENT)):
        raise ValueError("current carriers require one explicit current typed child")
    schema = value.get("schema")
    if schema == "hepta.hia.native-helpers.v1":
        if set(value) != {"schema", "target", "abi", "helpers"} or type(value["helpers"]) is not list:
            raise ValueError("invalid closed helper declarations")
        selectors = []
        for item in value["helpers"]:
            if (type(item) is not dict or set(item) != {"selector", "manifest_path", "manifest_sha256"}
                    or type(item["selector"]) is not str or not item["selector"]
                    or item["selector"] in selectors or not digest(item["manifest_sha256"])):
                raise ValueError("invalid or duplicate current helper selector")
            child_path = _path(item["manifest_path"], path.parent)
            child_raw = read(child_path, 16384)
            if sha256(child_raw).hexdigest() != item["manifest_sha256"]:
                raise ValueError("current helper manifest identity differs")
            captures.append((child_path, child_raw, 16384))
            selectors.append(item["selector"])
        if not selectors:
            raise ValueError("current carrier base cannot be empty")
        return tuple(selectors)
    if schema == "hepta.hia.native-helpers.v2":
        if set(value) != {"schema", "target", "abi", "helpers_bundle", "helpers_bundle_sha256",
                         "report_bundle", "report_bundle_sha256"}:
            raise ValueError("invalid current v2 child declaration")
        field = "helpers_bundle"
    elif schema in CURRENT:
        field = "base_bundle"
        if field not in value or field + "_sha256" not in value:
            raise ValueError("current carrier typed child lacks its explicit base")
    else:
        raise ValueError("unknown current carrier child schema")
    return _selectors(_path(value[field], path.parent), value[field + "_sha256"], captures,
                      top=False, seen=seen + (path,))


def create(package, base_path, expected_base, release_path, expected_release,
           expected_receipts, output):
    package, base_path, release_path, output = map(Path, (package, base_path, release_path, output))
    if (not digest(expected_base) or not digest(expected_release)
            or type(expected_receipts) is not dict
            or any(type(k) is not str or k not in BRIDGES or not digest(v)
                   for k, v in expected_receipts.items())):
        raise ValueError("current carrier inputs require explicit exact digests")
    for path in (package, base_path, release_path):
        if path != path.resolve(strict=True):
            raise ValueError("current carrier input paths must be canonical")
    captures = []
    selectors = _selectors(base_path, expected_base, captures)
    required = sorted(name for name, spec in BRIDGES.items() if spec[0] in selectors)
    if (not {"native-image", "cell-frame"} <= set(required)
            or sorted(expected_receipts) != required):
        raise ValueError("current receipt pins must exactly cover both carriers and selected Slot")

    def release_read(path):
        raw = read(path, 8 << 20)
        captures.append((path, raw, 8 << 20))
        return raw

    publication, _ = capture_release(release_path, expected_release, package, release_read)
    bridges = capture_bridge_records(package, expected_receipts, required, captures)
    captured_receipts = {path.name: raw for path, raw, _limit in captures}
    for name, kind in (("native-image", "image"), ("cell-frame", "cell")):
        receipt_name = BRIDGES[name][3]
        policy = decode(captured_receipts[receipt_name])["hia_policy"]
        role = publication["roles"][kind]
        if (canonical(policy["source"]) != canonical(role["source"])
                or canonical(policy["image"]) != canonical(role["image"])
                or canonical(policy["compiler"]) != canonical(publication["seed"])):
            raise ValueError("current host ABI differs from its actual native publication")
    value = {"schema": SCHEMA, "target": TARGET, "abi": ABI,
             "base_bundle": str(base_path), "base_bundle_sha256": expected_base,
             "policy_release": str(release_path), "policy_release_sha256": expected_release,
             "bridges": bridges}
    raw = canonical(value) + b"\n"
    if len(raw) > 65536:
        raise ValueError("current carrier capsule exceeds the unchanged bundle extent")

    def unchanged():
        if any(read(path, maximum) != before for path, before, maximum in captures):
            raise ValueError("current carrier capture input changed")

    unchanged()
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
    if read(output, 65536) != raw:
        raise ValueError("current carrier capsule output changed")
    unchanged()
    return {"path": str(output.resolve()), **pin(raw), "authority": "OPERATOR_MUST_PIN_THIS_DIGEST",
            "scope": "DATA_CAPTURE_ONLY", "product_qualification_claimed": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--base-bundle", type=Path, required=True)
    parser.add_argument("--expected-base-sha256", required=True)
    parser.add_argument("--policy-release", type=Path, required=True)
    parser.add_argument("--expected-publication-sha256", required=True)
    for name in BRIDGES:
        parser.add_argument("--" + name + "-receipt-sha256")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    receipts = {name: getattr(args, name.replace("-", "_") + "_receipt_sha256") for name in BRIDGES}
    receipts = {name: value for name, value in receipts.items() if value is not None}
    result = create(args.package.resolve(strict=True), args.base_bundle.resolve(strict=True),
                    args.expected_base_sha256, args.policy_release.resolve(strict=True),
                    args.expected_publication_sha256, receipts, args.output)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
