"""Restore the frozen generic corpus from its canonical native input pools.

This is a development data operation. It executes no compiler or reference
program and supplies no qualification result. Every restored file retains its
original Git blob, SHA-256, extent and mode from the merged historical corpus.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import struct

SELF = "tools/restore_hia_cold_generic_corpus.py"
MANIFEST = "tests/fixtures/hia_cold_generic_canonical_pool_v1.json"
MANIFEST_BYTES = 674629
MANIFEST_SHA256 = "91555aa8dc2c2a0b49d7a75d47d0d7d4b13d6b219100ab45fd0807c0aac591e7"
_EXECUTED_SOURCE = Path(__file__).read_bytes()
PREFIX = "examples/hia_bootstrap/cold_cases_generic/"


def _stamp(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_size,
            st.st_mtime_ns, st.st_ctime_ns)


def _relative(name):
    if type(name) is not str or not name:
        raise ValueError("noncanonical input path")
    p = PurePosixPath(name)
    if p.is_absolute() or str(p) != name or any(x in ("", ".", "..") for x in p.parts):
        raise ValueError("noncanonical input path")
    return p


def _capture(root, name, pin=None):
    relative = _relative(name)
    path = root
    for part in relative.parts:
        path = path / part
        if path.is_symlink():
            raise ValueError("linked corpus input: " + name)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("nonregular corpus input: " + name)
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read()
        after = os.fstat(fd)
        if _stamp(before) != _stamp(after) or len(raw) != before.st_size:
            raise ValueError("corpus input changed during capture: " + name)
    finally:
        os.close(fd)
    if _stamp(path.stat(follow_symlinks=False)) != _stamp(after):
        raise ValueError("corpus input identity changed: " + name)
    record = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
              "git_blob": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest(),
              "mode": "100755" if before.st_mode & 0o111 else "100644"}
    if pin is not None and any(record[k] != v for k, v in pin.items()):
        raise ValueError("frozen corpus input differs: " + name)
    return raw, record, _stamp(before)


def _verify(root, captures):
    for name, (raw, pin, stamp) in captures.items():
        now, actual, now_stamp = _capture(root, name, pin)
        if now != raw or actual != pin or now_stamp != stamp:
            raise ValueError("corpus input changed after restoration: " + name)
    if Path(__file__).read_bytes() != _EXECUTED_SOURCE:
        raise ValueError("executed corpus restorer source changed")


def restore(root, output):
    """Write the original 1,615-file tree to a fresh explicit external directory."""
    root = Path(root).resolve(strict=True)
    output = Path(output).resolve()
    if output == root or output.is_relative_to(root):
        raise ValueError("restoration output must be outside the source tree")
    if output.exists():
        raise ValueError("restoration output must be a new directory")
    captures = {}

    def take(name, pin=None):
        item = _capture(root, name, pin)
        previous = captures.setdefault(name, item)
        if previous != item:
            raise ValueError("corpus input changed between captures: " + name)
        return item[0]

    self_raw = take(SELF)
    if self_raw != _EXECUTED_SOURCE:
        raise ValueError("selected and executing corpus restorer source differ")
    manifest_raw = take(MANIFEST, {"bytes": MANIFEST_BYTES, "sha256": MANIFEST_SHA256})
    manifest = json.loads(manifest_raw)
    if (manifest["schema"] != "hia.cold.generic.canonical-pool-restoration.v1"
            or manifest["original_head"] != "0768fdf3975a48d5b199355348d3330c88c1acc6"
            or len(manifest["pools"]) != 13 or len(manifest["files"]) != 1601
            or len(manifest["metadata"]) != 14):
        raise ValueError("unsupported frozen generic corpus")
    pools = {}
    for name, pin in manifest["pools"].items():
        pools[name] = take(name, pin)
    metadata = {}
    for name, pin in manifest["metadata"].items():
        if not name.startswith(PREFIX) or "/" in name[len(PREFIX):]:
            raise ValueError("invalid metadata path")
        metadata[name] = take(name, pin)

    payloads, by_pool = {}, {name: [] for name in pools}
    for name, row in manifest["files"].items():
        _relative(name)
        suffix = name[len(PREFIX):] if name.startswith(PREFIX) else ""
        p = PurePosixPath(suffix)
        if (len(p.parts) != 2 or p.parts[0] not in ("sources", "documents")
                or p.stem != row["sha256"]
                or p.suffix != (".hepta" if p.parts[0] == "sources" else ".hiacore")):
            raise ValueError("invalid frozen payload path")
        offset, extent = row["offset"], row["bytes"]
        if type(offset) is not int or type(extent) is not int or offset < 32 or extent < 0:
            raise ValueError("invalid pool segment extent")
        pool = pools[row["pool"]]
        raw = pool[offset:offset + extent]
        git_blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        if (len(raw) != extent or hashlib.sha256(raw).hexdigest() != row["sha256"]
                or git_blob != row["git_blob"] or row["mode"] != "100644"):
            raise ValueError("pool segment differs from original blob: " + name)
        payloads[name] = raw
        by_pool[row["pool"]].append((offset, extent))

    for name, raw in pools.items():
        segments = sorted(by_pool[name])
        if raw[:8] != b"HIAQCS01" or struct.unpack_from("<3Q", raw, 8) != (len(segments), len(raw), 0):
            raise ValueError("canonical pool header differs")
        cursor = 32
        for offset, extent in segments:
            if offset != cursor:
                raise ValueError("canonical pool payload overlap or hole")
            cursor += extent
        if raw[cursor:] != b"\xa5" * (1 << 20) + bytes((1 << 20) + 8):
            raise ValueError("canonical pool padding differs")
    if sum(map(len, payloads.values())) != 25259234:
        raise ValueError("original payload extent differs")

    output.mkdir(mode=0o700)
    written = []
    for name, raw in sorted({**metadata, **payloads}.items()):
        path = output / name[len(PREFIX):]
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(raw)
        path.chmod(0o644)
        if path.read_bytes() != raw or stat.S_IMODE(path.stat().st_mode) != 0o644:
            raise ValueError("restored output bytes or mode differ: " + name)
        written.append({"path": str(path.relative_to(output)), "bytes": len(raw),
                        "sha256": hashlib.sha256(raw).hexdigest(), "mode": "100644"})
    _verify(root, captures)
    actual_names = sorted(str(p.relative_to(output)) for p in output.rglob("*") if p.is_file())
    if actual_names != sorted(row["path"] for row in written):
        raise ValueError("unexpected restored member")
    for row in written:
        raw, actual, _ = _capture(output, row["path"],
                                  {k: row[k] for k in ("bytes", "sha256", "mode")})
    _verify(root, captures)
    return {"schema": "hia.cold.generic.canonical-pool-restoration-result.v1",
            "original_head": manifest["original_head"], "restored_files": len(written),
            "payload_files": len(payloads), "payload_bytes": sum(map(len, payloads.values())),
            "metadata_files": len(metadata), "pool_count": len(pools),
            "source_inputs_stable": True, "files": written,
            "product_executed": False, "cold_qualification_claimed": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.report.exists():
        parser.error("report must be a new file")
    result = restore(args.source, args.output)
    with args.report.open("x") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
