"""Losslessly freeze local R20 proof metadata, without expanding either ZIP.

The Source archive's 237 original Git chunks remain the complete Source raw
transport.  The bounded ZIP remains local and in Actions; this capsule does not
claim to replace its complete machine-frame/raw evidence.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import time
import zlib


ROOT = Path(__file__).resolve().parent
OUT = ROOT / "final-handoff-r1"
PUBLICATION = ROOT.parent / "v120-source-parser-r20-harness/publication-r1"


def pin(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            "git_blob": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()}


def dump(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def main():
    started = time.monotonic()
    assert not OUT.exists()
    files = {}
    for p in ROOT.iterdir():
        if p.is_file() and p.suffix != ".zip":
            files["original/" + p.name] = p
    for folder in ("selected-originals", "source-manifest-readback-r1", "bounded-manifest-readback-r1"):
        for p in (ROOT / folder).rglob("*"):
            if p.is_file() and "changed-source" not in p.relative_to(ROOT).parts:
                files["original/" + str(p.relative_to(ROOT))] = p
    for name in (
        "REPORT.json", "INNER-CHUNKS-READBACK.json", "combined-source-OUTER-MEMBERS.json",
        "parser-bounded-OUTER-MEMBERS.json", "combined-source/API-RECEIPTS.json",
        "combined-source/ARCHIVE-UPLOAD-INTENT.json", "combined-source/EVIDENCE-MANIFEST.json",
        "combined-source/EVIDENCE-PIN.json", "parser-bounded/FINAL-SOURCE-MANIFEST.json",
        "parser-bounded/FIXED-SOURCE-MANIFEST.json", "parser-bounded/FORMAL-EXPECTED-IDS.json",
        "parser-bounded/FULL-SOURCE-RESULT.json", "parser-bounded/FULL-SOURCE-TESTS.json",
        "parser-bounded/PARSER-CONTROLS.json", "parser-bounded/RESULT.json",
    ):
        p = ROOT / "custody-stream-r1" / name
        files["original/custody-stream-r1/" + name] = p
    for p in PUBLICATION.rglob("*"):
        if p.is_file():
            files["formal-publication/" + str(p.relative_to(PUBLICATION))] = p
    index, pool, original_bytes, snapshots = [], {}, {}, {}
    for name, p in sorted(files.items()):
        rel = PurePosixPath(name)
        assert not rel.is_absolute() and ".." not in rel.parts
        before = p.lstat()
        assert stat.S_ISREG(before.st_mode) and not p.is_symlink()
        raw = p.read_bytes()
        identity = pin(raw)
        sha = identity["sha256"]
        if sha in original_bytes:
            assert original_bytes[sha] == raw
        else:
            original_bytes[sha] = raw
            pool[sha] = base64.b64encode(raw).decode("ascii")
        mode = stat.S_IMODE(before.st_mode)
        assert mode in (0o644, 0o755, 0o600)
        snapshots[name] = (p, before, raw)
        index.append({"path": name, "mode": mode, **identity, "cas_sha256": sha})
    decoded = {"schema": "hia.r20.final-original-metadata-cas.v1", "files": index, "pool": pool}
    raw = dump(decoded)
    compressed = zlib.compress(raw, 6)
    wrapper = {"schema": "hia.lossless-json-zlib-base64.v1", "encoding": "zlib+base64",
               "uncompressed": pin(raw), "compressed": pin(compressed),
               "payload": base64.b64encode(compressed).decode("ascii")}
    wrapper_raw = dump(wrapper)
    restored_raw = zlib.decompress(base64.b64decode(wrapper["payload"], validate=True))
    assert pin(restored_raw) == wrapper["uncompressed"] and restored_raw == raw
    restored = json.loads(restored_raw)
    assert restored["files"] == index
    for row in restored["files"]:
        b = base64.b64decode(restored["pool"][row["cas_sha256"]], validate=True)
        assert pin(b) == {k: row[k] for k in ("bytes", "sha256", "git_blob")}
        p, before, original = snapshots[row["path"]]
        after = p.lstat()
        assert (before.st_dev, before.st_ino, before.st_size, before.st_mode, before.st_mtime_ns) == (
            after.st_dev, after.st_ino, after.st_size, after.st_mode, after.st_mtime_ns)
        assert p.read_bytes() == original == b
    OUT.mkdir()
    (OUT / "METADATA-CAPSULE.zlib.json").write_bytes(wrapper_raw)
    (OUT / "METADATA-MANIFEST.json").write_bytes(dump(index))
    report = {
        "schema": "hia.r20.final-original-metadata-capsule-readback.v1",
        "status": "LOSSLESS_METADATA_CAPSULE_PASS", "files": len(index),
        "logical_bytes": sum(r["bytes"] for r in index), "unique_content_blobs": len(pool),
        "unique_bytes": sum(len(v) for v in original_bytes.values()),
        "capsule": pin(wrapper_raw), "decoded": pin(raw), "compressed": pin(compressed),
        "complete_captured_files_read_back": True, "captured_originals_before_after_equal": True,
        "scope": "Terminal API history, transfer records, complete ZIP member inventories, Source manifest, selected original reports, independent validators and complete readback proofs.",
        "Source_raw_archive": "All 7856 files/1295 directories are in the exact existing 237 Git chunks; this capsule contains their manifest and verification, not a second archive.",
        "bounded_raw_archive": "The complete bounded ZIP is retained locally and in Actions; only selected reports and metadata are inside this capsule.",
        "whole_outer_ZIPs_in_Git": False, "product_executions": 0, "new_native_or_cold_qualification": False,
        "originals_deleted": False, "seconds_for_metadata_only": time.monotonic() - started,
    }
    (OUT / "METADATA-READBACK.json").write_bytes(dump(report))
    print(json.dumps({k: report[k] for k in ("status", "files", "logical_bytes", "unique_bytes", "capsule", "seconds_for_metadata_only")}))


if __name__ == "__main__":
    main()
