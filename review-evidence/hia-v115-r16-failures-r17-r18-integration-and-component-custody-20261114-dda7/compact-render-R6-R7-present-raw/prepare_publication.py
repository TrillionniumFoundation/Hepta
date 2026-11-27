"""Prepare bounded transport parts for existing originals, without product execution."""
from pathlib import Path
import base64
import hashlib
import json

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "publication-r2"


def identity(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            "git_blob": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()}


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def put(path, raw):
    with path.open("xb") as stream:
        stream.write(raw)
    assert path.read_bytes() == raw


def main():
    OUT.mkdir(exist_ok=False)
    (OUT / "parts").mkdir()
    (OUT / "ACK").mkdir()
    report_raw = (ROOT / "attempt-r1/REPORT.json").read_bytes()
    report = json.loads(report_raw)
    assert report["status"] == "PASS" and report["logical_files"] == 272
    archive = (ROOT / "attempt-r1/COMPLETE-PRESENT-RAW.tar.gz").read_bytes()
    assert identity(archive) == report["archive"]
    entries = []
    parts = []
    for number, offset in enumerate(range(0, len(archive), 384 * 1024)):
        raw = archive[offset:offset + 384 * 1024]
        name = f"parts/{number:03d}.json"
        packet = encode({"schema": "hia.complete-raw.archive-part.v1", "number": number,
                         "offset": offset, "decoded": identity(raw), "encoding": "base64",
                         "payload": base64.b64encode(raw).decode("ascii")})
        put(OUT / name, packet)
        row = {"path": name, **identity(packet)}
        entries.append(row)
        parts.append({**row, "offset": offset, "decoded": identity(raw)})
    manifest_raw = (ROOT / "attempt-r1/RAW-MANIFEST.json").read_bytes()
    assert identity(manifest_raw) == report["manifest"]
    manifest = json.loads(manifest_raw)
    for name, path in (
        ("RAW-MANIFEST.json", ROOT / "attempt-r1/RAW-MANIFEST.json"),
        ("LOCAL-READBACK.json", ROOT / "attempt-r1/REPORT.json"),
        ("ORIGINAL-PLAN.json", ROOT / "plan-r1/PLAN.json"),
        ("archive_raw.py", ROOT / "archive_raw.py"),
        ("restore_complete_raw.py", ROOT / "restore_complete_raw_r2.py"),
        ("restore_complete_raw_r1.py", ROOT / "restore_complete_raw.py"),
        ("RESTORE-HELPER-R1-FAILURE.json", ROOT / "RESTORE-HELPER-R1-FAILURE.json"),
        ("prepare_publication.py", Path(__file__).resolve()),
    ):
        raw = path.read_bytes()
        put(OUT / name, raw)
        entries.append({"path": name, **identity(raw)})
    index = {"schema": "hia.compact-R6-R7.present-raw-publication.v1",
             "source_capsules": manifest["source_capsules"],
             "prior_R1_R5_full_present_recipe": manifest["prior_R1_R5_full_present_recipe"],
             "external_frozen_source_baseline": manifest["external_frozen_source_baseline"],
             "logical_files": 272, "logical_bytes": 100388719,
             "unique_objects": 165, "unique_bytes": 53742672,
             "archive": report["archive"], "manifest": report["manifest"], "parts": parts,
             "scope": "Complete fixed 272 present R6/R7 originals including actual large buffers; both candidates remain failed and unadopted.",
             "prior_missing_R1_originals_remain_missing": True,
             "all_historical_originals_retained": False, "local_full_restore_pass": True,
             "new_product_executions": 0, "new_qualification": False, "adopted": False}
    index_raw = encode(index)
    put(OUT / "INDEX.json", index_raw)
    entries.append({"path": "INDEX.json", **identity(index_raw)})
    plan = {"schema": "hia.complete-raw.git-publication-plan.v1", "entries": entries,
            "archive": report["archive"], "logical_files": 272, "logical_bytes": 100388719}
    put(OUT / "PLAN.json", encode(plan))
    full = bytearray()
    for row in parts:
        value = json.loads((OUT / row["path"]).read_bytes())
        raw = base64.b64decode(value["payload"], validate=True)
        assert identity(raw) == value["decoded"] == row["decoded"] and value["offset"] == len(full)
        full.extend(raw)
    assert bytes(full) == archive
    print(json.dumps({"status": "PASS", "parts": len(parts), "leaves": len(entries),
                      "archive": identity(archive), "transport_bytes": sum(r["bytes"] for r in entries),
                      "index": identity(index_raw)}, sort_keys=True))


if __name__ == "__main__":
    main()
