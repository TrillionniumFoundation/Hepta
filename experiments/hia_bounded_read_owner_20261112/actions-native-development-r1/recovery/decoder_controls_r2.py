"""Finite synthetic transport controls; never import or execute a product."""
import base64
from copy import deepcopy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile


ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "authoring/decode_small_channel_r2.py"
spec = importlib.util.spec_from_file_location("bounded_transport_decoder", PATH)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
OUT = ROOT / "authoring/decoder-controls-r2"
OUT.mkdir(exist_ok=False)
policy_raw = (ROOT / "control/policy.json").read_bytes()
targets_raw = (ROOT / "control/diagnostic-targets.json").read_bytes()
names = [row["name"] for row in json.loads(targets_raw)["targets"]]
contents = {names[0]: b"synthetic not a product receipt\n" * 350, names[1]: b""}
ledger = [dict(name=name, status="SELECTED_WHOLE_FILE", **module.pin(contents[name]))
          if name in contents else {"name": name, "status": "MISSING"} for name in names]
index = {"schema": "hepta.hia.bounded-read-small-channel-index.v1", "fixed_targets": 133,
         "selected_files": 2, "selected_raw_bytes": sum(map(len, contents.values())),
         "raw_limit": module.MAX_RAW, "stdout_limit": module.MAX_STREAM,
         "observation_raw_bytes": sum(map(len, contents.values())),
         "boundary": {"current_operation_bound": True, "closed_ECHILD": True,
                      "guardian_sha256": "0" * 64, "original_product_status_not_changed": True},
         "complete_original_artifact_transport_claimed": False, "product_status_changed": False,
         "records": ledger}
records = [("HIA_BOUNDED_READ_DIAGNOSTIC_BEGIN", {
    "schema": "hepta.hia.bounded-read-small-stream.v1", "run_id": 123456,
    "workflow_commit": module.WORKFLOW, "policy_sha256": module.POLICY_SHA,
    "raw_limit": module.MAX_RAW, "stdout_limit": module.MAX_STREAM}),
    ("HIA_BOUNDED_READ_DIAGNOSTIC_INDEX", index)]
frames = 0
for row in ledger:
    if row["name"] not in contents:
        continue
    records.append(("HIA_BOUNDED_READ_ORIGINAL_BEGIN", row))
    raw = contents[row["name"]]
    for offset in range(0, len(raw), 8192):
        block = raw[offset:offset + 8192]
        records.append(("HIA_BOUNDED_READ_ORIGINAL_FRAME", {"name": row["name"], "offset": offset,
            "bytes": len(block), "sha256": hashlib.sha256(block).hexdigest(),
            "base64": base64.b64encode(block).decode()}))
        frames += 1
    records.append(("HIA_BOUNDED_READ_ORIGINAL_END", row))
records.append(("HIA_BOUNDED_READ_DIAGNOSTIC_END", {
    "status": "BOUNDED_WHOLE_FILE_CHANNEL_COMPLETE", "selected_files": 2, "frames": frames,
    "selected_raw_bytes": sum(map(len, contents.values())),
    "index_sha256": hashlib.sha256(module.wire(index)).hexdigest(), "closed_ECHILD": True,
    "all_133_originals_transported": False, "complete_original_artifact_transport_claimed": False}))


def output(rows):
    return ("other original job text\n" + "".join(
        "2026-11-12T00:00:00.0000000Z " + key + " " + json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
        for key, value in rows)).encode()


good = output(records)
cases = [("whole_files_with_empty_file_and_multiple_frames", good, True)]


def mutated(name, mutate):
    rows = deepcopy(records)
    mutate(rows)
    cases.append((name, output(rows), False))


mutated("different_operation", lambda rows: rows[0][1].__setitem__("run_id", 123457))
mutated("missing_END", lambda rows: rows.pop())
mutated("duplicate_END", lambda rows: rows.append(rows[-1]))
mutated("partial_file", lambda rows: rows.pop(4))
mutated("overlap_frame", lambda rows: rows[4][1].__setitem__("offset", 0))
mutated("frame_digest_drift", lambda rows: rows[3][1].__setitem__("sha256", "f" * 64))
mutated("reordered_target_population", lambda rows: rows[1][1]["records"].reverse())
mutated("wrong_total_bytes", lambda rows: rows[1][1].__setitem__("selected_raw_bytes", 1))
mutated("missing_original_END", lambda rows: rows.pop(5))
cases.append(("duplicate_JSON_key", good.replace(b'"run_id":123456',
    b'"run_id":123456,"run_id":123456', 1), False))

results, originals = [], {}
for name, raw, wanted in cases:
    originals[name + ".log"] = raw
    try:
        report, recovered = module.decode(raw, 123456, policy_raw, targets_raw)
        observation = {"accepted": True, "files": report["files"], "frames": report["frames"],
                       "scope": report["status"],
                       "no_product_verification_claim": report["independently_verified_product_status"] is False}
        assert recovered == contents
        assert report["complete_original_artifact_recovered"] is False
    except Exception as error:
        observation = {"accepted": False, "type": type(error).__name__, "error": str(error)}
    assert observation["accepted"] is wanted, (name, observation)
    results.append({"id": name, "expected_acceptance": wanted, "observation": observation, "status": "PASS"})

archive = OUT / "synthetic-originals.tar.xz"
with tarfile.open(archive, "w:xz") as handle:
    for name, raw in sorted(originals.items()):
        member = tarfile.TarInfo(name)
        member.size, member.mode, member.uid, member.gid, member.mtime = len(raw), 0o400, 0, 0, 0
        handle.addfile(member, io.BytesIO(raw))
with tarfile.open(archive, "r:xz") as handle:
    members = handle.getmembers()
    assert len(members) == len(originals)
    for member in members:
        assert member.isfile() and member.mode == 0o400
        assert handle.extractfile(member).read() == originals[member.name]
raw = archive.read_bytes()
(OUT / "synthetic-originals.tar.xz.base64.txt").write_text(base64.b64encode(raw).decode() + "\n")
report = {"schema": "hepta.hia.bounded-read-small-transport-controls.v1", "status": "PASS",
          "decoder": module.pin(PATH.read_bytes()), "expected_ids": [row[0] for row in cases],
          "executed_ids": [row["id"] for row in results], "cases": results,
          "archive": module.pin(raw), "raw_members": {name: module.pin(body) for name, body in originals.items()},
          "archive_metadata": "Synthetic originals normalized to mode0400 uid/gid0 mtime0; not product modes",
          "product_executed": False, "network_or_workflow_triggered": False,
          "scope": "SYNTHETIC_TRANSPORT_ONLY_NO_ACTUAL_OPERATION_CLAIMS"}
(OUT / "report.json").write_bytes(module.wire(report))
print(json.dumps({"status": "PASS", "cases": len(results), "archive_bytes": len(raw),
                  "raw_bytes": sum(map(len, originals.values())), "product_executed": False}))
