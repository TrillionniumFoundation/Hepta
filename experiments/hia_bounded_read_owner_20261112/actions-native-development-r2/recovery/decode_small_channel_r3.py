"""Recover exact whole files from the frozen bounded-read A3/B3 (isolated r2 control) small channel.

This is a transport reader. It never promotes workflow success, a complete
small stream, or a producer's claimed boundary into product qualification.
"""
from __future__ import annotations

import argparse
import base64
from hashlib import sha1, sha256
import json
import os
from pathlib import Path
import re
import stat


CONTROL = "30f053a6585b29bf052e36806e4a657d5bda9935"
WORKFLOW = "d908b4f53d20710416dfb6a36571058ba78ea0c9"
POLICY_SHA = "7eeec008bc7e8b1dbdf4645c1eee96af6891e4de0de7b6d3e51554665df9451b"
TARGET_SHA = "683c66b046e02fc5e0e11d42b481f5db6583e0cc92b5733cc60fa6a64c27a8f2"
MAX_RAW = 512 << 10
MAX_STREAM = 1 << 20
MAX_INDEX = 64 << 10
MAX_OBSERVATION = 160 << 20
LINE = re.compile(r"^(?:\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z )?"
                  r"(HIA_BOUNDED_READ_(?:DIAGNOSTIC|ORIGINAL)_[A-Z]+) (.*)$")
STATUSES = {"SELECTED_WHOLE_FILE", "OMITTED_WHOLE_FILE_BUDGET", "MISSING", "REFUSED",
            "NOT_READ_UNCLOSED_PROCESS_BOUNDARY"}


def require(value, message):
    if not value:
        raise ValueError(message)


def pairs(values):
    result = {}
    for key, value in values:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def parse(raw):
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def pin(raw):
    return {"bytes": len(raw), "sha256": sha256(raw).hexdigest(),
            "git_blob_sha1": sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()}


def regular(path, maximum):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= maximum,
                "local input must be bounded regular bytes")
        blocks, remaining = [], before.st_size
        while remaining:
            block = os.read(descriptor, min(remaining, 65536))
            require(block, "local input ended early")
            blocks.append(block)
            remaining -= len(block)
        after = os.fstat(descriptor)
        fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
                  "st_size", "st_mtime_ns", "st_ctime_ns")
        require(all(getattr(before, key) == getattr(after, key) for key in fields),
                "local input changed while reading")
        return b"".join(blocks)
    finally:
        os.close(descriptor)


def decode(log_raw, run_id, policy_raw, targets_raw):
    require(type(run_id) is int and run_id > 0, "exact original run ID required")
    require(sha256(policy_raw).hexdigest() == POLICY_SHA, "frozen policy bytes differ")
    require(sha256(targets_raw).hexdigest() == TARGET_SHA, "frozen target bytes differ")
    policy, targets = parse(policy_raw), parse(targets_raw)
    require(policy["schema"] == "hia.bounded-read-actions-policy.v1"
            and policy["candidate"] == {"commit": "0e36619bc65ada7072c1e8a1f1454728036fee4e",
                "tree": "1d95802c453a006f077eb8735a6939b1957d500b", "leaves": 4025}
            and policy["controller_seconds"] == 180 and policy["cleanup_seconds"] == 3
            and policy["small_raw_bytes"] == MAX_RAW and policy["small_stdout_bytes"] == MAX_STREAM,
            "frozen source or original limits differ")
    names = [row["name"] for row in targets["targets"]]
    require(len(names) == len(set(names)) == 133, "full fixed target population differs")
    records = []
    protocol_size = 0
    for line in log_raw.decode("utf-8", "strict").splitlines():
        match = LINE.fullmatch(line)
        if match:
            kind, encoded = match.groups()
            protocol_size += len((kind + " " + encoded + "\n").encode())
            require(protocol_size <= MAX_STREAM, "small stream exceeded original stdout bound")
            value = parse(encoded)
            require(type(value) is dict, "protocol object is not a dictionary")
            records.append((kind, value))
    require(len(records) >= 3, "no complete small-channel envelope")
    require(records[0] == ("HIA_BOUNDED_READ_DIAGNOSTIC_BEGIN", {
        "schema": "hepta.hia.bounded-read-small-stream.v1", "run_id": run_id,
        "workflow_commit": WORKFLOW, "policy_sha256": POLICY_SHA,
        "raw_limit": MAX_RAW, "stdout_limit": MAX_STREAM}), "stream belongs to a different operation")
    require(records[1][0] == "HIA_BOUNDED_READ_DIAGNOSTIC_INDEX", "missing original full index")
    index = records[1][1]
    index_raw = wire(index)
    require(len(index_raw) <= MAX_INDEX and index["schema"] == "hepta.hia.bounded-read-small-channel-index.v1"
            and index["fixed_targets"] == 133 and index["raw_limit"] == MAX_RAW
            and index["stdout_limit"] == MAX_STREAM
            and index["complete_original_artifact_transport_claimed"] is False
            and index["product_status_changed"] is False, "index schema or scope differs")
    require(type(index["observation_raw_bytes"]) is int
            and 0 <= index["observation_raw_bytes"] <= MAX_OBSERVATION, "index observation budget differs")
    ledger = index["records"]
    require(type(ledger) is list and [row["name"] for row in ledger] == names,
            "complete ordered 133-target ledger differs")
    selected, budget = [], 0
    for row in ledger:
        status = row["status"]
        require(status in STATUSES, "unknown original ledger status")
        if status in {"SELECTED_WHOLE_FILE", "OMITTED_WHOLE_FILE_BUDGET"}:
            require(type(row["bytes"]) is int and 0 <= row["bytes"] <= 16 << 20
                    and re.fullmatch("[0-9a-f]{64}", row["sha256"])
                    and re.fullmatch("[0-9a-f]{40}", row["git_blob_sha1"]), "invalid original byte identity")
            fits = budget + row["bytes"] <= MAX_RAW
            require(fits == (status == "SELECTED_WHOLE_FILE"), "whole-file selection differs from fixed order")
            if fits:
                budget += row["bytes"]
                selected.append(row)
    require(type(index["selected_files"]) is int and index["selected_files"] == len(selected)
            and type(index["selected_raw_bytes"]) is int and index["selected_raw_bytes"] == budget,
            "index population or byte total differs")
    boundary = index["boundary"]
    require(type(boundary) is dict and type(boundary["closed_ECHILD"]) is bool
            and type(boundary["current_operation_bound"]) is bool,
            "producer boundary fields missing")
    require(boundary["closed_ECHILD"] == boundary["current_operation_bound"], "inconsistent producer boundary")
    if not boundary["closed_ECHILD"]:
        require(all(row["status"] == "NOT_READ_UNCLOSED_PROCESS_BOUNDARY" for row in ledger[4:]),
                "unclosed producer read child outputs")
    files, frame_count, cursor = {}, 0, 2
    for header in selected:
        require(cursor < len(records) and records[cursor] == ("HIA_BOUNDED_READ_ORIGINAL_BEGIN", header),
                "missing, reordered or mismatched original begin")
        cursor += 1
        blocks, offset = [], 0
        while offset < header["bytes"]:
            require(cursor < len(records) and records[cursor][0] == "HIA_BOUNDED_READ_ORIGINAL_FRAME",
                    "missing original frame")
            frame = records[cursor][1]
            require(set(frame) == {"name", "offset", "bytes", "sha256", "base64"}
                    and frame["name"] == header["name"] and type(frame["offset"]) is int
                    and frame["offset"] == offset and type(frame["bytes"]) is int
                    and frame["bytes"] == min(8192, header["bytes"] - offset), "frame ordering or extent differs")
            data = base64.b64decode(frame["base64"], validate=True)
            require(base64.b64encode(data).decode() == frame["base64"] and len(data) == frame["bytes"]
                    and sha256(data).hexdigest() == frame["sha256"], "frame bytes differ")
            blocks.append(data)
            offset += len(data)
            frame_count += 1
            cursor += 1
        raw = b"".join(blocks)
        require(pin(raw) == {key: header[key] for key in ("bytes", "sha256", "git_blob_sha1")},
                "complete original identity differs")
        require(cursor < len(records) and records[cursor] == ("HIA_BOUNDED_READ_ORIGINAL_END", header),
                "missing or mismatched original end")
        cursor += 1
        files[header["name"]] = raw
    expected_end = {"status": "BOUNDED_WHOLE_FILE_CHANNEL_COMPLETE", "selected_files": len(selected),
        "frames": frame_count, "selected_raw_bytes": budget, "index_sha256": sha256(index_raw).hexdigest(),
        "closed_ECHILD": boundary["closed_ECHILD"], "all_133_originals_transported": len(selected) == 133,
        "complete_original_artifact_transport_claimed": False}
    require(cursor == len(records) - 1 and records[cursor] == ("HIA_BOUNDED_READ_DIAGNOSTIC_END", expected_end),
            "missing, extra or incorrect stream END")
    return {"schema": "hepta.hia.bounded-read-small-channel-recovery.v1",
        "status": "WHOLE_FILE_CHANNEL_RECOVERED_NOT_PRODUCT_VERIFIED", "run_id": run_id,
        "control_commit": CONTROL, "workflow_commit": WORKFLOW, "policy_sha256": POLICY_SHA,
        "log": pin(log_raw), "protocol_bytes": protocol_size, "files": len(files), "frames": frame_count,
        "raw_bytes": budget, "index_sha256": sha256(index_raw).hexdigest(),
        "producer_boundary_claim": boundary, "independently_verified_product_status": False,
        "complete_original_artifact_recovered": False, "index": index}, files


def exclusive(path, raw):
    with path.open("xb") as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())
    require(path.read_bytes() == raw, "retained local bytes differ")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--targets", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    log = regular(args.log, 64 << 20)
    policy = regular(args.policy, 1 << 20)
    targets = regular(args.targets, 1 << 20)
    args.output.mkdir(mode=0o700, parents=False, exist_ok=False)
    exclusive(args.output / "original-job.log", log)
    exclusive(args.output / "frozen-policy.json", policy)
    exclusive(args.output / "frozen-targets.json", targets)
    try:
        report, files = decode(log, args.run_id, policy, targets)
        raw_root = args.output / "raw"
        raw_root.mkdir(mode=0o700)
        report["recovered"] = []
        for number, (name, raw) in enumerate(files.items()):
            local = "raw/" + str(number).zfill(3) + ".bin"
            exclusive(args.output / local, raw)
            report["recovered"].append({"name": name, "local": local, **pin(raw)})
        exclusive(args.output / "RECOVERY.json", wire(report))
    except BaseException as error:
        exclusive(args.output / "HOLD.json", wire({"status": "HOLD", "type": type(error).__name__,
            "error": str(error), "original_log": pin(log), "product_status_changed": False}))
        raise
    print(json.dumps({"status": report["status"], "files": report["files"], "frames": report["frames"],
                      "raw_bytes": report["raw_bytes"], "report": str(args.output / "RECOVERY.json")}))


if __name__ == "__main__":
    main()
