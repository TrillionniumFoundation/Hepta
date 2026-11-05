#!/usr/bin/env python3
"""Read-only check of the preserved diagnostic excerpts against the original ZIP."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import sys
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    args = parser.parse_args()
    if sys.flags.optimize:
        parser.error("run without -O or PYTHONOPTIMIZE so verification assertions remain enabled")
    evidence = json.loads(Path(__file__).with_name("dco-promotion-evidence.json").read_text())
    actual = hashlib.sha256(args.archive.read_bytes()).hexdigest()
    if actual != evidence["archive_sha256"]:
        parser.error("archive does not match the original #716 target artifact")
    endpoints = excerpts = 0
    with zipfile.ZipFile(args.archive) as archive:
        assert archive.read("source-commit.stdout").decode().strip() == evidence["hepta_head"]
        assert archive.read("source-tree.stdout").decode().strip() == evidence["hepta_tree"]
        counts = {}
        for name in archive.namelist():
            if name.endswith("openvpn.stdout"):
                count = archive.read(name).decode().count("out of sync")
                if count:
                    counts[name] = count
        assert counts == evidence["all_out_of_sync_counts"]
        for case in evidence["case_evidence"]:
            raw = archive.read("tunnel/cases/" + case["case"] + "/case.json")
            assert hashlib.sha256(raw).hexdigest() == case["original_case_sha256"]
            receipt = json.loads(raw)
            assert receipt["arms"] == case["arms"]
            assert receipt["status"] == case["original_status"]
            assert receipt.get("failure") == case["original_failure"]
            for role, endpoint in case["endpoints"].items():
                raw = archive.read(endpoint["path"])
                assert hashlib.sha256(raw).hexdigest() == endpoint["sha256"]
                assert receipt["observations"][role]["completed_rekeys"] == endpoint["original_completed_rekeys"]
                lines = raw.decode().splitlines()
                for event in endpoint["events"]:
                    assert lines[event["line"] - 1] == event["text"]
                    excerpts += 1
                endpoints += 1
    print(f"PASS: original source/tree, 4 failed receipts, {endpoints} endpoint hashes, {excerpts} exact excerpts, and all out-of-sync counts verified.")
    print("Original failure verdicts are unchanged. No artifact code was executed.")


if __name__ == "__main__":
    main()
