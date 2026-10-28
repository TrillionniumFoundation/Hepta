#!/usr/bin/env python3
"""Inventory selected branch deltas on one exact committed integration source.

Use complete local Git trees, never a capped compare-API file window. This is
source provenance and omission detection, not a semantic proof. Reconciled
blobs still require the documented conflict review and new qualification.
"""
from __future__ import annotations

import argparse
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SPEC_PATH = "docs/HIA_INTEGRATION_SOURCES.json"


def git(*args):
    return subprocess.check_output(["git", "-C", str(ROOT), *args], timeout=60)


def tree(commit):
    rows = {}
    for record in git("ls-tree", "-r", "-z", commit).split(b"\0"):
        if not record:
            continue
        mode, kind, rest = record.split(b" ", 2)
        identity, name = rest.split(b"\t", 1)
        if kind == b"blob":
            rows[name.decode()] = {"git_blob": identity.decode(), "mode": mode.decode()}
    return rows


def ancestor(before, after):
    result = subprocess.run(["git", "-C", str(ROOT), "merge-base", "--is-ancestor", before, after], timeout=60)
    if result.returncode not in (0, 1):
        raise ValueError("Unable to resolve pinned ancestor relationship")
    return result.returncode == 0


def inspect(expected_head):
    actual = git("rev-parse", "HEAD").decode().strip()
    if actual != expected_head:
        raise ValueError("E_INTEGRATION_HEAD: actual HEAD differs from the selected source")
    status = git("status", "--porcelain").decode()
    if status:
        raise ValueError("E_INTEGRATION_DIRTY: commit the selected source before auditing it")
    raw = git("show", actual + ":" + SPEC_PATH)
    spec = json.loads(raw)
    if spec.get("schema") != "hepta.hia.integration-sources.v1":
        raise ValueError("E_INTEGRATION_SPEC: unsupported inventory schema")
    selected, baseline = tree(actual), tree(spec["baseline"]["head"])
    donors = []
    for donor in spec["source_donors"]:
        source, common = tree(donor["head"]), tree(donor["delta_base"])
        paths = donor.get("paths", ["hepta", "tests", "tools", ".github"])
        changed = git("diff", "--no-renames", "--name-only", "-z", donor["delta_base"], donor["head"],
                      "--", *paths).decode().split("\0")
        records = []
        for path in sorted(name for name in changed if name):
            proposed, current, previous = source.get(path), selected.get(path), common.get(path)
            if path in donor["retained_baseline_paths"] and current is not None:
                disposition = "retained"
                relation = "baseline_contract_retained_or_extended"
                reason = donor["retained_baseline_paths"][path]
            elif current == proposed:
                disposition, relation = "retained", "exact_donor_blob"
                reason = "Identical blob and mode in the selected committed tree."
            elif current is None or current == previous:
                disposition, relation = "unintegrated", "missing_or_unchanged_delta_base"
                reason = "The selected delta is absent; require an explicit exclusion or source port."
            else:
                disposition, relation = "reconciled", "different_selected_blob_requires_semantic_review"
                reason = "Combined implementation differs from donor; use documented conflict decisions and fresh tests."
            records.append({"path": path, "disposition": disposition, "blob_relation": relation,
                            "reason": reason, "delta_base": previous, "donor": proposed,
                            "integration_baseline": baseline.get(path), "selected": current})
        donors.append({"pr": donor["pr"], "head": donor["head"], "delta_base": donor["delta_base"],
                       "head_is_ancestor_of_selected": ancestor(donor["head"], actual),
                       "actual_merge_base_with_selected": git("merge-base", donor["head"], actual).decode().strip(),
                       "disposition_counts": dict(Counter(row["disposition"] for row in records)), "files": records})
    earlier = [{**row, "head_is_ancestor_of_baseline": ancestor(row["head"], spec["baseline"]["head"]),
                "head_is_ancestor_of_selected": ancestor(row["head"], actual)}
               for row in spec["earlier_branch_dispositions"]]
    missing = [{"pr": donor["pr"], "path": row["path"]} for donor in donors for row in donor["files"]
               if row["disposition"] == "unintegrated"]
    return {"schema": "hepta.hia.integration-inventory.v1", "source_commit": actual,
            "source_tree": git("rev-parse", actual + "^{tree}").decode().strip(), "source_status": status,
            "spec_sha256": sha256(raw).hexdigest(), "baseline": spec["baseline"],
            "donors": donors, "earlier_branches": earlier,
            "unintegrated_selected_paths": missing, "explicit_unintegrated_scope": spec["unintegrated"],
            "historical_experiment_identities": spec["historical_experiment_identities"],
            "claims": {**spec["claims"], "no_selected_source_paths_obviously_missing": not missing}}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    if args.output.exists() or args.output.is_symlink():
        parser.error("output must be a new path")
    report = inspect(args.expected_head)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as stream:
        json.dump(report, stream, sort_keys=True, indent=2)
        stream.write("\n")
    print(json.dumps({"source_commit": report["source_commit"],
                      "unintegrated_selected_paths": report["unintegrated_selected_paths"]}))
    return 0 if not report["unintegrated_selected_paths"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
