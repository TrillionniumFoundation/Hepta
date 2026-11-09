#!/usr/bin/env python3
"""Replay unchanged persistent measurements and eight metadata mutations."""
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
import types
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tests import test_hia_ndu_persistent_cost_intervals as fixtures
from tools import replay_hia_ndu_persistent_ranker as candidate

BASE = "20eace37747fde9aa0fc9c14cdb0159db30f5161"
original_source = subprocess.check_output([
    "git", "show", BASE + ":tools/replay_hia_ndu_persistent_ranker.py"], cwd=ROOT)
original = types.ModuleType("original_persistent_replay")
original.__file__ = candidate.__file__
exec(compile(original_source, "original_persistent_replay.py", "exec"), original.__dict__)
fixtures.RetainedPersistentCostIntervalTests.setUpClass()
helper = fixtures.RetainedPersistentCostIntervalTests()
baseline = helper.replay_files(helper.files)
cases = []

for field, value in (("actual_campaign_wall_ns_to_summary", 1),
                     ("nested_cell_wall_added_again", True)):
    files = dict(helper.files)
    report = json.loads(files["result.json"])
    report[field] = value
    files["result.json"] = candidate.wire(report)
    cases.append((field, files))

for arm in ("prepared_ndu", "persistent_ndu"):
    def caller_exceeds_call(cells):
        cell = next(cell for cell in cells if cell["arm"] == arm)
        attempt = cell["owner_cost"]["attempts"][0]
        attempt["caller_wall_ns"] = cell["calls"][0]["wall_ns"] + 1
        attempt["queue_wait_ns"] = attempt["caller_wall_ns"] - attempt["wall_ns"]

    cases.append((arm + "_caller_exceeds_call", helper.changed_cells(caller_exceeds_call)))


def call_exceeds_cell(cells):
    cell = next(cell for cell in cells if cell["arm"] == "ordinary_scalar")
    cell["calls"][0]["wall_ns"] = cell["wall_ns"] + 1


cases.append(("call_timer_exceeds_cell", helper.changed_cells(call_exceeds_cell)))
for field, value in (("horizon", True), ("pair", 1.0), ("complete", 1)):
    files = dict(helper.files)
    report = json.loads(files["result.json"])
    row = report["analysis"][0] if field == "horizon" else report["analysis"][0]["pairs"][0]
    row[field] = value
    files["result.json"] = candidate.wire(report)
    cases.append(("analysis_type_" + field, files))

results = []
for name, files in cases:
    with patch.object(fixtures, "replay", original):
        old = helper.replay_files(files)
    assert old["raw_frame_identity_cleanup_and_cost_arithmetic_consistent"] is True
    try:
        helper.replay_files(files)
    except ValueError as error:
        results.append({"case": name, "original_accepts_inconsistent_record": True,
                        "candidate_rejects": True, "candidate_error": str(error)})
    else:
        raise AssertionError("candidate accepted the inconsistent case: " + name)

print(json.dumps({"schema": "hepta.hia.ndu-persistent-cost-interval-regression.v1",
    "base_commit": BASE,
    "base_replay_sha256": sha256(original_source).hexdigest(),
    "candidate_replay_sha256": sha256(Path(candidate.__file__).read_bytes()).hexdigest(),
    "retained_archive_sha256": "7f46424cdfb8171650bcf77dfb9b0c25412b4e877c413a90a9108b7604cd8cfd",
    "registration_sha256": sha256(helper.files["registration.json"]).hexdigest(),
    "original_measurements_replay": baseline,
    "counterexamples": results, "new_native_calls": 0,
    "new_timing_experiment": False, "economic_benefit_established": False,
    "p2_acceptance": "HOLD"}, indent=2, sort_keys=True))
