#!/usr/bin/env python3
"""Replay unchanged retained measurements and four cost-record mutations."""
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
import types
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tests import test_hia_ndu_prepared_cost_intervals as fixtures
from tools import replay_hia_ndu_prepared_ranker as candidate

BASE = "20eace37747fde9aa0fc9c14cdb0159db30f5161"
original_source = subprocess.check_output([
    "git", "show", BASE + ":tools/replay_hia_ndu_prepared_ranker.py"], cwd=ROOT)
original = types.ModuleType("original_prepared_replay")
original.__file__ = candidate.__file__
exec(compile(original_source, "original_prepared_replay.py", "exec"), original.__dict__)
fixtures.RetainedPreparedCostIntervalTests.setUpClass()
helper = fixtures.RetainedPreparedCostIntervalTests()
baseline = helper.replay_files(helper.files)
cases = []

for field, value in (("actual_campaign_wall_ns_to_summary", 1),
                     ("nested_cell_wall_added_again", True)):
    files = dict(helper.files)
    report = json.loads(files["result.json"])
    report[field] = value
    files["result.json"] = candidate.wire(report)
    cases.append((field, files))


def negative_queue(cells):
    cell = next(cell for cell in cells if cell["arm"] == "prepared_ndu")
    attempt = cell["prepared_cost"]["attempts"][0]
    attempt["queue_wait_ns"] = -1
    attempt["caller_wall_ns"] = attempt["wall_ns"] - 1


def call_exceeds_cell(cells):
    cell = next(cell for cell in cells if cell["arm"] == "one_shot_ndu")
    cell["calls"][0]["wall_ns"] = cell["wall_ns"] + 1


cases.extend((name, helper.changed_cells(mutate)) for name, mutate in (
    ("negative_queue_satisfying_old_equality", negative_queue),
    ("call_timer_exceeds_cell", call_exceeds_cell)))
results = []
for name, files in cases:
    with patch.object(fixtures, "replay", original):
        old = helper.replay_files(files)
    assert old["raw_identity_and_cost_arithmetic_consistent"] is True
    try:
        helper.replay_files(files)
    except ValueError as error:
        results.append({"case": name, "original_accepts_inconsistent_costs": True,
                        "candidate_rejects": True, "candidate_error": str(error)})
    else:
        raise AssertionError("candidate accepted the inconsistent cost case: " + name)

print(json.dumps({"schema": "hepta.hia.ndu-cost-interval-regression.v1",
    "base_commit": BASE,
    "base_replay_sha256": sha256(original_source).hexdigest(),
    "candidate_replay_sha256": sha256(Path(candidate.__file__).read_bytes()).hexdigest(),
    "retained_archive_sha256": "6f5017ea1de8708e304caa02988d6cf176b3a29df35bbc05881317d7687ffdd7",
    "registration_sha256": sha256(helper.files["registration.json"]).hexdigest(),
    "original_measurements_replay": baseline,
    "counterexamples": results, "new_native_calls": 0,
    "new_timing_experiment": False, "economic_benefit_established": False,
    "p2_acceptance": "HOLD"}, indent=2, sort_keys=True))
