"""Persistent campaign interval bounds checked against retained measurements."""
from copy import deepcopy
from hashlib import sha256
import io
import json
from pathlib import Path
import tarfile
import unittest
from unittest.mock import patch

from tools import replay_hia_ndu_persistent_ranker as replay


class PersistentCostIntervalTests(unittest.TestCase):
    def fixture(self):
        cells = [{"arm": "ordinary_scalar", "wall_ns": 80,
                  "calls": [{"wall_ns": 20}, {"wall_ns": 30}]}]
        for arm in ("prepared_ndu", "persistent_ndu"):
            cost = {"close_wall_ns": 5, "attempts": [
                {"wall_ns": 20, "queue_wait_ns": 0, "caller_wall_ns": 20},
                {"wall_ns": 30, "queue_wait_ns": 2, "caller_wall_ns": 32}]}
            if arm == "persistent_ndu":
                cost["preparation_wall_ns"] = 10
            else:
                cost["preparation"] = {"preparation_wall_ns": 10}
            cells.append({"arm": arm, "wall_ns": 120,
                          "calls": [{"wall_ns": 40}, {"wall_ns": 50}], "owner_cost": cost})
        return cells, {"actual_campaign_wall_ns_to_summary": 350,
                       "nested_cell_wall_added_again": False}

    def test_serial_owner_intervals_fit_their_enclosing_measurements(self):
        replay.check_cost_intervals(*self.fixture())

    def test_campaign_requires_all_cells_and_no_nested_double_count(self):
        for field, value in (("actual_campaign_wall_ns_to_summary", 319),
                             ("nested_cell_wall_added_again", True)):
            cells, report = self.fixture()
            report[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                replay.check_cost_intervals(cells, report)

    def test_every_arm_call_must_fit_its_cell(self):
        for arm in range(3):
            cells, report = self.fixture()
            cells[arm]["calls"][0]["wall_ns"] = cells[arm]["wall_ns"]
            with self.subTest(arm=arm), self.assertRaisesRegex(ValueError, "call intervals exceed"):
                replay.check_cost_intervals(cells, report)

    def test_both_owner_profiles_validate_queue_caller_and_call_containment(self):
        for arm in (1, 2):
            for mutation in ("negative", "boolean", "float", "caller_float", "sum", "outer"):
                cells, report = self.fixture()
                attempt = cells[arm]["owner_cost"]["attempts"][0]
                if mutation in ("negative", "boolean", "float"):
                    attempt["queue_wait_ns"] = {"negative": -1, "boolean": True, "float": 0.5}[mutation]
                    attempt["caller_wall_ns"] = attempt["wall_ns"] + attempt["queue_wait_ns"]
                elif mutation == "caller_float":
                    attempt["caller_wall_ns"] = float(attempt["caller_wall_ns"])
                elif mutation == "sum":
                    attempt["caller_wall_ns"] += 1
                else:
                    attempt["queue_wait_ns"] = 21
                    attempt["caller_wall_ns"] = 41
                with self.subTest(arm=arm, mutation=mutation), self.assertRaises(ValueError):
                    replay.check_cost_intervals(cells, report)

    def test_both_owner_preparation_and_close_remain_inside_the_cell(self):
        for arm in (1, 2):
            for field in ("preparation_wall_ns", "close_wall_ns"):
                cells, report = self.fixture()
                cost = cells[arm]["owner_cost"]
                target = cost["preparation"] if field == "preparation_wall_ns" and arm == 1 else cost
                target[field] = 100
                with self.subTest(arm=arm, field=field), self.assertRaisesRegex(ValueError, "owner serial intervals"):
                    replay.check_cost_intervals(cells, report)

    def test_owner_attempt_denominator_is_bound_to_calls(self):
        for arm in (1, 2):
            for delta in (-1, 1):
                cells, report = self.fixture()
                attempts = cells[arm]["owner_cost"]["attempts"]
                attempts.pop() if delta < 0 else attempts.append(deepcopy(attempts[-1]))
                with self.subTest(arm=arm, delta=delta), self.assertRaisesRegex(ValueError, "attempts differ"):
                    replay.check_cost_intervals(cells, report)

    def test_outer_timers_require_positive_exact_integers(self):
        for field in ("campaign", "cell", "call"):
            for invalid in (0, -1, True, 1.0):
                cells, report = self.fixture()
                target, key = ((report, "actual_campaign_wall_ns_to_summary") if field == "campaign"
                               else (cells[0], "wall_ns") if field == "cell"
                               else (cells[0]["calls"][0], "wall_ns"))
                target[key] = invalid
                with self.subTest(field=field, invalid=invalid), self.assertRaises(ValueError):
                    replay.check_cost_intervals(cells, report)




if __name__ == "__main__":
    unittest.main()
