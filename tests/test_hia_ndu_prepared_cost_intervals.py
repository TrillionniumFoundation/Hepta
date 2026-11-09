"""Measured interval consistency; no timing or economic-benefit attestation."""
from copy import deepcopy
from hashlib import sha256
import io
import json
from pathlib import Path
import tarfile
import unittest
from unittest.mock import patch

from tools import replay_hia_ndu_prepared_ranker as replay


class PreparedCostIntervalTests(unittest.TestCase):
    def fixture(self):
        # Independent hand-sized serial measurements. The full replay checks
        # the registered cohort, raw bytes and analysis before these bounds.
        cells = [
            {"arm": "one_shot_ndu", "wall_ns": 100,
             "calls": [{"wall_ns": 30}, {"wall_ns": 40}]},
            {"arm": "ordinary_scalar", "wall_ns": 80,
             "calls": [{"wall_ns": 20}, {"wall_ns": 30}]},
            {"arm": "prepared_ndu", "wall_ns": 120,
             "calls": [{"wall_ns": 40}, {"wall_ns": 50}],
             "prepared_cost": {"preparation": {"preparation_wall_ns": 10},
                 "close_wall_ns": 5, "attempts": [
                     {"wall_ns": 20, "queue_wait_ns": 0, "caller_wall_ns": 20},
                     {"wall_ns": 30, "queue_wait_ns": 2, "caller_wall_ns": 32}]}}]
        return cells, {"actual_campaign_wall_ns_to_summary": 350,
                       "nested_cell_wall_added_again": False}

    def test_nested_costs_are_bounded_with_outer_bookkeeping_retained(self):
        replay.check_cost_intervals(*self.fixture())

    def test_campaign_cannot_omit_any_serial_cell(self):
        cells, report = self.fixture()
        report["actual_campaign_wall_ns_to_summary"] = 299
        with self.assertRaisesRegex(ValueError, "cell intervals exceed"):
            replay.check_cost_intervals(cells, report)

    def test_campaign_cannot_add_nested_cells_twice(self):
        cells, report = self.fixture()
        report["nested_cell_wall_added_again"] = True
        with self.assertRaisesRegex(ValueError, "nested cell costs again"):
            replay.check_cost_intervals(cells, report)

    def test_call_intervals_cannot_exceed_their_cell(self):
        cells, report = self.fixture()
        cells[0]["calls"][0]["wall_ns"] = 61
        with self.assertRaisesRegex(ValueError, "call intervals exceed"):
            replay.check_cost_intervals(cells, report)

    def test_invalid_measured_integer_fields_are_refused(self):
        cells, report = self.fixture()
        fields = [(report, "actual_campaign_wall_ns_to_summary"),
                  (cells[0], "wall_ns"), (cells[0]["calls"][0], "wall_ns"),
                  (cells[2]["prepared_cost"]["preparation"], "preparation_wall_ns"),
                  (cells[2]["prepared_cost"], "close_wall_ns"),
                  (cells[2]["prepared_cost"]["attempts"][0], "wall_ns"),
                  (cells[2]["prepared_cost"]["attempts"][0], "caller_wall_ns")]
        for target, name in fields:
            original = target[name]
            for invalid in (0, -1, True, 1.0):
                target[name] = invalid
                with self.subTest(name=name, invalid=invalid), self.assertRaises(ValueError):
                    replay.check_cost_intervals(cells, report)
            target[name] = original

    def test_queue_cannot_use_negative_boolean_or_fractional_time(self):
        cells, report = self.fixture()
        attempt = cells[2]["prepared_cost"]["attempts"][0]
        for invalid in (-1, True, 0.5):
            attempt["queue_wait_ns"] = invalid
            attempt["caller_wall_ns"] = attempt["wall_ns"] + invalid
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                replay.check_cost_intervals(cells, report)

    def test_prepared_caller_and_outer_call_must_contain_service_and_queue(self):
        for mutation in ("sum", "outer"):
            cells, report = self.fixture()
            attempt = cells[2]["prepared_cost"]["attempts"][0]
            if mutation == "sum":
                attempt["caller_wall_ns"] += 1
            else:
                attempt["queue_wait_ns"] = 21
                attempt["caller_wall_ns"] = 41
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, "caller interval"):
                replay.check_cost_intervals(cells, report)

    def test_preparation_and_close_remain_inside_the_serial_cell(self):
        for field in ("preparation_wall_ns", "close_wall_ns"):
            cells, report = self.fixture()
            cost = cells[2]["prepared_cost"]
            target = cost["preparation"] if field == "preparation_wall_ns" else cost
            target[field] = 100
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "prepared serial intervals"):
                replay.check_cost_intervals(cells, report)

    def test_missing_or_extra_attempt_cannot_escape_call_interval_checks(self):
        for delta in (-1, 1):
            cells, report = self.fixture()
            attempts = cells[2]["prepared_cost"]["attempts"]
            attempts.pop() if delta < 0 else attempts.append(deepcopy(attempts[-1]))
            with self.subTest(delta=delta), self.assertRaisesRegex(ValueError, "attempts differ"):
                replay.check_cost_intervals(cells, report)


class RetainedPreparedCostIntervalTests(unittest.TestCase):
    """Exercise the real replay using retained original bytes, not new timings."""
    @classmethod
    def setUpClass(cls):
        archive_path = (Path(__file__).resolve().parents[1] / "review-evidence"
                        / "hia-ndu-prepared-20261108-5e6c" / "final-originals.tar.xz")
        raw = archive_path.read_bytes()
        if sha256(raw).hexdigest() != "6f5017ea1de8708e304caa02988d6cf176b3a29df35bbc05881317d7687ffdd7":
            raise AssertionError("retained archive identity differs")
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:xz") as archive:
            cls.files = {member.name: archive.extractfile(member).read()
                         for member in archive.getmembers() if member.isfile()}

    def replay_files(self, files):
        # No extraction or native process execution: substitute only the
        # retained campaign reads; the actual checker reads itself normally.
        root = Path("/__retained_prepared_ranking_campaign__")
        original_read = Path.read_bytes

        def read(path):
            return files[str(path.relative_to(root))] if path.is_relative_to(root) else original_read(path)

        registration = sha256(files["registration.json"]).hexdigest()
        with patch.object(Path, "read_bytes", read):
            return replay.replay(root, registration)

    def changed_cells(self, mutate):
        files = dict(self.files)
        cells = [json.loads(line) for line in files["cell-ledger.jsonl"].splitlines()]
        mutate(cells)
        files["cell-ledger.jsonl"] = b"\n".join(replay.wire(cell) for cell in cells) + b"\n"
        for cell in cells:
            name = "h%02d-p%02d-%s.json" % (cell["horizon"], cell["pair"], cell["arm"])
            files[name] = replay.wire(cell)
        return files

    def test_original_registered_bytes_still_replay_without_native_execution(self):
        result = self.replay_files(self.files)
        self.assertTrue(result["nested_cost_intervals_reconciled"])
        self.assertEqual(result["original_native_calls"], 1020)
        self.assertEqual(result["cells_replayed"], 72)
        self.assertFalse(result["economic_benefit_established"])

    def test_campaign_cost_mutations_are_rejected_with_all_original_cells_retained(self):
        for field, value in (("actual_campaign_wall_ns_to_summary", 1),
                             ("nested_cell_wall_added_again", True)):
            files = dict(self.files)
            report = json.loads(files["result.json"])
            report[field] = value
            files["result.json"] = replay.wire(report)
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.replay_files(files)

    def test_negative_queue_cannot_hide_behind_the_existing_sum_equality(self):
        def mutate(cells):
            cell = next(cell for cell in cells if cell["arm"] == "prepared_ndu")
            attempt = cell["prepared_cost"]["attempts"][0]
            attempt["queue_wait_ns"] = -1
            attempt["caller_wall_ns"] = attempt["wall_ns"] - 1

        with self.assertRaisesRegex(ValueError, "invalid measured integer"):
            self.replay_files(self.changed_cells(mutate))

    def test_call_timer_cannot_exceed_a_cell_with_unchanged_paired_analysis(self):
        def mutate(cells):
            cell = next(cell for cell in cells if cell["arm"] == "one_shot_ndu")
            cell["calls"][0]["wall_ns"] = cell["wall_ns"] + 1

        with self.assertRaisesRegex(ValueError, "call intervals exceed"):
            self.replay_files(self.changed_cells(mutate))


if __name__ == "__main__":
    unittest.main()
