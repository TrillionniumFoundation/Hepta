"""Adversarial admission controls; synthetic records are never qualification evidence."""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import unittest

from tools.hia_native_cold_admission import admit_native_report, read_json


ROOT = Path(__file__).resolve().parents[1]


class NativeColdAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.compiler = b"synthetic-component-admission-control"
        self.observer = bytes(1107)
        self.sources = {"control.hepta": sha256(b"control").hexdigest()}
        metadata = json.loads((ROOT / "docs/HIA_NATIVE_SELFHOST_METADATA.json").read_bytes())
        self.contract = {"profile": metadata["profile"],
                         "native_cold_qualification": metadata["native_cold_qualification"]}
        native = self.contract["native_cold_qualification"]
        self.report = {"schema": "hepta.hia.selfhost-cold-replay.v2",
            "status": "NATIVE_COLD_SELFHOST_REPLAY_PASS", "returncode": 0,
            "profile": self.contract["profile"], "source_manifest": self.sources,
            "checks": {name: True for name in native["checks"]},
            "qualification_wall_limit_seconds": 180, "cleanup_wall_limit_seconds": 3,
            "nested_wall_elapsed_ns": 1, "cleanup_wall_elapsed_ns": 0,
            "generation_sha256": [sha256(self.compiler).hexdigest()] * 3,
            "modified_generation_sha256": ["1" * 64, "2" * 64, "2" * 64],
            "seed_sha256": "3" * 64, "native_flat_observer_hex": self.observer.hex(),
            "scheduler": {**native["scheduler"], "peak_phase_workers": 2,
                "peak_archive_workers": 1, "peak_pending_archives": 2, "peak_unsealed_phases": 4},
            "qualification_families": {row["family"]: {"original": True, "modified": True}
                for row in native["phase_plan_catalog"] if row["kind"] == "qualification"},
            "phases": [{**row, "returncode": 0, "nodes_retained": row["node_count"],
                "cleanup_complete": True, "sealed": True,
                "journal_sha256": "4" * 64, "archive_sha256": "5" * 64}
                for row in native["phase_plan_catalog"]]}

    def admit(self, value):
        return admit_native_report(self.compiler, json.dumps(value).encode(),
            contract=self.contract, sources=self.sources, observer_bytes=self.observer)

    def test_exact_native_contract_accepts_control_record(self):
        self.assertEqual(self.admit(self.report), self.sources)

    def test_legacy_and_lookalike_conclusions_are_rejected(self):
        for field, value in (("schema", "hepta.hia.selfhost-cold-replay.v1"),
                ("status", "COLD_SELFHOST_REPLAY_PASS"), ("returncode", False),
                ("profile", "foreign"), ("source_manifest", {}), ("seed_sha256", "0" * 63),
                ("generation_sha256", ["1" * 64] * 3),
                ("modified_generation_sha256", ["2" * 64] * 3),
                ("native_flat_observer_hex", "00")):
            with self.subTest(field=field):
                changed = deepcopy(self.report)
                changed[field] = value
                with self.assertRaises(ValueError):
                    self.admit(changed)

    def test_time_and_scheduler_bounds_are_exact_integer_controls(self):
        for field, value in (("qualification_wall_limit_seconds", 181),
                ("cleanup_wall_limit_seconds", 4), ("nested_wall_elapsed_ns", 180_000_000_001),
                ("nested_wall_elapsed_ns", True), ("cleanup_wall_elapsed_ns", 3_000_000_001),
                ("cleanup_wall_elapsed_ns", -1)):
            with self.subTest(field=field, value=value):
                changed = deepcopy(self.report)
                changed[field] = value
                with self.assertRaises(ValueError):
                    self.admit(changed)
        for field, value in (("phase_workers", 3), ("archive_workers", True),
                ("peak_phase_workers", 3), ("peak_archive_workers", 0),
                ("peak_pending_archives", 3), ("peak_unsealed_phases", 5), ("foreign", 1)):
            with self.subTest(field=field):
                changed = deepcopy(self.report)
                changed["scheduler"][field] = value
                with self.assertRaises(ValueError):
                    self.admit(changed)

    def test_missing_fields_false_checks_and_partial_families_are_rejected(self):
        for field in self.report:
            with self.subTest(missing=field):
                changed = deepcopy(self.report)
                del changed[field]
                with self.assertRaises(ValueError):
                    self.admit(changed)
        for value in (False, 1, "true"):
            changed = deepcopy(self.report)
            changed["checks"][next(iter(changed["checks"]))] = value
            with self.assertRaises(ValueError):
                self.admit(changed)
        changed = deepcopy(self.report)
        changed["checks"]["isolated_python_without_site"] = True
        with self.assertRaises(ValueError):
            self.admit(changed)
        for value in (False, 1):
            changed = deepcopy(self.report)
            changed["qualification_families"]["capacity"]["modified"] = value
            with self.assertRaises(ValueError):
                self.admit(changed)

    def test_phase_omission_duplicates_node_loss_and_order_are_rejected(self):
        mutations = []
        changed = deepcopy(self.report)
        changed["phases"].pop()
        mutations.append(changed)
        changed = deepcopy(self.report)
        changed["phases"][-1] = deepcopy(changed["phases"][-2])
        mutations.append(changed)
        changed = deepcopy(self.report)
        changed["phases"].reverse()
        mutations.append(changed)
        for field, value in (("nodes_retained", 0), ("returncode", False),
                ("sealed", 1), ("cleanup_complete", False), ("journal_sha256", "bad"),
                ("plan_sha256", "0" * 64), ("family", "foreign")):
            changed = deepcopy(self.report)
            changed["phases"][0][field] = value
            mutations.append(changed)
        for index, changed in enumerate(mutations):
            with self.subTest(mutation=index), self.assertRaises(ValueError):
                self.admit(changed)

    def test_duplicate_keys_and_non_json_numbers_are_rejected(self):
        for raw in (b'{"returncode":1,"returncode":0}', b'{"x":NaN}', b'{"x":Infinity}',
                    b'{"phases":[{"sealed":false,"sealed":true}]}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                read_json(raw)


if __name__ == "__main__":
    unittest.main()
