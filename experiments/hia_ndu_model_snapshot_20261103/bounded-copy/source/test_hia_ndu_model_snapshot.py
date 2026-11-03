"""Bounded finite snapshots keep all validation and caller isolation guarantees."""
from copy import deepcopy
from pathlib import Path
import types
import unittest
from unittest.mock import patch

from hepta.hia_ndu_cost import CostModelError, validate_model
from tests.test_hia_ndu_cost import fixture


class ModelSnapshotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).resolve().parents[1] / "benchmarks/hia_ndu_cost/historical_hia_ndu_cost_18291446e048f760f5519823e865727ef51db11a.py"
        cls.old = types.ModuleType("hepta._snapshot_test_historical")
        cls.old.__package__ = "hepta"
        exec(compile(path.read_bytes(), str(path), "exec"), cls.old.__dict__)

    def test_detaches_every_container_and_preserves_shared_input_values(self):
        model = fixture(4)
        model["variants"][1]["valid"] = model["variants"][0]["valid"]
        before = deepcopy(model)
        snapshot = validate_model(model)
        self.assertEqual(snapshot, self.old.validate_model(model))
        snapshot["baseline"]["latency_ns"][0] = 19
        snapshot["variants"][0]["valid"][0] = False
        self.assertTrue(snapshot["variants"][1]["valid"][0])
        snapshot["variants"][1]["latency_ns"].clear()
        snapshot["variants"][0]["status"] = "rejected"
        snapshot["decision"]["gate_ns"] = 999
        snapshot["ready"].append("a")
        snapshot["variants"].clear()
        self.assertEqual(model, before)

    def test_tuple_array_compatibility_is_preserved(self):
        model = fixture(4)
        model["ready"] = tuple(model["ready"])
        model["baseline"]["latency_ns"] = tuple(model["baseline"]["latency_ns"])
        for variant in model["variants"]:
            variant["valid"] = tuple(variant["valid"])
            variant["latency_ns"] = tuple(variant["latency_ns"])
        model["variants"] = tuple(model["variants"])
        self.assertEqual(validate_model(model), self.old.validate_model(model))

    def test_empty_or_modified_comparison_registration_is_refused(self):
        from tools import qualify_hia_ndu_model_snapshot as qualification
        self.assertEqual(qualification.load_protocol()["cases"], 256)
        for raw in (b'{}', qualification.PROTOCOL.read_bytes().replace(b'"cases": 256', b'"cases": 0')):
            with patch.object(Path, "read_bytes", return_value=raw):
                with self.assertRaisesRegex(ValueError, "changed model-snapshot registration"):
                    qualification.load_protocol()

    def test_all_leaf_mutations_preserve_rejection(self):
        paths = []
        def visit(value, path):
            if type(value) is dict:
                for key, child in value.items():
                    visit(child, (*path, key))
            elif type(value) is list:
                for key, child in enumerate(value):
                    visit(child, (*path, key))
            else:
                paths.append(path)
        original = fixture(4)
        visit(original, ())
        for path in paths:
            for invalid in (None, [], {}, 0.5, "\ud800", "x" * 1000, 1 << 500):
                model = deepcopy(original)
                owner = model
                for key in path[:-1]:
                    owner = owner[key]
                owner[path[-1]] = invalid
                with self.subTest(path=path, kind=type(invalid).__name__):
                    with self.assertRaises((ValueError, TypeError)):
                        self.old.validate_model(model)
                    with self.assertRaises(CostModelError):
                        validate_model(model)

    def test_cycles_and_oversized_containers_are_bounded_before_copy(self):
        models = []
        for field in ("variants", "ready"):
            model = fixture()
            model[field] = [None] * 100000
            models.append(model)
        model = fixture()
        model["baseline"]["latency_ns"] = [None] * 100000
        models.append(model)
        model = fixture()
        model["variants"][0]["valid"].append(model)
        models.append(model)
        model = fixture()
        model["variants"][0]["latency_ns"] = model["variants"]
        models.append(model)
        for model in models:
            with self.assertRaises(CostModelError):
                validate_model(model)

    def test_non_builtin_types_never_invoke_conversion_hooks(self):
        class EvilList(list):
            def __iter__(self):
                raise AssertionError("custom iterator executed")
        class EvilDict(dict):
            def __iter__(self):
                raise AssertionError("custom dictionary iterator executed")
        class EvilStr(str):
            def __eq__(self, other):
                raise AssertionError("custom equality executed")
            __hash__ = str.__hash__
        class EvilInt(int):
            def __le__(self, other):
                raise AssertionError("custom comparison executed")
        models = [EvilDict(fixture())]
        for field, value in (("ready", EvilList()), ("schema", EvilStr(fixture()["schema"])),
                             ("budget_ns", EvilInt(1))):
            model = fixture(); model[field] = value; models.append(model)
        model = fixture(); model["variants"][0]["status"] = EvilStr("verified"); models.append(model)
        for model in models:
            with self.assertRaises(CostModelError):
                validate_model(model)

if __name__ == "__main__":
    unittest.main()
