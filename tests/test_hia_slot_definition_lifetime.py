"""Additional definition controls; original Slot Source3/Native6/Native4 stay intact."""
from __future__ import annotations
import copy
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import types
import unittest

from tests.hia_slot_operations_component_fixture import ComponentFixture
from tests.hia_slot_operations_qualification_support import (
    canonical, clean_environment, pin, product_snapshot, read_json, regular_bytes,
    run_owned, successful_exit, write_json)
from tools.build_hia_slot_mechanical_bundle import create
from tools.read_hia_slot_definition_lifetime import (
    decode_value, evaluate_step, readback, validate_fixture, validate_limits)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/slot_definition_lifetime_controls.json"
PREFIX = "HEPTA_HIA_SLOT_DEFINITION_ORIGINAL_NATIVE4"


def external_binding():
    # Parse the explicit authority first. A later read never replaces an
    # expected size or digest. Missing/partial/invalid inputs stay recorded HOLD.
    errors = []
    result = {"schema": "hepta.slot.definition.original-native4-binding.v1",
              "class_evidence": os.environ.get(PREFIX + "_EVIDENCE"),
              "readback": None, "terminal": None, "errors": errors}
    for key in ("readback", "terminal"):
        name = PREFIX + "_" + key.upper()
        values = {field: os.environ.get(name + "_" + field.upper())
                  for field in ("path", "bytes", "sha256")}
        try:
            if any(value is None for value in values.values()):
                raise ValueError("all explicit PATH/BYTES/SHA256 fields are required")
            if not values["bytes"].isdecimal() or str(int(values["bytes"])) != values["bytes"]:
                raise ValueError("size must be canonical decimal")
            size = int(values["bytes"])
            digest = values["sha256"]
            if (size <= 0 or len(digest) != 64
                    or any(value not in "0123456789abcdef" for value in digest)):
                raise ValueError("invalid explicit byte/digest binding")
            path = Path(values["path"])
            if not path.is_absolute():
                raise ValueError("explicit binding path must be absolute")
            result[key] = {"path": str(path), "bytes": size, "sha256": digest}
        except (ValueError, TypeError) as error:
            errors.append({"field": key, "message": str(error), "supplied": values})
    if result["class_evidence"] is None:
        errors.append({"field": "class_evidence", "message": "complete original class evidence is absent"})
    else:
        path = Path(result["class_evidence"])
        if not path.is_absolute():
            errors.append({"field": "class_evidence", "message": "class evidence must be an absolute path"})
    return result


class SlotDefinitionLifetimeSourceTests(unittest.TestCase):
    def test_00_complete_closed_23_control_fixture(self):
        fixture = read_json(FIXTURE)
        validate_fixture(fixture)
        self.assertEqual(len(fixture["cases"]), 23)
        self.assertEqual(fixture["source_methods"], 2)
        self.assertEqual(fixture["native_methods"], 1)
        self.assertEqual(fixture["cases"][14]["external_scopes"], ["observations"])
        self.assertEqual(fixture["cases"][15]["external_scopes"], ["installed"])
        self.assertEqual(fixture["cases"][19]["external_scopes"], ["admission", "installed"])

    def test_01_independent_reader_refuses_scope_type_and_counter_loss(self):
        fixture = read_json(FIXTURE)
        for mutation in ("missing", "duplicate", "reordered", "scope", "reflection"):
            changed = copy.deepcopy(fixture)
            if mutation == "missing":
                changed["cases"].pop()
            elif mutation == "duplicate":
                changed["cases"][1] = changed["cases"][0]
            elif mutation == "reordered":
                changed["cases"][0], changed["cases"][1] = changed["cases"][1], changed["cases"][0]
            elif mutation == "scope":
                changed["cases"][14]["external_scopes"] = []
            else:
                changed["qualification_limits"]["public_reflection_closed"] = True
            with self.assertRaises((ValueError, AssertionError)):
                validate_fixture(changed)
        for value in ({"bytes_hex": "0"}, {"bytes_hex": "AF"},
                      {"bytes_hex": "", "extra": True},
                      {"type": "list", "items": [], "extra": 1},
                      {"type": "dict", "items": [[1, "a"], [1, "b"]]},
                      {"type": "unsupported", "items": []}):
            with self.assertRaises((ValueError, AssertionError)):
                decode_value(value)
        self.assertEqual(decode_value({"bytes_hex": ""}), b"")
        self.assertEqual(type(decode_value({"type": "tuple", "items": []})), tuple)
        self.assertEqual(type(decode_value({"type": "list", "items": []})), list)
        for actual in ([b"", ""], [[], ()], [1, True], [0.0, -0.0]):
            with self.assertRaises((ValueError, AssertionError)):
                evaluate_step({"id": "typed-pair", "relation": "pair"}, actual, pid=123)
        before = {"schema": "hepta.slot.mechanical.execution-counters.v1",
            "pid": 123, "overflow": False, **{name: [0] * 16 for name in
                ("public_calls", "raw_frame_calls", "initialized", "final_receipts")}}
        actual = {"original": 17, "candidate": 17, "original_trace": [{"real": b""}],
            "candidate_trace": [{"real": b""}], "before": before,
            "after": copy.deepcopy(before), "entries": [{"actual_entry_returned": True}],
            "forbidden": []}
        # A claimed match/entry is insufficient when real C INITIALIZE/FINALIZE
        # counters did not move. This synthetic negative is not a native witness.
        with self.assertRaises((ValueError, AssertionError)):
            evaluate_step({"id": "false-native-pass", "relation": "healthy", "mode": 5, "count": 1},
                          actual, pid=123)
        limits = dict(fixture["qualification_limits"])
        limits["all_input_equivalence"] = True
        with self.assertRaises((ValueError, AssertionError)):
            validate_limits(limits)


class SlotDefinitionLifetimeNativeTests(ComponentFixture, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.fixture = read_json(FIXTURE)
        validate_fixture(cls.fixture)
        cls.base = cls.folder / "explicit-base-v1.json"
        write_json(cls.base, {
            "schema": "hepta.hia.native-helpers.v1", "target": "linux-x86_64-lp64",
            "abi": "hia-byte-six-argument-v1", "helpers": [
                {"selector": "HEPTA_HIA_SLOT_LEDGER_MANIFEST", "manifest_path": str(cls.decision),
                 "manifest_sha256": sha256(regular_bytes(cls.decision)).hexdigest()},
                {"selector": "HEPTA_HIA_SLOT_OPERATIONS_MANIFEST", "manifest_path": str(cls.controller),
                 "manifest_sha256": sha256(regular_bytes(cls.controller)).hexdigest()}]})
        cls.base_sha256 = sha256(regular_bytes(cls.base)).hexdigest()
        cls.bundle = cls.folder / "explicit-v5.json"
        receipt = ROOT / "hepta/_slot_mechanical_build.json"
        cls.bundle_pin = create(ROOT / "hepta", cls.base, cls.base_sha256,
                                sha256(regular_bytes(receipt)).hexdigest(), cls.bundle)
        cls.bundle_bytes = regular_bytes(cls.bundle)
        names = tuple(sorted(set(cls.inputs) | set(cls.fixture["control_files"])))
        cls.control_sources = product_snapshot(ROOT, names)
        cls.control_freeze = cls.folder / "control-source-freeze.json"
        write_json(cls.control_freeze, {
            "schema": "hepta.slot.definition.control-source-freeze.v1",
            "files": cls.control_sources,
            "scope": "additional diagnostic sources; original product admission is unchanged"})
        cls.control_freeze_sha256 = sha256(regular_bytes(cls.control_freeze)).hexdigest()
        cls.binding_path = cls.folder / "explicit-original-native4-binding.json"
        cls.binding = external_binding()
        write_json(cls.binding_path, cls.binding)
        cls.binding_pin = pin(cls.binding_path)
        cls.external_raw = {}
        for key in ("readback", "terminal"):
            expected = cls.binding[key]
            if expected is None:
                continue
            try:
                raw = regular_bytes(expected["path"])
                if {"bytes": len(raw), "sha256": sha256(raw).hexdigest()} != {
                        k: expected[k] for k in ("bytes", "sha256")}:
                    raise ValueError("external bytes differ from supplied prior authority")
                cls.external_raw[expected["path"]] = raw
            except (OSError, ValueError) as error:
                # The immutable binding still contains the supplied pin.
                # Each dependent child/reader will HOLD, never refresh it.
                cls.external_raw[expected["path"]] = None
        cls.additional_results = []

    def test_00_all_23_fresh_owned_controls_with_complete_original_native4(self):
        from tests.hia_slot_definition_lifetime_controls import common_arguments
        self.check_sources()
        evidence = self.folder / self._testMethodName
        evidence.mkdir(mode=0o700)
        plan = {"schema": "hepta.slot.definition.complete-plan.v1",
            "cases": [row["id"] for row in self.fixture["cases"]],
            "specifications": self.fixture["cases"], "parent_pid": os.getpid(),
            "fixture": {"path": str(FIXTURE), **pin(FIXTURE)},
            "product_freeze": {"path": str(self.product_freeze), **pin(self.product_freeze)},
            "control_freeze": {"path": str(self.control_freeze), **pin(self.control_freeze)},
            "controller": {"path": str(self.controller), **pin(self.controller)},
            "base": {"path": str(self.base), **pin(self.base)},
            "capsule": {key: self.bundle_pin[key] for key in ("path", "bytes", "sha256")},
            "external_binding": {"path": str(self.binding_path), **self.binding_pin},
            "qualification_limits": self.fixture["qualification_limits"],
            "new_outer_seconds": self.fixture["outer_seconds"],
            "original_case_budgets_changed": False}
        write_json(evidence / "planned.json", plan)
        rows, started, stopped = [], [], []
        with (evidence / "progress.jsonl").open("xb") as progress:
            for case in self.fixture["cases"]:
                name = case["id"]
                started.append(name)
                progress.write(canonical({"event": "started", "id": name}) + b"\n")
                progress.flush()
                directory = evidence / name
                args = types.SimpleNamespace(case=name, controller=self.controller, base_v1=self.base,
                    base_sha256=self.base_sha256, bridge_bundle=self.bundle,
                    expected_bridge_sha256=self.bundle_pin["sha256"],
                    product_freeze=self.product_freeze, product_freeze_sha256=self.product_freeze_sha256,
                    control_freeze=self.control_freeze,
                    control_freeze_sha256=self.control_freeze_sha256,
                    external_binding=self.binding_path, external_binding_bytes=self.binding_pin["bytes"],
                    external_binding_sha256=self.binding_pin["sha256"])
                result = run_owned(common_arguments(args, directory / "observation"),
                    cwd=ROOT, directory=directory / "owned", timeout_seconds=case["seconds"],
                    environment=clean_environment())
                row = {"case": name, "directory": str(directory), "result": result, "report": None}
                path = directory / "observation/report.json"
                if path.is_file():
                    row["report"] = {"path": str(path), **pin(path)}
                rows.append(row)
                stopped.append(name)
                progress.write(canonical({"event": "stopped", "id": name, "exit_code": result["exit_code"]}) + b"\n")
                progress.flush()
        type(self).additional_results = rows
        stable = (regular_bytes(self.bundle) == self.bundle_bytes
            and product_snapshot(ROOT, tuple(self.control_sources)) == self.control_sources
            and all(raw is not None and regular_bytes(path) == raw
                    for path, raw in self.external_raw.items()))
        report = {"schema": "hepta.slot.definition.complete-collection.v1",
            "status": "RECORDED" if all(successful_exit(row["result"]) for row in rows) and stable else "HOLD",
            "planned": plan["cases"], "started": started, "stopped": stopped,
            "commands": rows, "source_stable": stable, "plan": pin(evidence / "planned.json"),
            "qualification_limits": self.fixture["qualification_limits"]}
        write_json(evidence / "report.json", report)
        result = readback(evidence, ROOT, self.product_freeze, self.product_freeze_sha256,
            control_freeze=self.control_freeze, control_freeze_sha256=self.control_freeze_sha256,
            output=evidence / "independent-readback")
        write_json(evidence / "independent-readback.json", result)
        self.check_sources()
        self.assertEqual(result["status"], "PASS", result)

    @classmethod
    def tearDownClass(cls):
        try:
            if hasattr(cls, "bundle_bytes"):
                if (regular_bytes(cls.bundle) != cls.bundle_bytes
                        or product_snapshot(ROOT, tuple(cls.control_sources)) != cls.control_sources):
                    raise AssertionError("additional diagnostic inputs changed")
                write_json(cls.folder / "definition-component-custody.json", {
                    "schema": "hepta.slot.definition.component-custody.v1",
                    "new_commands": cls.additional_results, "logical_ids": 23,
                    "native_methods": 1, "original_gates_unchanged": cls.fixture["original_gates_unchanged"],
                    "qualification_limits": cls.fixture["qualification_limits"]})
        finally:
            super().tearDownClass()


if __name__ == "__main__":
    unittest.main()
