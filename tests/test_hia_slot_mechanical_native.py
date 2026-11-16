"""New explicit-v5 qualification; all original Slot classes remain unchanged.

This module requires a separately built, exact source-bound CPython extension.
It never compiles on import and never authorizes an installed worker implicitly.
"""
from __future__ import annotations
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import unittest
from tests.hia_slot_operations_component_fixture import ComponentFixture
from tests.hia_slot_operations_qualification_support import (
    canonical, clean_environment, regular_bytes, run_owned, successful_exit, write_json)
from tools.build_hia_slot_mechanical_bundle import create
ROOT = Path(__file__).resolve().parents[1]


class SlotMechanicalV5NativeTests(ComponentFixture, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.base = cls.folder / "explicit-base-v1.json"
        write_json(cls.base, {
            "schema": "hepta.hia.native-helpers.v1", "target": "linux-x86_64-lp64",
            "abi": "hia-byte-six-argument-v1", "helpers": [
                {"selector": "HEPTA_HIA_SLOT_LEDGER_MANIFEST",
                 "manifest_path": str(cls.decision), "manifest_sha256": sha256(cls.decision.read_bytes()).hexdigest()},
                {"selector": "HEPTA_HIA_SLOT_OPERATIONS_MANIFEST",
                 "manifest_path": str(cls.controller), "manifest_sha256": sha256(cls.controller.read_bytes()).hexdigest()}]})
        cls.base_sha256 = sha256(regular_bytes(cls.base)).hexdigest()
        receipt = ROOT / "hepta/_slot_mechanical_build.json"
        cls.bundle = cls.folder / "explicit-v5.json"
        cls.bundle_pin = create(ROOT / "hepta", cls.base, cls.base_sha256,
                                sha256(regular_bytes(receipt)).hexdigest(), cls.bundle)
        cls.bundle_bytes = regular_bytes(cls.bundle)
        cls.new_commands = []

    def run_complete(self, label, tool, arguments):
        self.check_sources()
        folder = self.folder / self._testMethodName
        command = [sys.executable, "-I", "-B", str(ROOT / tool), *map(str, arguments)]
        result = run_owned(command, cwd=ROOT, directory=folder / "owned",
                           timeout_seconds=1800, environment=clean_environment())
        self.new_commands.append({"method": self.id(), "label": label, "result": result})
        self.assertTrue(successful_exit(result), result)
        self.assertEqual(regular_bytes(self.bundle), self.bundle_bytes)
        self.check_sources()
        return folder

    def test_00_full_original248_derived7574_original_first_native_v5(self):
        evidence = self.folder / self._testMethodName / "observations"
        self.run_complete("complete-7822", "tools/qualify_hia_slot_mechanical_observations.py", [
            "--backend", "native", "--manifest", self.controller,
            "--product-freeze", self.product_freeze,
            "--product-freeze-sha256", self.product_freeze_sha256,
            "--bridge-bundle", self.bundle, "--expected-bridge-sha256", self.bundle_pin["sha256"],
            "--evidence", evidence])
        report = json.loads(regular_bytes(evidence / "independent-readback/report.json"))
        self.assertEqual(report["status"], "PASS")

    def test_01_full_public84_handled12_original_first_native_v5(self):
        evidence = self.folder / self._testMethodName / "observations"
        self.run_complete("public84-handled12", "tools/qualify_hia_slot_mechanical_public.py", [
            "--manifest", self.controller,
            "--product-freeze", self.product_freeze,
            "--product-freeze-sha256", self.product_freeze_sha256,
            "--bridge-bundle", self.bundle, "--expected-bridge-sha256", self.bundle_pin["sha256"],
            "--evidence", evidence])
        report = json.loads(regular_bytes(evidence / "report.json"))
        self.assertEqual(report["status"], "PASS")

    def test_02_complete_actual_admission_and_sealed_loader_controls(self):
        evidence = self.folder / self._testMethodName / "observations"
        self.run_complete("actual-admission25", "tools/qualify_hia_slot_mechanical_admission.py", [
            "--package", ROOT / "hepta", "--base-v1", self.base, "--base-sha256", self.base_sha256,
            "--bridge-bundle", self.bundle, "--expected-bridge-sha256", self.bundle_pin["sha256"],
            "--product-freeze", self.product_freeze,
            "--product-freeze-sha256", self.product_freeze_sha256, "--evidence", evidence])
        from tools.read_hia_slot_mechanical_admission import readback
        report = readback(evidence, ROOT, self.product_freeze, self.product_freeze_sha256)
        write_json(evidence / "independent-readback.json", report)
        self.assertEqual(report["status"], "PASS")

    def test_03_actual_wheel_original_worker_v5_source_and_unknown_replay(self):
        evidence = self.folder / self._testMethodName / "observations"
        self.run_complete("actual-wheel-v5", "tools/qualify_hia_slot_mechanical_installed.py", [
            "--controller", self.controller, "--decision", self.decision,
            "--product-freeze", self.product_freeze,
            "--product-freeze-sha256", self.product_freeze_sha256, "--evidence", evidence])
        from tools.read_hia_slot_mechanical_installed import Captures, verify
        captured = Captures()
        value = verify(evidence, ROOT, self.product_freeze, self.product_freeze_sha256, captured)
        captured.stable()
        write_json(evidence / "independent-readback.json", {
            "schema": "hepta.slot.mechanical.installed-readback.v1", "status": "PASS",
            "detail": value, "actual_inputs": captured.pins(), "product_imported_by_reader": False})

    @classmethod
    def tearDownClass(cls):
        try:
            if hasattr(cls, "bundle_bytes"):
                if regular_bytes(cls.bundle) != cls.bundle_bytes:
                    raise AssertionError("explicit administrator bundle changed")
                write_json(cls.folder / "v5-component-custody.json", {
                    "schema": "hepta.slot.mechanical.v5-component.v1",
                    "bundle": cls.bundle_pin, "new_commands": cls.new_commands,
                    "new_method_count": 4, "original_Source3_Native6_unchanged": True,
                    "original_v1_method_not_replaced": True, "whole_native_stack_qualified": False})
        finally:
            super().tearDownClass()


if __name__ == "__main__":
    unittest.main()
