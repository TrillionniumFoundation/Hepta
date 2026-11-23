"""Independent Source3 and actual owned-child Native1 for explicit Slot routes."""
from __future__ import annotations
import ast
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import threading
import types
import unittest

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/slot_mechanical_dual_route_originals.json"
CASES_FILE = ROOT / "tests/fixtures/slot_mechanical_dual_route_cases.json"

def definition(source, *names):
    value = ast.parse(source)
    for name in names:
        value = next(n for n in value.body if isinstance(n, (ast.ClassDef, ast.FunctionDef)) and n.name == name)
    return value

def dump(node):
    return ast.dump(node, include_attributes=False)

class SlotMechanicalDualRouteSourceTests(unittest.TestCase):
    def test_00_all_original_HIA_templates_finish_and_signature_binding_retained(self):
        frozen = json.loads(FIXTURE.read_bytes())
        selected = (ROOT / "hepta/hia_slot_operations_selection.py").read_text()
        frame = (ROOT / "hepta/hia_slot_operations_native.py").read_text()
        original_get = ast.parse(frozen["descriptor_get"].lstrip()).body[0]
        actual_get = definition(selected, "_SlotControlMethod", "__get__")
        # The two explicit version-dispatch statements are the only additions
        # inside the old selected descriptor. All legacy statements stay exact.
        self.assertIsInstance(actual_get.body[3], ast.Assign)
        self.assertEqual([x.id for x in actual_get.body[3].targets], ["bridge"])
        self.assertIsInstance(actual_get.body[4], ast.If)
        self.assertEqual(ast.unparse(actual_get.body[4].test), "bridge is not None")
        actual_get.body = actual_get.body[:3] + actual_get.body[5:]
        self.assertEqual(dump(actual_get), dump(original_get))
        original_finish = ast.parse(frozen["finish"].lstrip()).body[0]
        self.assertEqual(dump(definition(frame, "SlotOperationsFrame", "finish")),
                         dump(original_finish))
        for mode in range(1, 16):
            with self.subTest(mode=mode):
                self.assertEqual(dump(definition(selected, "_bridge_" + str(mode))),
                                 dump(ast.parse(frozen["templates"][str(mode)]).body[0]))
        self.assertNotIn("_preload_mechanical", frame)
        from tools.hia_frozen_component_sources import reviewed_source
        name = "hepta/hia_native_helpers.py"
        current = (ROOT / name).read_bytes()
        tree = ast.parse(reviewed_source(ROOT, name, current))
        registry = next(n for n in tree.body if isinstance(n, ast.Assign)
                        and any(isinstance(t, ast.Name) and t.id == "HELPERS" for t in n.targets))
        self.assertEqual(list(ast.literal_eval(registry.value)), frozen["helper_order"])
        from hepta.hia_native_helpers import HELPERS
        self.assertEqual([name for name in HELPERS if name in frozen["helper_order"]],
                         frozen["helper_order"])

    def test_01_actual_optional_authority_function_distinguishes_old_build_live_and_stale(self):
        source = (ROOT / "hepta/hia_native_helpers.py").read_text()
        nodes = [definition(source, name) for name in ("_check_scope_owner", "selected_mechanical_bridge")]
        namespace = {"os": os, "threading": threading, "_SCOPE_OWNER": None,
                      "_MECHANICAL_SCOPE": None, "_MECHANICAL_BUILD": None, "_ACTIVE": None,
                     "_MECHANICAL_SELECTED": False}
        exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])),
                     "<actual-route-authority-functions>", "exec"), namespace)
        lookup = namespace["selected_mechanical_bridge"]
        class Old:
            def __getattribute__(self, name):
                raise AssertionError("old v1 route probed a mechanical member")
        self.assertIsNone(lookup("slot-mechanical", "abi"))
        namespace["_ACTIVE"] = Old()
        namespace["_SCOPE_OWNER"] = (os.getpid(), threading.get_ident())
        self.assertIsNone(lookup("slot-mechanical", "abi"))
        calls = []
        token = object()
        class Actual:
            def mechanical_bridge(self, name, abi):
                calls.append((name, abi))
                return token
        authority = Actual()
        namespace.update(_ACTIVE=authority, _MECHANICAL_SCOPE=authority,
                         _MECHANICAL_SELECTED=True)
        self.assertIs(lookup("slot-mechanical", "abi"), token)
        namespace["_ACTIVE"] = Actual()
        with self.assertRaises(ValueError):
            lookup("slot-mechanical", "abi")
        namespace.update(_ACTIVE=None, _MECHANICAL_SCOPE=None, _MECHANICAL_BUILD=authority)
        self.assertIs(lookup("slot-mechanical", "abi"), token)
        namespace["_ACTIVE"] = authority
        with self.assertRaises(ValueError):
            lookup("slot-mechanical", "abi")
        namespace.update(_ACTIVE=authority, _MECHANICAL_SCOPE=authority, _MECHANICAL_BUILD=None,
                         _SCOPE_OWNER=(os.getpid()+1, threading.get_ident()))
        with self.assertRaises(ValueError):
            lookup("slot-mechanical", "abi")
        namespace.update(_ACTIVE=None, _MECHANICAL_SCOPE=None, _MECHANICAL_BUILD=None,
                         _SCOPE_OWNER=(os.getpid(), threading.get_ident()))
        with self.assertRaises(ValueError):
            lookup("slot-mechanical", "abi")
        namespace.update(_MECHANICAL_SELECTED=False,
                         _SCOPE_OWNER=(os.getpid()+1, threading.get_ident()))
        self.assertIsNone(lookup("slot-mechanical", "abi"))
        self.assertEqual(calls, [("slot-mechanical", "abi"), ("slot-mechanical", "abi")])
        controls = ast.parse((ROOT / "tests/hia_slot_mechanical_route_controls.py").read_text())
        planned = next(n for n in controls.body if isinstance(n, ast.Assign)
                       and any(isinstance(t, ast.Name) and t.id == "CASES" for t in n.targets))
        self.assertEqual(list(ast.literal_eval(planned.value)), json.loads(CASES_FILE.read_bytes())["cases"])

    def test_02_actual_readback_rejects_counter_drift_and_loaded_without_C_entry(self):
        from tools.read_hia_slot_mechanical_observations import (
            mechanical_counters, mechanical_counter_delta)
        def empty():
            return {"schema": "hepta.slot.mechanical.execution-counters.v1",
                    "pid": 17, "overflow": False,
                    **{n: [0]*16 for n in ("public_calls", "raw_frame_calls",
                                          "initialized", "final_receipts")}}
        before, after = empty(), empty()
        for name in ("public_calls", "initialized", "final_receipts"):
            after[name][5] = 1
        self.assertEqual(mechanical_counter_delta(before, after, 17, require_public=True)["initialized"][5], 1)
        invalid = []
        value = empty(); value["pid"] = 18; invalid.append(value)
        value = empty(); value["overflow"] = True; invalid.append(value)
        value = empty(); value["initialized"][5] = 1; invalid.append(value)
        value = empty(); value["public_calls"][5] = True; invalid.append(value)
        value = empty(); value["public_calls"].pop(); invalid.append(value)
        value = empty(); value["public_calls"][0] = 1; invalid.append(value)
        value = empty(); value["extra"] = 0; invalid.append(value)
        for index, value in enumerate(invalid):
            with self.subTest(index=index), self.assertRaises(ValueError):
                mechanical_counters(value, 17)
        with self.assertRaises(ValueError):
            mechanical_counter_delta(empty(), empty(), 17, require_public=True)
        with self.assertRaises(ValueError):
            mechanical_counter_delta(after, before, 17, require_public=False)
        raw = empty()
        raw["raw_frame_calls"][5] = raw["initialized"][5] = 1
        with self.assertRaises(ValueError):
            mechanical_counter_delta(empty(), raw, 17, require_public=True)

from tests.hia_slot_operations_component_fixture import ComponentFixture

class SlotMechanicalDualRouteNativeTests(ComponentFixture, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        from tests.hia_slot_operations_qualification_support import regular_bytes, write_json
        from tools.build_hia_slot_mechanical_bundle import create
        cls.base = cls.folder / "explicit-base-v1.json"
        write_json(cls.base, {"schema": "hepta.hia.native-helpers.v1",
            "target": "linux-x86_64-lp64", "abi": "hia-byte-six-argument-v1",
            "helpers": [
                {"selector": "HEPTA_HIA_SLOT_LEDGER_MANIFEST", "manifest_path": str(cls.decision),
                 "manifest_sha256": sha256(regular_bytes(cls.decision)).hexdigest()},
                {"selector": "HEPTA_HIA_SLOT_OPERATIONS_MANIFEST", "manifest_path": str(cls.controller),
                 "manifest_sha256": sha256(regular_bytes(cls.controller)).hexdigest()}]})
        cls.base_sha = sha256(regular_bytes(cls.base)).hexdigest()
        cls.bundle = cls.folder / "explicit-v5.json"
        cls.bundle_pin = create(ROOT / "hepta", cls.base, cls.base_sha,
            sha256(regular_bytes(ROOT / "hepta/_slot_mechanical_build.json")).hexdigest(), cls.bundle)

    def test_00_complete_seventeen_actual_routes_and_captured_authority_boundaries(self):
        from tests.hia_slot_operations_qualification_support import (
            clean_environment, regular_bytes, run_owned, successful_exit, write_json)
        from tools.read_hia_slot_mechanical_routes import readback
        cases = json.loads(regular_bytes(CASES_FILE))["cases"]
        root = self.folder / self._testMethodName
        root.mkdir(mode=0o700)
        commands, failures = [], []
        report = {"schema": "hepta.slot.mechanical.routes.v1", "status": "HOLD",
            "planned": cases, "started": [], "stopped": [],
            "product_freeze": {"path": str(self.product_freeze),
                              "sha256": self.product_freeze_sha256},
            "base_v1": {"path": str(self.base), "sha256": self.base_sha},
            "v5": self.bundle_pin, "controller": str(self.controller),
            "original_domains_replaced": False, "whole_native_stack_qualified": False}
        for case in cases:
            self.check_sources()
            target = root / case
            argv = [sys.executable, "-I", "-B",
                str(ROOT / "tests/hia_slot_mechanical_route_controls.py"),
                "--case", case, "--controller", str(self.controller),
                "--base-v1", str(self.base), "--base-sha256", self.base_sha,
                "--bridge-bundle", str(self.bundle),
                "--expected-bridge-sha256", self.bundle_pin["sha256"],
                "--product-freeze", str(self.product_freeze),
                "--product-freeze-sha256", self.product_freeze_sha256,
                "--output", str(target / "observation")]
            report["started"].append(case)
            result = run_owned(argv, cwd=ROOT, directory=target / "owned",
                               timeout_seconds=60, environment=clean_environment())
            report["stopped"].append(case)
            child = target / "observation/report.json"
            raw = regular_bytes(child) if child.is_file() else None
            commands.append({"case": case, "result": result,
                "report": None if raw is None else {
                    "path": str(child), "bytes": len(raw), "sha256": sha256(raw).hexdigest()}})
            if not successful_exit(result):
                failures.append(case)
            self.check_sources()
        report.update({"commands": commands, "failures": failures,
                       "status": "PASS" if not failures else "HOLD"})
        write_json(root / "report.json", report)
        actual = readback(root, ROOT, self.product_freeze, self.product_freeze_sha256)
        write_json(root / "independent-readback.json", actual)
        self.assertEqual(failures, [])
        self.assertEqual(actual["status"], "PASS")

if __name__ == "__main__":
    unittest.main()
