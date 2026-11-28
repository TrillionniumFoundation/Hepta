"""Current eight import capsules, using real Python import opcodes.

The old seven-capsule/308-fault module is separately executed unchanged in its
complete predecessor view. These 336 controls qualify the actual current source.
"""
from __future__ import annotations

import ast
from hashlib import sha256
import json
import os
from pathlib import Path
import textwrap
import unittest

from tests import test_hia_service_verification_imports as original

ROOT = Path(__file__).resolve().parents[1]
CURRENT = "_service_verification_import_behavior_inputs"


def _inputs(test):
    source = ROOT / "hepta/hia_agent_service.py"
    raw = source.read_bytes()
    captured = {source: raw}
    for name in ("tests/test_hia_service_verification_current_imports.py",
                 "tests/test_hia_service_verification_imports.py",
                 "tests/hia_behavior_original_preparation.py",
                 "hepta/hia_behavior_inputs.py"):
        path = ROOT / name
        captured[path] = path.read_bytes()
    test.addCleanup(original._assert_stable, captured)
    nodes = {node.name: node for node in ast.parse(raw).body
             if isinstance(node, ast.FunctionDef)}
    expected = {row[2] for row in original.CAPSULES} | {CURRENT}
    test.assertEqual({name for name in nodes
                      if name.startswith("_service_verification_import_")}, expected)
    identity_path = original.ORIGINALS / "source-identity.json"
    identity_raw = identity_path.read_bytes()
    captured[identity_path] = identity_raw
    test.assertEqual(sha256(identity_raw).hexdigest(), original.IDENTITY_SHA256)
    identity = json.loads(identity_raw)
    selected = {}
    for method, ordinal, capsule in original.CAPSULES:
        path = original.ORIGINALS / (method + ".py.txt")
        data = path.read_bytes()
        captured[path] = data
        test.assertEqual(original._pin(data), identity["originals"][path.name])
        function = ast.parse(textwrap.dedent(data.decode())).body[0]
        selected[capsule] = (nodes[capsule], original._imports(function)[ordinal])
    expected_new = ast.parse("from .hia_behavior_inputs import BehaviorInputs").body[0]
    selected[CURRENT] = (nodes[CURRENT], expected_new)
    test.assertEqual(len(selected), 8)
    return selected, captured


class CurrentServiceVerificationImportTests(unittest.TestCase):
    def test_01_all_eight_current_capsules_match_their_exact_import_contracts(self):
        selected, _ = _inputs(self)
        for name, (function, statement) in selected.items():
            with self.subTest(capsule=name):
                self.assertEqual(len(function.body), 2)
                self.assertIsInstance(function.body[0], ast.ImportFrom)
                self.assertEqual(original._signature(function.body[0]),
                                 original._signature(statement))
                self.assertIsInstance(function.body[1], ast.Return)
                value = function.body[1].value
                exports = [item.asname or item.name for item in statement.names]
                if len(exports) == 1:
                    self.assertIsInstance(value, ast.Name)
                    self.assertEqual(value.id, exports[0])
                else:
                    self.assertIsInstance(value, ast.Tuple)
                    self.assertTrue(all(isinstance(item, ast.Name) for item in value.elts))
                    self.assertEqual([item.id for item in value.elts], exports)
                self.assertFalse(function.decorator_list)
                self.assertFalse(function.args.vararg or function.args.kwarg
                                 or function.args.defaults or function.args.kw_defaults
                                 or function.args.kwonlyargs)

    def test_02_all_eight_preserve_real_import_order_and_value_identity(self):
        selected, _ = _inputs(self)
        for name, (function, statement) in selected.items():
            exports = [item.name for item in statement.names]
            for active in (False, True):
                with self.subTest(capsule=name, active_outer=active):
                    before = original._observed(function, statement, original=True,
                                                active_outer=active)
                    after = original._observed(function, statement, original=False,
                                               active_outer=active)
                    self.assertEqual(before["trace"], after["trace"])
                    expected = [("import", statement.module, statement.level,
                                 tuple(exports), "hepta", "hepta.hia_agent_service")]
                    expected += [("attribute", item) for item in exports]
                    self.assertEqual(before["trace"], expected)
                    for observed in (before, after):
                        self.assertNotIn("error", observed["seen"])
                        self.assertEqual(observed["fault_count"], 0)
                        self.assertTrue(observed["seen"]["outer_restored"])
                        value = observed["seen"]["value"]
                        values = (value,) if len(exports) == 1 else value
                        self.assertIsInstance(values, tuple)
                        self.assertEqual(len(values), len(exports))
                        for item, export in zip(values, exports):
                            self.assertIs(item, observed["tokens"][export])

    def test_03_all_336_current_faults_preserve_the_real_exception_protocol(self):
        selected, captured = _inputs(self)
        observations = []
        for name, (function, statement) in selected.items():
            sites = [("import",)] + [("attribute", item.name) for item in statement.names]
            for site in sites:
                for fault_type in original.FAULT_TYPES:
                    for active in (False, True):
                        with self.subTest(capsule=name, site=site,
                                          fault=fault_type.__name__, active_outer=active):
                            before = original._observed(function, statement, original=True,
                                                        site=site, fault_type=fault_type,
                                                        active_outer=active)
                            after = original._observed(function, statement, original=False,
                                                       site=site, fault_type=fault_type,
                                                       active_outer=active)
                            for observed in (before, after):
                                self.assertEqual(observed["fault_count"], 1)
                                self.assertIn("error", observed["seen"])
                                self.assertTrue(observed["seen"]["active_error"])
                                self.assertTrue(observed["seen"]["outer_restored"])
                                if site == ("import",) or fault_type is not AttributeError:
                                    self.assertIs(observed["seen"]["error"], observed["fault"])
                            self.assertEqual(before["trace"], after["trace"])
                            self.assertEqual(original._error_shape(before),
                                             original._error_shape(after))
                            observations.append({
                                "capsule": name, "site": site, "fault": fault_type.__name__,
                                "active_outer": active, "original_trace": before["trace"],
                                "current_trace": after["trace"],
                                "original_error": original._error_shape(before),
                                "current_error": original._error_shape(after),
                            })
        self.assertEqual(len(observations), 336)
        original._assert_stable(captured)
        evidence = os.environ.get("HIA_CURRENT_IMPORT_EVIDENCE")
        if evidence:
            output = Path(evidence)
            output.mkdir(mode=0o700, parents=True, exist_ok=True)
            def encode(value):
                if isinstance(value, type):
                    return value.__module__ + "." + value.__qualname__
                raise TypeError(type(value).__name__)
            report = {
                "scope": "CURRENT_EIGHT_CAPSULE_REAL_IMPORT_PROTOCOL",
                "current_capsules": sorted(selected), "fault_count": len(observations),
                "historical_308_qualified_here": False,
                "physical_sources": {str(path.relative_to(ROOT)): original._pin(data)
                                     for path, data in captured.items()},
                "observations": observations,
            }
            (output / "current-336.json").write_text(
                json.dumps(report, sort_keys=True, indent=2, default=encode) + "\n")


if __name__ == "__main__":
    unittest.main()
