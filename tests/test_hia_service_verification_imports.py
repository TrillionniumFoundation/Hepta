"""Exact frozen ImportFrom contracts for the seven verification capsules.

This independent Source module executes only the actual import capsule syntax
and the corresponding frozen ImportFrom statement with a fake import provider.
It does not execute the nine business bodies, HIA, SQL, or native code, and it
does not replace the complete original-first Source3/Native8 qualifications.
Each observation uses fresh code and fresh provider/error objects. No traceback,
exception attribute, GC state, or specialization history is reset or normalized.
"""
from __future__ import annotations

import ast
import builtins
import copy
from hashlib import sha256
import json
from pathlib import Path
import sys
import textwrap
import types
import unittest

ROOT = Path(__file__).resolve().parents[1]
ORIGINALS = ROOT / "tests/fixtures/hia_service_verification_original_r12"
IDENTITY_SHA256 = "bd082c0314bd216b1e0fb246cde21838d9e196fa4a1c2d290b7a0bcc69908980"
CAPSULES = (
    ("_behavior_equivalence", 0, "_service_verification_import_behavior_optimization"),
    ("_behavior_equivalence", 1, "_service_verification_import_behavior_widths"),
    ("_subject", 0, "_service_verification_import_subject_layout"),
    ("_hia_verify", 0, "_service_verification_import_verify_emitter"),
    ("_hia_verify", 1, "_service_verification_import_verify_checks"),
    ("_independent_native_refinement", 0, "_service_verification_import_refinement_safe"),
    ("_check_native_refinement_evidence", 0, "_service_verification_import_check_elf"),
)
FAULT_TYPES = (
    ImportError, AttributeError, RuntimeError, MemoryError,
    KeyboardInterrupt, SystemExit, ValueError,
)


def _pin(raw):
    return {"bytes": len(raw), "sha256": sha256(raw).hexdigest()}


def _signature(statement):
    return (statement.module, statement.level,
            tuple((item.name, item.asname) for item in statement.names))


def _imports(function):
    return sorted((node for node in ast.walk(function) if isinstance(node, ast.ImportFrom)),
                  key=lambda node: (node.lineno, node.col_offset))


def _assert_stable(captured):
    for path, original in captured.items():
        if path.read_bytes() != original:
            raise AssertionError("import contract input changed: " + str(path))


def _inputs(test):
    identity_path = ORIGINALS / "source-identity.json"
    identity_raw = identity_path.read_bytes()
    test.assertEqual(sha256(identity_raw).hexdigest(), IDENTITY_SHA256)
    identity = json.loads(identity_raw)
    service_path = ROOT / "hepta/hia_agent_service.py"
    service_raw = service_path.read_bytes()
    captured = {identity_path: identity_raw, service_path: service_raw}
    # Register before any parse/assertion that could fail after capture.
    test.addCleanup(_assert_stable, captured)
    service_tree = ast.parse(service_raw)
    service = next(node for node in service_tree.body
                   if isinstance(node, ast.ClassDef) and node.name == "HIAAgentService")
    functions = {node.name: node for node in service_tree.body
                 if isinstance(node, ast.FunctionDef)}
    actual_names = {name for name in functions if name.startswith("_service_verification_import_")}
    test.assertEqual(actual_names, {row[2] for row in CAPSULES})
    frozen, selected = {}, {}
    service_lines = service_raw.splitlines(keepends=True)
    for method, ordinal, capsule in CAPSULES:
        if method not in frozen:
            name = method + ".py.txt"
            path = ORIGINALS / name
            raw = path.read_bytes()
            captured[path] = raw
            test.assertEqual(_pin(raw), identity["originals"][name])
            node = ast.parse(textwrap.dedent(raw.decode("utf-8"))).body[0]
            test.assertIsInstance(node, ast.FunctionDef)
            test.assertEqual(node.name, method)
            original_method = next(item for item in service.body
                                   if isinstance(item, ast.FunctionDef) and item.name == method)
            first = min([original_method.lineno] +
                        [item.lineno for item in original_method.decorator_list])
            test.assertEqual(b"".join(service_lines[first - 1:original_method.end_lineno]), raw)
            frozen[method] = node
        statements = _imports(frozen[method])
        test.assertLess(ordinal, len(statements))
        selected[capsule] = (functions[capsule], statements[ordinal])
    test.assertEqual(sum(len(_imports(node)) for node in frozen.values()), 7)
    return selected


class _ImportProviderModule(types.ModuleType):
    def __getattribute__(self, name):
        if name.startswith("_probe_"):
            return types.ModuleType.__getattribute__(self, name)
        trace = types.ModuleType.__getattribute__(self, "_probe_trace")
        trace.append(("attribute", name))
        exports = types.ModuleType.__getattribute__(self, "_probe_exports")
        if name in exports:
            if types.ModuleType.__getattribute__(self, "_probe_site") == ("attribute", name):
                count = types.ModuleType.__getattribute__(self, "_probe_fault_count")
                types.ModuleType.__setattr__(self, "_probe_fault_count", count + 1)
                raise types.ModuleType.__getattribute__(self, "_probe_fault")
            return exports[name]
        return types.ModuleType.__getattribute__(self, name)


def _observed(function_node, statement, *, original, site=None,
              fault_type=None, active_outer=False):
    """Call the real IMPORT_NAME/IMPORT_FROM opcodes; no custom import emulator."""
    trace = []
    tokens = {item.name: object() for item in statement.names}
    module = _ImportProviderModule("verification_capsule_fixture." + statement.module)
    module._probe_trace = trace
    module._probe_exports = tokens
    module._probe_site = site
    module._probe_fault_count = 0
    fault = None if fault_type is None else fault_type("verification-import-provider-fault")
    module._probe_fault = fault
    import_fault_count = 0

    def import_provider(name, globals=None, locals=None, fromlist=(), level=0):
        nonlocal import_fault_count
        trace.append(("import", name, level, tuple(fromlist),
                      globals["__package__"], globals["__name__"]))
        if site == ("import",):
            import_fault_count += 1
            raise fault
        return module

    namespace = {
        "__name__": "hepta.hia_agent_service",
        "__package__": "hepta",
        "__builtins__": {**vars(builtins), "__import__": import_provider},
    }
    function = copy.deepcopy(function_node)
    if original:
        # Isolate the exact statement from the immutable full original. Only
        # its imported values are exposed; no business decision is synthesized.
        names = [ast.Name(id=item.asname or item.name, ctx=ast.Load())
                 for item in statement.names]
        value = names[0] if len(names) == 1 else ast.Tuple(elts=names, ctx=ast.Load())
        function.body = [copy.deepcopy(statement), ast.Return(value=value)]
    unit = ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[]))
    exec(compile(unit, "<verification-import-capsule>", "exec", dont_inherit=True), namespace)
    actual = namespace[function_node.name]
    arguments = [object() for _ in function_node.args.posonlyargs + function_node.args.args]
    outer = RuntimeError("verification-import-active-outer")
    seen = {}

    def invoke():
        try:
            value = actual(*arguments)
        except BaseException as error:
            # Keep the actual object and its actual traceback. No normalization
            # is written back, and neither lane reuses the other lane's error.
            seen.update(error=error, active_error=(sys.exception() is error))
        else:
            seen.update(value=value)

    if active_outer:
        try:
            raise outer
        except RuntimeError:
            invoke()
            seen["outer_restored"] = sys.exception() is outer
    else:
        invoke()
        seen["outer_restored"] = sys.exception() is None
    return {
        "trace": trace, "tokens": tokens, "module": module, "fault": fault,
        "outer": outer, "seen": seen,
        "fault_count": import_fault_count + module._probe_fault_count,
    }


def _identity(value, observed):
    if value is None:
        return "none"
    for name in ("fault", "outer", "module"):
        if value is observed[name]:
            return name
    # Unknown identity must be inspected instead of reducing it to id/repr.
    raise AssertionError("unbound import-protocol identity: " + type(value).__name__)


def _error_shape(observed):
    error = observed["seen"]["error"]
    shape = {
        "type": type(error), "args": error.args,
        "is_provider_fault": error is observed["fault"],
        "cause": _identity(error.__cause__, observed),
        "context": _identity(error.__context__, observed),
        "suppress_context": error.__suppress_context__,
        "active_error": observed["seen"]["active_error"],
        "outer_restored": observed["seen"]["outer_restored"],
    }
    for attribute in ("name", "path"):
        if hasattr(error, attribute):
            shape[attribute] = getattr(error, attribute)
    if hasattr(error, "obj"):
        shape["obj_identity"] = _identity(error.obj, observed)
    return shape


class ServiceVerificationImportSourceTests(unittest.TestCase):
    def test_01_all_seven_capsules_match_frozen_ImportFrom_AST(self):
        selected = _inputs(self)
        for _, _, name in CAPSULES:
            with self.subTest(capsule=name):
                function, statement = selected[name]
                self.assertEqual(len(function.body), 2)
                self.assertIsInstance(function.body[0], ast.ImportFrom)
                self.assertEqual(_signature(function.body[0]), _signature(statement))
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

    def test_02_real_import_provider_success_preserves_order_and_value_identity(self):
        selected = _inputs(self)
        for _, _, name in CAPSULES:
            function, statement = selected[name]
            exports = [item.name for item in statement.names]
            for active in (False, True):
                with self.subTest(capsule=name, active_outer=active):
                    original = _observed(function, statement, original=True, active_outer=active)
                    candidate = _observed(function, statement, original=False, active_outer=active)
                    self.assertEqual(original["trace"], candidate["trace"])
                    expected = [("import", statement.module, statement.level,
                                 tuple(exports), "hepta", "hepta.hia_agent_service")]
                    expected += [("attribute", item) for item in exports]
                    self.assertEqual(original["trace"], expected)
                    for observed in (original, candidate):
                        self.assertNotIn("error", observed["seen"])
                        self.assertEqual(observed["fault_count"], 0)
                        self.assertTrue(observed["seen"]["outer_restored"])
                        value = observed["seen"]["value"]
                        values = (value,) if len(exports) == 1 else value
                        self.assertIsInstance(values, tuple)
                        self.assertEqual(len(values), len(exports))
                        for item, export in zip(values, exports):
                            self.assertIs(item, observed["tokens"][export])

    def test_03_every_import_and_from_attribute_fault_preserves_real_exception_protocol(self):
        selected = _inputs(self)
        checked = 0
        for _, _, name in CAPSULES:
            function, statement = selected[name]
            sites = [("import",)] + [("attribute", item.name) for item in statement.names]
            for site in sites:
                for fault_type in FAULT_TYPES:
                    for active in (False, True):
                        with self.subTest(capsule=name, site=site,
                                          fault=fault_type.__name__, active_outer=active):
                            original = _observed(function, statement, original=True,
                                                 site=site, fault_type=fault_type,
                                                 active_outer=active)
                            candidate = _observed(function, statement, original=False,
                                                  site=site, fault_type=fault_type,
                                                  active_outer=active)
                            for observed in (original, candidate):
                                self.assertEqual(observed["fault_count"], 1)
                                self.assertIn("error", observed["seen"])
                                self.assertTrue(observed["seen"]["active_error"])
                                self.assertTrue(observed["seen"]["outer_restored"])
                                # IMPORT_FROM is allowed to translate AttributeError
                                # exactly as the original opcode does. Every other
                                # injected exception must remain that same object.
                                if site == ("import",) or fault_type is not AttributeError:
                                    self.assertIs(observed["seen"]["error"], observed["fault"])
                            self.assertEqual(original["trace"], candidate["trace"])
                            self.assertEqual(_error_shape(original), _error_shape(candidate))
                            checked += 1
        self.assertEqual(checked, 308)


if __name__ == "__main__":
    unittest.main()


# The original three methods and 308 faults remain unchanged in their complete
# predecessor source view. Current eight-capsule controls have separate IDs.
from tests.hia_behavior_original_preparation import bind_original_import_tests
bind_original_import_tests(globals())
