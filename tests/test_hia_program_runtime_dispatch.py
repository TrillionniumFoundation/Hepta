"""Original VM semantics plus actual prepared dispatch invalidation controls."""
from __future__ import annotations
import ast
import copy
from hashlib import sha256
from pathlib import Path
from types import MappingProxyType, MethodType
import unittest
from unittest.mock import patch

from hepta import hia_program_runtime as runtime
from hepta import hia_program_runtime_dispatch as dispatch
from hepta import hia_program_runtime_prepared as metadata
from hepta.hia_program import verify_program
from tests import test_hia_program_runtime_prepared as original
from tests.test_hia_program import arithmetic, b, c, f, i, m, ret

LIMITS = (4_000_000, 16 << 20, None, 128)


class OriginalRuntimeDispatchTests(original.PreparedRuntimeSourceTests):
    """Run all three original complete method bodies through explicit dispatch."""
    def setUp(self):
        super().setUp()
        self.original_machine = original._Machine
        def machine(program, *limits):
            return dispatch.fresh_machine(
                program, limits, dispatch.prepare_runtime_dispatch(program))
        original._Machine = machine
        self.addCleanup(setattr, original, "_Machine", self.original_machine)


class RuntimeDispatchAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.checked = verify_program(arithmetic())
        self.program = metadata.prepare_runtime_program(self.checked)
        self.plan = dispatch.prepare_runtime_dispatch(self.program)
        self.assertIsNotNone(self.plan)

    def run_machine(self, plan=None):
        machine = dispatch.fresh_machine(self.program, LIMITS, self.plan if plan is None else plan)
        return machine, machine.invoke(machine.functions["calculate"], [2, 3])

    def test_exact_source_and_immutable_whole_program_metadata(self):
        self.assertEqual(sha256(Path(runtime.__file__).read_bytes()).hexdigest(),
                         dispatch._RUNTIME_SHA256)
        self.assertTrue(dispatch._ordinary_bindings())
        self.assertIsNone(dispatch.prepare_runtime_dispatch(self.checked))
        for target in (self.plan.functions, self.plan.function_objects,
                       self.plan.functions["calculate"][1]):
            with self.assertRaises(TypeError):
                target["new"] = None
        with self.assertRaises(AttributeError):
            self.plan.canonical = b"changed"
        with self.assertRaises(AttributeError):
            del self.plan.functions
        machine, result = self.run_machine()
        self.assertIs(type(machine), runtime._Machine)
        self.assertEqual(result, [5])
        self.assertTrue(self.plan.relations)
        self.assertEqual(machine.steps, original._observe(
            self.checked, "calculate", [2, 3])["machine"]["steps"])

    def test_function_replacement_and_changed_code_keep_dynamic_path(self):
        error = LookupError("actual changed operation")
        def changed(machine, instruction, env, depth):
            raise error
        before = runtime._Machine.operation
        with patch.object(runtime._Machine, "operation", changed):
            self.assertIsNone(dispatch.prepare_runtime_dispatch(self.program))
            machine = self.plan.new_machine(self.program, *LIMITS)
            with self.assertRaises(LookupError) as caught:
                machine.invoke(machine.functions["calculate"], [2, 3])
            self.assertIs(caught.exception, error)
        original_code = before.__code__
        try:
            def changed_code(machine, instruction, env, depth):
                raise LookupError("actual changed operation code")
            before.__code__ = changed_code.__code__
            self.assertIsNone(dispatch.prepare_runtime_dispatch(self.program))
            machine = self.plan.new_machine(self.program, *LIMITS)
            with self.assertRaises(LookupError):
                machine.invoke(machine.functions["calculate"], [2, 3])
        finally:
            before.__code__ = original_code
        self.assertEqual(self.run_machine()[1], [5])

    def test_original_constructor_and_invocation_replacements_are_not_skipped(self):
        error = RuntimeError("actual constructor replacement")
        def initialize(machine, *args):
            raise error
        with patch.object(runtime._Machine, "__init__", initialize):
            with self.assertRaises(RuntimeError) as caught:
                self.plan.new_machine(self.program, *LIMITS)
            self.assertIs(caught.exception, error)
        def invoke(machine, function, arguments, depth=0):
            return [73]
        with patch.object(runtime._Machine, "invoke", invoke):
            self.assertEqual(self.run_machine()[1], [73])

    def test_late_instance_operation_and_call_function_replacement_are_observed(self):
        machine = self.plan.new_machine(self.program, *LIMITS)
        error = LookupError("actual instance replacement")
        def changed(instruction, env, depth):
            raise error
        machine.operation = changed
        with self.assertRaises(LookupError) as caught:
            machine.invoke(machine.functions["calculate"], [2, 3])
        self.assertIs(caught.exception, error)
        changed_program = metadata.prepare_runtime_program(
            verify_program(arithmetic("int.mul.checked")))
        machine = self.plan.new_machine(self.program, *LIMITS)
        machine.functions["calculate"] = changed_program.as_dict()["functions"][0]
        self.assertEqual(machine.invoke(machine.functions["calculate"], [2, 3]), [6])

    def test_operation_changed_during_actual_first_instruction_is_observed(self):
        document = m(f("sum", [], ["i32"], ["trap"], [
            b("entry", [], [c("x", "i32", 2), c("y", "i32", 3),
                           i("int.add.checked", ["x", "y"], [("z", "i32")])], ret("z"))]))
        program = metadata.prepare_runtime_program(verify_program(document))
        plan = dispatch.prepare_runtime_dispatch(program)
        machine = plan.new_machine(program, *LIMITS)
        before = runtime._Machine.operation
        tick = runtime._Machine.tick
        error = LookupError("instruction-time method change")
        def changed(machine, instruction, env, depth):
            raise error
        def changing_tick(current):
            tick(current)
            if current.steps == 2:
                runtime._Machine.operation = changed
        try:
            with patch.object(runtime._Machine, "tick", changing_tick):
                with self.assertRaises(LookupError) as caught:
                    machine.invoke(machine.functions["sum"], [])
                self.assertIs(caught.exception, error)
                self.assertEqual(machine.steps, 2)
        finally:
            runtime._Machine.operation = before

    def test_word_dispatch_binding_change_retains_dynamic_lookup(self):
        document = m(f("word", [("s", "readbuf")], ["u64"], ["read", "trap"], [
            b("entry", [("s", "readbuf")],
              [c("zero", "usize", 0),
               i("buffer.load.u64.le", ["s", "zero"], [("n", "u64")])], ret("n"))]))
        document["schema"] = "hepta.hia.program.v9"
        checked = verify_program(document)
        program = metadata.prepare_runtime_program(checked)
        plan = dispatch.prepare_runtime_dispatch(program)
        changed = MappingProxyType(dict(runtime.WORD_LOADS, **{"buffer.load.u64.le": "big"}))
        with patch.object(runtime, "WORD_LOADS", changed):
            self.assertIsNone(dispatch.prepare_runtime_dispatch(program))
            machine = plan.new_machine(program, *LIMITS)
            owner = runtime._Owner(-1, bytearray(range(8)))
            actual = machine.invoke(machine.functions["word"], [runtime._View(owner, False)])
            self.assertEqual(actual, [int.from_bytes(bytes(range(8)), "big")])

    def test_changed_program_full_bytes_decode_once_and_keep_original_data(self):
        changed = verify_program(arithmetic("int.mul.checked"))
        before = self.checked.canonical_bytes
        try:
            object.__setattr__(self.checked, "canonical_bytes", changed.canonical_bytes)
            self.assertIsNone(dispatch.prepare_runtime_dispatch(self.program))
            machine, result = self.run_machine()
            self.assertEqual(result, [6])
            self.assertNotIn("_dispatch_functions", vars(machine))
        finally:
            object.__setattr__(self.checked, "canonical_bytes", before)
        self.assertEqual(self.run_machine()[1], [5])

    def test_changed_decoder_preserves_single_effect_and_exception_identity(self):
        error = RuntimeError("actual selected decoder")
        calls = []
        def changed(*args, **kwargs):
            calls.append((args, kwargs))
            raise error
        with patch.object(metadata._program_module, "decode_internal_canonical", changed):
            self.assertIsNone(dispatch.prepare_runtime_dispatch(self.program))
            with self.assertRaises(RuntimeError) as caught:
                self.plan.new_machine(self.program, *LIMITS)
            self.assertIs(caught.exception, error)
        self.assertEqual(len(calls), 1)

    def test_explicit_observer_view_requires_complete_current_source_and_fixture(self):
        from tempfile import TemporaryDirectory
        from tests import hia_runtime_dispatch_source_history as history
        root = Path(__file__).resolve().parents[1]
        with history.observer_source_view(root) as prior:
            self.assertEqual(history.pin((prior / history.OBSERVER).read_bytes()),
                             history.PRIOR_PIN)
        with TemporaryDirectory() as directory:
            stage = Path(directory).resolve()
            for name in (history.SELF, history.OBSERVER, history.FIXTURE):
                path = stage / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((root / name).read_bytes())
            fixture = stage / history.FIXTURE
            captured = fixture.read_bytes()
            fixture.unlink()
            with self.assertRaises(FileNotFoundError):
                with history.observer_source_view(stage):
                    self.fail("missing fixed history admitted")
            fixture.write_bytes(captured)
            with self.assertRaises(ValueError):
                with history.observer_source_view(stage):
                    path = stage / history.OBSERVER
                    path.write_bytes(path.read_bytes() + b"\n")

    def test_whole_source_late_change_refuses_new_dispatch_and_is_restored(self):
        path = Path(runtime.__file__)
        before = path.read_bytes()
        try:
            path.write_bytes(before + b"\n")
            self.assertIsNone(dispatch.prepare_runtime_dispatch(self.program))
        finally:
            path.write_bytes(before)
        self.assertEqual(path.read_bytes(), before)
        self.assertIsNotNone(dispatch.prepare_runtime_dispatch(self.program))


if __name__ == "__main__":
    unittest.main()
