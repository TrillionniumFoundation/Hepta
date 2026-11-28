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

    def test_completed_entry_releases_machine_without_cyclic_collection(self):
        import weakref
        machine = self.plan.new_machine(self.program, *LIMITS)
        self.assertIn("invoke", vars(machine))
        reference = weakref.ref(machine)
        self.assertEqual(machine.invoke(machine.functions["calculate"], [2, 3]), [5])
        self.assertNotIn("invoke", vars(machine))
        del machine
        self.assertIsNone(reference())

    def test_exception_releases_only_its_own_invocation_binding(self):
        machine = self.plan.new_machine(self.program, 1, LIMITS[1], None, LIMITS[3])
        with self.assertRaises(runtime.HIAProgramBudgetExceeded):
            machine.invoke(machine.functions["calculate"], [2, 3])
        self.assertNotIn("invoke", vars(machine))
        machine = self.plan.new_machine(self.program, *LIMITS)
        tick = runtime._Machine.tick
        def replacement(*args):
            return [91]
        def change(current):
            tick(current)
            current.invoke = replacement
        with patch.object(runtime._Machine, "tick", change):
            self.assertEqual(machine.invoke(machine.functions["calculate"], [2, 3]), [5])
        self.assertIs(machine.invoke, replacement)

    def test_default_values_and_constant_types_match_executed_source(self):
        method = runtime._Machine.invoke
        operation = runtime._Machine.operation
        defaults, code = method.__defaults__, operation.__code__
        try:
            method.__defaults__ = (False,)
            self.assertFalse(dispatch._ordinary_bindings())
            self.assertIsNone(dispatch._source_methods())
            method.__defaults__ = defaults
            constants = list(code.co_consts)
            index = next(i for i, value in enumerate(constants) if type(value) is bool)
            constants[index] = int(constants[index])
            operation.__code__ = code.replace(co_consts=tuple(constants))
            self.assertIsNone(dispatch._source_methods())
        finally:
            method.__defaults__, operation.__code__ = defaults, code
        self.assertTrue(dispatch._ordinary_bindings())
        self.assertIsNotNone(dispatch._source_methods())

    def test_actual_dynamic_operation_lookup_keeps_original_effect_count(self):
        calls = []
        def read_attribute(machine, name):
            if name == "operation":
                calls.append(name)
            return object.__getattribute__(machine, name)
        with patch.object(runtime._Machine, "__getattribute__", read_attribute):
            self.assertIsNone(dispatch.prepare_runtime_dispatch(self.program))
            machine = self.plan.new_machine(self.program, *LIMITS)
            self.assertNotIn("_dispatch_functions", vars(machine))
            self.assertEqual(machine.invoke(machine.functions["calculate"], [2, 3]), [5])
        self.assertEqual(calls, ["operation"])

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


class RuntimeDispatchComparisonTests(unittest.TestCase):
    def prepare(self, opcode):
        parameters = [("a", "i32"), ("b", "i32")]
        document = m(f("compare", parameters, ["bool"], [], [
            b("entry", parameters, [i(opcode, ["a", "b"], [("value", "bool")])],
              ret("value"))]))
        program = metadata.prepare_runtime_program(verify_program(document))
        plan = dispatch.prepare_runtime_dispatch(program)
        self.assertIsNotNone(plan)
        handler, prepared = plan.functions["compare"][1]["entry"][0]
        return program, plan, handler, prepared

    def test_all_six_exact_integer_comparisons_keep_results_and_machine_ticks(self):
        for suffix in ("eq", "ne", "lt", "le", "gt", "ge"):
            program, plan, handler, prepared = self.prepare("compare." + suffix)
            relation = dict(plan.relations[0])
            self.assertEqual(relation["specialization"], "exact-int-comparison.v1")
            self.assertEqual(relation["original_fallback_sha256"], relation["body_sha256"])
            for arguments in ((0, 0), (-2, 3), (3, -2), (-2147483648, 2147483647)):
                with self.subTest(opcode=suffix, arguments=arguments):
                    old = runtime._Machine(program, *LIMITS)
                    new = plan.new_machine(program, *LIMITS)
                    expected = old.invoke(old.functions["compare"], list(arguments))
                    actual = new.invoke(new.functions["compare"], list(arguments))
                    self.assertEqual(actual, expected)
                    self.assertEqual(
                        {k: v for k, v in vars(new).items() if type(v) in (int, bool, str, float, type(None))},
                        {k: v for k, v in vars(old).items() if type(v) in (int, bool, str, float, type(None))})

    def test_integer_subclass_retains_all_six_original_comparison_effects(self):
        events = []
        class Number(int):
            def __eq__(self, other): events.append("eq"); return int(self) == int(other)
            def __ne__(self, other): events.append("ne"); return int(self) != int(other)
            def __lt__(self, other): events.append("lt"); return int(self) < int(other)
            def __le__(self, other): events.append("le"); return int(self) <= int(other)
            def __gt__(self, other): events.append("gt"); return int(self) > int(other)
            def __ge__(self, other): events.append("ge"); return int(self) >= int(other)
        for suffix in ("eq", "ne", "lt", "le", "gt", "ge"):
            program, plan, handler, prepared = self.prepare("compare." + suffix)
            machine = runtime._Machine(program, *LIMITS)
            old_env, new_env = {"a": Number(2), "b": 3}, {"a": Number(2), "b": 3}
            events.clear()
            expected = machine.operation(prepared[0], old_env, 0)
            old_events = list(events)
            events.clear()
            actual = handler(machine, prepared, new_env, 0)
            self.assertEqual(actual, expected)
            self.assertEqual(events, old_events)
            self.assertEqual(events, ["eq", "ne", "lt", "le", "gt", "ge"])
            self.assertIs(new_env["value"], old_env["value"])

    def test_nonselected_comparison_exception_identity_is_not_removed(self):
        error = RuntimeError("original unselected rich comparison")
        events = []
        class Number(int):
            def __eq__(self, other): events.append("eq"); return True
            def __ne__(self, other): events.append("ne"); return False
            def __lt__(self, other): events.append("lt"); raise error
        program, plan, handler, prepared = self.prepare("compare.eq")
        machine = runtime._Machine(program, *LIMITS)
        for invoke in (lambda env: machine.operation(prepared[0], env, 0),
                       lambda env: handler(machine, prepared, env, 0)):
            events.clear()
            with self.assertRaises(RuntimeError) as caught:
                invoke({"a": Number(2), "b": 3})
            self.assertIs(caught.exception, error)
            self.assertEqual(events, ["eq", "ne", "lt"])

    def test_live_native_and_package_scalar_prefixes_still_win(self):
        program, plan, handler, prepared = self.prepare("compare.lt")
        calls = []
        class Scalar:
            def operation(self, opcode, typ, args):
                calls.append(("native", opcode, typ, args))
                return False
            def package_integer_operation(self, opcode, typ, args):
                calls.append(("package", opcode, typ, args))
                return False
        machine = runtime._Machine(program, *LIMITS)
        machine.scalar_reference = Scalar()
        env = {"a": 2, "b": 3}
        handler(machine, prepared, env, 0)
        self.assertIs(env["value"], False)
        machine.scalar_reference = None
        machine.package_scalar_reference = lambda: Scalar()
        env = {"a": 2, "b": 3}
        handler(machine, prepared, env, 0)
        self.assertIs(env["value"], False)
        self.assertEqual(calls, [
            ("native", "compare.lt", "bool", [2, 3]),
            ("package", "compare.lt", "bool", [2, 3])])

    def test_unknown_opcode_cannot_acquire_a_comparison_specialization(self):
        parts = dispatch._operation_parts()
        ordinal, (_, body) = next((index, item) for index, item in enumerate(parts[-2])
                                  if ast.unparse(item[0]) == "op.startswith('compare.')")
        with self.assertRaises(ValueError):
            dispatch._handler(parts, ordinal, body, "compare.unknown")


class RuntimeDispatchOpcodeChoiceTests(unittest.TestCase):
    def prepare(self, opcode):
        parameters = [("a", "i32"), ("b", "i32")]
        document = m(f("calculate", parameters, ["i32"], ["trap"], [
            b("entry", parameters, [i(opcode, ["a", "b"], [("value", "i32")])],
              ret("value"))]))
        checked = verify_program(document)
        program = metadata.prepare_runtime_program(checked)
        plan = dispatch.prepare_runtime_dispatch(program)
        self.assertIsNotNone(plan)
        handler, prepared = plan.functions["calculate"][1]["entry"][0]
        return program, plan, handler, prepared

    def test_all_static_choices_preserve_original_selected_operations(self):
        for opcode in sorted(dispatch._STATIC_ARITHMETIC):
            program, plan, handler, prepared = self.prepare(opcode)
            self.assertEqual(plan.relations[0]["specialization"], "static-opcode-expressions.v1")
            for args in ((5, 2), (-3, 1), (2147483647, 1), (-2147483648, 31)):
                with self.subTest(opcode=opcode, args=args):
                    observations = []
                    for fast in (False, True):
                        machine = (plan.new_machine(program, *LIMITS) if fast else
                                   runtime._Machine(program, *LIMITS))
                        try:
                            result = ("return", machine.invoke(machine.functions["calculate"], list(args)))
                        except (runtime.HIAProgramTrap, runtime.HIAProgramBudgetExceeded) as error:
                            result = ("exception", type(error), str(error), vars(error))
                        observations.append((result, machine.steps))
                    self.assertEqual(*observations)

    def test_selected_global_check_and_wrap_are_still_dynamic(self):
        for opcode, name in (("int.add.checked", "_checked"), ("int.mul.wrap", "_wrap"),
                             ("int.shl.checked", "_wrap"), ("bit.xor", "_wrap")):
            program, plan, handler, prepared = self.prepare(opcode)
            machine = runtime._Machine(program, *LIMITS)
            calls = []
            error = RuntimeError("selected original helper")
            def changed(*args):
                calls.append(args)
                raise error
            with patch.object(runtime, name, changed):
                for invoke in (lambda env: machine.operation(prepared[0], env, 0),
                               lambda env: handler(machine, prepared, env, 0)):
                    calls.clear()
                    with self.assertRaises(RuntimeError) as caught:
                        invoke({"a": 5, "b": 2})
                    self.assertIs(caught.exception, error)
                    self.assertEqual(len(calls), 1)

    def test_non_builtin_operands_keep_only_the_original_selected_operator(self):
        events = []
        class Number(int):
            def __add__(self, other): events.append("add"); return int(self) + int(other)
            def __sub__(self, other): events.append("sub"); return int(self) - int(other)
            def __mul__(self, other): events.append("mul"); return int(self) * int(other)
            def __and__(self, other): events.append("and"); return int(self) & int(other)
            def __or__(self, other): events.append("or"); return int(self) | int(other)
            def __xor__(self, other): events.append("xor"); return int(self) ^ int(other)
        for opcode in sorted(dispatch._STATIC_ARITHMETIC - {"int.shl.checked", "int.shr.checked"}):
            program, plan, handler, prepared = self.prepare(opcode)
            machine = runtime._Machine(program, *LIMITS)
            events.clear();old_env = {"a": Number(5), "b": 2}
            machine.operation(prepared[0], old_env, 0);old_events = list(events)
            events.clear();new_env = {"a": Number(5), "b": 2}
            handler(machine, prepared, new_env, 0)
            self.assertEqual(events, old_events)
            self.assertEqual(len(events), 1)
            self.assertEqual(new_env["value"], old_env["value"])

    def test_unknown_static_opcode_is_rejected(self):
        with self.assertRaises(ValueError):
            dispatch._opcode_body([], "int.add.unknown")


if __name__ == "__main__":
    unittest.main()
