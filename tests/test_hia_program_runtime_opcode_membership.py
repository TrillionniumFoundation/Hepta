"""Exact previous-operation controls for ordinary opcode membership preparation."""
from __future__ import annotations

import ast
from hashlib import sha256
from pathlib import Path
from types import CodeType, FunctionType
import unittest

from hepta import hia_program_runtime as runtime
from hepta import hia_program_runtime_prepared as prepared_module
from hepta import hia_reference_runtime_sources as source_history
from hepta.hia_program import verify_program
from tests import test_hia_program_runtime_prepared as original
from tests import test_hia_program_runtime_arithmetic as original_arithmetic

_PREVIOUS = "341f245bedfc14d459459ba4dbe9b4a0e0f36a3a409a1b549a1e1debb88a9aaa"
_CURRENT = "62d6f1a120f89c4bc1699fe9b305eda63ee10a41111c50a200f4ddbbaf208f8d"
_ORIGINAL_TEST = "ce78a3faac842b6447c390fa2da9ebbceb635a1b60f54decc97d89eb9bb2110b"
_ARITHMETIC_TEST = "c7ce91bf59f06a13c60994ca0957719adf3efa8623113b70535fbe7e9319c113"


def previous_source(raw):
    if type(raw) is not bytes or sha256(raw).hexdigest() != _CURRENT:
        raise ValueError("current operation source differs")
    previous, inverse = source_history._PACKAGE_PREDECESSORS[_CURRENT]
    if previous != _PREVIOUS:
        raise ValueError("operation source relation differs")
    lines = raw.splitlines(keepends=True)
    for start, stop, replacement in reversed(inverse):
        lines[start:stop] = [replacement]
    restored = b"".join(lines)
    if sha256(restored).hexdigest() != _PREVIOUS:
        raise ValueError("complete preceding operation source differs")
    return restored


def clone(function, namespace):
    value = FunctionType(function.__code__, namespace, function.__name__,
                         function.__defaults__, function.__closure__)
    value.__kwdefaults__ = function.__kwdefaults__
    return value


def previous_machine():
    raw = previous_source(Path(runtime.__file__).read_bytes())
    compiled = compile(raw, "<pinned-complete-341f-runtime>", "exec", dont_inherit=True)
    pending, codes = [compiled], []
    while pending:
        item = pending.pop()
        if item.co_qualname == "_Machine.operation":
            codes.append(item)
        pending.extend(x for x in item.co_consts if type(x) is CodeType)
    if len(codes) != 1:
        raise ValueError("preceding operation code is not unique")
    operation = FunctionType(codes[0], vars(runtime), "operation")
    class PreviousMachine(runtime._Machine):
        pass
    PreviousMachine.operation = operation
    return PreviousMachine


class OpcodeMembershipSourceTests(unittest.TestCase):
    def setUp(self):
        self.selector = original.os.environ.pop(original._SELECTOR, original._MISSING)
        self.assertEqual(sha256(Path(original.__file__).read_bytes()).hexdigest(), _ORIGINAL_TEST)
        self.assertEqual(sha256(Path(original_arithmetic.__file__).read_bytes()).hexdigest(), _ARITHMETIC_TEST)
        self.previous = previous_machine()

    def tearDown(self):
        if self.selector is original._MISSING:
            original.os.environ.pop(original._SELECTOR, None)
        else:
            original.os.environ[original._SELECTOR] = self.selector

    def test_whole_source_inverse_and_single_AST_change(self):
        raw = Path(runtime.__file__).read_bytes()
        previous = previous_source(raw)
        self.assertEqual(sha256(raw).hexdigest(), _CURRENT)
        self.assertEqual(sha256(previous).hexdigest(), _PREVIOUS)
        self.assertEqual(source_history.word_runtime_source(raw),
                         source_history.word_runtime_source(previous))
        self.assertEqual(sha256(source_history.word_runtime_source(raw)).hexdigest(),
                         source_history.WORD_RUNTIME_SHA256)
        old, new = ast.parse(previous), ast.parse(raw)
        expression = ast.parse(
            '{f"int.{a}.{m}" for a in ("add", "sub", "mul") for m in ("checked", "wrap")}',
            mode="eval").body
        expected = ast.dump(expression, include_attributes=False)
        old_matches = [n for n in ast.walk(old) if isinstance(n, ast.SetComp)
                       and ast.dump(n, include_attributes=False) == expected]
        new_matches = [n for n in ast.walk(new) if isinstance(n, ast.IfExp)
                       and isinstance(n.orelse, ast.SetComp)
                       and ast.dump(n.orelse, include_attributes=False) == expected]
        self.assertEqual(len(old_matches), 1)
        self.assertEqual(len(new_matches), 1)
        change = new_matches[0]
        self.assertEqual(ast.dump(change.test, include_attributes=False),
                         ast.dump(ast.parse('().__class__.__class__(op) is "".__class__', mode="eval").body,
                                  include_attributes=False))
        self.assertEqual(ast.literal_eval(change.body),
                         {"int.add.checked", "int.add.wrap", "int.sub.checked",
                          "int.sub.wrap", "int.mul.checked", "int.mul.wrap"})
        self.assertEqual(ast.dump(old, include_attributes=False).replace(expected,
                         ast.dump(change, include_attributes=False), 1),
                         ast.dump(new, include_attributes=False))

    def test_unknown_or_mixed_complete_sources_are_rejected(self):
        raw = Path(runtime.__file__).read_bytes()
        previous = previous_source(raw)
        for changed in (raw + b"\n", bytearray(raw), raw.decode(),
                        raw.replace(b'().__class__.__class__(op)', b'().__class__.__class__(ox)', 1),
                        raw.replace(b"int.add.wrap", b"int.add.wrAp", 1),
                        previous.replace(b"8 > extent - index", b"7 > extent - index", 1)):
            with self.subTest(kind=type(changed).__name__):
                with self.assertRaises(ValueError):
                    previous_source(changed)
                with self.assertRaises(ValueError):
                    source_history.word_runtime_source(changed)

    def original_method(self, name):
        counts = {"previous": 0, "current": 0}
        def machine(program, *limits):
            if type(program) is prepared_module._PreparedRuntimeProgram:
                counts["current"] += 1
                return runtime._Machine(program, *limits)
            counts["previous"] += 1
            return self.previous(program, *limits)
        method = vars(original.PreparedRuntimeSourceTests)[name]
        namespace = dict(method.__globals__)
        namespace["_Machine"] = machine
        namespace["_observe"] = clone(original._observe, namespace)
        namespace["_observe_borrowed"] = clone(original._observe_borrowed, namespace)
        clone(method, namespace)(self)
        self.assertGreater(counts["current"], 0)
        if name != "test_readonly_snapshot_and_fresh_entry_state":
            self.assertGreater(counts["previous"], 0)

    def test_original_49_reports_and_stopped_storage_against_previous_source(self):
        self.original_method("test_default_execution_reports_and_stopped_storage_match")

    def test_original_readonly_snapshot_and_fresh_entry_state(self):
        self.original_method("test_readonly_snapshot_and_fresh_entry_state")

    def test_original_dynamic_bytes_decoders_and_custom_providers(self):
        self.original_method("test_changed_bytes_bindings_selectors_and_custom_providers_use_original")

    def test_180_full_width_arithmetic_reports_match_previous_operation(self):
        count = 0
        for typ in ("i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64", "isize", "usize"):
            lo, hi = original.program_module.integer_range(typ)
            for op in ("int.add.checked", "int.add.wrap", "int.sub.checked",
                       "int.sub.wrap", "int.mul.checked", "int.mul.wrap"):
                for args in ((lo, 1), (hi, 1), (hi, 2)):
                    with self.subTest(type=typ, op=op, args=args):
                        checked = verify_program(original.arithmetic(op, typ))
                        expected = original_arithmetic._observe(self.previous, checked, "calculate", args)
                        self.assertEqual(original_arithmetic._observe(
                            runtime._Machine, checked, "calculate", args), expected)
                        count += 1
        self.assertEqual(count, 180)

    def test_private_opcode_hash_effects_and_exception_identity_match_previous_operation(self):
        checked = verify_program(original.arithmetic())
        for fault in (None, MemoryError("private opcode hash")):
            with self.subTest(fault=type(fault).__name__):
                expected = original_arithmetic._private_instruction_observation(self.previous, checked, fault)
                actual = original_arithmetic._private_instruction_observation(runtime._Machine, checked, fault)
                self.assertEqual(actual, expected)
                if fault is not None:
                    self.assertTrue(actual["outcome"][-1])


    def test_replaced_type_names_after_private_instruction_read_keep_original_effects(self):
        checked = verify_program(original.arithmetic())
        constants = []
        pending = list(runtime._Machine.operation.__code__.co_consts)
        while pending:
            value = pending.pop()
            if type(value) is str and value in (
                    "int.add.checked", "int.add.wrap", "int.sub.checked",
                    "int.sub.wrap", "int.mul.checked", "int.mul.wrap"):
                constants.append(value)
            elif type(value) in (tuple, frozenset):
                pending.extend(value)
        self.assertTrue(any(value == "int.add.checked" for value in constants))
        for binding in ("type", "str"):
            for private in (False, True):
                for fail_hash in (False, True):
                    with self.subTest(binding=binding, private=private, fail_hash=fail_hash):
                        fault = MemoryError("actual private metadata fault")
                        def observe(factory):
                            machine = factory(checked, *original._LIMITS)
                            function = machine.functions["calculate"]
                            values = dict(function["blocks"][0]["ops"][0])
                            events = []
                            class Opcode(str):
                                def __hash__(self):
                                    events.append(("hash", str(self)))
                                    if fail_hash:
                                        raise fault
                                    return str.__hash__(self)
                                def __eq__(self, other):
                                    events.append(("equal", other, any(other is item for item in constants)))
                                    return str.__eq__(self, other)
                                def split(self, *args, **kwargs):
                                    events.append(("split", args, tuple(kwargs.items())))
                                    return str.split(self, *args, **kwargs)
                                def endswith(self, *args, **kwargs):
                                    events.append(("endswith", args, tuple(kwargs.items())))
                                    return str.endswith(self, *args, **kwargs)
                            if private:
                                values["op"] = Opcode(values["op"])
                            def shadow(*args):
                                events.append(("shadow-type-call", len(args)))
                                raise fault
                            replacement = shadow if binding == "type" else Opcode
                            before = vars(runtime).get(binding, original._MISSING)
                            class Instruction:
                                def __getitem__(self, key):
                                    events.append(("item", key))
                                    if key == "op":
                                        setattr(runtime, binding, replacement)
                                    return values[key]
                            environment = {param["name"]: value
                                           for param, value in zip(function["params"], (2, 3))}
                            try:
                                try:
                                    value = machine.operation(Instruction(), environment, 0)
                                except BaseException as error:
                                    outcome = ("error", type(error), error.args, error is fault)
                                else:
                                    outcome = ("returned", value)
                            finally:
                                if before is original._MISSING:
                                    delattr(runtime, binding)
                                else:
                                    setattr(runtime, binding, before)
                            return (events, outcome, environment, original._machine_state(machine))
                        self.assertEqual(observe(runtime._Machine), observe(self.previous))



if __name__ == "__main__":
    unittest.main(verbosity=2)
