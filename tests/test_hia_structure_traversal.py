"""Exact c80 traversal outcomes and mutation boundaries survive allocation tuning.

The two frozen references below retain the c80eb2e bodies verbatim, apart from
names. They are test-only algorithms, never a production fallback/cache. The
references use the live module globals through FunctionType so patched budgets,
error types and unchanged string accounting are exactly the same inputs.
"""
from __future__ import annotations

import copy
import inspect
import itertools
import json
import random
import sys
import types
import unittest
from unittest.mock import patch

from hepta import hia_program as core
from tests.test_hia_program import arithmetic, resource_program

def _reference_structure(value):
    """Count exact canonical JSON bytes AND nodes before json.dumps.

    In-process dicts are not byte-bounded by the text preflight. The active
    identity set also refuses cycles, and queued leaf counts refuse huge
    container fanout before extending the work stack. This is a size gate,
    not a replacement for the canonical HIA typed SSA/ownership verifier.
    """
    pending = [(value, 0, False)]
    active = set()
    count, queued, size = 0, 1, 0
    while pending:
        current, depth, leaving = pending.pop()
        if leaving:
            active.remove(id(current))
            continue
        queued -= 1
        count += 1
        if count > MAX_NODES or depth > MAX_DEPTH:
            _reject("program exceeds structural budget", "E_HIA_LIMIT")
        if type(current) in (dict, list):
            identity = id(current)
            if identity in active:
                _reject("cyclic HIA JSON structure", "E_HIA_FORMAT")
            active.add(identity)
            children = len(current)
            if children > MAX_NODES - count - queued:
                _reject("program exceeds queued-node budget", "E_HIA_LIMIT")
            queued += children
            size += 2 + max(0, children - 1)  # container plus commas
            if type(current) is dict:
                size += children  # colons
                for key in current:
                    if type(key) is not str:
                        _reject("non-string JSON key", "E_HIA_FORMAT")
                    size += _json_string_bytes(key, MAX_BYTES - size)
                values = current.values()
            else:
                values = current
            pending.append((current, depth, True))
            pending.extend((child, depth + 1, False) for child in values)
        elif type(current) is str:
            size += _json_string_bytes(current, MAX_BYTES - size)
        elif type(current) is bool:
            size += 4 if current else 5
        elif type(current) is int:
            # Fail without converting a potentially enormous host integer
            # into a decimal string merely to discover it exceeds 8 MiB.
            if current.bit_length() > MAX_BYTES * 4:
                _reject("integer exceeds JSON byte budget", "E_HIA_LIMIT")
            size += len(str(current))
        elif current is None:
            size += 4
        else:
            _reject("only bounded integer JSON values are supported", "E_HIA_FORMAT")
        if size > MAX_BYTES:
            _reject("program exceeds byte budget before encoding", "E_HIA_LIMIT")
    return size


def _reference_bounded_detached_snapshot(root):
    """Capture caller-owned JSON containers before byte accounting/encoding.

    `_structure(original)` followed by `json.dumps(original)` is a check/use
    race if another thread mutates the original dict or list. Instead retain
    bounded references to each container's children, build a separate plain
    dict/list tree, and validate/serialize *that exact detached tree*.
    A nested caller tree is not claimed to be atomically snapshotted.
    Every supported capture is independently rechecked by _structure.
    """
    pending = [(root, None, None, 0, False)]
    active = set()
    count, queued = 0, 1
    result = None
    while pending:
        node, parent, slot, depth, leaving = pending.pop()
        if leaving:
            active.remove(id(node))
            continue
        queued -= 1
        count += 1
        if count > MAX_NODES or depth > MAX_DEPTH:
            _reject("caller-owned tree exceeds snapshot budget", "E_HIA_LIMIT")
        kind = type(node)
        if kind in (dict, list):
            identity = id(node)
            if identity in active:
                _reject("cyclic caller-owned HIA tree", "E_HIA_FORMAT")
            active.add(identity)
            available = MAX_NODES - count - queued
            if len(node) > available:
                _reject("caller-owned tree exceeds queued-node budget", "E_HIA_LIMIT")
            children = []
            try:
                if kind is dict:
                    for key, child in node.items():
                        if type(key) is not str:
                            _reject("non-string caller-owned JSON key", "E_HIA_FORMAT")
                        if len(children) >= available:
                            _reject("caller-owned dictionary grew past node budget",
                                    "E_HIA_LIMIT")
                        children.append((key, child))
                    copy = {}
                else:
                    for child in node:
                        if len(children) >= available:
                            _reject("caller-owned list grew past node budget",
                                    "E_HIA_LIMIT")
                        children.append(child)
                    copy = [None] * len(children)
            except RuntimeError as exc:
                raise HIAProgramRejected(
                    "caller-owned tree mutated during bounded snapshot",
                    "E_HIA_FORMAT") from exc
            if parent is None:
                result = copy
            else:
                parent[slot] = copy
            queued += len(children)
            pending.append((node, None, None, depth, True))
            if kind is dict:
                pending.extend((child, copy, key, depth + 1, False)
                               for key, child in reversed(children))
            else:
                pending.extend((child, copy, index, depth + 1, False)
                               for index, child in reversed(list(enumerate(children))))
        else:
            if kind not in (str, int, bool) and node is not None:
                _reject("unsupported caller-owned JSON node", "E_HIA_FORMAT")
            if parent is None:
                result = node
            else:
                parent[slot] = node
    return result


LEGACY_STRUCTURE = types.FunctionType(_reference_structure.__code__, core.__dict__)
LEGACY_SNAPSHOT = types.FunctionType(_reference_bounded_detached_snapshot.__code__, core.__dict__)


def outcome(call):
    try:
        return ("returned", call())
    except Exception as exc:
        causes = []
        cause = exc.__cause__
        while cause is not None:
            causes.append((type(cause).__module__, type(cause).__qualname__, str(cause)))
            cause = cause.__cause__
        return ("raised", type(exc).__module__, type(exc).__qualname__,
                getattr(exc, "code", None), str(exc), causes)


def at_boundary(function, marker, mutate, value, *, predicate=lambda frame: True):
    """Deterministically mutate caller bytes at one real traversal boundary."""
    lines, first = inspect.getsourcelines(function)
    targets = {first + offset for offset, line in enumerate(lines) if marker in line}
    if not targets:
        raise AssertionError("mutation boundary marker missing: " + marker)
    previous = sys.gettrace()
    fired = []

    def trace(frame, event, arg):
        if (not fired and event == "line" and frame.f_code is function.__code__
                and frame.f_lineno in targets and predicate(frame)):
            fired.append(True)
            mutate()
        return trace

    try:
        sys.settrace(trace)
        observed = outcome(lambda: function(value))
    finally:
        sys.settrace(previous)
    if not fired:
        raise AssertionError("mutation boundary was not reached")
    return observed


class StructureTraversalTests(unittest.TestCase):
    def compare(self, value):
        for baseline, candidate in ((LEGACY_SNAPSHOT, core._bounded_detached_snapshot),
                                    (LEGACY_STRUCTURE, core._structure)):
            self.assertEqual(outcome(lambda: baseline(value)),
                             outcome(lambda: candidate(value)))

    def test_deterministic_graph_and_budget_corpus_preserves_complete_outcomes(self):
        rng = random.Random(689447)
        leaves = [None, False, True, 0, 1, -1, 1 << 64, "", "word", "\x00\n\\\"",
                  "é中🌍", "\ud800", "\udfff", 1.5, float("nan"), object(), ()]

        def value(depth=0):
            if depth >= 5 or rng.randrange(4) == 0:
                return rng.choice(leaves)
            children = [value(depth + 1) for _ in range(rng.randrange(5))]
            if rng.randrange(2):
                return children
            return {(str(index) if rng.randrange(8) else index): child
                    for index, child in enumerate(children)}

        for index in range(2400):
            node = value()
            with self.subTest(case=index), patch.multiple(
                    core, MAX_NODES=rng.choice((1, 2, 8, 31, 128, core.MAX_NODES)),
                    MAX_DEPTH=rng.choice((0, 1, 3, 8, core.MAX_DEPTH)),
                    MAX_BYTES=rng.choice((0, 1, 7, 32, 127, 1024, core.MAX_BYTES))):
                self.compare(node)

    def test_cycle_alias_and_sibling_error_priority_remain_exact(self):
        loop = []; loop.append(loop)
        linked = {}; linked["self"] = linked
        mixed = [linked]; linked["mixed"] = mixed
        shared = ["hello", {"value": [True, 4]}]
        for node in (loop, linked, mixed, [shared, shared],
                     {"left": shared, "right": shared}):
            self.compare(node)
        # Snapshot visits left-to-right; structure visits right-to-left and
        # accounts all object keys before any object value. Error precedence
        # must not change when several independent failures are available.
        failures = [object(), "\ud800", "\x00" * 20, loop, [None] * 40]
        for left, right in itertools.permutations(failures, 2):
            with patch.multiple(core, MAX_NODES=32, MAX_BYTES=32, MAX_DEPTH=4):
                for node in ([left, right], {"first": left, "last": right},
                             {"first": left, 1: right}):
                    self.compare(node)

    def test_real_node_depth_byte_and_large_integer_boundaries(self):
        for count in (core.MAX_NODES - 2, core.MAX_NODES - 1, core.MAX_NODES):
            self.compare([None] * count)
        for depth in (core.MAX_DEPTH - 1, core.MAX_DEPTH, core.MAX_DEPTH + 1):
            node = None
            for _ in range(depth):
                node = [node]
            self.compare(node)
        for maximum in (1, 7, 32, 255):
            with patch.object(core, "MAX_BYTES", maximum):
                for integer in (0, -(1 << (maximum * 4 - 1)),
                                1 << (maximum * 4 - 1), 1 << (maximum * 4)):
                    self.compare([integer])
        for node in ({"x": "\x00" * 17}, {"x": "é中🌍"}, [False, True, None, -1],
                     {"\n": "\x7f" * 20}):
            exact = len(json.dumps(node, ensure_ascii=False, separators=(",", ":")).encode())
            for budget in (exact - 1, exact, exact + 1):
                with patch.object(core, "MAX_BYTES", budget):
                    self.compare(node)

    def test_capture_remains_detached_and_separate_aliases_are_not_reused(self):
        shared = [1, {"value": [2]}]
        original = {"left": shared, "right": shared}
        snapshot = core._bounded_detached_snapshot(original)
        self.assertEqual(snapshot, original)
        self.assertIsNot(snapshot, original)
        self.assertIsNot(snapshot["left"], snapshot["right"])
        self.assertIsNot(snapshot["left"][1], snapshot["right"][1])
        self.assertIsNot(snapshot["left"][1]["value"], shared[1]["value"])
        shared[1]["value"][:] = ["changed"]
        original.clear()
        self.assertEqual(snapshot, {"left": [1, {"value": [2]}],
                                    "right": [1, {"value": [2]}]})

    def test_repeated_string_accounting_keeps_every_occurrence_and_error_order(self):
        for text in ("name", "\x00\n\\\"", "é中🌍", "\ud800"):
            for node in ([text, text, text], {"name": [{"name": text}] * 3}):
                for budget in range(1, 70):
                    with patch.object(core, "MAX_BYTES", budget):
                        self.compare(node)
        # Traverse beyond the bounded arithmetic table and then repeat both
        # early and late strings. All serialized bytes remain independently
        # charged, including occurrences which no longer fit that table.
        node = ["key_" + str(index) for index in range(1500)]
        node = node + node[:20] + node[-20:]
        exact = len(json.dumps(node, separators=(",", ":")).encode())
        for budget in (exact - 20, exact - 1, exact, exact + 1):
            with patch.object(core, "MAX_BYTES", budget):
                self.compare(node)

    def test_oversized_string_refuses_before_any_memo_hash_lookup(self):
        looked_up = []
        previous = sys.getprofile()

        def observe(frame, event, arg):
            if (event == "c_call" and frame.f_code.co_name == "string_bytes"
                    and getattr(arg, "__name__", None) == "get"):
                looked_up.append(True)

        try:
            sys.setprofile(observe)
            with patch.object(core, "MAX_BYTES", 32):
                for node in ("x" * 65536, ["x" * 65536], {"x" * 65536: None}):
                    self.compare(node)
        finally:
            sys.setprofile(previous)
        self.assertEqual(looked_up, [], "byte refusal must precede memo hashing")

    def test_custom_objects_and_subclasses_do_not_gain_execution_hooks(self):
        class Bomb:
            def fail(self, *args, **kwargs):
                raise AssertionError("caller hook executed")
            __iter__ = __len__ = __repr__ = __str__ = __eq__ = fail

        class ListSubclass(list):
            __iter__ = Bomb.fail

        class DictSubclass(dict):
            items = Bomb.fail

        class StrSubclass(str):
            __str__ = Bomb.fail

        class IntSubclass(int):
            __str__ = Bomb.fail

        for node in (Bomb(), ListSubclass([1]), DictSubclass(x=1),
                     StrSubclass("text"), IntSubclass(2),
                     {StrSubclass("key"): 1}, {"value": Bomb()}):
            self.compare(node)
            self.assertEqual(outcome(lambda: core._bounded_detached_snapshot(node))[1:3],
                             (core.HIAProgramRejected.__module__, "HIAProgramRejected"))

    def test_growth_and_dictionary_mutation_during_bounded_capture(self):
        for kind in (list, dict):
            observed = []
            for function in (LEGACY_SNAPSHOT, core._bounded_detached_snapshot):
                value = [1] if kind is list else {"a": 1}

                def grow():
                    if kind is list:
                        value.extend([2] * 16)
                    else:
                        value.update({str(index): index for index in range(16)})

                with patch.object(core, "MAX_NODES", 8):
                    observed.append(at_boundary(function, "children = []", grow, value))
            self.assertEqual(*observed)
            self.assertEqual(observed[0][0], "raised")
            self.assertEqual(observed[0][3], "E_HIA_LIMIT")

        observed = []
        for function in (LEGACY_SNAPSHOT, core._bounded_detached_snapshot):
            value = {"a": 1, "b": 2}
            observed.append(at_boundary(function, "children.append((key, child))",
                                        lambda: value.update(c=3), value))
        self.assertEqual(*observed)
        self.assertEqual(observed[0][3], "E_HIA_FORMAT")
        self.assertEqual(observed[0][-1][0][1], "RuntimeError")

    def test_mutation_after_child_capture_cannot_change_detached_cells(self):
        for kind in (list, dict):
            observed = []
            for function in (LEGACY_SNAPSHOT, core._bounded_detached_snapshot):
                value = [1, 2] if kind is list else {"a": 1, "b": 2}

                def replace():
                    value.clear()
                    if kind is list:
                        value.extend([object()] * 100)
                    else:
                        value["new"] = object()

                observed.append(at_boundary(function, "if parent is None:", replace, value))
            self.assertEqual(*observed)
            self.assertEqual(observed[0], ("returned", [1, 2] if kind is list else {"a": 1, "b": 2}))

    def test_full_verifier_and_wire_results_remain_identical(self):
        fixtures = [arithmetic(), resource_program()]
        for source in list(fixtures):
            wrong = copy.deepcopy(source); wrong["claims"] = {"trusted": True}; fixtures.append(wrong)
            wrong = copy.deepcopy(source); wrong["module"] = "bad name"; fixtures.append(wrong)
            wrong = copy.deepcopy(source); wrong["functions"][0]["blocks"][0]["ops"][0]["op"] = "unknown"; fixtures.append(wrong)
        for source in fixtures:
            for submitted in (source, json.dumps(source), json.dumps(source).encode()):
                current = outcome(lambda: core.verify_program(submitted).canonical_bytes)
                with patch.multiple(core, _bounded_detached_snapshot=LEGACY_SNAPSHOT,
                                    _structure=LEGACY_STRUCTURE):
                    prior = outcome(lambda: core.verify_program(submitted).canonical_bytes)
                self.assertEqual(prior, current)


if __name__ == "__main__":
    unittest.main()
