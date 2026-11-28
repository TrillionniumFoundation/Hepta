"""Observer-v3 controls; original bodies, inputs, tests and budgets remain fixed."""
from __future__ import annotations

import ast
import base64
from copy import deepcopy
import gc
import gzip
from hashlib import sha256
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import threading
import unittest
from unittest.mock import patch
import weakref

from tests import hia_service_bootstrap_observer as observer
from tests import hia_service_bootstrap_oracle as oracle
from tests import hia_service_bootstrap_support as support
from tools import qualify_hia_service_bootstrap_finite as finite
from tools import read_hia_service_bootstrap as reader

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/hia_bootstrap_case_terminal_original_source_v1.json"
FIXTURE_PIN = {"bytes": 94869, "sha256": "f450880ac19e0152b3093a3e4030fb23d42d48f289df880544f8564fbbda4896"}


def originals():
    raw, value, _ = support.capture_json(FIXTURE, FIXTURE_PIN)
    if value["schema"] != "hepta.hia.bootstrap-case-terminal-original-source.v1":
        raise ValueError("wrong full-source predecessor")
    result = {}
    for name, record in value["files"].items():
        data = gzip.decompress(base64.b64decode(record["gzip_base64"], validate=True))
        if support.bytes_pin(data) != {k: record[k] for k in ("bytes", "sha256")}:
            raise ValueError("complete original source bytes differ")
        result[name] = data
    support.exact_reread(FIXTURE, raw)
    return result


class CaseTerminalTests(unittest.TestCase):
    def setUp(self):
        self.gc_before = (gc.isenabled(), gc.get_threshold())
        self.assertTrue(self.gc_before[0])
        self.cases = oracle.cases()[0]
        self.case = next(row for row in self.cases if row["id"] == "_program.normal.outer0")

    def tearDown(self):
        self.assertEqual((gc.isenabled(), gc.get_threshold()), self.gc_before)

    def _world(self, case=None):
        case = self.case if case is None else case
        terminal = observer.CaseTerminal(case)
        world = oracle.World(case)
        terminal.retain(world)
        return terminal, world

    def _observe(self, case=None):
        case = self.case if case is None else case
        terminal = observer.CaseTerminal(case)
        actual, trace = oracle.observe(case, retain_world=terminal.retain)
        late = []
        raw, frozen = observer.seal_record(actual, late.append)
        record = terminal.finish()
        return raw, frozen, trace, late, record

    def _late_release(self, *, active=False, reversed_order=False):
        terminal, world = self._world()
        late = []
        world.events.seal(self.case["id"], 0, "events", [], late.append)
        first = oracle.Atom(world, "first")
        second = oracle.Atom(world, "second")
        if active:
            try:
                raise world.outer
            except oracle.OuterError:
                if reversed_order:
                    del second, first
                else:
                    del first, second
        elif reversed_order:
            del second, first
        else:
            del first, second
        del world
        terminal.finish()
        return late

    def _compare_late(self, expected, actual):
        with TemporaryDirectory(prefix="hia-bootstrap-case-late-") as directory:
            root = Path(directory)
            left = b"".join(support.canonical(row) + b"\n" for row in expected)
            right = b"".join(support.canonical(row) + b"\n" for row in actual)
            (root / "original.jsonl").write_bytes(left)
            (root / "candidate.jsonl").write_bytes(right)
            count, pin = finite._compare_terminal_late(
                root / "candidate.jsonl", root / "original.jsonl",
                support.bytes_pin(right), support.bytes_pin(left), root / "differences.jsonl")
            differences = [row for _, _, row in support.json_lines(root / "differences.jsonl", pin)]
            return count, differences

    def test_full_original_eight_test_methods_and_all_other_oracle_code_are_unchanged(self):
        prior = originals()
        names = ("tests/test_hia_service_bootstrap_sources.py",
                 "tests/test_hia_service_bootstrap_qualification.py")
        methods = []
        for name in names:
            self.assertEqual((ROOT / name).read_bytes(), prior[name])
            tree = ast.parse(prior[name])
            for cls in tree.body:
                if isinstance(cls, ast.ClassDef) and cls.name in (
                        "ServiceBootstrapStaticSourceTests",
                        "ServiceBootstrapQualificationSourceTests"):
                    methods.extend(n.name for n in cls.body
                                   if isinstance(n, ast.FunctionDef) and n.name.startswith("test_"))
        self.assertEqual(len(methods), 8)
        name = "tests/hia_service_bootstrap_oracle.py"
        actual = (ROOT / name).read_text()
        signature = ("def observe(case, *, functions=None, namespace=None, captured_builtins=None,\n"
                     "            retain_world=None):")
        hook = "        if retain_world is not None:\n            retain_world(world)\n"
        self.assertEqual(actual.count(signature), 1)
        self.assertEqual(actual.count(hook), 1)
        restored = actual.replace(signature, "def observe(case, *, functions=None, namespace=None, captured_builtins=None):")
        restored = restored.replace(hook, "")
        self.assertEqual(restored.encode(), prior[name])
        self.assertEqual(len(self.cases), 232)
        self.assertEqual(sha256((oracle.FIXTURE / "observation-domain.json").read_bytes()).hexdigest(),
                         "cb514a6ba953e6ffb3cbf293ded95fb1bd6631cb42a06212345bb94987221c57")
        for name, expected in oracle.METHOD_PINS.items():
            self.assertEqual(sha256((oracle.FIXTURE / (name + ".py.txt")).read_bytes()).hexdigest(), expected)

    def test_real_case_seal_and_one_collection_release_cycle_without_changing_gc(self):
        terminal, world = self._world()
        world.external["observer_cycle"] = world
        reference = weakref.ref(world)
        del world
        before = gc.get_stats()
        row = terminal.finish()
        after = gc.get_stats()
        self.assertIsNone(reference())
        self.assertEqual(row["retained_worlds"], 1)
        self.assertEqual(row["released_worlds"], 1)
        self.assertEqual(row["collection_calls"], 1)
        self.assertGreaterEqual(after[-1]["collections"] - before[-1]["collections"], 1)
        self.assertEqual(row["gc_before"], row["gc_after"])
        self.assertEqual((gc.isenabled(), gc.get_threshold()), self.gc_before)
        with self.assertRaises(ValueError):
            terminal.finish()

    def test_throw_instance_worlds_finish_before_any_later_outer_case(self):
        case = next(row for row in self.cases if row["id"] == "generator_protocol.throw-instance.outer1")
        raw, actual, trace, late, row = self._observe(case)
        self.assertEqual(row["released_worlds"], 2)
        self.assertEqual(len(actual["parts"]), 2)
        self.assertTrue(late)
        for event in late:
            self.assertEqual(event["id"], case["id"])
            self.assertEqual(event["field"], "events")
            self.assertEqual(event["value"]["event"], "delete")
            self.assertIsNone(event["value"]["active"])
        self.assertEqual(support.parse(raw), actual)
        self.assertEqual(trace["id"], case["id"])

    def test_real_provider_release_keeps_active_exception_and_full_late_mismatch(self):
        ordinary = self._late_release()
        exceptional = self._late_release(active=True)
        self.assertEqual(len(ordinary), 2)
        self.assertEqual(len(exceptional), 2)
        for event in ordinary:
            self.assertIsNone(event["value"]["active"])
        for event in exceptional:
            active = event["value"]["active"]
            self.assertTrue(active["same_outer"])
            self.assertEqual(active["known_identity"], "outer")
        count, rows = self._compare_late(ordinary, exceptional)
        self.assertEqual(count, 2)
        self.assertEqual([row["expected"] for row in rows], ordinary)
        self.assertEqual([row["actual"] for row in rows], exceptional)

    def test_real_release_order_is_not_sorted_or_filtered(self):
        ordinary = self._late_release()
        reversed_events = self._late_release(reversed_order=True)
        self.assertEqual([row["value"]["object"] for row in ordinary], ["first#1", "second#1"])
        self.assertEqual([row["value"]["object"] for row in reversed_events], ["second#1", "first#1"])
        self.assertEqual(self._compare_late(ordinary, reversed_events)[0], 2)
        self.assertEqual(self._compare_late(ordinary, ordinary)[0], 0)
        self.assertEqual(self._compare_late(ordinary, ordinary[:1])[0], 1)

    def test_actual_strong_provider_reference_cannot_be_certified_released(self):
        terminal, world = self._world()
        provider = oracle.Atom(world, "leaked-provider")
        reference = weakref.ref(world)
        del world
        with self.assertRaisesRegex(ValueError, "survived"):
            terminal.finish()
        self.assertIsNotNone(reference())
        del provider
        gc.collect()
        self.assertIsNone(reference())

    def test_active_exception_context_and_other_thread_are_rejected_before_collection(self):
        terminal, world = self._world()
        del world
        try:
            raise RuntimeError("real surrounding exception")
        except RuntimeError:
            with self.assertRaisesRegex(ValueError, "context"):
                terminal.finish()
            with self.assertRaisesRegex(ValueError, "exception-free"):
                observer.CaseTerminal(self.case)
        token = oracle._THREAD_LABEL.set("changed-test-context")
        try:
            with self.assertRaisesRegex(ValueError, "context"):
                terminal.finish()
        finally:
            oracle._THREAD_LABEL.reset(token)
        errors = []
        def other_thread():
            try:
                terminal.finish()
            except BaseException as error:
                errors.append((type(error), str(error)))
        thread = threading.Thread(target=other_thread)
        thread.start()
        thread.join(timeout=3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(errors), 1)
        self.assertIs(errors[0][0], ValueError)
        self.assertIn("context", errors[0][1])
        self.assertEqual(terminal.finish()["released_worlds"], 1)

    def test_actual_gc_configuration_change_is_rejected_and_original_restored(self):
        terminal, world = self._world()
        del world
        try:
            gc.set_threshold(self.gc_before[1][0] + 1, *self.gc_before[1][1:])
            with self.assertRaisesRegex(ValueError, "GC"):
                terminal.finish()
        finally:
            gc.set_threshold(*self.gc_before[1])
        try:
            gc.disable()
            with self.assertRaisesRegex(ValueError, "GC"):
                terminal.finish()
            with self.assertRaisesRegex(ValueError, "exception-free"):
                observer.CaseTerminal(self.case)
        finally:
            gc.enable()
        self.assertEqual(terminal.finish()["gc_after"]["thresholds"], list(self.gc_before[1]))

    def test_unrelated_repeated_missing_and_reused_world_are_rejected(self):
        terminal, world = self._world()
        with self.assertRaises(ValueError):
            terminal.retain(world)
        with self.assertRaises(ValueError):
            terminal.retain(object())
        del world
        terminal.finish()
        with self.assertRaises(ValueError):
            terminal.retain(object())
        incomplete = observer.CaseTerminal(self.case)
        with self.assertRaises(ValueError):
            incomplete.finish()
        other = dict(self.case, id="unrelated")
        wrong = oracle.World(other)
        with self.assertRaises(ValueError):
            incomplete.retain(wrong)
        del wrong

    def test_collection_exception_propagates_without_terminal_receipt(self):
        terminal, world = self._world()
        world.external["cycle"] = world
        reference = weakref.ref(world)
        del world
        with patch.object(gc, "collect", side_effect=RuntimeError("actual collection failure path")):
            with self.assertRaisesRegex(RuntimeError, "collection failure"):
                terminal.finish()
        gc.collect()
        self.assertIsNone(reference())
        with self.assertRaises(ValueError):
            terminal.finish()

    def test_data_only_reader_rejects_full_boundary_mutations_missing_and_wrong_order(self):
        raw, actual, trace, late, boundary = self._observe()
        with TemporaryDirectory(prefix="hia-bootstrap-case-reader-") as directory:
            root = Path(directory)
            (root / "observations.jsonl").write_bytes(raw + b"\n")
            report = {"count": 1, "ordered_ids": [self.case["id"]],
                      "case_terminal_protocol": support.CASE_TERMINAL_SCHEMA,
                      "files": {"observations.jsonl": support.file_pin(root / "observations.jsonl")}}
            def publish(rows):
                data = b"".join(support.canonical(row) + b"\n" for row in rows)
                (root / "case-terminals.jsonl").write_bytes(data)
                report["files"]["case-terminals.jsonl"] = support.bytes_pin(data)
            publish([boundary])
            self.assertEqual(support.case_terminals(root, report, [self.case])["count"], 1)
            self.assertEqual(list(reader.rows(root, report, [self.case])), [actual])
            mutations = [
                ("schema", "hepta.hia.service-bootstrap-case-terminal.v0"),
                ("id", "another-case"), ("retained_worlds", 2), ("retained_worlds", True),
                ("released_worlds", 0), ("collection_calls", 0), ("collection_calls", True),
                ("active_exception_before", {"type": "hidden"}),
                ("active_exception_after", {"type": "hidden"}),
                ("context", "changed"), ("main_thread", False),
                ("gc_before", {"enabled": False, "thresholds": list(gc.get_threshold())}),
                ("gc_after", {"enabled": True, "thresholds": [1, 2, 3]}),
                ("gc_after", {"enabled": True, "thresholds": [True, 2, 3]}),
            ]
            for key, value in mutations:
                changed = deepcopy(boundary)
                changed[key] = value
                publish([changed])
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    list(reader.rows(root, report, [self.case]))
            for rows in ([], [boundary, boundary], [{k: v for k, v in boundary.items() if k != "gc_after"}],
                         [{**boundary, "ignored_extra": True}]):
                publish(rows)
                with self.assertRaises(ValueError):
                    list(reader.rows(root, report, [self.case]))
            publish([boundary])
            report["case_terminal_protocol"] = "old"
            with self.assertRaises(ValueError):
                list(reader.rows(root, report, [self.case]))
            report["case_terminal_protocol"] = support.CASE_TERMINAL_SCHEMA
            pin = report["files"]["case-terminals.jsonl"]
            (root / "case-terminals.jsonl").write_bytes((root / "case-terminals.jsonl").read_bytes() + b"\n")
            self.assertEqual(report["files"]["case-terminals.jsonl"], pin)
            with self.assertRaises(ValueError):
                list(reader.rows(root, report, [self.case]))

    def test_original_budget_and_terminal_natural_exit_guards_remain(self):
        prior = originals()
        before = ast.parse(prior["tools/qualify_hia_service_bootstrap_finite.py"])
        after = ast.parse((ROOT / "tools/qualify_hia_service_bootstrap_finite.py").read_bytes())
        def node(tree, name):
            return next(item for item in tree.body if isinstance(item, ast.FunctionDef) and item.name == name)
        self.assertEqual(ast.dump(node(before, "_compare_terminal_late"), include_attributes=False),
                         ast.dump(node(after, "_compare_terminal_late"), include_attributes=False))
        old_support = ast.parse(prior["tests/hia_service_bootstrap_support.py"])
        new_support = ast.parse((ROOT / "tests/hia_service_bootstrap_support.py").read_bytes())
        self.assertEqual(ast.dump(node(old_support, "run_child"), include_attributes=False),
                         ast.dump(node(new_support, "run_child"), include_attributes=False))
        old_child = node(before, "child")
        new_child = node(after, "child")
        def budget(function):
            return next(item for item in function.body if isinstance(item, ast.Assign)
                        and any(isinstance(target, ast.Name) and target.id == "seconds" for target in item.targets))
        self.assertEqual(ast.dump(budget(old_child), include_attributes=False),
                         ast.dump(budget(new_child), include_attributes=False))


if __name__ == "__main__":
    unittest.main()
