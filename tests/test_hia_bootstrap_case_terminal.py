"""Observer-v3 controls; original bodies, inputs, tests and budgets remain fixed."""
from __future__ import annotations

import ast
import base64
from copy import deepcopy
import gc
import gzip
from hashlib import sha256
import json
import os
import signal
import subprocess
import time
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



class CaseByteStorageTests(unittest.TestCase):
    def test_all_original_case_bytes_order_and_slices_are_exact(self):
        cases = oracle.cases()[0]
        storage = observer.CaseBytes(cases)
        self.assertEqual(len(storage), 232)
        self.assertEqual(oracle.canonical(list(storage)), oracle.canonical(cases))
        self.assertEqual(storage[:], cases)
        self.assertEqual(storage[-1], cases[-1])
        self.assertEqual(storage[::-3], cases[::-3])
        self.assertEqual([row["id"] for row in storage], [row["id"] for row in cases])

    def test_mutation_of_a_decoded_case_does_not_change_later_views(self):
        cases = oracle.cases()[0]
        original = oracle.canonical(cases)
        storage = observer.CaseBytes(cases)
        decoded = storage[0]
        decoded["id"] = "changed-private-copy"
        decoded["added"] = [{"mutable": True}]
        cases[1]["id"] = "changed-original-input-object"
        self.assertEqual(oracle.canonical(list(storage)), original)
        self.assertIsNot(storage[0], storage[0])
        with self.assertRaises(IndexError):
            storage[len(storage)]
        with self.assertRaises(TypeError):
            storage[0] = decoded

    def test_non_json_object_lists_do_not_create_a_case_store(self):
        for value in (None, (), {}, b"[]", [None], [1]):
            with self.subTest(value=value), self.assertRaises(ValueError):
                observer.CaseBytes(value)
        class Foreign(dict):
            pass
        with self.assertRaises(ValueError):
            observer.CaseBytes([Foreign(id="not-an-admitted-json-object")])

    def test_observer_full_predecessor_and_full_collection_body_are_preserved(self):
        raw = (ROOT / "tests/hia_service_bootstrap_observer.py").read_text()
        start = raw.index("class CaseBytes(tuple):\n")
        end = raw.index("class VMEntry:\n", start)
        prior = raw[:start] + raw[end:]
        insertion = "    cases = CaseBytes(cases)\n    del input_value\n"
        self.assertEqual(prior.count(insertion), 1)
        prior = prior.replace(insertion, "")
        self.assertEqual(sha256(prior.encode()).hexdigest(),
                         "659fb6e0266d19a60bb03417a47869e8a17e3621daa8dcbc41c79fe74cf66b65")
        # The complete predecessor comparison also retains finish(), with its
        # one full gc.collect(), unchanged; it does not replace a generation.


@unittest.skipUnless(sys.platform.startswith("linux"), "actual Linux pidfd/subreaper controls")
class OwnedChildTreeTests(unittest.TestCase):
    def _command(self, root, mode, *, clear_child_environment=False):
        grandchild = (
            "import os,json,time,sys; from pathlib import Path; "
            "Path(sys.argv[1]).write_text(json.dumps({'pid':os.getpid(),"
            "'pgid':os.getpgrp(),'sid':os.getsid(0)})); time.sleep(60)")
        program = (
            "import os,json,time,sys,subprocess; from pathlib import Path\n"
            "root=Path(sys.argv[1]); mode=sys.argv[2]\n"
            "child=subprocess.Popen([sys.executable,'-I','-B','-c',"
            + repr(grandchild) + ",str(root/'grandchild.json')],start_new_session=True,"
            + ("env={}" if clear_child_environment else "env=os.environ.copy()") + ")\n"
            "limit=time.monotonic()+2\n"
            "while not (root/'grandchild.json').exists():\n"
            " if time.monotonic()>=limit: raise RuntimeError('child not ready')\n"
            " time.sleep(.002)\n"
            "(root/'parent.json').write_text(json.dumps({'pid':os.getpid(),'pgid':os.getpgrp()}))\n"
            "if mode=='exit':\n"
            " (root/'run').mkdir(); (root/'run/report.json').write_text("
            "json.dumps({'pid':os.getpid(),'pgid':os.getpgrp()}))\n"
            "else: time.sleep(60)\n")
        return [sys.executable, "-I", "-B", "-c", program, str(root), mode]

    def _read(self, root, name):
        return json.loads((root / name).read_bytes())

    def _assert_complete(self, root):
        result = self._read(root, "run.result.json")
        terminal = self._read(root, "run.tree-terminal.json")
        parent = self._read(root, "parent.json")
        child = self._read(root, "grandchild.json")
        self.assertNotEqual(parent["pgid"], child["pgid"])
        self.assertEqual(child["pid"], child["pgid"])
        self.assertEqual(child["pid"], child["sid"])
        self.assertTrue(terminal["all_captured_reaped"])
        self.assertEqual(terminal["unattributed_children"], [])
        self.assertIn(child["pid"], [row["pid"] for row in terminal["descendants_captured"]])
        self.assertIn(str(child["pid"]), terminal["descendants_reaped"])
        self.assertFalse((Path("/proc") / str(child["pid"])).exists())
        self.assertFalse((Path("/proc") / str(parent["pid"])).exists())
        self.assertEqual(result["cleanup"]["after"], [])
        self.assertEqual(result["cleanup_seconds"], 3)
        self.assertEqual(terminal["restored_subreaper"],
                         self._read(root, "run.tree-start.json")["previous_subreaper"])
        return result

    def test_timeout_cleans_actual_independent_session_and_reaps_it(self):
        with TemporaryDirectory(prefix="hia-bootstrap-owned-timeout-") as directory:
            root = Path(directory)
            with self.assertRaisesRegex(RuntimeError, "complete owned bootstrap child failed"):
                support.run_owned_tree(root, "run", self._command(root, "block"), seconds=1)
            result = self._assert_complete(root)
            self.assertIs(result["timeout"], True)
            self.assertEqual(result["returncode"], -signal.SIGKILL)
            self.assertLess(result["elapsed_seconds"], 4)

    def test_natural_parent_exit_still_cleans_actual_session_descendant(self):
        with TemporaryDirectory(prefix="hia-bootstrap-owned-natural-") as directory:
            root = Path(directory)
            result, report, raw = support.run_owned_tree(
                root, "run", self._command(root, "exit"), seconds=3)
            self._assert_complete(root)
            self.assertEqual(result["returncode"], 0)
            self.assertIs(result["timeout"], False)

    def test_existing_unrelated_process_is_not_signaled(self):
        unrelated = subprocess.Popen([sys.executable, "-I", "-B", "-c",
                                      "import time; time.sleep(60)"],
                                     start_new_session=True)
        try:
            with TemporaryDirectory(prefix="hia-bootstrap-owned-unrelated-") as directory:
                root = Path(directory)
                support.run_owned_tree(root, "run", self._command(root, "exit"), seconds=3)
                self._assert_complete(root)
                self.assertIsNone(unrelated.poll())
                captured = self._read(root, "run.tree-terminal.json")["descendants_captured"]
                self.assertNotIn(unrelated.pid, [row["pid"] for row in captured])
        finally:
            unrelated.kill()
            unrelated.wait(timeout=3)

    def test_supervisor_exception_keeps_descendant_cleanup_and_original_budget(self):
        with TemporaryDirectory(prefix="hia-bootstrap-owned-interrupt-") as directory:
            root = Path(directory)
            old = signal.getsignal(signal.SIGUSR1)
            def interrupt(signum, frame):
                raise RuntimeError("actual controller interruption")
            signal.signal(signal.SIGUSR1, interrupt)
            sent = []
            def notify_ready():
                limit = time.monotonic() + 2
                while not (root / "parent.json").exists() and time.monotonic() < limit:
                    time.sleep(.002)
                if (root / "parent.json").exists():
                    sent.append(True)
                    os.kill(os.getpid(), signal.SIGUSR1)
            notifier = threading.Thread(target=notify_ready)
            notifier.start()
            try:
                with self.assertRaisesRegex(RuntimeError, "complete owned bootstrap child failed"):
                    support.run_owned_tree(root, "run", self._command(root, "block"), seconds=3)
                result = self._assert_complete(root)
                self.assertEqual(result["supervisor_error"]["type"], "RuntimeError")
                self.assertEqual(result["supervisor_error"]["text"], "actual controller interruption")
                self.assertIs(result["timeout"], False)
            finally:
                notifier.join(timeout=3)
                signal.signal(signal.SIGUSR1, old)
            self.assertEqual(sent, [True])
            self.assertFalse(notifier.is_alive())

    def test_unattributed_adopted_child_is_refused_without_signaling_it(self):
        with TemporaryDirectory(prefix="hia-bootstrap-owned-unattributed-") as directory:
            root = Path(directory)
            try:
                with self.assertRaisesRegex(RuntimeError, "complete owned bootstrap child failed"):
                    support.run_owned_tree(root, "run",
                        self._command(root, "exit", clear_child_environment=True), seconds=3)
                result = self._read(root, "run.result.json")
                terminal = self._read(root, "run.tree-terminal.json")
                child = self._read(root, "grandchild.json")
                self.assertIn("no verified owned-tree identity", result["cleanup_error"]["text"])
                self.assertFalse(terminal["all_captured_reaped"])
                self.assertIn(child["pid"], [row["pid"] for row in terminal["unattributed_children"]])
                self.assertTrue((Path("/proc") / str(child["pid"])).exists())
            finally:
                # This test created the clean-environment child and retained its
                # explicit PID. The controller correctly did not claim it.
                child_path = root / "grandchild.json"
                if child_path.exists():
                    pid = self._read(root, "grandchild.json")["pid"]
                    try:
                        descriptor = os.pidfd_open(pid)
                    except ProcessLookupError:
                        descriptor = None
                    if descriptor is not None:
                        try:
                            signal.pidfd_send_signal(descriptor, signal.SIGKILL)
                            os.waitpid(pid, 0)
                        finally:
                            os.close(descriptor)

if __name__ == "__main__":
    unittest.main()
