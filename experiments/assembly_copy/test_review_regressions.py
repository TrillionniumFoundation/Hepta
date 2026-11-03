"""Independent regression candidates for assembly-copy admission.

Run with python -m unittest experiments.assembly_copy.test_review_regressions -v
No production monkeypatch is retained after a test.
"""
import copy
from functools import partial
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta import ast, modules, parser
from hepta._loader_ops import LegacyLoaderOps
from experiments.assembly_copy.owner import Owner, Limits, _DEEPCOPY, _Ops
from experiments.request_load.context import Rejected

TEXT = 'fn main()->Unit effects {} {}'


class ReviewRegressions(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.directory = Path(tmp.name)
        self.entry = self.directory / 'main.hepta'
        self.entry.write_text(TEXT)

    def root_copy_calls(self, action):
        calls = []
        previous = sys.getprofile()
        def observe(frame, event, arg):
            if (event == 'call' and frame.f_code is _DEEPCOPY.__code__
                    and frame.f_back.f_code is _Ops.deepcopy.__code__):
                calls.append(type(frame.f_locals['x']).__name__)
        sys.setprofile(observe)
        try:
            action()
        finally:
            sys.setprofile(previous)
        return calls

    def test_synthesized_deepcopy_getattr_refused_without_execution(self):
        events = []
        value = ast.Expr('int', 1)
        def getattr_(self, name):
            events.append(name)
            if name == '__deepcopy__':
                return lambda memo: self
            raise AttributeError(name)
        with patch.object(ast.Expr, '__getattr__', getattr_, create=True):
            with self.assertRaises(Rejected):
                Owner()._ops.deepcopy(copy.deepcopy, value)
        self.assertEqual(events, [])

    def test_constructor_class_dispatch_refused_without_execution(self):
        events = []
        def hook(value, memo):
            events.append(value)
            return value
        with patch.dict(copy._deepcopy_dispatch, {type: hook}):
            with self.assertRaises(Rejected):
                Owner()._ops.deepcopy(copy.deepcopy, ast.Expr('int', 1))
        self.assertEqual(events, [])

    def test_synthetic_slot_state_refused_without_descriptor(self):
        events = []
        value = ast.Expr('int', 1)
        def danger(self):
            events.append('descriptor')
            return 123
        with patch.object(ast.Expr, '__slotnames__', ['danger'], create=True):
            with patch.object(ast.Expr, 'danger', property(danger), create=True):
                with self.assertRaises(Rejected):
                    Owner()._ops.deepcopy(copy.deepcopy, value)
        self.assertEqual(events, [])

    def test_lazy_empty_slot_cache_allows_repeated_copies(self):
        value = ast.Expr('int', 1)
        owner = Owner()
        first = owner._ops.deepcopy(copy.deepcopy, value)
        second = owner._ops.deepcopy(copy.deepcopy, value)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)

    def test_failure_traceback_does_not_retain_legacy_temporaries(self):
        for fail in (False, True):
            with self.subTest(fail=fail):
                events = []
                class Operation(partial):
                    def __del__(self):
                        events.append('callable finalized')
                class Argument:
                    def __del__(self):
                        events.append('argument finalized')
                class Namespace:
                    @property
                    def deepcopy(self):
                        return Operation(int if fail else id)
                held_exception = None
                try:
                    LegacyLoaderOps().deepcopy(Namespace().deepcopy, Argument())
                except TypeError as error:
                    held_exception = error
                    events.append('caught')
                expected = ['callable finalized', 'argument finalized']
                if fail:
                    expected.append('caught')
                self.assertEqual(events, expected)
                # Keep the traceback alive through the timing assertion.
                if fail:
                    self.assertIsNotNone(held_exception.__traceback__)

    def test_actual_loader_captures_hook_before_argument_and_finalizes_before_writes(self):
        events = []
        clones = []
        real_copy = copy.deepcopy
        class Copier:
            def __init__(self, label):
                self.label = label
            def __call__(self, value):
                events.append('call:' + self.label + ':' + type(value).__name__)
                result = real_copy(value)
                clones.append(result)
                return result
            def __del__(self):
                events.append('delete:' + self.label)
        class Namespace:
            label = 'old'
            @property
            def deepcopy(self):
                events.append('resolve:' + self.label)
                return Copier(self.label)
        namespace = Namespace()
        class Unit(modules.Unit):
            def __getattribute__(self, name):
                if name == 'program':
                    events.append('argument:program')
                    namespace.label = 'new'
                return super().__getattribute__(name)
        def setattr_(self, name, value):
            if any(self is clone for clone in clones):
                events.append('write:' + type(self).__name__ + '.' + name)
            object.__setattr__(self, name, value)
        with patch.object(modules, 'copy', namespace), patch.object(modules, 'Unit', Unit):
            with patch.object(ast.Program, '__setattr__', setattr_), patch.object(ast.Function, '__setattr__', setattr_):
                modules.load_project(self.entry)
        self.assertEqual(events[:5], ['resolve:old', 'argument:program',
            'call:old:Program', 'delete:old', 'write:Program.structs'])
        second = events.index('call:new:Function')
        self.assertEqual(events[second:second + 3],
            ['call:new:Function', 'delete:new', 'write:Function.name'])

    def test_actual_loader_failure_releases_both_temporaries_before_catch(self):
        events = []
        class Operation(partial):
            def __del__(self):
                events.append('callable finalized')
        class Argument:
            def __del__(self):
                events.append('argument finalized')
        class Namespace:
            @property
            def deepcopy(self):
                events.append('resolve')
                return Operation(int)
        class Unit(modules.Unit):
            def __getattribute__(self, name):
                if name == 'program':
                    events.append('argument')
                    return Argument()
                return super().__getattribute__(name)
        held_exception = None
        with patch.object(modules, 'copy', Namespace()), patch.object(modules, 'Unit', Unit):
            try:
                modules.load_project(self.entry)
            except TypeError as error:
                held_exception = error
                events.append('caught')
            self.assertEqual(events, ['resolve', 'argument', 'callable finalized',
                'argument finalized', 'caught'])
            self.assertIsNotNone(held_exception.__traceback__)

    def test_actual_loader_argument_failure_releases_captured_callable(self):
        events = []
        class Operation(partial):
            def __del__(self):
                events.append('callable finalized')
        class Namespace:
            @property
            def deepcopy(self):
                events.append('resolve')
                return Operation(id)
        class Unit(modules.Unit):
            def __getattribute__(self, name):
                if name == 'program':
                    events.append('argument')
                    raise LookupError('argument failed')
                return super().__getattribute__(name)
        held_exception = None
        with patch.object(modules, 'copy', Namespace()), patch.object(modules, 'Unit', Unit):
            try:
                modules.load_project(self.entry)
            except LookupError as error:
                held_exception = error
                events.append('caught')
            self.assertEqual(events, ['resolve', 'argument', 'callable finalized', 'caught'])
            self.assertIsNotNone(held_exception.__traceback__)

    def test_post_copy_cancellation_consumes_visits_and_is_terminal(self):
        owner = Owner()
        checkpoints = []
        def checkpoint():
            checkpoints.append(owner.context.counts['copy_visits'])
            if len(checkpoints) == 2:
                raise TimeoutError('cancel after copy')
        owner.context.checkpoint = checkpoint
        def cancel():
            with self.assertRaisesRegex(TimeoutError, 'after copy'):
                owner._ops.deepcopy(copy.deepcopy, [1, 2, 3])
        self.assertEqual(self.root_copy_calls(cancel), ['list'])
        self.assertEqual(checkpoints, [0, 4])
        self.assertEqual(owner.context.counts['copy_visits'], 4)
        self.assertTrue(owner.context.closed)
        with self.assertRaises(Rejected):
            owner._ops.deepcopy(copy.deepcopy, [])

    def test_copy_failure_consumes_completed_preflight(self):
        value = []
        for _ in range(150):
            value = [value]
        owner = Owner(Limits(copy_depth=151))
        old_limit = sys.getrecursionlimit()
        try:
            sys.setrecursionlimit(200)
            with self.assertRaises(RecursionError):
                owner._ops.deepcopy(copy.deepcopy, value)
        finally:
            sys.setrecursionlimit(old_limit)
        self.assertEqual(owner.context.counts['copy_visits'], 151)
        self.assertTrue(owner.context.closed)

    def test_149_refuses_second_site_and_150_admits_both(self):
        owner = Owner(Limits(copy_visits=149))
        def refuse():
            with self.assertRaisesRegex(Rejected, 'copy_visits'):
                owner.load(self.entry)
        self.assertEqual(self.root_copy_calls(refuse), ['Program'])
        self.assertEqual(owner.context.counts['copy_visits'], 149)
        self.assertEqual(owner._handles, [])
        self.assertTrue(owner.context.closed)
        exact = Owner(Limits(copy_visits=150))
        self.assertEqual(self.root_copy_calls(lambda: exact.load(self.entry)),
            ['Program', 'Function'])
        self.assertEqual(exact.context.counts['copy_visits'], 150)

    def test_module_cumulative_235_refuses_236_admits(self):
        self.entry.write_text('import dep; ' + TEXT)
        (self.directory / 'dep.hepta').write_text('pub fn helper()->Unit effects {} {}')
        owner = Owner(Limits(copy_visits=235))
        def refuse():
            with self.assertRaisesRegex(Rejected, 'copy_visits'):
                owner.load(self.entry)
        self.assertEqual(self.root_copy_calls(refuse), ['Program', 'Function'])
        self.assertEqual(owner.context.counts['copy_visits'], 235)
        exact = Owner(Limits(copy_visits=236))
        self.assertEqual(self.root_copy_calls(lambda: exact.load(self.entry)),
            ['Program', 'Function', 'Function'])
        self.assertEqual(exact.context.counts['copy_visits'], 236)
        self.assertEqual(exact.context.counts['modules'], 2)

    def test_real_parser_40_operand_tree_depth_131(self):
        self.entry.write_text('fn main()->i32 effects {} { return '
            + ' + '.join('1' for _ in range(40)) + '; }')
        parser.parse(self.entry.read_text())
        refused = Owner(Limits(copy_depth=130))
        def refuse():
            with self.assertRaisesRegex(Rejected, 'copy_depth'):
                refused.load(self.entry)
        self.assertEqual(self.root_copy_calls(refuse), [])
        self.assertTrue(refused.context.closed)
        exact = Owner(Limits(copy_depth=131))
        exact.load(self.entry)
        self.assertEqual(exact.context.counts['parses'], 1)


if __name__ == '__main__':
    unittest.main()
