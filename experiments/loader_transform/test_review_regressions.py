"""Independent loader-transform review regressions; run with repo on PYTHONPATH."""
import copy
from dataclasses import asdict
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from hepta import ast, modules
from hepta._loader_ops import LegacyLoaderOps
from experiments.normal_loader_extraction import baseline
from experiments.loader_transform.owner import Owner, Limits, _BINDINGS
from experiments.request_load.context import Rejected

TEXT = 'fn main()->Unit effects {} {}'

class TransformReviewRegressions(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.entry = Path(temporary.name) / 'main.hepta'
        self.entry.write_text(TEXT)

    def transform_events(self, action):
        events = []
        old = sys.getprofile()
        def profile(frame, event, arg):
            if event != 'call':
                return
            if frame.f_code is ast.Type.__init__.__code__ and frame.f_back.f_code.co_name == 'transform':
                events.append('Type constructor')
            if (frame.f_code.co_name in ('<listcomp>', '<dictcomp>', '<genexpr>')
                    and frame.f_code.co_filename == modules.__file__
                    and '.transform.' in frame.f_code.co_qualname):
                events.append(frame.f_code.co_name)
        sys.setprofile(profile)
        try:
            action()
        finally:
            sys.setprofile(old)
        return events

    def test_empty_function_exact_14_and_depth_2(self):
        owner = Owner(Limits(transform_visits=14, transform_depth=2))
        handle = owner.load(self.entry)
        self.assertEqual(owner.context.counts['transform_visits'], 14)
        self.assertEqual(asdict(handle.project.program), asdict(modules.load_project(self.entry).program))
        denied = Owner(Limits(transform_visits=13))
        with self.assertRaisesRegex(Rejected, 'transform_visits'):
            denied.load(self.entry)
        self.assertEqual(denied.context.counts['transform_visits'], 13)
        self.assertEqual(denied._handles, [])
        self.assertTrue(denied.context.closed)

    def test_first_child_depth_denial_precedes_reconstruction(self):
        owner = Owner(Limits(transform_depth=1))
        def action():
            with self.assertRaisesRegex(Rejected, 'transform_depth'):
                owner.load(self.entry)
        denied_lines = []
        old_trace = sys.gettrace()
        def trace(frame, event, arg):
            if (event == 'line' and frame.f_code.co_name == 'transform'
                    and frame.f_code.co_filename == modules.__file__
                    and frame.f_locals.get('depth') == 2):
                denied_lines.append(frame.f_lineno - frame.f_code.co_firstlineno)
            return trace
        sys.settrace(trace)
        try:
            self.assertEqual(self.transform_events(action), [])
        finally:
            sys.settrace(old_trace)
        # CPython 3.12 inlines list comprehensions; observing no profile call
        # alone is insufficient. The denied child executes only its seam line.
        self.assertEqual(denied_lines, [1])
        self.assertEqual(owner.context.counts['transform_visits'], 1)

    def test_type_entry_denial_precedes_constructor(self):
        owner = Owner(Limits(transform_visits=2))
        def action():
            with self.assertRaisesRegex(Rejected, 'transform_visits'):
                owner.load(self.entry)
        self.assertNotIn('Type constructor', self.transform_events(action))
        self.assertEqual(owner.context.counts['transform_visits'], 2)
        self.assertTrue(owner.context.closed)

    def test_forty_operands_exact_333_and_depth_84(self):
        self.entry.write_text('fn main()->i32 effects {} { return ' + ' + '.join('1' for _ in range(40)) + '; }')
        owner = Owner(Limits(transform_visits=333, transform_depth=84))
        owner.load(self.entry)
        self.assertEqual(owner.context.counts['transform_visits'], 333)
        self.assertEqual(owner.context.counts['copy_visits'], 3824)
        owner = Owner(Limits(transform_depth=83))
        with self.assertRaisesRegex(Rejected, 'transform_depth'):
            owner.load(self.entry)
        self.assertTrue(owner.context.closed)
        owner = Owner(Limits(transform_visits=332))
        with self.assertRaisesRegex(Rejected, 'transform_visits'):
            owner.load(self.entry)
        self.assertEqual(owner.context.counts['transform_visits'], 332)

    def test_shared_type_is_visited_per_occurrence_and_reconstructed_twice(self):
        self.entry.write_text('fn main(x:i32)->i32 effects {} { return x; }')
        owner = Owner()
        original = owner._ops.deepcopy
        alias = []
        def copy_then_alias(copier, value):
            result = original(copier, value)
            if type(result) is ast.Function:
                result.params[0].type = result.return_type
                alias.append(result.return_type)
            return result
        owner._ops.deepcopy = copy_then_alias
        handle = owner.load(self.entry)
        function = handle.project.program.functions[0]
        # The seam must not memoize/skip either occurrence. Existing transform
        # creates separate Types even though deepcopy normally preserves aliases.
        self.assertEqual(function.params[0].type, function.return_type)
        self.assertIsNot(function.params[0].type, function.return_type)
        self.assertIsNot(function.params[0].type, alias[0])
        ordinary = Owner(); ordinary.load(self.entry)
        self.assertEqual(owner.context.counts['transform_visits'], ordinary.context.counts['transform_visits'])

    def test_callback_alias_swaps_refused_before_hook_execution(self):
        for name, original in _BINDINGS:
            with self.subTest(name=name):
                owner = Owner()
                replacement = Mock(side_effect=AssertionError('replacement executed'))
                def checkpoint():
                    setattr(modules, name, replacement)
                owner.context.checkpoint = checkpoint
                try:
                    with self.assertRaisesRegex(Rejected, 'transform alias'):
                        owner._ops.transform_visit(1)
                finally:
                    setattr(modules, name, original)
                replacement.assert_not_called()
                self.assertEqual(owner.context.counts['transform_visits'], 0)
                self.assertTrue(owner.context.closed)

    def test_deleted_admission_hook_refuses_with_terminal_diagnostic(self):
        original = LegacyLoaderOps.transform_visit
        owner = Owner()
        try:
            del LegacyLoaderOps.transform_visit
            with self.assertRaisesRegex(Rejected, 'transform admission hook'):
                owner.load(self.entry)
        finally:
            LegacyLoaderOps.transform_visit = original
        self.assertTrue(owner.context.closed)

    def test_swallowed_nested_transform_stays_terminal(self):
        owner = Owner()
        def checkpoint():
            try:
                owner._ops.transform_visit(1)
            except Rejected:
                pass
        owner.context.checkpoint = checkpoint
        with self.assertRaisesRegex(Rejected, 'terminal'):
            owner._ops.transform_visit(1)
        self.assertEqual(owner.context.counts['transform_visits'], 0)
        self.assertTrue(owner.context.closed)

    def legacy_trace(self, api, failure):
        events = []
        clones = []
        real_copy = copy.deepcopy
        class Constructor:
            def __init__(self, label): self.label = label
            def __instancecheck__(self, value): return isinstance(value, ast.Type)
            def __call__(self, *args):
                events.append('construct:' + self.label)
                if failure == 'constructor':
                    raise LookupError('constructor failure')
                return ast.Type(*args)
            def __del__(self): events.append('finalize:' + self.label)
        class Arguments:
            def __iter__(self):
                events.append('iterate arguments')
                api.Type = Constructor('new')
                if failure == 'argument':
                    raise LookupError('argument failure')
                return iter(())
        class CopyNamespace:
            @staticmethod
            def deepcopy(value):
                result = real_copy(value)
                if type(result) is ast.Function:
                    clones.append(result)
                    object.__setattr__(result.return_type, 'args', Arguments())
                return result
        def setattr_(self, name, value):
            if name == 'return_type' and any(self is clone for clone in clones):
                events.append('write return_type')
            object.__setattr__(self, name, value)
        held = None
        original_type = api.Type
        api.Type = Constructor('old')
        try:
            with patch.object(api, 'copy', CopyNamespace), patch.object(ast.Function, '__setattr__', setattr_):
                try:
                    api.load_project(self.entry)
                except LookupError as error:
                    held = error
                    events.append('caught')
                result = list(events)
                if failure:
                    self.assertIsNotNone(held.__traceback__)
        finally:
            api.Type = original_type
        # Keep the held traceback alive until after taking the trace snapshot.
        return result

    def test_legacy_constructor_capture_before_argument_and_release_before_write(self):
        expected = self.legacy_trace(baseline.modules, None)
        actual = self.legacy_trace(modules, None)
        self.assertEqual(actual, expected)
        self.assertEqual(actual, ['iterate arguments', 'construct:old', 'finalize:old', 'write return_type'])

    def test_legacy_argument_failure_releases_captured_constructor_before_catch(self):
        expected = self.legacy_trace(baseline.modules, 'argument')
        actual = self.legacy_trace(modules, 'argument')
        self.assertEqual(actual, expected)
        self.assertEqual(actual, ['iterate arguments', 'finalize:old', 'caught'])

    def test_legacy_constructor_failure_retains_same_callable_in_held_traceback(self):
        expected = self.legacy_trace(baseline.modules, 'constructor')
        actual = self.legacy_trace(modules, 'constructor')
        self.assertEqual(actual, expected)
        self.assertEqual(actual, ['iterate arguments', 'construct:old', 'caught'])

if __name__ == '__main__':
    unittest.main(verbosity=2)
