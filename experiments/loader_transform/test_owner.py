import ast as syntax
from dataclasses import asdict
import inspect
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from hepta import ast, modules, packages
from hepta._loader_ops import LegacyLoaderOps
from experiments.assembly_copy.owner import Owner as CopyOwner
from experiments.request_load.context import Rejected
from .owner import Owner, Limits, _BINDINGS

TEXT='fn main()->Unit effects {} {}'


class TransformTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name);self.entry=self.root/'main.hepta';self.entry.write_text(TEXT)

    def package(self):
        (self.root/'hepta.toml').write_text('[package]\nname="example"\nversion="1.0.0"\nsource_root="."\nentry="main.hepta"\n')

    def test_positive_integer_limits(self):
        for name in ('transform_visits','transform_depth'):
            for value in (0,-1,True,1.5,'10'):
                with self.subTest(name=name,value=value),self.assertRaises(ValueError):
                    Limits(**{name:value})

    def test_exact_empty_function_14(self):
        owner=Owner(Limits(transform_visits=14));handle=owner.load(self.entry)
        self.assertEqual(owner.context.counts['transform_visits'],14)
        self.assertEqual(owner.context.counts['copy_visits'],150)
        self.assertEqual(handle.project.report(),modules.load_project(self.entry).report())

    def test_one_under_is_terminal_and_keeps_attempts(self):
        owner=Owner(Limits(transform_visits=13))
        with self.assertRaisesRegex(Rejected,'transform_visits'):owner.load(self.entry)
        self.assertEqual(owner.context.counts['transform_visits'],13)
        self.assertEqual(owner._handles,[]);self.assertTrue(owner.context.closed)
        with self.assertRaisesRegex(Rejected,'terminal'):owner.load(self.entry)

    def test_empty_module_has_no_transform_work(self):
        self.entry.write_text('module main;')
        owner=Owner(Limits(transform_visits=1));owner.load(self.entry)
        self.assertEqual(owner.context.counts['transform_visits'],0)

    def test_exact_depth_two_and_refused_depth_one(self):
        Owner(Limits(transform_depth=2)).load(self.entry)
        owner=Owner(Limits(transform_depth=1))
        with self.assertRaisesRegex(Rejected,'transform_depth'):owner.load(self.entry)
        self.assertEqual(owner.context.counts['transform_visits'],1)

    def test_invalid_private_depth_never_runs_comparison_hooks(self):
        class Evil:
            def __lt__(self,other):raise AssertionError('comparison')
        for value in (True,0,-1,'1',Evil()):
            with self.subTest(value=type(value)):
                owner=Owner()
                with self.assertRaisesRegex(Rejected,'invalid transform depth'):
                    owner._ops.transform_visit(value)
                self.assertEqual(owner.context.counts['transform_visits'],0)

    def test_wide_functions_count_cumulatively(self):
        self.entry.write_text('\n'.join('fn f'+str(i)+'()->Unit effects {} {}' for i in range(100)))
        owner=Owner(Limits(transform_visits=1400));owner.load(self.entry)
        self.assertEqual(owner.context.counts['transform_visits'],1400)
        refused=Owner(Limits(transform_visits=1399))
        with self.assertRaisesRegex(Rejected,'transform_visits'):refused.load(self.entry)
        self.assertEqual(refused.context.counts['transform_visits'],1399)

    def test_reload_quota_cumulative(self):
        owner=Owner(Limits(transform_visits=27));owner.load(self.entry)
        with self.assertRaisesRegex(Rejected,'transform_visits'):owner.load(self.entry)
        self.assertEqual(owner.context.counts['transform_visits'],27)

    def test_multiple_modules_share_transform_quota(self):
        self.entry.write_text('import lib;'+TEXT)
        (self.root/'lib.hepta').write_text('pub fn helper()->Unit effects {} {}')
        owner=Owner(Limits(transform_visits=28));owner.load(self.entry)
        self.assertEqual(owner.context.counts['transform_visits'],28)
        owner=Owner(Limits(transform_visits=27))
        with self.assertRaisesRegex(Rejected,'transform_visits'):owner.load(self.entry)
        self.assertEqual(owner.context.counts['transform_visits'],27)

    def test_revalidation_adds_no_visits(self):
        owner=Owner(Limits(transform_visits=14));handle=owner.load(self.entry)
        self.assertTrue(handle.unchanged());self.assertTrue(handle.unchanged())
        self.assertEqual(owner.context.counts['transform_visits'],14)

    def test_prior_copy_profile_has_no_counter(self):
        owner=CopyOwner();owner.load(self.entry)
        self.assertNotIn('transform_visits',owner.context.counts)

    def test_copy_budget_remains_independent(self):
        owner=Owner(Limits(copy_visits=149))
        with self.assertRaisesRegex(Rejected,'copy_visits'):owner.load(self.entry)
        self.assertEqual(owner.context.counts['transform_visits'],0)

    def test_rejected_visit_precedes_type_reconstruction(self):
        owner=Owner(Limits(transform_visits=2));hook=Mock(side_effect=AssertionError('Type reconstructed'))
        def checkpoint():
            if owner.context.counts['copy_visits']==150:
                ast.Type.__init__=hook
        owner.context.checkpoint=checkpoint
        with patch.object(ast.Type,'__init__',ast.Type.__init__):
            with self.assertRaisesRegex(Rejected,'transform_visits'):owner.load(self.entry)
        hook.assert_not_called()
        self.assertEqual(owner.context.counts['transform_visits'],2)
        self.assertEqual(owner.context.counts['copy_visits'],150)

    def test_transform_failure_keeps_admitted_work(self):
        owner=Owner()
        def broken(*args,**kwargs):raise ValueError('reconstruction failed')
        def checkpoint():
            if owner.context.counts['copy_visits']==150:ast.Type.__init__=broken
        owner.context.checkpoint=checkpoint
        with patch.object(ast.Type,'__init__',ast.Type.__init__):
            with self.assertRaisesRegex(ValueError,'reconstruction failed'):owner.load(self.entry)
        self.assertEqual(owner.context.counts['transform_visits'],3)
        self.assertTrue(owner.context.closed)

    def test_alias_replacements_refused_without_invocation(self):
        for name,_ in _BINDINGS:
            owner=Owner();hook=Mock(side_effect=AssertionError('hook'))
            with self.subTest(name=name),patch.object(modules,name,hook):
                with self.assertRaisesRegex(Rejected,'transform alias'):owner.load(self.entry)
                hook.assert_not_called()
            self.assertEqual(owner.context.counts['transform_visits'],0)

    def test_checkpoint_alias_replacement_refused(self):
        for name,original in _BINDINGS:
            owner=Owner();hook=Mock(side_effect=AssertionError('hook'))
            def checkpoint():setattr(modules,name,hook)
            owner.context.checkpoint=checkpoint
            with self.subTest(name=name),patch.object(modules,name,original):
                with self.assertRaisesRegex(Rejected,'transform alias'):owner._ops.transform_visit(1)
                hook.assert_not_called()
            self.assertEqual(owner.context.counts['transform_visits'],0)

    def test_replaced_entry_seam_refused(self):
        owner=Owner();hook=Mock(side_effect=AssertionError('seam'))
        with patch.object(LegacyLoaderOps,'transform_visit',hook):
            with self.assertRaisesRegex(Rejected,'transform admission'):owner.load(self.entry)
            hook.assert_not_called()

    def test_cancellation_before_visit_is_terminal(self):
        owner=Owner()
        def cancel():raise TimeoutError('cancelled')
        owner.context.checkpoint=cancel
        with self.assertRaises(TimeoutError):owner._ops.transform_visit(1)
        self.assertEqual(owner.context.counts['transform_visits'],0)
        self.assertTrue(owner.context.closed)

    def test_swallowed_reentrancy_is_terminal(self):
        owner=Owner()
        def swallow():
            try:owner._ops.transform_visit(1)
            except Rejected:pass
        owner.context.checkpoint=swallow
        with self.assertRaisesRegex(Rejected,'terminal'):owner._ops.transform_visit(1)
        self.assertEqual(owner.context.counts['transform_visits'],0)

    def test_locked_refusal_does_not_modify_lock(self):
        self.package();packages.write_lock(self.root)
        lock=self.root/'Hepta.lock';before=lock.read_bytes()
        owner=Owner(Limits(transform_visits=13))
        with self.assertRaisesRegex(Rejected,'transform_visits'):owner.load(self.entry,locked=True)
        self.assertEqual(lock.read_bytes(),before)
        self.assertEqual(owner._handles,[])

    def test_stale_lock_and_override_refused_before_transform(self):
        self.package();packages.write_lock(self.root);self.entry.write_text(TEXT+' ')
        owner=Owner()
        with self.assertRaises(ast.HeptaError):owner.load(self.entry,locked=True)
        self.assertEqual(owner.context.counts['transform_visits'],0)
        owner=Owner()
        with self.assertRaisesRegex(Rejected,'overrides'):owner.load(self.entry,source_overrides={})
        self.assertEqual(owner.context.counts['transform_visits'],0)

    def test_legacy_seam_is_noop_without_argument_access(self):
        class Evil:
            def __getattribute__(self,name):raise AssertionError('attribute')
            def __bool__(self):raise AssertionError('truth')
        self.assertIsNone(LegacyLoaderOps().transform_visit(Evil()))

    def test_static_entry_and_all_recursive_depth_edges(self):
        tree=syntax.parse(inspect.getsource(modules))
        function=next(n for n in syntax.walk(tree) if isinstance(n,syntax.FunctionDef) and n.name=='transform')
        self.assertEqual(syntax.unparse(function.body[0]),'ops.transform_visit(depth)')
        calls=[n for n in syntax.walk(tree) if isinstance(n,syntax.Call)
               and isinstance(n.func,syntax.Name) and n.func.id=='transform']
        recursive=[n for n in calls if function.lineno<=n.lineno<=function.end_lineno]
        self.assertEqual(len(recursive),6);self.assertEqual(len(calls),7)
        for call in recursive:
            self.assertEqual(len(call.args),3)
            self.assertEqual(syntax.unparse(call.args[2]),'depth + 1')
        root=next(n for n in calls if n not in recursive)
        self.assertEqual(len(root.args),2)

    def test_all_80_examples_match_graphs_and_diagnostics(self):
        root=Path(__file__).resolve().parents[2];passed=failed=0
        for entry in sorted((root/'examples').rglob('*.hepta')):
            with self.subTest(entry=str(entry.relative_to(root))):
                try:expected=modules.load_project(entry)
                except ast.HeptaError as old:
                    with self.assertRaises(ast.HeptaError) as new:Owner().load(entry)
                    self.assertEqual(new.exception.diagnostic.to_dict(),old.diagnostic.to_dict());failed+=1
                else:
                    actual=Owner().load(entry).project
                    self.assertEqual(actual.report(),expected.report())
                    self.assertEqual(actual.source_bytes,expected.source_bytes)
                    self.assertEqual(asdict(actual.program),asdict(expected.program));passed+=1
        self.assertEqual((passed,failed),(68,12))


if __name__=='__main__':unittest.main()
