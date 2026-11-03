import ast as syntax
import copy
import copyreg
from dataclasses import asdict
import inspect
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from hepta import ast, modules, parser
from hepta._loader_ops import LegacyLoaderOps
from experiments.request_load.context import Rejected
from experiments.parser_appends.owner import Owner as AppendOwner
from .owner import Owner, Limits, _preflight, _DEEPCOPY

TEXT = 'fn main()->Unit effects {} {}'


class CopyTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        self.entry=Path(tmp.name)/'main.hepta'; self.entry.write_text(TEXT)

    def copied(self, value, **limits):
        owner=Owner(Limits(**limits)); result=owner._ops.deepcopy(copy.deepcopy,value)
        return owner,result

    def count(self,value):
        owner=Owner(); _preflight(value,owner.context)
        return owner.context.counts['copy_visits']

    def profile_copy(self, action):
        calls=[]; previous=sys.getprofile()
        def observe(frame,event,arg):
            if event=='call' and frame.f_code is _DEEPCOPY.__code__: calls.append(frame)
        sys.setprofile(observe)
        try: action()
        finally: sys.setprofile(previous)
        return len(calls)

    def test_positive_integer_limits(self):
        for name in ('copy_visits','copy_depth'):
            for value in (0,-1,True,1.5,'10'):
                with self.subTest(name=name,value=value),self.assertRaises(ValueError):
                    Limits(**{name:value})

    def test_exact_empty_function_total_150(self):
        owner=Owner(Limits(copy_visits=150));handle=owner.load(self.entry)
        self.assertEqual(owner.context.counts['copy_visits'],150)
        self.assertEqual(owner.context.counts['ast_nodes'],3)
        self.assertEqual(owner.context.counts['parser_appends'],1)
        self.assertEqual(handle.project.report(),modules.load_project(self.entry).report())

    def test_empty_program_16_and_function_67(self):
        self.assertEqual(self.count(parser.parse('')),16)
        program=parser.parse(TEXT)
        self.assertEqual(self.count(program),83)
        self.assertEqual(self.count(program.functions[0]),67)

    def test_exact_and_one_over_visits_before_copy(self):
        owner,result=self.copied([1,2],copy_visits=3)
        self.assertEqual(result,[1,2]);self.assertEqual(owner.context.counts['copy_visits'],3)
        owner=Owner(Limits(copy_visits=2))
        def refuse():
            with self.assertRaisesRegex(Rejected,'copy_visits'):
                owner._ops.deepcopy(copy.deepcopy,[1,2])
        self.assertEqual(self.profile_copy(refuse),0)
        self.assertEqual(owner.context.counts['copy_visits'],2)
        self.assertTrue(owner.context.closed)

    def test_empty_containers_and_scalars_count_one(self):
        for value in (None,False,4,1.5,'s',[],(),{},set()):
            with self.subTest(value=value): self.assertEqual(self.count(value),1)

    def test_dict_keys_values_and_dataclass_state_count(self):
        self.assertEqual(self.count({'a':1,'b':[]}),5)
        self.assertEqual(self.count(ast.Type('i64')),10)

    def test_aliases_are_revisited_but_copy_memo_preserves_identity(self):
        child=[1];value=[child,child]
        owner,result=self.copied(value,copy_visits=5)
        self.assertEqual(owner.context.counts['copy_visits'],5)
        self.assertIs(result[0],result[1]);self.assertIsNot(result[0],child)

    def test_unchanged_tuple_dag_is_expanded_not_unique_counted(self):
        value=(1,)
        for _ in range(8): value=(value,value)
        owner=Owner(Limits(copy_visits=30))
        def refuse():
            with self.assertRaisesRegex(Rejected,'copy_visits'):
                owner._ops.deepcopy(copy.deepcopy,value)
        self.assertEqual(self.profile_copy(refuse),0)
        self.assertEqual(owner.context.counts['copy_visits'],30)
        self.assertGreater(self.count(value),500)

    def test_cycles_rejected_before_copy(self):
        values=[]; values.append(values)
        owner=Owner()
        def refuse():
            with self.assertRaisesRegex(Rejected,'cyclic'): owner._ops.deepcopy(copy.deepcopy,values)
        self.assertEqual(self.profile_copy(refuse),0)
        self.assertTrue(owner.context.closed)

    def test_dataclass_and_dict_cycles_rejected(self):
        value=ast.Expr('name');value.value=value
        mapping={};mapping['self']=mapping
        for item in (value,mapping):
            with self.subTest(item=type(item)),self.assertRaisesRegex(Rejected,'cyclic'):
                self.copied(item)

    def test_depth_counts_scalars_and_alias_paths(self):
        child=[1];value=[child,[child]]
        owner,result=self.copied(value,copy_depth=4)
        self.assertEqual(result,value)
        with self.assertRaisesRegex(Rejected,'copy_depth'): self.copied(value,copy_depth=3)
        with self.assertRaisesRegex(Rejected,'copy_depth'): self.copied([1],copy_depth=1)

    def test_unknown_metaclass_never_hashes_or_compares(self):
        class Meta(type):
            def __hash__(self): raise AssertionError('hash')
            def __eq__(self,other): raise AssertionError('eq')
        class Evil(metaclass=Meta):
            def __getattribute__(self,name): raise AssertionError('getattr')
        with self.assertRaisesRegex(Rejected,'unknown'): self.copied(Evil())

    def test_subclass_rejected_without_iteration(self):
        class Evil(list):
            def __iter__(self): raise AssertionError('iteration')
        with self.assertRaisesRegex(Rejected,'unknown'): self.copied(Evil())

    def test_noncanonical_fields_rejected(self):
        for action in ('extra','missing'):
            value=ast.Type('i64')
            if action=='extra': value.__dict__['extra']=1
            else: del value.__dict__['name']
            with self.subTest(action=action),self.assertRaisesRegex(Rejected,'field shape'):
                self.copied(value)

    def test_bad_dictionary_keys_and_set_members_refused(self):
        for value in ({1:'x'},{('x',):'x'},{1}):
            with self.subTest(value=value),self.assertRaisesRegex(Rejected,'exact strings'):
                self.copied(value)

    def test_ast_deepcopy_hook_refused_without_call(self):
        hook=Mock(side_effect=AssertionError('hook'))
        with patch.object(ast.Expr,'__deepcopy__',hook,create=True):
            with self.assertRaisesRegex(Rejected,'copy hook'): self.copied(ast.Expr('int',1))
            hook.assert_not_called()

    def test_ast_attribute_hook_refused_without_call(self):
        hook=Mock(side_effect=AssertionError('attribute'))
        value=ast.Expr('int',1)
        with patch.object(ast.Expr,'__getattribute__',hook):
            with self.assertRaisesRegex(Rejected,'copy hook'): self.copied(value)
            hook.assert_not_called()

    def test_unknown_state_descriptor_refused_without_call(self):
        hook=Mock(side_effect=AssertionError('descriptor'))
        class Unknown:
            __dict__=property(hook)
        with self.assertRaisesRegex(Rejected,'unknown'): self.copied(Unknown())
        hook.assert_not_called()

    def test_ast_reduce_hook_refused_without_call(self):
        hook=Mock(side_effect=AssertionError('reduce'))
        with patch.object(ast.Expr,'__reduce_ex__',hook):
            with self.assertRaisesRegex(Rejected,'copy hook'): self.copied(ast.Expr('int',1))
            hook.assert_not_called()

    def test_dispatch_and_copyreg_hooks_refused(self):
        hook=Mock(side_effect=AssertionError('dispatch'))
        for table,cls in ((copy._deepcopy_dispatch,list),(copyreg.dispatch_table,ast.Expr)):
            with patch.dict(table,{cls:hook}):
                with self.assertRaisesRegex(Rejected,'copy dispatch'): self.copied([])
                hook.assert_not_called()

    def test_capture_replacement_refused(self):
        hook=Mock(side_effect=AssertionError('captured'))
        owner=Owner()
        with self.assertRaisesRegex(Rejected,'captured'): owner._ops.deepcopy(hook,[])
        hook.assert_not_called()

    def test_module_copy_replacement_refused(self):
        hook=Mock(side_effect=AssertionError('copy'))
        owner=Owner()
        with patch.object(copy,'deepcopy',hook):
            with self.assertRaisesRegex(Rejected,'copy hook'): owner.load(self.entry)
            hook.assert_not_called()

    def test_no_callbacks_between_preflight_and_copy(self):
        owner=Owner();events=[];value=[1,2,3]
        def checkpoint(): events.append(owner.context.counts['copy_visits'])
        owner.context.checkpoint=checkpoint
        result=owner._ops.deepcopy(copy.deepcopy,value)
        self.assertEqual(result,value);self.assertEqual(events,[0,4])

    def test_entry_callback_mutation_is_fully_admitted(self):
        owner=Owner(Limits(copy_visits=2));value=[]
        def mutate(): value.extend([1,2,3])
        owner.context.checkpoint=mutate
        def refuse():
            with self.assertRaisesRegex(Rejected,'copy_visits'): owner._ops.deepcopy(copy.deepcopy,value)
        self.assertEqual(self.profile_copy(refuse),0)

    def test_cancellation_terminal_before_copy(self):
        owner=Owner()
        def cancel(): raise TimeoutError('cancelled')
        owner.context.checkpoint=cancel
        def refuse():
            with self.assertRaises(TimeoutError): owner._ops.deepcopy(copy.deepcopy,[])
        self.assertEqual(self.profile_copy(refuse),0)
        self.assertTrue(owner.context.closed);self.assertEqual(owner.context.counts['copy_visits'],0)

    def test_swallowed_reentrancy_remains_terminal(self):
        owner=Owner()
        def swallow():
            try: owner._ops.deepcopy(copy.deepcopy,[])
            except Rejected: pass
        owner.context.checkpoint=swallow
        with self.assertRaisesRegex(Rejected,'terminal'): owner._ops.deepcopy(copy.deepcopy,[])
        self.assertEqual(owner.context.counts['copy_visits'],0)

    def test_reload_budget_cumulative(self):
        owner=Owner(Limits(copy_visits=150));owner.load(self.entry)
        with self.assertRaisesRegex(Rejected,'copy_visits'): owner.load(self.entry)
        self.assertEqual(owner.context.counts['copy_visits'],150)

    def test_revalidation_adds_no_copy_visits(self):
        owner=Owner();handle=owner.load(self.entry)
        before=owner.context.counts['copy_visits'];self.assertTrue(handle.unchanged())
        self.assertEqual(owner.context.counts['copy_visits'],before)

    def test_old_profile_does_not_acquire_new_quota(self):
        owner=AppendOwner();owner.load(self.entry)
        self.assertNotIn('copy_visits',owner.context.counts)

    def test_legacy_exact_argument_and_callable(self):
        value=object();result=object();hook=Mock(return_value=result)
        self.assertIs(LegacyLoaderOps().deepcopy(hook,value),result)
        hook.assert_called_once_with(value)

    def test_normal_loader_only_two_admitted_copy_sites(self):
        tree=syntax.parse(inspect.getsource(modules))
        calls=[n for n in syntax.walk(tree) if isinstance(n,syntax.Call)
               and isinstance(n.func,syntax.Attribute) and n.func.attr=='deepcopy']
        self.assertEqual(len(calls),2)
        for node in calls:
            self.assertEqual(syntax.unparse(node.func),'ops.deepcopy')
            self.assertEqual(syntax.unparse(node.args[0]),'copy.deepcopy')

    def test_all_80_examples_graph_and_diagnostic_parity(self):
        root=Path(__file__).resolve().parents[2];passed=failed=0
        for entry in sorted((root/'examples').rglob('*.hepta')):
            with self.subTest(entry=str(entry.relative_to(root))):
                try: expected=modules.load_project(entry)
                except ast.HeptaError as old:
                    with self.assertRaises(ast.HeptaError) as new: Owner().load(entry)
                    self.assertEqual(new.exception.diagnostic.to_dict(),old.diagnostic.to_dict());failed+=1
                else:
                    actual=Owner().load(entry).project
                    self.assertEqual(actual.report(),expected.report())
                    self.assertEqual(actual.source_bytes,expected.source_bytes)
                    self.assertEqual(asdict(actual.program),asdict(expected.program));passed+=1
        self.assertEqual((passed,failed),(68,12))


if __name__=='__main__': unittest.main()
