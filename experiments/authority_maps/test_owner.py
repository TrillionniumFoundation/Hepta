import copy
from dataclasses import asdict
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hepta import modules, packages
from experiments.owned_loader import owner as owned
from experiments.assembly_copy.owner import _DEEPCOPY
from experiments.loader_transform.owner import Owner as PreviousOwner
from experiments.loader_transform.test_authority_audit import plain_visits
from experiments.request_load.context import Rejected
from .owner import Owner, Limits

TEXT = 'fn main()->Unit effects {} {}'


class AuthorityMapTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.root = Path(temp.name); self.entry = self.root / 'main.hepta'
        self.entry.write_text(TEXT)

    def package(self):
        (self.root / 'hepta.toml').write_text('[package]\nname="example"\nversion="1.0.0"\nsource_root="."\nentry="main.hepta"\n')

    def copied(self, owner, value, name='package_state'):
        return owner._authority_copy(_DEEPCOPY, value, name)

    def test_positive_integer_limits(self):
        for name in ('authority_visits', 'authority_depth'):
            for value in (0, -1, True, 1.5, '1'):
                with self.subTest(name=name,value=value), self.assertRaises(ValueError):
                    Limits(**{name:value})

    def test_exact_standalone_seven(self):
        owner = Owner(Limits(authority_visits=7,authority_depth=2)); handle = owner.load(self.entry)
        self.assertEqual(owner.context.counts['authority_visits'],7)
        self.assertEqual(owner.context.counts['copy_visits'],150)
        self.assertEqual(owner.context.counts['transform_visits'],14)
        self.assertEqual(handle.project.report(), modules.load_project(self.entry).report())
        self.assertTrue(handle.unchanged())

    def test_one_below_no_handle_terminal(self):
        owner = Owner(Limits(authority_visits=6))
        with self.assertRaisesRegex(Rejected,'authority_visits'): owner.load(self.entry)
        self.assertEqual(owner.context.counts['authority_visits'],6)
        self.assertEqual(owner._handles,[]); self.assertTrue(owner.context.closed)
        with self.assertRaisesRegex(Rejected,'terminal'): owner.load(self.entry)

    def test_depth_one_denies_first_key(self):
        owner = Owner(Limits(authority_depth=1))
        with self.assertRaisesRegex(Rejected,'authority_depth'): owner.load(self.entry)
        self.assertEqual(owner.context.counts['authority_visits'],1)

    def test_cumulative_across_loads(self):
        owner = Owner(Limits(authority_visits=13)); owner.load(self.entry)
        with self.assertRaisesRegex(Rejected,'authority_visits'): owner.load(self.entry)
        self.assertEqual(owner.context.counts['authority_visits'],13)
        self.assertEqual(len(owner._handles),1)

    def test_empty_roots_and_none_count_one_each(self):
        owner = Owner()
        for value,name in (({},'source_bytes'),({},'bindings'),({},'package_state'),(None,'package_state')):
            self.assertEqual(self.copied(owner,value,name),value)
        self.assertEqual(owner.context.counts['authority_visits'],4)

    def test_exact_map_formulas(self):
        for name,value in (('source_bytes',{'a':b'x','b':b'y'}),('bindings',{'a':'b','b':'c'})):
            owner=Owner(Limits(authority_visits=5)); result=self.copied(owner,value,name)
            self.assertEqual(result,value); self.assertIsNot(result,value)
            self.assertEqual(owner.context.counts['authority_visits'],5)

    def test_generated_and_locked_snapshot_formula(self):
        self.package(); packages.write_lock(self.root)
        for locked in (False,True):
            owner=Owner(); handle=owner.load(self.entry,locked=locked)
            graph=handle.project; state=graph.package_state
            records=state['packages']; edges=sum(len(record['dependencies']) for record in records.values())
            snapshot=9+12*len(records)+2*edges+2*len(state['files'])
            self.assertEqual(snapshot,25)
            expected=plain_visits(graph.source_bytes)+plain_visits(graph.bindings)+snapshot
            self.assertEqual(owner.context.counts['authority_visits'],expected)
            exact=Owner(Limits(authority_visits=expected)); exact.load(self.entry,locked=locked)
            with self.assertRaisesRegex(Rejected,'authority_visits'):
                Owner(Limits(authority_visits=expected-1)).load(self.entry,locked=locked)

    def test_alias_expanded_count_memo_preserved(self):
        shared={'x':'y'}; value={'a':shared,'b':shared}
        owner=Owner(Limits(authority_visits=9)); result=self.copied(owner,value)
        self.assertEqual(owner.context.counts['authority_visits'],9)
        self.assertIs(result['a'],result['b']); self.assertIsNot(result['a'],shared)
        with self.assertRaisesRegex(Rejected,'authority_visits'):
            self.copied(Owner(Limits(authority_visits=8)),value)

    def test_separate_copies_have_separate_memos(self):
        shared={'x':'y'}; owner=Owner()
        one=self.copied(owner,shared,'bindings'); two=self.copied(owner,shared,'package_state')
        self.assertIsNot(one,two); self.assertEqual(one,two)
        self.assertEqual(owner.context.counts['authority_visits'],6)

    def test_bytes_identity_and_size_are_not_units(self):
        for size in (1,1_000_000):
            payload=b'x'*size; owner=Owner(Limits(authority_visits=3))
            result=self.copied(owner,{'a':payload},'source_bytes')
            self.assertIs(result['a'],payload)
            self.assertEqual(owner.context.counts['authority_visits'],3)

    def test_cycle_refused_without_recursion(self):
        value={}; value['self']=value; owner=Owner()
        with self.assertRaisesRegex(Rejected,'cyclic'): self.copied(owner,value)
        self.assertEqual(owner.context.counts['authority_visits'],3)

    def test_deep_graph_iterative_refusal(self):
        value='leaf'
        for _ in range(2000): value={'x':value}
        owner=Owner(Limits(authority_depth=20))
        with self.assertRaisesRegex(Rejected,'authority_depth'): self.copied(owner,value)
        self.assertTrue(owner.context.closed)

    def test_exact_depth_boundary(self):
        value={'a':{'b':'c'}}
        owner=Owner(Limits(authority_depth=3)); self.copied(owner,value)
        self.assertEqual(owner.context.counts['authority_visits'],5)
        with self.assertRaisesRegex(Rejected,'authority_depth'):
            self.copied(Owner(Limits(authority_depth=2)),value)

    def test_bad_root_and_schema_rejected(self):
        for name,value in (('source_bytes',None),('bindings',None),('source_bytes',{'a':'x'}),
                           ('bindings',{'a':b'x'}),('bindings',{'a':{}}),('package_state',{'a':None}),
                           ('package_state',{'a':1}),('package_state',{'a':[]}),('package_state',{1:'x'})):
            with self.subTest(name=name,value=value),self.assertRaises(Rejected):
                self.copied(Owner(),value,name)

    def test_unknown_objects_no_protocol_hooks(self):
        class Evil:
            def __deepcopy__(self,memo): raise AssertionError('deepcopy hook')
            def __reduce_ex__(self,p): raise AssertionError('reduce hook')
            def __getattribute__(self,n): raise AssertionError('getattribute hook')
        class Dict(dict):
            def items(self): raise AssertionError('items hook')
        class Str(str):
            def __deepcopy__(self,memo): raise AssertionError('str hook')
        class Bytes(bytes):
            def __deepcopy__(self,memo): raise AssertionError('bytes hook')
        for name,value in (('package_state',{'a':Evil()}),('package_state',Dict()),
                           ('package_state',{'a':Str('x')}),('source_bytes',{'a':Bytes(b'x')})):
            with self.subTest(name=name),self.assertRaises(Rejected): self.copied(Owner(),value,name)

    def test_bytes_dispatch_and_reducer_replacements(self):
        for table in (copy._deepcopy_dispatch,copy.dispatch_table):
            with patch.dict(table,{bytes:lambda *args: (_ for _ in ()).throw(AssertionError('hook'))}):
                with self.assertRaisesRegex(Rejected,'bytes copy dispatch'):
                    self.copied(Owner(),{'a':b'x'},'source_bytes')

    def test_dict_dispatch_replacement(self):
        with patch.dict(copy._deepcopy_dispatch,{dict:lambda *a:None}):
            with self.assertRaisesRegex(Rejected,'copy dispatch'): self.copied(Owner(),{})

    def test_captured_copier_rejected_before_call(self):
        calls=[]
        with self.assertRaisesRegex(Rejected,'captured authority copier'):
            Owner()._authority_copy(lambda value:calls.append(value),{},'bindings')
        self.assertEqual(calls,[])

    def test_checkpoint_can_mutate_input_before_preflight(self):
        value={}; calls=[]
        def checkpoint():
            calls.append(1)
            if len(calls)==1:value['a']='b'
        owner=Owner(checkpoint=checkpoint); result=self.copied(owner,value)
        self.assertEqual(result,{'a':'b'}); self.assertEqual(calls,[1,1])
        self.assertEqual(owner.context.counts['authority_visits'],3)

    def test_checkpoint_swap_dispatch_detected(self):
        original=copy._deepcopy_dispatch[bytes]
        def checkpoint():copy._deepcopy_dispatch[bytes]=lambda *a:None
        try:
            with self.assertRaisesRegex(Rejected,'bytes copy dispatch'):
                self.copied(Owner(checkpoint=checkpoint),{'a':b'x'},'source_bytes')
        finally:copy._deepcopy_dispatch[bytes]=original

    def test_post_copy_cancellation_no_refund(self):
        calls=[]
        def checkpoint():
            calls.append(1)
            if len(calls)==2:raise RuntimeError('cancel')
        owner=Owner(checkpoint=checkpoint)
        with self.assertRaisesRegex(RuntimeError,'cancel'):self.copied(owner,{'a':'b'})
        self.assertEqual(owner.context.counts['authority_visits'],3); self.assertTrue(owner.context.closed)

    def test_preflight_refusal_never_enters_real_deepcopy(self):
        import sys
        calls=[]
        def trace(frame,event,arg):
            if event == 'call' and frame.f_code is _DEEPCOPY.__code__:
                calls.append(1)
            return trace
        old=sys.gettrace();sys.settrace(trace)
        try:
            with self.assertRaisesRegex(Rejected,'authority_visits'):
                self.copied(Owner(Limits(authority_visits=2)),{'a':'b'})
        finally:sys.settrace(old)
        self.assertEqual(calls,[])

    def test_swallowed_reentrant_callback_remains_terminal(self):
        active=[False]
        def checkpoint():
            if active[0]:
                try:owner.load(self.entry)
                except Rejected:pass
        owner=Owner(checkpoint=checkpoint);active[0]=True
        with self.assertRaisesRegex(Rejected,'terminal'):
            self.copied(owner,{'a':'b'})
        self.assertEqual(owner.context.counts['authority_visits'],0)

    def test_late_package_failure_no_handle(self):
        class FailPackage(Owner):
            def _authority_copy(self,deepcopy,value,name):
                if name=='package':raise OSError('package copy')
                return super()._authority_copy(deepcopy,value,name)
        owner=FailPackage()
        with self.assertRaisesRegex(OSError,'package copy'):owner.load(self.entry)
        self.assertEqual(owner.context.counts['authority_visits'],7)
        self.assertEqual(owner._handles,[]);self.assertTrue(owner.context.closed)

    def test_unknown_map_name_terminal(self):
        owner=Owner()
        with self.assertRaisesRegex(Rejected,'unknown authority map name'):
            self.copied(owner,{},'other')
        self.assertEqual(owner.context.counts['authority_visits'],0)

    def test_package_copy_is_explicitly_unmetered(self):
        self.package(); owner=Owner(); handle=owner.load(self.entry)
        authority=owner._handles[0][1]
        self.assertIsNot(authority.package,handle.project.package)
        self.assertIsNot(authority.package.root,handle.project.package.root)
        self.assertEqual(authority.package.root,handle.project.package.root)
        count=owner.context.counts['authority_visits']
        self.copied(owner,handle.project.package,'package')
        self.assertEqual(owner.context.counts['authority_visits'],count)

    def test_public_mutation_does_not_erase_authority(self):
        owner=Owner(); handle=owner.load(self.entry)
        handle.project.source_bytes.clear();handle.project.bindings.clear()
        self.entry.write_text(TEXT+'\n')
        self.assertFalse(handle.unchanged())

    def test_previous_profile_not_charged(self):
        owner=PreviousOwner();owner.load(self.entry)
        self.assertNotIn('authority_visits',owner.context.counts)

    def test_all_example_reports_and_asts(self):
        paths=sorted(Path('examples').rglob('*.hepta')); good=bad=0
        for entry in paths:
            try: baseline=modules.load_project(entry)
            except Exception as before:
                with self.assertRaises(type(before)) as caught:Owner().load(entry)
                self.assertEqual(str(caught.exception),str(before));bad+=1
            else:
                candidate=Owner().load(entry).project
                self.assertEqual(candidate.report(),baseline.report())
                self.assertEqual(asdict(candidate.program),asdict(baseline.program));good+=1
        self.assertEqual((good,bad),(68,12))


if __name__=='__main__':unittest.main()
