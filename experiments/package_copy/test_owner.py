import copy
from dataclasses import asdict
from pathlib import Path
import random
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta import modules, packages
from experiments.request_load.context import Rejected
from experiments.shallow_authority.owner import Owner as PreviousOwner
from .owner import Owner, Limits, _COPY


def warm(text='/a/b'):
    value = Path(text)
    value.parts
    return value


def package():
    return packages.Package(warm(), 'sample', '1.0.0', warm('/a/b/lib.hepta'),
                            'lib', warm(), {}, b'manifest')


def observed(value, operation=None):
    events=[]; depth=0; previous=sys.getprofile()
    def profile(frame,event,arg):
        nonlocal depth
        if frame.f_code is _COPY.__code__:
            if event=='call':
                depth+=1;events.append((type(frame.f_locals['x']),depth))
            elif event=='return':depth-=1
    sys.setprofile(profile)
    try:result=(_COPY(value) if operation is None else operation())
    finally:sys.setprofile(previous)
    return result,events


class PackageCopyTests(unittest.TestCase):
    def do_copy(self, owner, value):
        return owner._authority_copy(_COPY,value,'package')

    def test_positive_limits(self):
        for field in ('package_copy_calls','package_copy_depth'):
            for bad in (0,-1,True,1.0,'2'):
                with self.subTest(field=field,bad=bad),self.assertRaises(ValueError):Limits(**{field:bad})

    def test_none_one_call_and_terminal(self):
        owner=Owner(Limits(package_copy_calls=1));self.assertIsNone(self.do_copy(owner,None))
        self.assertEqual(owner.context.counts['package_copy_calls'],1)
        with self.assertRaisesRegex(Rejected,'package_copy_calls'):self.do_copy(owner,None)
        with self.assertRaisesRegex(Rejected,'terminal'):self.do_copy(owner,None)

    def test_exact_call_boundary_and_one_below(self):
        value=package();_,events=observed(value);count=len(events)
        owner=Owner(Limits(package_copy_calls=count));result=self.do_copy(owner,value)
        self.assertEqual(result,value);self.assertEqual(owner.context.counts['package_copy_calls'],count)
        owner=Owner(Limits(package_copy_calls=count-1));calls=[]
        def operation():
            with self.assertRaisesRegex(Rejected,'package_copy_calls'):self.do_copy(owner,value)
        _,calls=observed(value,operation)
        self.assertEqual(calls,[]);self.assertEqual(owner.context.counts['package_copy_calls'],count-1)

    def test_exact_depth_and_one_below(self):
        value=package();_,events=observed(value);depth=max(d for _,d in events)
        self.do_copy(Owner(Limits(package_copy_depth=depth)),value)
        owner=Owner(Limits(package_copy_depth=depth-1))
        def operation():
            with self.assertRaisesRegex(Rejected,'package_copy_depth'):self.do_copy(owner,value)
        self.assertEqual(observed(value,operation)[1],[])

    def test_cumulative_fresh_memos(self):
        value=package();count=len(observed(value)[1]);owner=Owner(Limits(package_copy_calls=count*2))
        a=self.do_copy(owner,value);b=self.do_copy(owner,value)
        self.assertIsNot(a,b);self.assertIsNot(a.root,b.root)
        self.assertEqual(owner.context.counts['package_copy_calls'],count*2)
        with self.assertRaises(Rejected):self.do_copy(owner,value)

    def test_dag_cycle_aliases(self):
        value=package();child=package();value.dependencies={'a':child,'b':child,'self':value}
        child.dependencies={'root':value};child.source_root=value.root
        owner=Owner();result=self.do_copy(owner,value)
        self.assertIs(result.dependencies['a'],result.dependencies['b'])
        self.assertIs(result.dependencies['self'],result)
        self.assertIs(result.dependencies['a'].dependencies['root'],result)
        self.assertIs(result.dependencies['a'].source_root,result.root)
        self.assertEqual(owner.context.counts['package_copy_calls'],len(observed(value)[1]))

    def test_shared_dependency_dictionary(self):
        value=package();child=package();value.dependencies={'child':child};child.dependencies=value.dependencies
        owner=Owner();result=self.do_copy(owner,value)
        self.assertIs(result.dependencies,result.dependencies['child'].dependencies)
        self.assertEqual(owner.context.counts['package_copy_calls'],len(observed(value)[1]))

    def test_shared_state_partial_output_unchanged(self):
        value=package();child=package();child.__dict__=value.__dict__;value.dependencies['child']=child
        original=_COPY(value);owner=Owner();result=self.do_copy(owner,value)
        self.assertEqual(set(vars(result.dependencies['child'])),set(vars(original.dependencies['child'])))
        self.assertNotIn('dependencies',vars(result.dependencies['child']))
        self.assertIsNot(vars(result),vars(result.dependencies['child']))
        self.assertEqual(owner.context.counts['package_copy_calls'],len(observed(value)[1]))

    def test_equal_distinct_paths_not_collapsed(self):
        value=package();value.source_root=warm(str(value.root));self.assertIsNot(value.root,value.source_root)
        owner=Owner();result=self.do_copy(owner,value)
        self.assertEqual(result.root,result.source_root);self.assertIsNot(result.root,result.source_root)
        self.assertEqual(owner.context.counts['package_copy_calls'],len(observed(value)[1]))

    def test_seeded_graphs_match_real_call_counts_and_depth(self):
        for seed in range(50):
            rng=random.Random(seed);nodes=[package() for _ in range(rng.randint(1,9))]
            for item in nodes:
                item.dependencies={str(i):rng.choice(nodes) for i in range(rng.randint(0,4))}
                if rng.random()<.5:item.source_root=item.root
            for item in nodes:
                if rng.random()<.2:item.dependencies=rng.choice(nodes).dependencies
                if rng.random()<.15:item.__dict__=rng.choice(nodes).__dict__
            root=nodes[0];_,events=observed(root);count=len(events);depth=max(d for _,d in events)
            owner=Owner(Limits(package_copy_calls=count,package_copy_depth=depth));self.do_copy(owner,root)
            self.assertEqual(owner.context.counts['package_copy_calls'],count)
            if depth>1:
                with self.assertRaises(Rejected):self.do_copy(Owner(Limits(package_copy_depth=depth-1)),root)

    def test_bad_root_no_user_hooks(self):
        calls=[]
        class Foreign:
            def __getattribute__(self,name):calls.append(name);raise AssertionError(name)
            def __deepcopy__(self,memo):calls.append('copy')
        with self.assertRaises(Rejected):self.do_copy(Owner(),Foreign())
        self.assertEqual(calls,[])

    def test_bad_state_shape(self):
        for mutation in ('extra','missing'):
            value=package()
            if mutation=='extra':value.extra=1
            else:del value.kind
            with self.assertRaises(Rejected):self.do_copy(Owner(),value)

    def test_invalid_field_types(self):
        for name in ('root','entry','source_root','name','version','kind','dependencies','manifest_bytes'):
            value=package();setattr(value,name,object())
            with self.subTest(field=name),self.assertRaises(Rejected):self.do_copy(Owner(),value)

    def test_cross_role_state_dictionary_refused(self):
        value=package();value.dependencies=vars(value)
        with self.assertRaisesRegex(Rejected,'across roles'):self.do_copy(Owner(),value)

    def test_dependency_key_and_value_refused(self):
        for dependencies in ({1:package()},{'bad':None}):
            value=package();value.dependencies=dependencies
            with self.assertRaises(Rejected):self.do_copy(Owner(),value)

    def test_entry_callback_mutation_is_inspected(self):
        value=package();calls=[]
        def callback():
            calls.append(1)
            if len(calls)==1:value.name=object()
        with self.assertRaises(Rejected):self.do_copy(Owner(checkpoint=callback),value)
        self.assertEqual(calls,[1])

    def test_exit_cancel_no_refund(self):
        value=package();count=len(observed(value)[1]);calls=[]
        def callback():
            calls.append(1)
            if len(calls)==2:raise RuntimeError('cancel')
        owner=Owner(checkpoint=callback)
        with self.assertRaisesRegex(RuntimeError,'cancel'):self.do_copy(owner,value)
        self.assertEqual(owner.context.counts['package_copy_calls'],count);self.assertTrue(owner.context.closed)

    def test_previous_profile_remains_uncharged(self):
        value=package();owner=PreviousOwner();result=owner._authority_copy(_COPY,value,'package')
        self.assertEqual(result,value);self.assertNotIn('package_copy_calls',owner.context.counts)

    def test_previous_profile_cold_path_behavior_unchanged(self):
        value=package();value.root=Path('/cold/path')
        if sys.version_info[:2]==(3,12):self.assertFalse(hasattr(value.root,'_tail_cached'))
        PreviousOwner()._authority_copy(_COPY,value,'package')
        if sys.version_info[:2]==(3,12):self.assertTrue(hasattr(value.root,'_tail_cached'))

    def test_path_slots_and_cold_output(self):
        value=package();before=value.root.parts;owner=Owner();result=self.do_copy(owner,value)
        if sys.version_info[:2]==(3,12):
            self.assertTrue(hasattr(value.root,'_tail_cached'));self.assertFalse(hasattr(result.root,'_tail_cached'))
        self.assertEqual(result.root.parts,before)

    def test_cold_partial_or_missing_consumed_slots_refuse_without_repair(self):
        slots=('_drv','_root','_tail_cached') if sys.version_info[:2]==(3,12) else ('_parts',)
        for name in slots:
            value=package();delattr(value.root,name)
            with self.subTest(slot=name),self.assertRaises(Rejected):self.do_copy(Owner(),value)
            self.assertFalse(hasattr(value.root,name))

    def test_unused_slots_not_traversed(self):
        value=package()
        if sys.version_info[:2]==(3,12):value.root._raw_paths=object()
        else:value.root._pparts=object()
        self.do_copy(Owner(),value)

    def test_large_strings_do_not_claim_byte_accounting(self):
        value=package();before=len(observed(value)[1]);value.name='x'*100000;value.manifest_bytes=b'x'*100000
        owner=Owner();result=self.do_copy(owner,value)
        self.assertEqual(owner.context.counts['package_copy_calls'],before)
        self.assertIs(result.name,value.name);self.assertIs(result.manifest_bytes,value.manifest_bytes)

    def test_load_quota_failure_no_handle_after_earlier_work(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);entry=root/'main.hepta';entry.write_text('fn main()->Unit effects {} {}')
            (root/'hepta.toml').write_text('[package]\nname="example"\nversion="1.0.0"\nsource_root="."\nentry="main.hepta"\n')
            owner=Owner(Limits(package_copy_calls=1))
            with self.assertRaises(Rejected):owner.load(entry)
            self.assertEqual(owner._handles,[]);self.assertEqual(owner.context.counts['shallow_fields'],11)
            self.assertGreater(owner.context.counts['authority_visits'],0)

    def test_all_eighty_examples(self):
        good=bad=0
        for path in sorted(Path('examples').rglob('*.hepta')):
            try:before=modules.load_project(path)
            except Exception as expected:
                with self.assertRaises(type(expected)) as caught:Owner().load(path)
                self.assertEqual(str(caught.exception),str(expected));bad+=1
            else:
                owner=Owner();after=owner.load(path).project
                self.assertEqual(after.report(),before.report());self.assertEqual(asdict(after.program),asdict(before.program))
                self.assertGreater(owner.context.counts['package_copy_calls'],0);good+=1
        self.assertEqual((good,bad),(68,12))


if __name__=='__main__':unittest.main()
