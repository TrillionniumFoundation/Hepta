import copy
from dataclasses import fields, asdict
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta import modules
from experiments.authority_maps.owner import Owner as PreviousOwner
from experiments.owned_loader import owner as owned
from experiments.request_load.context import Rejected
from .owner import Owner, Limits, _COPY, _CLASS

TEXT='fn main()->Unit effects {} {}'


def graph():
    value=object.__new__(_CLASS)
    for field in fields(_CLASS):setattr(value,field.name,None)
    return value


class ShallowTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);self.entry=self.root/'main.hepta';self.entry.write_text(TEXT)

    def shallow(self,owner,value):return owner._authority_shallow(_COPY,value)

    def test_positive_integer_limit(self):
        for value in (0,-1,True,1.5,'11'):
            with self.subTest(value=value),self.assertRaises(ValueError):Limits(shallow_fields=value)

    def test_exact_eleven_and_earlier_counts(self):
        owner=Owner(Limits(shallow_fields=11));handle=owner.load(self.entry)
        self.assertEqual(owner.context.counts['shallow_fields'],11)
        self.assertEqual(owner.context.counts['authority_visits'],7)
        self.assertEqual(owner.context.counts['copy_visits'],150)
        self.assertEqual(owner.context.counts['transform_visits'],14)
        self.assertEqual(handle.project.report(),modules.load_project(self.entry).report())
        self.assertTrue(handle.unchanged())

    def test_one_below_no_shallow_or_maps_or_handle(self):
        owner=Owner(Limits(shallow_fields=10));calls=[];old=sys.getprofile()
        def observe(frame,event,arg):
            if event=='call' and frame.f_code is _COPY.__code__:calls.append(1)
        sys.setprofile(observe)
        try:
            with self.assertRaisesRegex(Rejected,'shallow_fields'):owner.load(self.entry)
        finally:sys.setprofile(old)
        self.assertEqual(calls,[]);self.assertEqual(owner.context.counts['shallow_fields'],10)
        self.assertEqual(owner.context.counts['authority_visits'],0)
        self.assertEqual(owner._handles,[]);self.assertTrue(owner.context.closed)
        with self.assertRaisesRegex(Rejected,'terminal'):owner.load(self.entry)

    def test_cumulative_twenty_two_and_twenty_one(self):
        owner=Owner(Limits(shallow_fields=22));owner.load(self.entry);owner.load(self.entry)
        self.assertEqual(owner.context.counts['shallow_fields'],22)
        owner=Owner(Limits(shallow_fields=21));owner.load(self.entry)
        with self.assertRaisesRegex(Rejected,'shallow_fields'):owner.load(self.entry)
        self.assertEqual(owner.context.counts['shallow_fields'],21)
        self.assertEqual(len(owner._handles),1)

    def test_shallow_aliases_point_to_original_nodes(self):
        value=graph();shared=[];value.program=value;value.sources=vars(value)
        value.modules=shared;value.c_imports=shared
        result=self.shallow(Owner(),value)
        self.assertIsNot(result,value);self.assertIsNot(vars(result),vars(value))
        self.assertIs(result.program,value);self.assertIs(result.sources,vars(value))
        self.assertIs(result.modules,shared);self.assertIs(result.c_imports,shared)

    def test_no_value_protocols_visited(self):
        class Evil:
            def __getattribute__(self,name):raise AssertionError('attribute')
            def __copy__(self):raise AssertionError('copy')
            def __deepcopy__(self,memo):raise AssertionError('deepcopy')
            def __reduce_ex__(self,protocol):raise AssertionError('reduce')
        value=graph();evil=Evil();value.program=evil
        result=self.shallow(Owner(),value);self.assertIs(result.program,evil)

    def test_huge_value_has_same_eleven_units(self):
        for size in (1,100000):
            value=graph();value.sources=['x']*size;owner=Owner(Limits(shallow_fields=11))
            result=self.shallow(owner,value)
            self.assertIs(result.sources,value.sources);self.assertEqual(owner.context.counts['shallow_fields'],11)

    def test_exact_root_type_without_unknown_hooks(self):
        class Meta(type):
            def __hash__(self):raise AssertionError('hash')
            def __eq__(self,other):raise AssertionError('eq')
        class Evil(metaclass=Meta):
            def __getattribute__(self,name):raise AssertionError('attribute')
        class Sub(_CLASS):pass
        for value in (None,{},Evil(),object.__new__(Sub)):
            with self.subTest(cls=type(value).__name__),self.assertRaisesRegex(Rejected,'exact LoadedProject'):
                self.shallow(Owner(),value)

    def test_missing_extra_and_replaced_keys(self):
        for mutation in ('missing','extra','unknown','subclass'):
            value=graph()
            if mutation=='missing':del value.program
            elif mutation=='extra':value.extra=None
            else:
                del value.program
                if mutation=='unknown':vars(value)['unknown']=None
                else:
                    class Str(str):pass
                    vars(value)[Str('program')]=None
            with self.subTest(mutation=mutation),self.assertRaisesRegex(Rejected,'shallow state'):
                self.shallow(Owner(),value)

    def test_dict_subclass_state_refused_without_iteration(self):
        class Dict(dict):
            def __iter__(self):raise AssertionError('iteration')
        value=graph();value.__dict__=Dict(vars(value))
        with self.assertRaisesRegex(Rejected,'state shape'):self.shallow(Owner(),value)

    def test_captured_copy_refused_before_call(self):
        calls=[]
        with self.assertRaisesRegex(Rejected,'captured shallow copier'):
            Owner()._authority_shallow(lambda value:calls.append(value),graph())
        self.assertEqual(calls,[])

    def test_dataclass_init_is_not_a_shallow_copy_hook(self):
        value=graph()
        def fail(*args,**kwargs):raise AssertionError('constructor init')
        with patch.object(_CLASS,'__init__',fail):
            result=self.shallow(Owner(),value)
        self.assertIs(type(result),_CLASS);self.assertEqual(vars(result),vars(value))

    def test_dispatch_entry_and_reducer_refused(self):
        for table in (copy._copy_dispatch,copy.dispatch_table):
            with patch.dict(table,{_CLASS:lambda *args:(_ for _ in ()).throw(AssertionError('hook'))}):
                with self.assertRaisesRegex(Rejected,'shallow copy dispatch'):self.shallow(Owner(),graph())

    def test_dispatch_table_replacement_refused(self):
        with patch.object(copy,'_copy_dispatch',dict(copy._copy_dispatch)):
            with self.assertRaisesRegex(Rejected,'shallow copy dispatch'):self.shallow(Owner(),graph())

    def test_custom_copy_hook_refused_without_execution(self):
        with patch.object(_CLASS,'__copy__',lambda self:(_ for _ in ()).throw(AssertionError('hook')),create=True):
            with self.assertRaisesRegex(Rejected,'shallow class hook'):self.shallow(Owner(),graph())

    def test_reduction_and_getattr_hooks_refused(self):
        for name in ('__reduce__','__reduce_ex__','__getstate__','__setstate__','__getattr__'):
            with self.subTest(name=name),patch.object(_CLASS,name,lambda *args:None,create=True):
                with self.assertRaisesRegex(Rejected,'shallow class hook'):self.shallow(Owner(),graph())

    def test_slot_metadata_refused(self):
        for name,value in (('__slots__',()),('__slotnames__',['danger'])):
            with patch.object(_CLASS,name,value,create=True):
                with self.assertRaisesRegex(Rejected,'slot metadata'):self.shallow(Owner(),graph())

    def test_checkpoint_mutation_inspected_then_two_callbacks(self):
        value=graph();calls=[]
        def checkpoint():
            calls.append(1)
            if len(calls)==1:value.program='mutated'
        owner=Owner(checkpoint=checkpoint);result=self.shallow(owner,value)
        self.assertEqual(result.program,'mutated');self.assertEqual(calls,[1,1])
        self.assertEqual(owner.context.counts['shallow_fields'],11)

    def test_checkpoint_hook_swap_refused(self):
        original=copy._copy_dispatch.get(_CLASS);missing=_CLASS not in copy._copy_dispatch
        def checkpoint():copy._copy_dispatch[_CLASS]=lambda x:None
        try:
            with self.assertRaisesRegex(Rejected,'dispatch'):self.shallow(Owner(checkpoint=checkpoint),graph())
        finally:
            if missing:copy._copy_dispatch.pop(_CLASS,None)
            else:copy._copy_dispatch[_CLASS]=original

    def test_post_copy_cancel_no_refund(self):
        calls=[]
        def checkpoint():
            calls.append(1)
            if len(calls)==2:raise RuntimeError('cancel')
        owner=Owner(checkpoint=checkpoint)
        with self.assertRaisesRegex(RuntimeError,'cancel'):self.shallow(owner,graph())
        self.assertTrue(owner.context.closed);self.assertEqual(owner.context.counts['shallow_fields'],11)
        with self.assertRaisesRegex(Rejected,'terminal'):self.shallow(owner,graph())

    def test_previous_profile_keeps_no_shallow_counter(self):
        owner=PreviousOwner();owner.load(self.entry)
        self.assertNotIn('shallow_fields',owner.context.counts)

    def test_package_path_remain_separate_copies(self):
        (self.root/'hepta.toml').write_text('[package]\nname="example"\nversion="1.0.0"\nsource_root="."\nentry="main.hepta"\n')
        owner=Owner(Limits(shallow_fields=11));handle=owner.load(self.entry)
        authority=owner._handles[0][1]
        self.assertEqual(owner.context.counts['shallow_fields'],11)
        self.assertEqual(owner.context.counts['authority_visits'],31)
        self.assertIsNot(authority.package,handle.project.package)
        self.assertIsNot(authority.package.root,handle.project.package.root)
        self.assertEqual(authority.package.root,handle.project.package.root)
        # Shallow-copied fields untouched by the four deepcopies still alias.
        self.assertIs(authority.program,handle.project.program)
        self.assertIs(authority.entry,handle.project.entry)

    def test_all_eighty_example_outcomes(self):
        good=bad=0
        for path in sorted(Path('examples').rglob('*.hepta')):
            try:before=modules.load_project(path)
            except Exception as expected:
                with self.assertRaises(type(expected)) as caught:Owner().load(path)
                self.assertEqual(str(caught.exception),str(expected));bad+=1
            else:
                after=Owner().load(path).project
                self.assertEqual(after.report(),before.report())
                self.assertEqual(asdict(after.program),asdict(before.program));good+=1
        self.assertEqual((good,bad),(68,12))


if __name__=='__main__':unittest.main()
