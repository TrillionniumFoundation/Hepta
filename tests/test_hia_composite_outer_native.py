"""Complete outer-owner differential, ordered refusals and opaque object custody."""
from contextlib import ExitStack
from copy import deepcopy
import ctypes
import gc
import gzip
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import unittest
from unittest.mock import patch
import weakref

from hepta import hia_program_composite as composite
from hepta.hia_composite_outer_native import (NativeCompositeOuter, NativeOuterInvocation,
    installed_composite_outer, SELECTOR, OUTER_MAGIC, ACK_MAGIC, OBJECTS, WORKSPACE_BYTES)
from hepta.hia_composite_functions_native import NativeFunctionSession, WORKSPACE_BYTES as FUNCTION_BYTES
from hepta.hia_composite_types_native import SESSION_BYTES as TYPE_BYTES
from hepta.hia_task_helpers_native import WORKSPACE_BYTES as HELPER_BYTES
from hepta.hia_program import HIAProgramRejected, verify_core
from hepta.hia_program_runtime import execute_program
from tests.test_hia_composite_function_terms_native import state
from tests.test_hia_program import b,c,f,ret
from tests import test_hia_program_composite as nominal
from tests import test_hia_composite_returned_loans as loans
from tests import test_hia_partial_record as partial
from tests.test_hia_composite_constructor_native import simple

DEVELOPMENT=('HEPTA_HIA_COMPOSITE_OUTER_DEVELOPMENT_MANIFEST',
 'HEPTA_HIA_COMPOSITE_CONSTRUCTOR_DEVELOPMENT_MANIFEST','HEPTA_HIA_COMPOSITE_FUNCTIONS_DEVELOPMENT_MANIFEST',
 'HEPTA_HIA_COMPOSITE_TYPES_DEVELOPMENT_MANIFEST','HEPTA_HIA_TASK_HELPERS_DEVELOPMENT_MANIFEST')
SELECTORS=(SELECTOR,'HEPTA_HIA_COMPOSITE_CONSTRUCTOR_MANIFEST','HEPTA_HIA_COMPOSITE_FUNCTIONS_MANIFEST',
 'HEPTA_HIA_COMPOSITE_TYPES_MANIFEST','HEPTA_HIA_TASK_HELPERS_MANIFEST')
HOST=('_reference_initialize','_reference_function','_reference_parameters','_reference_check_task',
 'loan_origins','_reference_helper','parameters','check_task','fresh','reserve_values',
 'flat_parameters','constant','zeros','drop_padding','helper')


def forbidden(*args,**kwargs):
    raise AssertionError('retained nominal semantic owner invoked')


class OuterFrameTests(unittest.TestCase):
    def fresh(self):
        obj=NativeOuterInvocation.__new__(NativeOuterInvocation)
        obj._phase=None;obj._request=obj._functions=obj._helpers=0
        obj._broken=obj._completed=False
        obj._output=ctypes.create_string_buffer(64)
        return obj

    def call(self,obj,action,phase,request=0,handle=0,functions=0,helpers=0,error=0):
        frame=(OUTER_MAGIC,action,error,phase,request,handle,functions,helpers)
        struct.pack_into('<8Q',obj._output,0,*frame)
        return obj._frame(64)

    def test_correlated_helper_function_ack_and_completion(self):
        obj=self.fresh();self.call(obj,0,0);self.call(obj,2,10,1)
        self.call(obj,3,20,1);self.call(obj,7,22,1)
        self.call(obj,5,21,1,OBJECTS+1024,helpers=1)
        self.call(obj,0,10,1,helpers=1);self.call(obj,4,11,1,OBJECTS,1,1)
        self.call(obj,0,0,1,functions=1,helpers=1);self.call(obj,2,2000,1,functions=1,helpers=1)
        with self.assertRaises(HIAProgramRejected):self.call(obj,2,2000,1,functions=1,helpers=1)

    def test_unknown_crossed_replayed_or_unissued_frames(self):
        for change in ('phase','request','object','helper_without_lease','helper_ack','early_function','error_kind'):
            obj=self.fresh();self.call(obj,0,0);self.call(obj,2,10,1)
            with self.subTest(change=change),self.assertRaises(HIAProgramRejected):
                if change=='phase':self.call(obj,3,123,1)
                elif change=='request':self.call(obj,3,20,2)
                elif change=='object':self.call(obj,4,11,1,OBJECTS+5,1)
                elif change=='helper_without_lease':self.call(obj,5,21,1,OBJECTS+1024,helpers=1)
                elif change=='helper_ack':self.call(obj,0,10,1)
                elif change=='early_function':self.call(obj,4,11,1,OBJECTS,2)
                else:self.call(obj,1,2000,1,error=1)
            with self.assertRaises(HIAProgramRejected):self.call(obj,3,20,1)


class NativeOuterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tests.hia_composite_function_fixture import composite_function_fixture
        fixture = composite_function_fixture()
        cls.env=fixture.complete_environment
        cls.bundle=fixture.outer_bundle
        cls.fixture_scope=fixture.scope
        cls.evidence=Path(os.environ['HEPTA_HIA_OUTER_EVIDENCE']) if os.environ.get('HEPTA_HIA_OUTER_EVIDENCE') else None
        if cls.evidence is not None:cls.evidence.mkdir(parents=True,exist_ok=True)
        cls.rows=[];cls.entries={'owner':0,'render':0};cls.custody=False;cls.borrowed=[];cls.faults=[]
        images={}
        for name,image in cls.bundle.images.items():
            proxy=type('ActualEntry',(),{})();delegate=image._entry
            def entry(*args,name=name,delegate=delegate):
                cls.entries[name]+=1
                checked=cls.custody and name=='owner' and args[1] in (FUNCTION_BYTES,TYPE_BYTES,HELPER_BYTES)
                before=sha256(memoryview(args[0])).hexdigest() if checked else None
                result=delegate(*args)
                if checked:
                    after=sha256(memoryview(args[0])).hexdigest()
                    cls.borrowed.append({'bytes':args[1],'before':before,'after':after})
                    if before!=after:raise AssertionError('borrowed workspace changed')
                return result
            proxy._entry=entry;images[name]=proxy
        cls.measured=NativeCompositeOuter(images,types_source_sha256=cls.bundle.dependencies[next(
            path for path in cls.bundle.dependencies if path.name=='composite_types.hepta')],
            helpers_source_sha256=cls.bundle.dependencies[next(
            path for path in cls.bundle.dependencies if path.name=='task_helpers.hepta')],
            function_sources_sha256={name:cls.bundle.dependencies[path] for name,path in
                __import__('hepta.hia_composite_functions_native',fromlist=['SOURCES']).SOURCES.items()})

    @classmethod
    def tearDownClass(cls):
        if cls.evidence is not None:
            (cls.evidence/'summary.json').write_text(json.dumps({'comparisons':len(cls.rows),
                'equal':sum(row['equal'] for row in cls.rows),'entries':cls.entries,'borrowed':cls.borrowed,
                'helper_header_fault_controls':cls.faults,
                'fixture_scope':cls.fixture_scope,
                'scope':'ACTUAL_OUTER_COMPONENT_TEST_NOT_WHOLE_STACK_QUALIFICATION'},indent=2)+'\n')

    def compare(self,label,document,*,legacy=False,custody=False):
        outcomes=[];orders=[];source=deepcopy(document)
        before=json.dumps(source,sort_keys=True)
        original_function=NativeFunctionSession.function
        self.__class__.custody=custody
        for native in (False,True):
            owner=None;order=[]
            def called(session,fn):
                order.append(fn['name'])
                return original_function(session,fn)
            try:
                with ExitStack() as stack:
                    stack.enter_context(patch.dict(os.environ,{**self.env,SELECTOR:''}))
                    for name in HOST:stack.enter_context(patch.object(composite._Elaborator,name,new=forbidden))
                    stack.enter_context(patch.object(NativeFunctionSession,'function',new=called))
                    if native:
                        stack.enter_context(patch.object(composite._Elaborator,'_reference_lower',new=forbidden))
                        stack.enter_context(patch.object(composite._Elaborator,'function',new=forbidden))
                    current=deepcopy(source);owner=composite._Elaborator(current,legacy=legacy)
                    helpers=owner._native_function_session.helpers
                    try:
                        core=self.measured.lower(owner) if native else owner._reference_lower()
                        outcome={'status':'accepted','core':core}
                    except HIAProgramRejected as error:
                        outcome={'status':'rejected','error':[type(error).__name__,error.code,str(error)]}
                    self.assertIs(owner._native_function_session.helpers,helpers)
                    outcome['state']=state(owner);outcomes.append(outcome);orders.append(order)
                    self.assertEqual(json.dumps(current,sort_keys=True),before)
            finally:
                if owner is not None:
                    owner._native_function_session.close();owner.types.close()
                    owner.__dict__.clear()
                gc.collect()
        equal=outcomes[0]==outcomes[1] and orders[0]==orders[1]
        row={'label':label,'source':source,'legacy':legacy,'orders':orders,
             'expected':outcomes[0],'actual':outcomes[1],'equal':equal}
        if self.evidence is not None:
            with gzip.open(self.evidence/'outcomes.jsonl.gz','at',encoding='utf-8') as stream:
                json.dump(row,stream,sort_keys=True,separators=(',',':'));stream.write('\n')
        self.rows.append({'label':label,'equal':equal,'status':outcomes[1]['status']})
        self.assertTrue(equal,label)
        return outcomes[1],orders[1]

    def test_ordinary_profiles_helpers_cache_and_readonly_leases(self):
        factories=[nominal.stored_loan_program,nominal.enum_owner_program,nominal.task_program,
            nominal.scalar_task_program,nominal.owned_result_task_program,partial.roundtrip_program,
            partial.task_partial_program,partial.chain_partial_program,loans.pair_program,
            loans.task_program,loans.direct_downgrade_program]
        for factory in factories:
            outcome,order=self.compare('ordinary-'+factory.__module__+'.'+factory.__name__,factory(),
                                       custody=factory is nominal.scalar_task_program)
            self.assertEqual(outcome['status'],'accepted')
            checked=verify_core(outcome['core'])
            if factory is nominal.stored_loan_program:
                for flag in (False,True):self.assertEqual(execute_program(checked,'stored',[flag])['result'],91)
        for version in range(1,5):
            self.compare('profile-'+str(version),simple(version=version))
        self.compare('legacy-v1',nominal.scalar_task_program(),legacy=True)

    def test_export_sorting_primitive_only_and_zero_width_nominals(self):
        doc=simple(version=4);doc['types']=[nominal.record('Empty',[])]
        names=['z','aa','A','a','_','Z','a_']
        doc['functions']=[f(name,[],[],[],[b('entry',[],[],ret())]) for name in names]
        doc['functions'] += [f('zero_width',[('input','Empty')],['Empty'],[],
                                  [b('entry',[('input','Empty')],[],ret('input'))]),
                             f('read_view',[('input','readbuf')],['readbuf'],[],
                                  [b('entry',[('input','readbuf')],[],ret('input'))])]
        doc['functions'][-1]['return_loans']=[loans.origin('input')]
        outcome,_=self.compare('exports-order-and-exclusions',doc)
        self.assertEqual(outcome['core']['exports'],sorted(names))

    def test_late_block_inventory_after_every_function(self):
        choice=nominal.enum('Choice',[('a',[]),('b',[])])
        blocks=[b('entry',[('value','Choice')],[],nominal.match('value',('a','one',[]),('b','two',[]))),
                b('one',[],[],ret()),b('two',[],[],ret())]
        blocks += [b('unused_'+str(i),[],[],ret()) for i in range(4093)]
        huge=f('huge',[('value','Choice')],[],[],blocks)
        doc=loans.v4([choice],huge)
        result,order=self.compare('generated-blocks-cross-core-limit',doc)
        self.assertEqual(result['error'][1],'E_HIA_LIMIT')
        later=f('later',[],[],[],[b('entry',[],[],ret())]);later['blocks']=None
        doc['functions'].append(later)
        result,order=self.compare('later-function-error-before-block-inventory',doc)
        self.assertEqual(result['error'][1],'E_HIA_CFG')
        self.assertEqual(order,['huge','later'])

    def test_late_helper_function_inventory_after_every_function(self):
        doc=nominal.scalar_task_program()
        while len(doc['functions'])<1024:
            name='extra_'+str(len(doc['functions']))
            doc['functions'].append(f(name,[],[],[],[b('entry',[],[],ret())]))
        result,order=self.compare('helpers-cross-core-function-limit',doc)
        self.assertEqual(result['error'][1],'E_HIA_LIMIT')
        self.assertEqual(len(order),1024)
        doc['functions'][-1]['blocks']=None
        result,order=self.compare('later-function-error-before-helper-inventory',doc)
        self.assertEqual(result['error'][1],'E_HIA_CFG')
        self.assertEqual(len(order),1024)

    def test_opaque_large_complete_core_and_later_error_priority(self):
        definitions=[nominal.record('A',[('p'+str(i),'u8') for i in range(64)]),
                     nominal.record('R',[('part'+str(i),'A') for i in range(8)])]
        parameters=[('input','R')]
        large=f('large',parameters,['R']*1000,[],[b('entry',parameters,[],ret(*(['input']*1000)))])
        doc=loans.v4(definitions,large)
        result,order=self.compare('opaque-core-larger-than-eight-mib',doc)
        self.assertEqual(result['status'],'accepted')
        size=len(json.dumps(result['core'],separators=(',',':')).encode())
        self.assertGreater(size,8<<20)
        with self.assertRaises(HIAProgramRejected) as error:verify_core(result['core'])
        self.assertEqual(error.exception.code,'E_HIA_LIMIT')
        later=f('later',[],[],[],[b('entry',[],[],ret())]);later['blocks']=None
        doc['functions'].append(later)
        result,order=self.compare('later-error-before-final-large-core-admission',doc)
        self.assertEqual(result['error'][1],'E_HIA_CFG')
        self.assertEqual(order,['large','later'])

    def test_actual_abi_bad_ack_borrow_poison_and_private_reuse_refusal(self):
        with patch.dict(os.environ,{**self.env,SELECTOR:''}):
            for mode in ('ack','borrow','output'):
                owner=composite._Elaborator(simple(version=4));invocation=NativeOuterInvocation(self.measured.images,owner)
                try:
                    invocation._invoke(invocation._wire)
                    if mode=='ack':
                        with self.assertRaises(HIAProgramRejected):
                            invocation._invoke(struct.pack('<4Q',ACK_MAGIC,0,1,OBJECTS))
                    else:
                        source=ctypes.create_string_buffer(HELPER_BYTES if mode=='borrow' else 1)
                        result=invocation.images['owner']._entry(source,HELPER_BYTES if mode=='borrow' else 0,
                            invocation._output,64 if mode=='borrow' else 63,invocation._workspace,WORKSPACE_BYTES)
                        self.assertEqual(result,0xfffffff1)
                    with self.assertRaises(HIAProgramRejected):invocation._invoke(invocation._wire)
                finally:
                    invocation._workspace=invocation._output=None
                    invocation._leased_helpers.invocation=None
                    owner._native_function_session.close();owner.types.close()
            owner=composite._Elaborator(nominal.scalar_task_program())
            try:
                result=self.measured.lower(owner);before=state(owner)
                with self.assertRaises(HIAProgramRejected):self.measured.lower(owner)
                self.assertEqual(state(owner),before)
                self.assertTrue(result['functions'])
            finally:
                owner._native_function_session.close();owner.types.close()

    def test_actual_helper_header_and_workspace_metadata_are_one_lease(self):
        for fault in ('serial','name','error','payload','extent','reserved','magic'):
            with self.subTest(fault=fault),ExitStack() as stack:
                stack.enter_context(patch.dict(os.environ,{**self.env,SELECTOR:''}))
                for name in HOST:stack.enter_context(patch.object(composite._Elaborator,name,new=forbidden))
                stack.enter_context(patch.object(composite._Elaborator,'_reference_lower',new=forbidden))
                owner=composite._Elaborator(nominal.scalar_task_program())
                original=owner._native_function_session.helpers
                replacement=type('ActualHelperFaultControl',(),{})()
                calls=[]
                def entry(source,size,output,capacity,workspace,workspace_size):
                    raw=ctypes.string_at(source,size)
                    extent=original._entry(source,size,output,capacity,workspace,workspace_size)
                    header=struct.unpack_from('<8Q',output)
                    row={'extent_before':extent,'header_before':list(header),
                         'workspace_metadata':list(struct.unpack_from('<8Q',workspace,4096)),
                         'input_sha256':sha256(raw).hexdigest(),
                         'input_unchanged':ctypes.string_at(source,size)==raw,
                         'payload_sha256':sha256(ctypes.string_at(ctypes.addressof(output)+64,extent-64)).hexdigest()}
                    if not calls:
                        field={'serial':2,'name':3,'error':1,'payload':4,'reserved':5,'magic':0}.get(fault)
                        if field is not None:struct.pack_into('<Q',output,field*8,header[field]+1)
                        else:extent+=1
                    row['header_after']=list(struct.unpack_from('<8Q',output))
                    row['extent_after']=extent;calls.append(row)
                    return extent
                replacement._entry=entry
                owner._native_function_session.helpers=replacement
                try:
                    with self.assertRaises(HIAProgramRejected) as error:self.measured.lower(owner)
                    self.assertEqual(error.exception.code,'E_HIA_TYPE')
                    self.assertEqual(len(calls),1)
                    self.assertTrue(calls[0]['input_unchanged'])
                    self.faults.append({'fault':fault,'calls':calls,
                                       'error':[error.exception.code,str(error.exception)]})
                    if self.evidence is not None:
                        (self.evidence/'helper-header-faults.json').write_text(json.dumps(self.faults,indent=2)+'\n')
                finally:
                    owner._native_function_session.close();owner.types.close()

    def test_actual_refusal_releases_unpublished_types_and_borrowed_workspace(self):
        from hepta.hia_composite_constructor_native import installed_composite_constructor, NativeConstructorInvocation
        from hepta import hia_composite_outer_native as outer_module
        held=[];rows=[]
        with patch.dict(os.environ,self.env):
            constructor=installed_composite_constructor(self.env[SELECTORS[1]])
            active=[];refs=[];entries=[]
            images=dict(constructor.images);delegate=images['owner']._entry
            proxy=type('ActualConstructorFrameFault',(),{})()
            def actual_entry(*args):
                result=delegate(*args);entries.append(result)
                invocation=active[0]
                if invocation.types is not None and not refs:
                    refs.extend([weakref.ref(invocation.types._state),weakref.ref(invocation.types._output)])
                    struct.pack_into('<Q',args[2],0,0)
                return result
            proxy._entry=actual_entry;images['owner']=proxy
            owner=composite._Elaborator.__new__(composite._Elaborator)
            invocation=NativeConstructorInvocation(images,owner,simple(version=4))
            own_buffer=weakref.ref(invocation._workspace);active.append(invocation)
            try:invocation.initialize()
            except HIAProgramRejected as error:held.append(error)
            else:self.fail('corrupted real post-type-init frame accepted')
            active.clear();del invocation;gc.collect()
            self.assertFalse(hasattr(owner,'native_types'))
            self.assertEqual(len(refs),2)
            self.assertTrue(all(ref() is None for ref in refs))
            self.assertIsNone(own_buffer())
            rows.append({'case':'unpublished_types_after_bad_frame','owner_entries':len(entries),
                         'types_released':True,'own_buffer_released':True})

            owners=[];borrowed=[]
            original_init=composite._Elaborator.__init__
            def capture(owner,*args,**kwargs):
                original_init(owner,*args,**kwargs)
                owners.append(owner)
                borrowed.append(weakref.ref(owner._native_function_session._workspace))
            document=simple(version=4);later=dict(document['functions'][0])
            later['name'],later['blocks']='later',None
            document['functions'].append(later)
            try:
                with patch.object(composite._Elaborator,'__init__',new=capture),\
                     patch.object(outer_module,'selected_composite_outer',new=lambda:self.measured):
                    verify_core(document)
            except HIAProgramRejected as error:held.append(error)
            else:self.fail('later malformed function accepted')
            self.assertEqual(held[-1].code,'E_HIA_CFG')
            self.assertEqual(len(owners),1)
            # The frozen f50 candidate does not incorporate the separate v63
            # public finally yet. Execute that close operation explicitly; it
            # is idempotent when this test is subsequently integrated with v63.
            owners[0]._native_function_session.close();owners[0].native_types.close()
            owners.clear();gc.collect()
            self.assertIsNone(borrowed[0]())
            rows.append({'case':'public_late_error_after_session_close','borrowed_buffer_released':True,
                         'public_cleanup_explicit_in_frozen_baseline':True})
        self.assertEqual(len(held),2)
        if self.evidence is not None:
            (self.evidence/'held-error-lifetimes.json').write_text(json.dumps(rows,indent=2)+'\n')


if __name__=='__main__':unittest.main()
