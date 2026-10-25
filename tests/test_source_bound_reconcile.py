import copy
import hashlib
import importlib.util
import json
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from hepta import source_bound_reconcile as mod
from hepta.hsir_v1 import integrate_v0, verify_v1

SRC='fn f(a: i32) -> i32 effects {panic} { let mut b: i32 = 0; while b < a { b = b + 1; } return b; }'
SHA=hashlib.sha256(SRC.encode()).hexdigest()
P='same.hepta'
SPAN={'path': P, 'start':0, 'end':1,'line':1,'column':1}

def expr(op, ty, value=None, *args):
    return {'node':'expr','op':op,'type':ty,'value':value,'args':list(args),'type_args':[],'span':SPAN}

def stmt(op, fields):
    return {'node':'stmt','op':op,'data':fields,'span':SPAN}

A=expr('name','i32','a')
B=expr('name','i32','b')
ZERO=expr('int','i32',0)
ONE=expr('int','i32',1)
SOURCE_BODY=[
    stmt('let',{'name':'b','type':{'node':'type','name':'i32','args':[],'length':None},'mutable':True,'expr':ZERO}),
    stmt('while',{'condition':expr('binary','bool','<',B,A),'body':[
        stmt('assign',{'target':B,'expr':expr('binary','i32','+',B,ONE)})]}),
    stmt('return',{'expr':B})
]


def make_legacy():
    record = {'schema':'hepta.hsir.v0','profile':'checked_typed_ast_not_verified_mir',
            'module':'test','source_sha256':SHA,'project_sha256':None,
            'claims':{'native_borrow_validation':False,'translation_correctness_proved':False,
                      'whole_language_soundness_proved':False,'foreign_contracts_proved':False},
            'imports':[], 'structs':[], 'enums':[], 'external_obligations':[],
            'foreign_assumptions':[], 'volatile_accesses':[], 'owned_types':[],
            'resource_contracts':{}, 'all_expressions_typed':True,'untyped_expressions':[],
            'functions':[{'name':'f', 'extern_c':False,'export_c':False,'return_mode':'value',
                          'return_origin':None,'type_params':[],'type_bounds':{},'resources':{},
                          'params':[{'name':'a','mode':'value','type':'i32'}],
                          'returns':'i32', 'declared_effects':['panic'],'inferred_effects':['panic'],
                          'public':False,'body':copy.deepcopy(SOURCE_BODY)}]}
    record['sha256'] = hashlib.sha256(json.dumps(record,sort_keys=True,
        separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()).hexdigest()
    return record

def envelope(legacy=None):
    return integrate_v0(legacy or make_legacy())

class Tests(unittest.TestCase):
    def test_simple_ast_normalization(self):
        legacy=make_legacy()
        out=mod.require_safe_source_bound(legacy)
        self.assertEqual(out[0]['body'][1]['fields']['condition']['operation'],'binary')
        self.assertEqual(out[0]['body'][1]['fields']['body'][0]['fields']['expr']['operands'][1]['value'],1)
        self.assertEqual(out[0]['param_types'][0]['type'], {'type':'i32','args':[],'length':None})
        self.assertFalse(out[0]['resource_contract'])

    def test_identical_semantics_validate(self):
        legacy=make_legacy()
        frozen=mod.require_safe_source_bound(legacy)
        mod.assert_same_derived_semantics(legacy,{"functions":copy.deepcopy(frozen)})
        wrong=copy.deepcopy(frozen)
        wrong[0]['body'][1]['fields']['condition']['value']='>'
        with self.assertRaisesRegex(mod.SourceBoundReconcileRejected,'DIVERGENT_BODY'):
            mod.assert_same_derived_semantics(legacy,{"functions":wrong})

    def test_ffi_and_owned_rejected(self):
        for field, value in [('external_obligations',[{'function':'f'}]),
                             ('owned_types',['Buffer<u8>']), ('foreign_assumptions',[{}]),
                             ('resource_contracts',{'f':{'heap_allocations':0}})]:
            legacy=make_legacy(); legacy[field]=value
            with self.subTest(field=field),self.assertRaisesRegex(mod.SourceBoundReconcileRejected,'EXTERNAL_OR_OWNED'):
                mod.require_safe_source_bound(legacy)

    def test_borrow_generics_cast_unsupported_rejected(self):
        for field,value in [('return_mode','read'),('return_origin','a'),('type_params',['T'])]:
            legacy=make_legacy(); legacy['functions'][0][field]=value
            with self.subTest(field=field),self.assertRaises(mod.SourceBoundReconcileRejected):
                mod.require_safe_source_bound(legacy)
        legacy=make_legacy(); legacy['functions'][0]['params'][0]['mode']='mut'
        with self.assertRaisesRegex(mod.SourceBoundReconcileRejected,'BORROWED_PARAMETER'):
            mod.require_safe_source_bound(legacy)

    def test_hidden_call_and_bad_name_rejected(self):
        legacy=make_legacy(); legacy['functions'][0]['body'].append(stmt('expr',{'expr':expr('call','i32','danger',A)}))
        with self.assertRaisesRegex(mod.SourceBoundReconcileRejected,'EXPRESSION_OPERATOR'):
            mod.require_safe_source_bound(legacy)
        legacy=make_legacy(); legacy['functions'][0]['body'][1]['data']['body'][0]['data']['target']['value']='x::y'
        with self.assertRaisesRegex(mod.SourceBoundReconcileRejected,'NONLOCAL_NAME'):
            mod.require_safe_source_bound(legacy)

    def test_project_form_and_public_type_check(self):
        legacy=make_legacy();legacy['imports']=[{'name':'foo'}]
        with self.assertRaisesRegex(mod.SourceBoundReconcileRejected,'MULTIMODULE'):
            mod.require_safe_source_bound(legacy)
        legacy=make_legacy();legacy['functions'][0]['returns']='Buffer<u8>'
        with self.assertRaisesRegex(mod.SourceBoundReconcileRejected,'NONSCALAR_TYPE'):
            mod.require_safe_source_bound(legacy)

    def test_reconcile_exact_source_native(self):
        legacy=make_legacy()
        frozen={'source_sha256':SHA,'sha256':'d'*64,
                'functions':mod.require_safe_source_bound(legacy)}
        class NativeResult:
            program='program'
            checked='checked'
            report={'ok':True,'status':'checked','checks':{'rust_borrows_types':'rustc_checked'},'assumptions':[]}
        pipeline=types.ModuleType('hepta.pipeline')
        pipeline.analyze=lambda source,path,**kwargs: NativeResult()
        hsir=types.ModuleType('hepta.hsir')
        class Frozen:
            def as_dict(self):return frozen
        hsir.lower_checked_program=lambda program,checked: Frozen()
        with patch.dict(sys.modules,{'hepta.pipeline':pipeline,'hepta.hsir':hsir}), \
             patch.object(mod,'integrate_v0',return_value={'dummy':'target'}), \
             patch.object(mod,'lower_verified_v1_scalar_ssa',return_value={'verified':True}):
            out=mod.reconcile_source_bound_to_ssa(envelope(legacy),SRC,path=P,rustc='/explicit/rustc')
        self.assertEqual(out['source_sha256'],SHA)
        self.assertTrue(out['ssa_verified']['verified'])
        self.assertFalse(out['claims']['whole_language_soundness_proved'])
        self.assertTrue(out['claims']['native_target_compiler_passed'])
        self.assertFalse(out['external_project_identity_revalidated'])

    def test_reconcile_refuses_unqualified_native(self):
        legacy=make_legacy()
        class NativeResult:
            report={'ok':True,'status':'frontend_only','checks':{'rust_borrows_types':'not_run'}}
        pipeline=types.ModuleType('hepta.pipeline')
        pipeline.analyze=lambda *args,**kwargs: NativeResult()
        with patch.dict(sys.modules,{'hepta.pipeline':pipeline}):
            with self.assertRaisesRegex(mod.SourceBoundReconcileRejected,'NATIVE_REVALIDATION'):
                mod.reconcile_source_bound_to_ssa(envelope(legacy),SRC,path=P)

    def test_reconcile_source_hash_rejected_before_compiler(self):
        with self.assertRaisesRegex(mod.SourceBoundReconcileRejected,'SOURCE_SHA_MISMATCH'):
            mod.reconcile_source_bound_to_ssa(envelope(),SRC+' ')

    def test_unhashable_malformed_operations_fail_closed(self):
        legacy=make_legacy()
        legacy['functions'][0]['body'][1]['data']['condition']['op'] = []
        with self.assertRaisesRegex(mod.SourceBoundReconcileRejected,'EXPRESSION_OPERATOR'):
            mod.require_safe_source_bound(legacy)
        legacy=make_legacy()
        legacy['functions'][0]['body'][1]['data']['condition']['value'] = []
        with self.assertRaisesRegex(mod.SourceBoundReconcileRejected,'BINARY_OPERATOR'):
            mod.require_safe_source_bound(legacy)

    def test_malformed_ast_rejected(self):
        legacy=make_legacy();legacy['functions'][0]['body'][0]['data']['type']['length']=3
        with self.assertRaisesRegex(mod.SourceBoundReconcileRejected,'COMPLEX_TYPE'):
            mod.require_safe_source_bound(legacy)

if __name__=='__main__': unittest.main()
