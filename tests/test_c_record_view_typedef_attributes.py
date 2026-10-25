"""Modeled AST regressions only: no Clang, native ABI or runtime claims."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hepta.c_migrate import MigrationRejected, migrate_c_project
from hepta.c_record_views import CRecordViewTranslator
from hepta.c_translation import CTranslator
from test_c_project_typedef_attributes import MODEL, capture, typedef


def contract(functions=None):
    return {'schema':'hepta.c-record-views.v1',
            'records':{'State':{'buffers':{'data':{'length_field':'n','add':0}}}},
            'functions':functions or {}}


def record(raw='int *', canonical=None, state='unsigned int'):
    typ={'qualType':raw}
    if canonical is not None:typ['desugaredQualType']=canonical
    return {'kind':'RecordDecl','name':'State','tagUsed':'struct','completeDefinition':True,
            'loc':{'file':'input.c','offset':10},'inner':[
                {'kind':'FullComment'},
                {'kind':'FieldDecl','name':'data','type':typ,'inner':[{'kind':'FullComment'}]},
                {'kind':'FieldDecl','name':'n','type':{'qualType':state}}]}


def function(raw='StateAlias *'):
    return {'kind':'FunctionDecl','name':'touch','type':{'qualType':'void ('+raw+')'},
            'inner':[{'kind':'ParmVarDecl','name':'ctx','id':'parameter', 'type':{'qualType':raw}}]}


class RecordViewTypedefAttributeTests(unittest.TestCase):
    def collect(self, units, *, models=None, functions=None):
        with tempfile.TemporaryDirectory() as tmp:
            cap=capture(Path(tmp))
            cap['configurations']=[dict(cap['configurations'][0],index=i,
                model=dict((models or [MODEL]*len(units))[i])) for i in range(len(units))]
            t=CRecordViewTranslator(cap,contract(functions))
            with patch('hepta.c_translation.invoke',side_effect=[json.dumps({'kind':'TranslationUnitDecl','inner':n}) for n in units]):
                t.collect()
            return t

    def reject(self, nodes, code='E_C_ATTRIBUTE'):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            with patch('hepta.c_migration_project.capture_project',return_value=capture(root)), \
                 patch('hepta.c_migration_project.verify_capture'), \
                 patch('hepta.c_translation.invoke',return_value=json.dumps({'kind':'TranslationUnitDecl','inner':nodes})):
                result=migrate_c_project(root/'compile_commands.json',root/'out',contracts=contract())
            self.assertFalse(result['ok'],result)
            self.assertIn(code,[d['code'] for d in result['diagnostics']],result)
            self.assertFalse((root/'out').exists())

    def test_plain_typed_pointer_alias_and_comments(self):
        t=self.collect([[typedef('Ptr','int *',file='system.h',comment=True),record('Ptr','int *')]])
        self.assertEqual(t.records['C_State'],[('f_data','view:i32'),('f_n','u32')])

    def test_system_pointer_attribute_before_desugaring(self):
        for attr in ('AlignedAttr','ModeAttr','FutureABIAttr'):
            with self.subTest(attr=attr):
                self.reject([typedef('Ptr','int *',attrs=(attr,),file='system.h'),record('Ptr','int *')])

    def test_system_pointee_attribute_before_desugaring(self):
        self.reject([typedef('Wide','int',attrs=('AlignedAttr',),file='system.h'),record('Wide *','int *')])

    def test_system_pointer_and_scalar_multihop_chains(self):
        for attr_name in ('Element','BasePtr','Ptr'):
            nodes=[typedef('Element','int',attrs=('AlignedAttr',) if attr_name=='Element' else (),file='system.h'),
                   typedef('BasePtr','Element *',attrs=('AlignedAttr',) if attr_name=='BasePtr' else (),file='system.h'),
                   typedef('Ptr','BasePtr',attrs=('AlignedAttr',) if attr_name=='Ptr' else (),file='system.h')]
            with self.subTest(alias=attr_name):self.reject(nodes+[record('Ptr','int *')])

    def test_used_header_scalar_chain_rejects(self):
        for where in ('input.c','types.h'):
            with self.subTest(where=where):
                self.reject([typedef('Element',attrs=('AlignedAttr',),file=where),typedef('Wide','Element',file=where),record('Wide *','int *')])

    def test_plain_header_chain_remains_supported(self):
        t=self.collect([[typedef('Element',file='types.h'),typedef('Wide','Element',file='types.h'),record('Wide *','int *')]])
        self.assertEqual(t.records['C_State'][0],('f_data','view:i32'))

    def test_unused_system_attribute_remains_context(self):
        t=self.collect([[typedef('Unused','int *',attrs=('AlignedAttr',),file='system.h'),record()]])
        self.assertEqual(t.records['C_State'][0],('f_data','view:i32'))
        self.assertNotIn('Unused',t.aliases)

    def test_pointer_redeclaration_cannot_erase_attribute(self):
        self.reject([typedef('Ptr','int *',attrs=('AlignedAttr',),file='system.h'),
                     typedef('Ptr','int *',file='system.h'),record('Ptr','int *')])

    def test_field_unit_one_attribute_not_hidden_by_unit_zero(self):
        with self.assertRaises(MigrationRejected) as error:
            self.collect([[typedef('Ptr','int *',file='system.h'),record('Ptr','int *')],
                          [typedef('Ptr','int *',attrs=('AlignedAttr',),file='system.h'),record('Ptr','int *')]])
        self.assertEqual(error.exception.code,'E_C_ATTRIBUTE')

    def test_unused_unit_zero_attribute_does_not_poison_unit_one(self):
        t=self.collect([[typedef('Ptr','int *',attrs=('AlignedAttr',),file='system.h')],
                        [typedef('Ptr','int *',file='system.h'),record('Ptr','int *')]])
        self.assertEqual(t.records['C_State'][0],('f_data','view:i32'))

    def test_scalar_field_canonical_typedef_context(self):
        t=self.collect([[typedef('uint32_t','unsigned long long',file='system.h'),record(state='uint32_t')]])
        self.assertEqual(t.records['C_State'][1],('f_n','u64'))

    def test_forward_record_and_comments_preserved(self):
        forward={'kind':'RecordDecl','name':'State','tagUsed':'struct','loc':{'file':'input.c','offset':0}}
        t=self.collect([[forward,record()]])
        self.assertEqual(t.inventory[0]['status'],'record_forward_resolved')

    def test_mixed_models_still_reject(self):
        with self.assertRaises(MigrationRejected) as error:
            self.collect([[record()],[record()]],models=[MODEL,dict(MODEL,char_unsigned=True)])
        self.assertEqual(error.exception.code,'E_C_PROJECT_MODEL')

    def signature_context(self, attribute_unit=None):
        functions={'touch':{'records':{'ctx':{'access':'read'}},'slices':{}}}
        # Construct the signature-only context without an unresolved prototype.
        t=CRecordViewTranslator({'configurations':[{'model':dict(MODEL)},{'model':dict(MODEL)}]},contract(functions))
        t.record_nodes={'State':record()}
        t.typedef_types={u:{'StateAlias':{'qualType':'struct State'}} for u in (0,1)}
        t.typedef_declarations={u:{'StateAlias':[typedef('StateAlias','struct State',attrs=('AlignedAttr',) if attribute_unit==u else (),file='system.h')]} for u in (0,1)}
        return t

    def test_signature_attribute_rethrown_before_fallback(self):
        t=self.signature_context(attribute_unit=1)
        with self.assertRaises(MigrationRejected) as error:t.signature(function(),'touch',1,MODEL)
        self.assertEqual(error.exception.code,'E_C_ATTRIBUTE')

    def test_signature_explicit_unit_ignores_other_unit_attribute(self):
        t=self.signature_context(attribute_unit=0)
        result=t.signature(function(),'touch',1,MODEL)
        self.assertTrue(result['params'][0]['record'])
        self.assertEqual(result['params'][0]['type'],'C_State')

    def test_malformed_pointer_field_still_rejects(self):
        for raw in ('int **','int (*)(int)','const int *','volatile int *'):
            with self.subTest(raw=raw):self.reject([record(raw)],code='E_C_VIEW_FIELD')

    def test_cyclic_pointer_alias_metadata_terminates(self):
        t=self.signature_context()
        t.typedef_declarations[0]['Cycle']=[typedef('Cycle','Cycle *',file='system.h')]
        t._check_typedef_attributes('Cycle',0)
        # Metadata traversal does not admit an unsupported value type.
        t.typedef_types[0]['Cycle']={'qualType':'Cycle *'}
        with self.assertRaises(MigrationRejected):t.typ('Cycle',unit=0)

    def test_canonical_familiar_names_use_captured_types(self):
        t=self.signature_context()
        t.typedef_types[1].update({'uint32_t':{'qualType':'int'},
            'size_t':{'qualType':'unsigned long'},'ptrdiff_t':{'qualType':'long'}})
        self.assertEqual(t.typ('uint32_t',unit=1),'i32')
        self.assertEqual(t.typ('size_t',unit=1),'usize')
        self.assertEqual(t.typ('ptrdiff_t',unit=1),'isize')
        t.typedef_types[1]['size_t']={'qualType':'unsigned int'}
        self.assertEqual(t.typ('size_t',unit=1),'u32')

    def test_default_signature_scalar_and_slice_use_explicit_unit(self):
        cap={'configurations':[{'model':dict(MODEL)},{'model':dict(MODEL)}]}
        t=CTranslator(cap,{'schema':'hepta.c-contracts.v1','functions':{
            'consume':{'slices':{'data':{'length':'n','access':'read'}}}}})
        t.typedef_types={0:{'Element':{'qualType':'unsigned int'}},1:{'Element':{'qualType':'int'}}}
        t.typedef_declarations={0:{'Element':[typedef('Element','unsigned int',attrs=('AlignedAttr',))]},
                                1:{'Element':[typedef('Element','int')]}}
        fn={'kind':'FunctionDecl','name':'consume','type':{'qualType':'Element (Element *, unsigned int)'},'inner':[
            {'kind':'ParmVarDecl','name':'data','id':'data','type':{'qualType':'Element *'}},
            {'kind':'ParmVarDecl','name':'n','id':'n','type':{'qualType':'unsigned int'}}]}
        result=t.signature(fn,'consume',1,MODEL)
        self.assertEqual(result['return'],'i32')
        self.assertEqual(result['params'][0]['type'],'i32')
        with self.assertRaises(MigrationRejected) as error:t.signature(fn,'consume',0,MODEL)
        self.assertEqual(error.exception.code,'E_C_ATTRIBUTE')

    def test_default_record_field_context_is_not_global_alias(self):
        cap={'configurations':[{'model':dict(MODEL)},{'model':dict(MODEL)}]}
        t=CTranslator(cap)
        t.aliases={'Element':'u32'}
        t.typedef_types={1:{'Element':{'qualType':'int'}}}
        self.assertEqual(t.field_type('State',{'type':{'qualType':'Element'}},unit=1),'i32')


if __name__=='__main__':unittest.main()
