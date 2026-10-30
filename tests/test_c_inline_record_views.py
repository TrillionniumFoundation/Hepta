"""Admission and runtime regressions for the new fixed inline-byte profile.

These checks retain the physical/original C type gate, exercise malformed
contracts before adaptation, and verify the scalar initializer never reads or
zeros the caller's payload. They make no general source-equivalence claim.
"""
import copy
import ctypes
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from hepta.c_inline_record_views import CInlineRecordViewTranslator, snapshot_inline_contracts
from hepta.c_migrate import MigrationRejected
from tools.migrate_c_inline_record_project import migrate_inline_project, load_contract

SOURCE='''#include <stdint.h>
typedef struct Packet Packet;
struct Packet { unsigned char bytes[8]; uint8_t cursor; };
void init(Packet *p) { p->cursor=0; }
void append(Packet *p, const unsigned char *input, uint8_t count) {
  uint8_t i;
  for(i=0; i<count; i++) { p->bytes[p->cursor]=input[i]; p->cursor=(p->cursor+1)&7; }
}
unsigned char lookup(Packet *p, uint8_t index) { return p->bytes[index]; }
'''
CONTRACT={'schema':'hepta.c-inline-record-views.v1','records':{'Packet':{'buffers':{'bytes':{'length':8}}}},
 'functions':{'init':{'records':{'p':{'access':'mut'}},'slices':{},'scalar_initializer':True},
              'append':{'records':{'p':{'access':'mut'}},'slices':{'input':{'length':'count','access':'read'}}},
              'lookup':{'records':{'p':{'access':'read'}},'slices':{}}}}

class InlineRecordAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='hepta-inline-tests-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.counter=0
        self.clang=shutil.which(os.environ.get('CLANG','clang-20')) or shutil.which('clang')
        self.cc=shutil.which('gcc');self.assertIsNotNone(self.clang);self.assertIsNotNone(self.cc)

    def migrate(self,source=SOURCE,contract=None,native=False):
        self.counter+=1;work=self.root/str(self.counter);work.mkdir();(work/'input.c').write_text(source)
        database=work/'compile_commands.json';database.write_text(json.dumps([{'directory':str(work),'file':'input.c','arguments':['clang','-std=c11','-c','input.c']}]))
        report=migrate_inline_project(database,work/'translated',contracts=copy.deepcopy(CONTRACT if contract is None else contract),clang=self.clang,cc=self.cc,verify_native=native)
        return report,work

    def reject(self,source,code=None,contract=None):
        result,work=self.migrate(source,contract);self.assertFalse(result['ok'],{'status':result['status'],'diagnostics':result['diagnostics']})
        self.assertFalse((work/'translated').exists())
        if code:self.assertIn(code,[d['code'] for d in result['diagnostics']],result['diagnostics'])
        return result

    def test_actual_checked_native_body_preserves_payload_and_handles_u8_length(self):
        result,work=self.migrate(native=True);self.assertTrue(result['ok'],result['diagnostics'])
        self.assertEqual(len(result['functions']),3);self.assertFalse(result['claims']['rust_codegen_used'])
        self.assertTrue(result['source_type_admission']);self.assertTrue(result['declaration_inventory_complete'])
        class Packet(ctypes.Structure):_fields_=[('bytes',ctypes.c_uint8*8),('cursor',ctypes.c_uint8)]
        lib=ctypes.CDLL(str(work/'translated/libtranslated.so'))
        lib.init.argtypes=[ctypes.POINTER(Packet)];lib.init.restype=None
        lib.append.argtypes=[ctypes.POINTER(Packet),ctypes.POINTER(ctypes.c_uint8),ctypes.c_uint8];lib.append.restype=None
        lib.lookup.argtypes=[ctypes.POINTER(Packet),ctypes.c_uint8];lib.lookup.restype=ctypes.c_uint8
        record=Packet();ctypes.memset(ctypes.byref(record),0xa5,ctypes.sizeof(record));lib.init(ctypes.byref(record))
        self.assertEqual(list(record.bytes),[0xa5]*8);self.assertEqual(record.cursor,0)
        data=(ctypes.c_uint8*10)(*range(10));lib.append(ctypes.byref(record),data,10)
        self.assertEqual(list(record.bytes),[8,9,2,3,4,5,6,7]);self.assertEqual(record.cursor,2)
        self.assertEqual([lib.lookup(ctypes.byref(record),i) for i in range(8)],list(record.bytes))

    def test_malformed_slice_maps_reject_before_attribute_dispatch(self):
        for bad in [None,[],{'input':None},{'input':{'length':'count','access':'read','extra':1}}]:
            contract=copy.deepcopy(CONTRACT);contract['functions']['append']['slices']=bad
            self.reject(SOURCE,'E_C_INLINE_CONTRACT',contract)

    def test_contract_graph_intake_rejects_subclasses_cycles_and_boolean_extent(self):
        class Mapping(dict):pass
        with self.assertRaises(MigrationRejected):snapshot_inline_contracts(Mapping(CONTRACT))
        cyclic=copy.deepcopy(CONTRACT);cyclic['cycle']=cyclic
        with self.assertRaises(MigrationRejected):snapshot_inline_contracts(cyclic)
        bad=copy.deepcopy(CONTRACT);bad['records']['Packet']['buffers']['bytes']['length']=True
        with self.assertRaises(MigrationRejected):CInlineRecordViewTranslator({},bad)

    def test_contract_file_rejects_duplicate_keys_and_symlink(self):
        path=self.root/'bad.json';path.write_text('{"schema":"x","schema":"y"}')
        with self.assertRaises(MigrationRejected):load_contract(path)
        actual=self.root/'valid.json';actual.write_text(json.dumps(CONTRACT));link=self.root/'link';link.symlink_to(actual)
        with self.assertRaises(MigrationRejected):load_contract(link)

    def test_fixed_byte_array_extent_and_qualifiers_are_not_reinterpreted(self):
        for changed in ['unsigned char bytes[9]','unsigned short bytes[8]','volatile unsigned char bytes[8]','unsigned char *bytes']:
            with self.subTest(changed=changed):self.reject(SOURCE.replace('unsigned char bytes[8]',changed),'E_C_INLINE_ARRAY')

    def test_private_extent_cannot_be_supplied_or_overwritten_by_source(self):
        self.reject(SOURCE.replace('uint8_t cursor;','uint8_t cursor; uint8_t hepta_inline_extent_bytes;'),'E_C_INLINE_NAME')

    def test_initializer_must_write_each_scalar_once_without_old_state_or_payload_read(self):
        for body in ['p->cursor=p->cursor;','p->cursor=p->bytes[0];','p->cursor=0; p->bytes[0]=0;','p->cursor=0; p->cursor=0;','p->cursor=1;','']:
            with self.subTest(body=body):self.reject(SOURCE.replace('p->cursor=0;',body),'E_C_INLINE_INITIALIZER')

    def test_signed_length_and_missing_length_reject(self):
        self.reject(SOURCE.replace('uint8_t count','int8_t count'),'E_C_POINTER_CONTRACT')
        contract=copy.deepcopy(CONTRACT);contract['functions']['append']['slices']['input']['length']='absent'
        self.reject(SOURCE,'E_C_POINTER_CONTRACT',contract)

    def test_read_only_record_and_const_input_cannot_be_mutated(self):
        self.reject(SOURCE.replace('return p->bytes[index];','p->cursor=1; return p->bytes[index];'),'E_C_READ_ONLY')
        contract=copy.deepcopy(CONTRACT);contract['functions']['append']['slices']['input']['access']='mut'
        self.reject(SOURCE,'E_C_POINTER_CONTRACT',contract)

    def test_nonsemantic_claims_do_not_authorize_extra_or_absent_slices(self):
        for key,increment in [('input',1),('absent',1),('input',True),('input',2)]:
            contract=copy.deepcopy(CONTRACT);contract['functions']['append']['slice_extra']={key:increment}
            self.reject(SOURCE,'E_C_INLINE_CONTRACT',contract)

    def test_unused_global_and_function_attributes_keep_full_capture_rejection(self):
        self.reject(SOURCE+'\nint unused_global;\n','E_C_TOPLEVEL')
        self.reject(SOURCE.replace('void append(', '__attribute__((noinline)) void append('),'E_C_ATTRIBUTE')

    def test_fixed_array_requires_original_type_receipt_and_vla_still_rejects(self):
        result,_=self.migrate(SOURCE.replace('const unsigned char *input, uint8_t count','const unsigned char input[8], uint8_t count'))
        self.assertTrue(result['ok'],result['diagnostics'])
        parameters=[p for receipt in result['source_type_admission'] for row in receipt['functions'] for p in row['parameters'] if p.get('name')=='input']
        self.assertTrue(parameters)
        self.assertTrue(all(p['state']=='fixed' and p['shape']['kind']=='ConstantArray' for p in parameters))
        self.reject(SOURCE.replace('const unsigned char *input, uint8_t count','uint8_t count, const unsigned char input[count]'),'E_C_VLA_PARAMETER')

    def test_contract_cannot_add_uncaptured_function_or_record_by_value(self):
        contract=copy.deepcopy(CONTRACT);contract['functions']['missing']={'records':{},'slices':{}}
        self.reject(SOURCE,'E_C_CONTRACT',contract)
        contract=copy.deepcopy(CONTRACT);contract['functions']['clone']={'records':{},'slices':{}}
        self.reject(SOURCE+'\nPacket clone(Packet p) { return p; }\n','E_C_VIEW_VALUE_ABI',contract)

if __name__=='__main__':unittest.main()
