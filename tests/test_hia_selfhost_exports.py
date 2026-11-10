"""Independent Core, genuine ELF symbols/linking and SysV multi-export calls."""
from __future__ import annotations
import copy
import ctypes
from pathlib import Path
import subprocess
import tempfile
import unittest

from hepta.hia_agent_assembly import assemble_program
from hepta.hia_program import execute_program
from tools.hia_selfhost_exports_cases import (SCALAR_TYPES,document,allocated_document,
    dense_document,assembly,refusals)
from tools.qualify_hia_selfhost import build_seed,compile_stage,invoke,INVALID,NO_SPACE,SAMPLE


class ExportSourceTests(unittest.TestCase):
    def test_independent_Core_interfaces_values_and_complete_private_checks(self):
        checked=assemble_program(assembly(document()))
        for count in range(17):
            self.assertEqual(execute_program(checked,'sum_'+str(count),list(range(count)))['values'],[sum(range(count))])
        self.assertEqual(execute_program(checked,'via_private',[])['values'],[41])
        self.assertEqual(execute_program(checked,'aaB',[])['values'],[8])
        self.assertEqual(execute_program(checked,'aba',[])['values'],[9])
        self.assertEqual(execute_program(assemble_program(assembly(allocated_document())),'allocated_size',[17])['values'],[17])
        assemble_program(assembly(dense_document()))
        with self.assertRaises(ValueError):assemble_program(refusals()['invalid-private-body'])
        # Unit parameters and multiple scalar returns are legal Core, but have
        # no reviewed scalar C export ABI. Keep those scopes distinguishable.
        assemble_program(refusals()['unit-parameter'])
        assemble_program(refusals()['multiple-results'])

    def test_actual_compiler_word_helpers_keep_endianness_bounds_and_prior_writes(self):
        from tools.qualify_hia_selfhost_exports import word_reference
        rows=word_reference()
        self.assertEqual(len(rows),28)
        self.assertEqual(sum('expected_trap' in row for row in rows),22)
        partial=next(r for r in rows if r['id']=='compiler-word-put-0-7')
        self.assertEqual(partial['expected_hex'],'efcdab89674523')


class ExportNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc=document();checked=assemble_program(assembly(cls.doc))
        assert execute_program(checked,'via_private',[])['values']==[41]
        # Establish the two-object semantics BEFORE building any successor.
        # Both objects deliberately contain a differently valued private helper
        # with the same source identifier. Only public names are prefixed.
        cls.link_documents=[];cls.link_reference={}
        cls.link_arguments=[250,65000,4000000000,2**64-10,17,-120,-32000,
            -2000000000,-(2**63)+7,-9,True,3,4,5,6,7]
        for prefix,private in (('left_',41),('right_',59)):
            doc=copy.deepcopy(cls.doc)
            allocator=allocated_document()
            doc['functions'].extend(allocator['functions'])
            doc['exports'].extend(allocator['exports'])
            names={f['name']:prefix+f['name'][:128-len(prefix)] for f in doc['functions']
                if f['name']!='private_value'}
            for f in doc['functions']:
                if f['name']=='private_value':f['blocks'][0]['ops'][0]['attrs']['value']=private
                f['name']=names.get(f['name'],f['name'])
                for block in f['blocks']:
                    for op in block['ops']:
                        if op['op']=='call':
                            callee=op['attrs']['function']
                            op['attrs']['function']=names.get(callee,callee)
            doc['exports']=[names[name] for name in doc['exports']]
            doc['module']=prefix+'library'
            checked=assemble_program(assembly(doc))
            for name,args in (('mixed',cls.link_arguments),('via_private',[]),
                              ('allocated_size',[37]),('identity_i8',[-120]),
                              ('identity_bool',[True])):
                result=execute_program(checked,prefix+name,args)
                assert result['status']=='returned',result
                assert result['resources']['live_owners']==0,result
                cls.link_reference[prefix+name]=int(result['values'][0])
            cls.link_documents.append(doc)
        cls.temporary=tempfile.TemporaryDirectory(prefix='hia-native-exports-')
        cls.folder=Path(cls.temporary.name);cls.serial=0
        seed,_=build_seed(cls.folder)
        compiler=(Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/selfhost.hiaasm').read_bytes()
        cls.first,_=compile_stage(cls.folder,'B1',seed,compiler,image_format='seed-shared')
        cls.second,_=compile_stage(cls.folder,'B2',cls.first,compiler)
        assert cls.first.read_bytes()==cls.second.read_bytes()

    @classmethod
    def tearDownClass(cls):cls.temporary.cleanup()

    def linked(self,doc,label):
        from hepta.hia_program_native import _inspect_object
        from hepta.object_symbols import inspect_object_symbols
        obj,receipt=compile_stage(self.folder,label,self.second,assembly(doc))
        self.assertEqual(receipt['forbidden_compiler_modules_loaded'],[])
        _inspect_object(obj.read_bytes(),tuple(doc['exports']))
        inventory=inspect_object_symbols(obj.read_bytes(),"ELF64",62)
        self.assertEqual(inventory['defined'],frozenset(doc['exports']))
        library=self.folder/(label+'.so')
        subprocess.run(['cc','-shared','-Wl,-z,defs,-z,noexecstack,-z,relro,-z,now',str(obj),'-o',str(library)],check=True,capture_output=True)
        return ctypes.CDLL(str(library)),obj,inventory

    def test_all_supported_scalar_ABI_widths_dirty_highs_all_argument_positions(self):
        lib,obj,inventory=self.linked(self.doc,'widths-and-arity')
        self.assertNotIn('private_value',inventory['defined'])
        with self.assertRaises(AttributeError):getattr(lib,'private_value')
        for typ in SCALAR_TYPES:
            signed=typ.startswith('i');bits=int(typ[1:]) if typ[1:].isdigit() else 64
            if typ=='bool':bits=1
            function=getattr(lib,'identity_'+typ);function.argtypes=[ctypes.c_uint64]
            function.restype=ctypes.c_int64 if signed else ctypes.c_uint64
            mask=(1<<bits)-1
            for raw in (0,1,2**64-1,0x123456789abcdef0,1<<(bits-1)):
                expected=raw&mask
                if signed and expected&(1<<(bits-1)):expected-=1<<bits
                self.assertEqual(function(raw),expected,(typ,raw))
        for count in range(17):
            function=getattr(lib,'sum_'+str(count));function.argtypes=[ctypes.c_uint64]*count
            function.restype=ctypes.c_uint64
            values=[(i+1)*0x1723456789abcd for i in range(count)]
            self.assertEqual(function(*values),sum(values)&(2**64-1))
        mixed=getattr(lib,'mixed');mixed.argtypes=[ctypes.c_uint64]*16;mixed.restype=ctypes.c_uint64
        for pattern in (2**64-1,0x123456789abcdef0):
            values=[pattern-i for i in range(16)];expected=0
            for typ,value in zip(SCALAR_TYPES+SCALAR_TYPES[:5],values):
                bits=1 if typ=='bool' else int(typ[1:]) if typ[1:].isdigit() else 64
                value&=(1<<bits)-1
                if typ.startswith('i') and value&(1<<(bits-1)):value-=1<<bits
                expected+=value
            self.assertEqual(mixed(*values),expected&((1<<64)-1))
        lib.no_result.argtypes=[];lib.no_result.restype=None;lib.no_result()
        lib.unit_result.argtypes=[];lib.unit_result.restype=ctypes.c_uint64
        self.assertEqual(lib.unit_result(),0)
        for name,result in (('via_private',41),('_',7),('aaB',8),('aba',9),('block',10),('call',11),('read',12),('exports',13),('long_'+'x'*123,14)):
            function=getattr(lib,name);function.argtypes=[];function.restype=ctypes.c_uint64
            self.assertEqual(function(),result)

    def test_actual_compiler_word_helpers_preserve_trap_and_partial_write_order(self):
        from tools.qualify_hia_selfhost_exports import word_reference,qualify_words
        checks={}
        qualify_words(self.folder,self.second,checks,word_reference(),'word-test')
        self.assertEqual(len(checks),28)
        self.assertTrue(all(checks.values()),checks)

    def test_dynamic_import_symbol_indices_with_real_allocator_lifetime(self):
        lib,obj,inventory=self.linked(allocated_document(),'allocator')
        self.assertEqual(inventory['undefined'],frozenset({'calloc','free'}))
        lib.allocated_size.argtypes=[ctypes.c_uint64];lib.allocated_size.restype=ctypes.c_uint64
        for size in (0,1,17,4096):self.assertEqual(lib.allocated_size(size),size)
        lib.second.argtypes=[];lib.second.restype=ctypes.c_uint64;self.assertEqual(lib.second(),2)

    def test_two_HIA_objects_link_together_with_typed_C_callers(self):
        """Real link unit, not two isolated ctypes loads or a module-graph claim."""
        from hepta.object_symbols import inspect_object_symbols
        objects=[];defined=set()
        for i,doc in enumerate(self.link_documents):
            obj,receipt=compile_stage(self.folder,'two-objects-'+str(i),self.second,assembly(doc))
            self.assertEqual(receipt['forbidden_compiler_modules_loaded'],[])
            symbols=inspect_object_symbols(obj.read_bytes(),'ELF64',62)
            self.assertEqual(symbols['defined'],frozenset(doc['exports']))
            self.assertEqual(symbols['undefined'],frozenset({'calloc','free'}))
            self.assertNotIn('private_value',symbols['defined'])
            self.assertTrue(defined.isdisjoint(symbols['defined']))
            defined.update(symbols['defined']);objects.append(obj)
        types='uint8_t,uint16_t,uint32_t,uint64_t,uintptr_t,int8_t,int16_t,int32_t,int64_t,intptr_t,bool,uint8_t,uint16_t,uint32_t,uint64_t,uintptr_t'
        args='UINT8_C(250),UINT16_C(65000),UINT32_C(4000000000),UINT64_MAX-9,17,-120,-32000,-INT32_C(2000000000),INT64_MIN+7,-9,true,3,4,5,6,7'
        declarations=[];checks=[]
        for prefix in ('left_','right_'):
            declarations.extend((f'extern uint64_t {prefix}mixed({types});',
                f'extern uint64_t {prefix}via_private(void);',
                f'extern uintptr_t {prefix}allocated_size(uintptr_t);',
                f'extern int8_t {prefix}identity_i8(int8_t);',
                f'extern bool {prefix}identity_bool(bool);'))
            for name,call in (('mixed',args),('via_private',''),
                              ('allocated_size','37'),('identity_i8','-120'),
                              ('identity_bool','true')):
                expected=self.link_reference[prefix+name]
                literal=f'UINT64_C({expected})' if expected>=0 else str(expected)
                checks.append(f'  if ({prefix}{name}({call}) != {literal}) return {len(checks)+1};')
        driver=self.folder/'two-objects-caller.c'
        driver.write_text('#include <stdint.h>\n#include <stdbool.h>\n'+
            '\n'.join(declarations)+'\nint main(void) {\n'+
            '\n'.join(checks)+'\n  return 0;\n}\n')
        executable=self.folder/'two-objects-caller'
        subprocess.run(['cc','-std=c11','-O2','-Wall','-Wextra','-Werror',
            '-Wl,-z,defs,-z,noexecstack,-z,relro,-z,now',str(driver),
            *(str(obj) for obj in objects),'-o',str(executable)],
            check=True,capture_output=True)
        result=subprocess.run([str(executable)],capture_output=True,timeout=10)
        self.assertEqual((result.returncode,result.stdout,result.stderr),(0,b'',b''))

    def test_full_export_table_and_longest_names(self):
        lib,obj,inventory=self.linked(dense_document(),'dense128')
        self.assertEqual(len(inventory['defined']),128)
        for i in range(128):
            function=getattr(lib,'export_'+str(i));function.argtypes=[];function.restype=ctypes.c_uint64
            self.assertEqual(function(),i)

    def test_exports_do_not_select_semantics_by_hash_or_declaration_order(self):
        for order in (0,1):
            doc=copy.deepcopy(self.doc)
            if order:
                doc['functions'].reverse();doc['exports'].reverse()
            lib,_,_=self.linked(doc,'order'+str(order))
            for name,expected in (('aaB',8),('aba',9),('via_private',41)):
                function=getattr(lib,name);function.argtypes=[];function.restype=ctypes.c_uint64
                self.assertEqual(function(),expected)

    def test_invalid_exports_cannot_write_any_output_or_hide_bad_private_body(self):
        for i,(name,source) in enumerate(refusals().items()):
            with self.subTest(name=name):
                result,output=invoke(self.folder,'refuse'+str(i),self.second,source,
                    workspace_fill=0xa5,capacity=8192)
                self.assertEqual(result['status'],'returned',result)
                self.assertEqual(result['core_u32'],INVALID,result)
                self.assertTrue(result['output_unchanged'])
        source=assembly(dense_document())
        result,output=invoke(self.folder,'short-output',self.second,source,capacity=1)
        self.assertEqual(result['core_u32'],NO_SPACE)
        self.assertTrue(result['output_unchanged'])

    def test_legacy_borrowed_entry_reproduction_and_poisoned_workspace(self):
        source=SAMPLE.read_bytes()
        first,_=compile_stage(self.folder,'legacy',self.second,source)
        second,_=compile_stage(self.folder,'legacy-poisoned',self.second,source,workspace_fill=0xa5)
        self.assertEqual(first.read_bytes(),second.read_bytes())
