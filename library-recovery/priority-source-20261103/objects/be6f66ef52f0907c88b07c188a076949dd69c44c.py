#!/usr/bin/env python3
"""HIA bounded-profile regression and actual Clang/GCC oracle comparison."""
import ctypes
import copy
import json
import os
import random
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from hia_probe import (Rejected, SCHEMA, UINT32, emit_native_c, identity,
                       interpret_scalar, translate_clang_scalar, verify_linear_resource,
                       verify_scalar)

EXPRESSION_CASES = {
    'add': ('a + b', lambda a,b: (a+b)&UINT32),
    'sub': ('a - b', lambda a,b: (a-b)&UINT32),
    'mul': ('a * b', lambda a,b: (a*b)&UINT32),
    'xor': ('a ^ b', lambda a,b: a^b),
    'and': ('a & b', lambda a,b: a&b),
    'or': ('a | b', lambda a,b: a|b),
    'nested': ('((a + 3u) * (b ^ 7u)) - a', lambda a,b: (((a+3)* (b^7))-a)&UINT32),
}

def sample_program():
    return {'schema':SCHEMA, 'name':'f','params':[{'name':'a','type':'u32'}, {'name':'b','type':'u32'}],
            'ops':[{'id':'v0','opcode':'int.add.wrap','args':['a','b']}], 'result':'v0'}

class ScalarTests(unittest.TestCase):
    def expect_reject(self, code, call):
        with self.assertRaises(Rejected) as c:
            call()
        self.assertEqual(c.exception.code,code)

    def test_positive_wrap(self):
        self.assertEqual(interpret_scalar(sample_program(), [UINT32, 42]), 41)
        self.assertEqual(interpret_scalar(sample_program(), [0, 0]), 0)
        self.assertEqual(interpret_scalar(sample_program(), [123, 456]), 579)

    def test_immutable_snapshot(self):
        source=sample_program()
        snap=verify_scalar(source)
        digest=identity(snap)
        source['ops'][0]['args'][1]='malicious'
        self.assertEqual(identity(snap),digest)
        self.assertEqual(interpret_scalar(snap,[2,3]),5)
        self.expect_reject('E_SSA',lambda: interpret_scalar(source,[2,3]))

    def test_unknown_schema(self):
        p=sample_program();p['schema']='hepta.audit.scalar-u32.v99'
        self.expect_reject('E_VERSION',lambda:verify_scalar(p))

    def test_extra_fields(self):
        p=sample_program();p['safety_certificate']=True
        self.expect_reject('E_SCHEMA',lambda:verify_scalar(p))

    def test_noninteger_and_bool_arguments(self):
        self.expect_reject('E_INVOKE',lambda:interpret_scalar(sample_program(),[True,0]))
        self.expect_reject('E_INVOKE',lambda:interpret_scalar(sample_program(),[-1,0]))
        self.expect_reject('E_INVOKE',lambda:interpret_scalar(sample_program(),[UINT32+1,0]))

    def test_use_before_definition(self):
        p=sample_program();p['ops'][0]['args'][0]='v1'
        self.expect_reject('E_SSA',lambda:verify_scalar(p))

    def test_duplicate_ssa(self):
        p=sample_program();p['ops'][0]['id']='a'
        self.expect_reject('E_SSA',lambda:verify_scalar(p))

    def test_bad_const(self):
        p=sample_program();p['ops']=[{'id':'v0','opcode':'const','value':True}]
        self.expect_reject('E_CONST',lambda:verify_scalar(p))

    def test_unsupported_instruction(self):
        p=sample_program();p['ops'][0]['opcode']='raw.ptr.load'
        self.expect_reject('E_OPCODE',lambda:verify_scalar(p))

    def test_instructions_budget(self):
        p=sample_program();p['ops']=[{'id':f'v{i}','opcode':'const','value':1} for i in range(257)]
        self.expect_reject('E_OP_BUDGET',lambda:verify_scalar(p))

    def test_undefined_return(self):
        p=sample_program();p['result']='unknown'
        self.expect_reject('E_RETURN',lambda:verify_scalar(p))

    def test_bad_op_attributes(self):
        p=sample_program();p['ops'][0]['secret']='yes'
        self.expect_reject('E_OPCODE',lambda:verify_scalar(p))

class ResourceTests(unittest.TestCase):
    def test_valid_read_move_drop(self):
        ops=[{'op':'owner.new','id':'x','bytes':128},
             {'op':'borrow.read','owner':'x','id':'r1'},
             {'op':'borrow.read','owner':'x','id':'r2'},
             {'op':'loan.end','id':'r2'}, {'op':'loan.end','id':'r1'},
             {'op':'owner.move','from':'x','to':'y'},
             {'op':'borrow.mut','owner':'y','id':'w'},
             {'op':'loan.end','id':'w'}, {'op':'owner.drop','id':'y'}]
        receipt=verify_linear_resource(ops)
        self.assertEqual(receipt['peak_payload_bytes'],128)
        self.assertEqual(receipt['authority'],'DENY_ALL')

    def test_mut_alias_forbidden(self):
        ops=[{'op':'owner.new','id':'x','bytes':128},
             {'op':'borrow.read','owner':'x','id':'r'},
             {'op':'borrow.mut','owner':'x','id':'w'},
             {'op':'loan.end','id':'r'}, {'op':'loan.end','id':'w'},
             {'op':'owner.drop','id':'x'}]
        with self.assertRaises(Rejected) as e:verify_linear_resource(ops)
        self.assertEqual(e.exception.code,'E_ALIAS')

    def test_mut_read_forbidden(self):
        ops=[{'op':'owner.new','id':'x','bytes':1},
             {'op':'borrow.mut','owner':'x','id':'w'},
             {'op':'borrow.read','owner':'x','id':'r'}]
        with self.assertRaises(Rejected) as e:verify_linear_resource(ops)
        self.assertEqual(e.exception.code,'E_ALIAS')

    def test_move_during_loan_forbidden(self):
        ops=[{'op':'owner.new','id':'x','bytes':1},
             {'op':'borrow.read','owner':'x','id':'r'},
             {'op':'owner.move','from':'x','to':'y'}]
        with self.assertRaises(Rejected) as e:verify_linear_resource(ops)
        self.assertEqual(e.exception.code,'E_RESOURCE')

    def test_drop_during_loan_forbidden(self):
        ops=[{'op':'owner.new','id':'x','bytes':1},
             {'op':'borrow.read','owner':'x','id':'r'},
             {'op':'owner.drop','id':'x'}]
        with self.assertRaises(Rejected) as e:verify_linear_resource(ops)
        self.assertEqual(e.exception.code,'E_RESOURCE')

    def test_double_drop_forbidden(self):
        ops=[{'op':'owner.new','id':'x','bytes':1},
             {'op':'owner.drop','id':'x'},
             {'op':'owner.drop','id':'x'}]
        with self.assertRaises(Rejected) as e:verify_linear_resource(ops)
        self.assertEqual(e.exception.code,'E_RESOURCE')

    def test_leak_forbidden(self):
        with self.assertRaises(Rejected) as e:verify_linear_resource([{'op':'owner.new','id':'x','bytes':1}])
        self.assertEqual(e.exception.code,'E_LEAK')

    def test_budget_forbidden(self):
        with self.assertRaises(Rejected) as e:verify_linear_resource([{'op':'owner.new','id':'x','bytes':9}],8)
        self.assertEqual(e.exception.code,'E_RESOURCE')

    def test_extra_effect_forbidden(self):
        with self.assertRaises(Rejected) as e:verify_linear_resource([{'op':'owner.drop','id':'x','force':True}])
        self.assertEqual(e.exception.code,'E_RESOURCE')

class MigrationTests(unittest.TestCase):
    def test_each_operator_translates(self):
        for name,(expr,oracle) in EXPRESSION_CASES.items():
            with self.subTest(name=name):
                src=f'unsigned int {name}(unsigned int a, unsigned int b) {{ return {expr}; }}'
                p=translate_clang_scalar(src,name)
                self.assertEqual(p['schema'],SCHEMA)
                self.assertEqual(interpret_scalar(p,[UINT32,11]),oracle(UINT32,11))

    def test_other_function_rejected(self):
        src='unsigned int f(unsigned int a){return a;} unsigned int g(unsigned int a){return a;}'
        with self.assertRaises(Rejected) as e:translate_clang_scalar(src,'f')
        self.assertEqual(e.exception.code,'E_WHOLE_UNIT')

    def test_globals_rejected(self):
        src='unsigned int extra=1; unsigned int f(unsigned int a){return a+extra;}'
        with self.assertRaises(Rejected) as e:translate_clang_scalar(src,'f')
        self.assertIn(e.exception.code,['E_WHOLE_UNIT','E_REF'])

    def test_preprocessor_rejected(self):
        with self.assertRaises(Rejected) as e:translate_clang_scalar('#define FOO 1\nunsigned int f(unsigned int a){return a+FOO;}','f')
        self.assertEqual(e.exception.code,'E_SOURCE')

    def test_pointer_rejected(self):
        with self.assertRaises(Rejected) as e:translate_clang_scalar('unsigned int f(unsigned int *a){return *a;}','f')
        self.assertEqual(e.exception.code,'E_TYPE')

    def test_signed_overflow_rejected(self):
        with self.assertRaises(Rejected) as e:translate_clang_scalar('int f(int a){return a+1;}','f')
        self.assertEqual(e.exception.code,'E_TYPE')

    def test_division_rejected(self):
        with self.assertRaises(Rejected) as e:translate_clang_scalar('unsigned int f(unsigned int a,unsigned int b){return a/b;}','f')
        self.assertEqual(e.exception.code,'E_EXPR')

    def test_control_flow_rejected(self):
        with self.assertRaises(Rejected) as e:translate_clang_scalar('unsigned int f(unsigned int a){if(a)return 1;return 0;}','f')
        self.assertEqual(e.exception.code,'E_BODY')

    def test_implicit_conversion_rejected(self):
        with self.assertRaises(Rejected) as e:translate_clang_scalar('unsigned int f(unsigned int a){return (unsigned char)a;}','f')
        self.assertEqual(e.exception.code,'E_CAST')

    def test_oversized_source_rejected(self):
        with self.assertRaises(Rejected) as e:translate_clang_scalar(' '*65537,'f')
        self.assertEqual(e.exception.code,'E_SOURCE')

    def test_no_silent_partial_outputs(self):
        with self.assertRaises(Rejected):
            translate_clang_scalar('unsigned int f(unsigned int a){return a+1;} int g;','f')

    def test_native_clang_gcc_differential(self):
        if shutil.which('clang') is None or shutil.which('gcc') is None:
            self.skipTest('requires both real clang and gcc')
        samples=[0,1,2,3,7,256,0x80000000,UINT32,UINT32-1,0x12345678,0x87654321]
        rng=random.Random(20261031)
        pairs=[(a,b) for a in samples for b in samples]
        pairs.extend((rng.randrange(UINT32+1),rng.randrange(UINT32+1)) for _ in range(200))
        for label,(expr,oracle) in EXPRESSION_CASES.items():
            src=f'unsigned int {label}(unsigned int a, unsigned int b) {{ return {expr}; }}\n'
            p=translate_clang_scalar(src,label)
            generated=emit_native_c(p,'hia_entry')
            with tempfile.TemporaryDirectory(prefix='hia-native-') as folder:
                source=Path(folder)/'source.c'; source.write_text(src)
                native=Path(folder)/'native.c'; native.write_text(generated)
                for compiler in ['clang','gcc']:
                    paths=[]
                    for tag,sp in [('original',source),('hia',native)]:
                        binary=Path(folder)/f'{compiler}-{tag}.so'
                        run=subprocess.run([compiler,'-std=c11','-O3','-fPIC','-shared',
                                            '-Wall','-Wextra','-Werror',str(sp),'-o',str(binary)],
                                           text=True,capture_output=True,timeout=20)
                        self.assertEqual(run.returncode,0,(label,compiler,tag,run.stderr))
                        self.assertGreater(binary.stat().st_size,0)
                        lib=ctypes.CDLL(str(binary))
                        fn=getattr(lib,label if tag=='original' else 'hia_entry')
                        fn.argtypes=[ctypes.c_uint32,ctypes.c_uint32]
                        fn.restype=ctypes.c_uint32
                        paths.append(fn)
                    original,hia=paths
                    for a,b in pairs:
                        expected=oracle(a,b)
                        self.assertEqual(interpret_scalar(p,[a,b]),expected,(label,compiler,a,b,'vm'))
                        self.assertEqual(original(a,b),expected,(label,compiler,a,b,'original'))
                        self.assertEqual(hia(a,b),expected,(label,compiler,a,b,'hia'))

if __name__=='__main__':
    unittest.main(verbosity=2)

class AdditionalAdversarialTests(unittest.TestCase):
    def test_owner_ssa_identity_cannot_be_reused(self):
        ops=[{'op':'owner.new','id':'x','bytes':1},
             {'op':'owner.drop','id':'x'},
             {'op':'owner.new','id':'x','bytes':1},
             {'op':'owner.drop','id':'x'}]
        with self.assertRaises(Rejected) as err:verify_linear_resource(ops)
        self.assertEqual(err.exception.code,'E_RESOURCE')

    def test_ended_loan_id_cannot_be_reused(self):
        ops=[{'op':'owner.new','id':'x','bytes':1},
             {'op':'borrow.read','owner':'x','id':'r'},
             {'op':'loan.end','id':'r'},
             {'op':'borrow.read','owner':'x','id':'r'}]
        with self.assertRaises(Rejected) as err:verify_linear_resource(ops)
        self.assertEqual(err.exception.code,'E_RESOURCE')

    def test_ast_preflight_rejects_deep_chain(self):
        from hia_probe import _validate_ast_tree
        node={'kind':'IntegerLiteral'}
        for _ in range(132):
            node={'kind':'ParenExpr','inner':[node]}
        with self.assertRaises(Rejected) as err:_validate_ast_tree(node)
        self.assertEqual(err.exception.code,'E_AST_DEPTH')

    def test_ast_preflight_rejects_wide_chain(self):
        from hia_probe import _validate_ast_tree
        node={'kind':'CompoundStmt','inner':[{'kind':'IntegerLiteral'} for _ in range(4097)]}
        with self.assertRaises(Rejected) as err:_validate_ast_tree(node)
        self.assertEqual(err.exception.code,'E_AST_BUDGET')

    def test_ast_preflight_rejects_malformed_child(self):
        from hia_probe import _validate_ast_tree
        with self.assertRaises(Rejected) as err:_validate_ast_tree({'kind':'ReturnStmt','inner':{}})
        self.assertEqual(err.exception.code,'E_AST')
