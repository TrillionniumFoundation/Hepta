"""Copy rvalue projection must evaluate once without erasing owners or loans."""
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import unittest

from hepta.ast import HeptaError
from hepta.backend import emit_rust
from hepta.c_backend import emit_c
from hepta.checker import check
from hepta.parser import parse
from hepta.resource_ir import ResourceIRError, verify_resource_ir
from hepta.resource_lowering import lower_resource_ir

CC=os.environ.get('CC') or shutil.which('gcc')
RUSTC=os.environ.get('RUSTC') or shutil.which('rustc')
PREFIX='''
struct Matrix{rows:[[i64;2];2]}
struct Cell{x:i64}
struct Pair{left:i64,right:i64}
fn set(a:mut i64,b:i64)->Unit effects{write}{a=b;}
fn pair<T:Copy>(x:T)->[T;2] effects{} {return [x,x];}
fn selected<T:Copy>(x:T)->T effects{panic}{return pair::<T>(x)[1];}
fn count<T:Copy>(x:T)->usize effects{} {return len(pair::<T>(x));}
fn next(x:mut i64)->i64 effects{write,panic}{x=x+1;return x;}
fn values(x:mut i64)->[i64;2] effects{write,panic}{return [next(mut x),next(mut x)];}
fn matrix(x:mut i64)->Matrix effects{write,panic}{return Matrix{rows:[values(mut x),values(mut x)]};}
fn index()->usize effects{} {return 1;}
fn position(x:read i64)->usize effects{panic}{return (x-1) as usize;}
fn loan(x:mut [i64;2])->mut [i64;2] effects{} {return mut x;}
'''
CASES={
    'literal_and_generic':'assert(selected::<i64>(3)==3);assert(count::<i64>(3)==2);assert([10,20][index()]==20);assert(pair::<i64>(7)[1]==7);assert(len(pair::<i64>(7))==2);',
    'nested_copy_aggregates':'assert([[1,2],[3,4]][index()][0]==3);assert([Cell{x:4},Cell{x:9}][index()].x==9);assert(pair::<[i64;2]>([5,6])[1][0]==5);',
    'once_and_base_before_index':'let mut n:i64=0;assert(values(mut n)[position(read n)]==2);assert(n==2);assert(len(values(mut n))==2);assert(n==4);assert(matrix(mut n).rows[1][0]==7);assert(n==8);assert(len(matrix(mut n).rows[0])==2);assert(n==12);',
    'short_circuit':'let mut n:i64=0;assert(true || values(mut n)[0]==0);assert(!(false && len(values(mut n))==0));assert(n==0);assert(false || values(mut n)[0]==1);assert(n==2);',
    'owners_remain_live':'let b=buffer(2);assert(pair::<i64>(7)[0]==7);assert(len(b)==2);drop(move b);',
    'disjoint_field_during_temporary_projection':'let mut p=Pair{left:1,right:2};set(mut p.left,pair::<i64>(p.right)[0]);assert(p.left==2);assert(p.right==2);',
    'named_and_returned_loan':'let mut xs:[i64;2]=[1,2];xs[1]=9;assert(xs[1]==9);assert(loan(mut xs)[0]==1);xs[0]=4;assert(xs[0]==4);',
}
TRAPS={
    'length_boundary':'let x=pair::<i64>(7)[bad()];',
    'maximum_index':'let x=pair::<i64>(7)[huge()];',
    'nested_outer_boundary':'let x=[[1,2],[3,4]][bad()][0];',
    'nested_inner_boundary':'let x=[[1,2],[3,4]][0][bad()];',
    'length_keeps_projection_bounds':'let n=len([[1,2],[3,4]][bad()]);',
}
EXTRA='fn bad()->usize effects{} {return 2;}fn huge()->usize effects{} {return 18446744073709551615;}'


def frontend(body,extra=''):
    p=parse(PREFIX+EXTRA+extra+'fn main()->Unit effects{alloc,block,panic,write}{'+body+'}')
    c=check(p)
    if not c.ok: raise AssertionError([d.to_dict() for d in c.diagnostics])
    return p,c


class ResourceArrayValueTests(unittest.TestCase):
    def test_copy_contexts_verify_and_emit_without_bypassing_gate(self):
        for name,body in CASES.items():
            with self.subTest(name=name):
                p,c=frontend(body);graph=lower_resource_ir(p,c)
                self.assertTrue(verify_resource_ir(graph)['ok'])
                self.assertTrue(all(v is False for v in graph['claims'].values()))
                self.assertIn('int main(void)',emit_c(p,c))

    def test_graph_preserves_one_root_call_and_ordered_index_reads(self):
        p,c=frontend('let mut n:i64=0;let x=values(mut n)[position(read n)];let y=len(matrix(mut n).rows[0]);')
        g=lower_resource_ir(p,c);main=next(f for f in g['functions'] if f['name']=='main')
        ops=main['blocks'][0]['ops'];calls=[o['function'] for o in ops if o['op']=='call']
        self.assertEqual(calls,['values','position','matrix'])
        base=next(i for i,o in enumerate(ops) if o['op']=='call' and o['function']=='values')
        index=next(i for i,o in enumerate(ops) if o['op']=='call' and o['function']=='position')
        self.assertLess(base,index)
        self.assertTrue(any(o['op']=='end_borrow' for o in ops[base+1:index]))
        arrays={v['id'] for v in main['locals'] if g['types'][v['type']]['kind']=='array'}
        self.assertTrue(any(o['op']=='use' and o.get('place',{}).get('root') in arrays and o['place']['path']==['*'] for o in ops))

    def test_returned_and_ambient_loans_are_not_ended_by_copy_projection(self):
        cases=[
            ('let mut xs:[i64;2]=[1,2];let x=loan(mut xs)[read_index(read xs)];',
                'fn read_index(x:read [i64;2])->usize effects{panic}{return (x[0]-1) as usize;}'),
            ('let mut n:i64=0;let x=hold(mut n,pair::<i64>(7)[position(read n)]);',
                'fn hold(x:mut i64,y:i64)->i64 effects{} {return y;}'),
        ]
        for body,extra in cases:
            p,c=frontend(body,extra)
            with self.assertRaises(ResourceIRError) as error:lower_resource_ir(p,c)
            self.assertEqual(error.exception.code,'E_RIR_LOAN_CONFLICT')

    def test_copy_call_loan_ends_before_effectful_index_but_c_boundary_stays(self):
        extra='''fn copy_bytes(b:read Buffer<u8>)->[u8;2] effects{panic}{return [b[0],b[1]];}
fn consume(b:take Buffer<u8>)->usize effects{alloc,block}{drop(move b);return 1;}'''
        p,c=frontend('let b=buffer(2);let x=copy_bytes(read b)[consume(move b)];',extra)
        self.assertTrue(verify_resource_ir(lower_resource_ir(p,c))['ok'])
        with self.assertRaises(HeptaError) as error:emit_c(p,c)
        self.assertEqual(error.exception.diagnostic.code,'E_C_BACKEND_EVALUATION')

    def test_temporary_borrow_owner_array_and_owner_projection_stay_rejected(self):
        for source,code in zip([
            'fn accept(x:read [i64;2])->Unit effects{} {}fn main()->Unit effects{} {accept(read [1,2]);}',
            'fn main()->Unit effects{alloc,block,panic}{let x=[buffer(1)];}',
            'struct Owner{b:Buffer<u8>,n:i64}fn owner()->Owner effects{alloc,block,panic}{return Owner{b:buffer(1),n:2};}fn main()->Unit effects{alloc,block,panic}{let x=owner().n;}',
        ],['E_LVALUE','E_NESTED_LINEAR','E_LINEAR_TEMPORARY']):
            checked=check(parse(source))
            self.assertFalse(checked.ok)
            self.assertIn(code,[d.code for d in checked.diagnostics])

    def native(self,rust):
        for name,body in {**CASES,**TRAPS}.items():
            p,c=frontend(body)
            with self.subTest(name=name),tempfile.TemporaryDirectory() as td:
                root=Path(td);src=root/('program.rs' if rust else 'program.c')
                src.write_text(emit_rust(p,c,crate_type='bin') if rust else emit_c(p,c))
                for opt in ('0','3'):
                    exe=root/'program'
                    command=([RUSTC,'--edition=2021','-C','opt-level='+opt,'-C','overflow-checks=yes','-C','panic=abort',str(src),'-o',str(exe)] if rust else [CC,'-std=c11','-O'+opt,'-fsanitize=undefined','-fno-sanitize-recover=all',str(src),'-lm','-o',str(exe)])
                    built=subprocess.run(command,capture_output=True,text=True,timeout=60);self.assertEqual(built.returncode,0,built.stderr)
                    run=subprocess.run([str(exe)],capture_output=True,text=True,timeout=10)
                    self.assertEqual(run.returncode,-signal.SIGABRT if name in TRAPS else 0,run.stderr)
                    if not rust:self.assertNotIn('runtime error:',run.stderr)

    @unittest.skipUnless(RUSTC,'native Rust required')
    def test_rust_keeps_loan_conflicts_and_accepts_copy_before_owner_consumption(self):
        rejected = [
            ('let mut xs:[i64;2]=[1,2];let x=loan(mut xs)[read_index(read xs)];',
             'fn read_index(x:read [i64;2])->usize effects{panic}{return (x[0]-1) as usize;}'),
            ('let mut n:i64=0;let x=hold(mut n,pair::<i64>(7)[position(read n)]);',
             'fn hold(x:mut i64,y:i64)->i64 effects{} {return y;}'),
        ]
        accepted = ('let b=buffer(2);let x=copy_bytes(read b)[consume(move b)];assert(x==0);',
                    'fn copy_bytes(b:read Buffer<u8>)->[u8;2] effects{panic}{return [b[0],b[1]];}'
                    'fn consume(b:take Buffer<u8>)->usize effects{alloc,block}{drop(move b);return 1;}')
        for body,extra in [*rejected,accepted]:
            p,c=frontend(body,extra)
            with tempfile.TemporaryDirectory() as td:
                src=Path(td)/'program.rs';exe=Path(td)/'program'
                src.write_text(emit_rust(p,c,crate_type='bin'))
                built=subprocess.run([RUSTC,'--edition=2021','--error-format=json',str(src),'-o',str(exe)],capture_output=True,text=True,timeout=60)
                if (body,extra) in rejected:
                    self.assertNotEqual(built.returncode,0)
                    errors=[json.loads(line) for line in built.stderr.splitlines() if line.startswith('{')]
                    self.assertTrue({'E0502','E0499'} & {d.get('code',{}).get('code') for d in errors if d.get('code')},built.stderr)
                else:
                    self.assertEqual(built.returncode,0,built.stderr)
                    run=subprocess.run([str(exe)],capture_output=True,text=True,timeout=10)
                    self.assertEqual(run.returncode,0,run.stderr)

    @unittest.skipUnless(CC,'native GCC required')
    def test_native_c_copy_arrays_o0_o3(self):self.native(False)

    @unittest.skipUnless(RUSTC,'native Rust required')
    def test_native_rust_copy_arrays_o0_o3(self):self.native(True)

if __name__=='__main__':unittest.main()
