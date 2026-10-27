import json
from pathlib import Path
from tempfile import TemporaryDirectory
from tools.qualify_hia_program import function, block, constant as c, operation as op, ret, jump, branch
from hepta.hia_program import verify_program, execute_program
from hepta.hia_program_llvm import _can_elide_zero_initialization, emit_program_llvm, compile_program_llvm
from hepta.clang_capture import run_bounded
opaque = function('opaque_loop', [('n','usize'),('rounds','u32')], ['usize'], ['alloc'], [
 block('entry',[('n','usize'),('rounds','u32')],[op('buffer.try_new',['n'],[('b','buffer'),('ok','bool')]),c('zero','u32',0)],branch('ok','loop',['b','rounds','zero'],'failed',['b'])),
 block('loop',[('lb','buffer'),('limit','u32'),('iteration','u32')],[op('compare.lt',['iteration','limit'],[('more','bool')])],branch('more','body',['lb','limit','iteration'],'done',['lb'])),
 block('body',[('bb','buffer'),('blimit','u32'),('bi','u32')],[op('borrow.mut',['bb'],[('m','mutbuf')]),op('borrow.read',['m'],[('r','readbuf')]),op('buffer.len',['r'],[('metadata','usize')]),op('loan.end',['r']),op('loan.end',['m']),op('owner.move',['bb'],[('moved','buffer')]),c('one','u32',1),op('int.add.wrap',['bi','one'],[('next','u32')])],jump('loop','moved','blimit','next')),
 block('done',[('db','buffer')],[op('buffer.len',['db'],[('length','usize')]),op('owner.drop',['db'])],ret('length')),
 block('failed',[('fb','buffer')],[op('owner.drop',['fb']),c('error','usize',999)],ret('error'))])
read = function('read_nonentry',[('n','usize')],['u8'],['alloc','read','trap'],[
 block('entry',[('n','usize')],[op('buffer.new',['n'],[('b','buffer')])],jump('read','b')),
 block('read',[('rb','buffer')],[c('zero','usize',0),op('borrow.read',['rb'],[('r','readbuf')]),op('buffer.load',['r','zero'],[('v','u8')]),op('loan.end',['r']),op('owner.drop',['rb'])],ret('v'))])
make = function('make_owner',[('n','usize')],['buffer'],['alloc','trap'],[
 block('entry',[('n','usize')],[op('buffer.new',['n'],[('b','buffer')])],ret('b'))])
through = function('read_returned',[('n','usize')],['u8'],['alloc','read','trap'],[
 block('entry',[('n','usize')],[op('call',['n'],[('b','buffer')],function='make_owner'),c('zero','usize',0),op('borrow.read',['b'],[('r','readbuf')]),op('buffer.load',['r','zero'],[('v','u8')]),op('loan.end',['r']),op('owner.drop',['b'])],ret('v'))])
assert [_can_elide_zero_initialization(f) for f in (opaque,read,make,through)] == [True,False,False,False]
p = verify_program({'schema':'hepta.hia.program.v1','module':'independent_zero_elision_audit','functions':[opaque,read,make,through]})
checks = [('opaque_loop',[0,7],0,{}),('opaque_loop',[1,7],1,{}),('opaque_loop',[13,2],999,{'allocation_fail_at':1}),('opaque_loop',[1<<63,2],999,{}),('opaque_loop',[17,4],17,{}),('read_nonentry',[1],0,{}),('read_returned',[1],0,{})]
for name,args,expect,kwargs in checks:
 result=execute_program(p,name,args,**kwargs)
 assert result['result']==expect, result
 assert result['resources']['live_owners']==0, result
ir=emit_program_llvm(p)
driver=r'''
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
size_t opaque_loop(size_t,uint32_t);
uint8_t read_nonentry(size_t);
uint8_t read_returned(size_t);
void *__real_malloc(size_t);
void __real_free(void*);
static void *live[64];
static unsigned attempts, nm, nc, nf, active, bad;
static void remember(void *p){if(!p)return;for(int i=0;i<64;i++)if(!live[i]){live[i]=p;active++;return;}bad=1;}
void *__wrap_malloc(size_t n){attempts++;nm++;if(n==13)return 0;void*p=__real_malloc(n);if(p)memset(p,0xA7,n);remember(p);return p;}
void *__wrap_calloc(size_t n,size_t s){attempts++;nc++;void*p=__real_malloc(n*s);if(p)memset(p,0,n*s);remember(p);return p;}
void __wrap_free(void *p){if(!p)return;for(int i=0;i<64;i++)if(live[i]==p){live[i]=0;active--;nf++;__real_free(p);return;}bad=1;}
int main(void){
 if(opaque_loop(0,7)!=0 || opaque_loop(1,7)!=1 || opaque_loop(13,2)!=999 || opaque_loop(((size_t)1)<<63,2)!=999 || opaque_loop(17,4)!=17)return 2;
 if(read_nonentry(1)!=0 || read_returned(1)!=0)return 3;
 printf("attempts=%u malloc=%u calloc=%u frees=%u live=%u bad=%u\n",attempts,nm,nc,nf,active,bad);
 return attempts!=5 || nm!=3 || nc!=2 || nf!=4 || active!=0 || bad!=0;
}
'''
with TemporaryDirectory(prefix='hia-zero-independent-') as directory:
 path=Path(directory); obj=path/'candidate.o'; source=path/'observer.c'; binary=path/'observer'
 receipt=compile_program_llvm(ir,program=p,output=obj,clang='/usr/lib/llvm-20/bin/clang',kind='object')
 source.write_text(driver)
 linked=run_bounded(['/usr/lib/llvm-20/bin/clang','-O2',str(source),str(obj),'-Wl,--wrap=malloc','-Wl,--wrap=calloc','-Wl,--wrap=free','-o',str(binary)])
 assert linked.returncode==0, linked.stderr
 actual=run_bounded([str(binary)])
 assert actual.returncode==0,(actual.returncode,actual.stdout,actual.stderr)
 print(json.dumps({'ok':True,'finite_native_cases':len(checks),'observer':actual.stdout.strip(),'core_sha256':p.sha256,'implementation_sha256':ir.implementation_sha256,'scope':'optimized metadata-only loop with nested loans/owner moves; non-entry read; returned owner; zero/capacity/NULL'}))
