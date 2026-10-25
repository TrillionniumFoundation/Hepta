import copy, hashlib, json, os, subprocess, sys, tempfile
from pathlib import Path
root=Path('/tmp/hepta-owned-independent-365fcb');sys.path.insert(0,str(root))
from hepta.pipeline import analyze
from hepta.backend import compile_rust
from hepta.resource_lowering import lower_resource_ir
from hepta.resource_ir import verify_resource_ir
rustc='/workspace/scratch/0817a147930b/toolchains/rust-1.90.0/bin/rustc'
source=r'''
struct Box<T>{value:T}
enum Pair<A,B>{Both(A,B)}
fn identity<T:Owned>(value:take T)->T effects {} {return move value;}
fn swap<A:Owned,B:Owned>(value:take Pair<A,B>)->Pair<B,A> effects {} {
 match move value {Pair::Both(a,b)=>{return Pair::Both(move b,move a);}}
}
fn view<T:Owned>(value:read T)->read T effects {} {return read value;}
fn route<U:Owned>(value:read U)->read U effects {} {return read view::<U>(read value);}
fn copied<T:Copy>(value:T)->T effects {} {return value;}
fn unused<T:Owned>(value:take T)->Unit effects {alloc,block} {drop(move value);}
fn wrapper<U:Owned>(value:take U)->Result<Box<U>,u8> effects {} {return Result::Ok(Box{value:move identity::<U>(move value)});}
fn main()->Unit effects {alloc,block,panic} {
 let a:Buffer<u8>=buffer(17);
 let b:Box<Buffer<u8>>=Box{value:move buffer(31)};
 let both:Pair<Buffer<u8>,Box<Buffer<u8>>>=Pair::Both(move a,move b);
 let flipped=swap::<Buffer<u8>,Box<Buffer<u8>>>(move both);
 match move flipped {Pair::Both(left,right)=>{
  assert(len(read left.value)==31);
  assert(len(route::<Buffer<u8>>(read right))==17);
  let wrapped=wrapper::<Buffer<u8>>(move right);
  drop(move wrapped);drop(move left);
 }}
 assert(copied::<u64>(9)==9);
}
'''
files=['hepta/checker.py','hepta/resource_ir.py','hepta/resource_lowering.py','hepta/backend.py','hepta/parser.py','hepta/ast.py']
identity={p:hashlib.sha256((root/p).read_bytes()).hexdigest() for p in files}
r={'schema':'hepta.independent-owned-generic-audit.v1','implementation_commit':'365fcb16515fec41aac6f00aec61fdbfb5f728eb','implementation_files':identity,'source_sha256':hashlib.sha256(source.encode()).hexdigest(),'native':{},'graph_mutations':[],'frontend_negatives':[],'whole_language_soundness_proved':False}
a=analyze(source,rustc=rustc,crate_type='bin')
assert a.report['ok'],a.report['diagnostics']
doc=lower_resource_ir(a.program,a.checked)
assert verify_resource_ir(doc)['ok']
with tempfile.TemporaryDirectory(prefix='hepta-owned-independent-native-') as tmp:
 b=compile_rust(a.rust,rustc=rustc,crate_type='bin',output=Path(tmp)/'run');assert b['ok'],b
 p=subprocess.run([b['artifact']],capture_output=True,text=True,timeout=15);assert p.returncode==0,p.stderr
 r['native']={'exit_code':p.returncode,'build':b,'independent_graph_validation':verify_resource_ir(doc)}
def fn(g,n):return next(f for f in g['functions'] if f['name']==n)
def calls(g,n):return [o for block in fn(g,n)['blocks'] for o in block['ops'] if o['op']=='call']
def mutate(name,change):
 g=copy.deepcopy(doc);change(g);result=verify_resource_ir(g);assert not result['ok'],name
 r['graph_mutations'].append({'case':name,'rejected':True,'diagnostic':result['diagnostics'][0]})
mutate('universal_owned_body_missing_drop',lambda g:fn(g,'unused')['blocks'][0].update(ops=[o for o in fn(g,'unused')['blocks'][0]['ops'] if o['op']!='drop']))
mutate('bound_downgrade_with_take',lambda g:g['types']['@unused::T'].update(bound='Copy'))
mutate('caller_type_argument_callee_scope_escape',lambda g:calls(g,'wrapper')[0].update(type_args=['@identity::T']))
mutate('owned_call_receives_copy_scalar',lambda g:calls(g,'wrapper')[0].update(type_args=['u8']))
mutate('generic_call_arity_erasure',lambda g:calls(g,'wrapper')[0].pop('type_args'))
mutate('foreign_generic_parameter_in_local',lambda g:fn(g,'copied')['locals'][0].update(type='@unused::T') if fn(g,'copied')['locals'] else fn(g,'copied')['locals'].append({'id':'foreign','type':'@unused::T','mutable':False}))
mutate('concrete_box_replaces_owned_payload',lambda g:g['types']['Box<Buffer<u8>>']['fields'][0].update(type='u8'))
mutate('instantiated_enum_payload_permutation',lambda g:g['types']['Pair<Box<Buffer<u8>>, Buffer<u8>>']['variants'][0].update(fields=['Buffer<u8>','Box<Buffer<u8>>']))
mutate('unbound_parameter_table_entry',lambda g:g['types'].update({'@ghost::T':{'kind':'parameter','function':'ghost','name':'T','bound':'Owned'}}))
mutate('false_source_refinement_claim',lambda g:g['claims'].update(source_to_ir_refinement_proved=True))
mutate('foreign_return_parameter_scope',lambda g:fn(g,'view')['returns'].update(type='@route::U'))
negative=[
 ('duplicate_parameter_constraint', 'fn dup<T:Owned,T:Copy>(x:T)->T effects {} {return x;}'),
 ('scoped_owned_as_copy_call', 'fn c<T:Copy>(x:T)->T effects {} {return x;}fn f<T:Owned>(x:take T)->T effects {} {return move c::<T>(move x);}'),
 ('copy_as_owned_call', 'fn c<T:Owned>(x:take T)->T effects {} {return move x;}fn f<T:Copy>(x:T)->T effects {} {return c::<T>(move x);}'),
 ('borrowed_abstract_owner_consumed', 'fn f<T:Owned>(x:read T)->T effects {} {return move x;}'),
 ('owned_hidden_in_raw_generic', 'struct Ptr<T>{value:raw const T}fn f<T:Owned>(x:take Ptr<T>)->Unit effects {alloc,block} {drop(move x);}'),
 ('generic_body_leak_without_call', 'fn f<T:Owned>(x:take T)->Unit effects {} {}'),
]
for name,s in negative:
 result=analyze(s,native=False).report;assert not result['ok'],name
 r['frontend_negatives'].append({'case':name,'diagnostics':[d['code'] for d in result['diagnostics']]})
assert identity=={p:hashlib.sha256((root/p).read_bytes()).hexdigest() for p in files}
r.update(ok=True,source_unchanged=True)
out=Path('/tmp/hepta-owned-generic-independent-audit.json');out.write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({'ok':r['ok'],'native_exit':r['native']['exit_code'],'graph_mutations':len(r['graph_mutations']),'frontend_negatives':len(r['frontend_negatives']),'path':str(out)}))
