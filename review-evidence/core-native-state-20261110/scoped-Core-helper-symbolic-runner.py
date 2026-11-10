"""Exact checked HIA helper equivalence under private-header invariants only.

Trusted finite symbolic Core interpreter + Z3; not native ISA, whole compiler,
reachability of private invariants or whole-language correctness proof.
"""
from pathlib import Path
from hashlib import sha256
import json,subprocess,sys
B=Path(__file__).resolve().parents[1];R=B/'agent-core-native-state-cost-development';E=B/'evidence';D=E/'core-private-state-words-smt-01'
sys.path.insert(0,str(R));import z3 as z
from hepta.hia_agent_assembly import assemble_program
from tools.generate_hia_selfhost import document
assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=R,text=True).strip()=='79b53adaab0dd8d6869f6682e4a30810fc501156'
assert not subprocess.check_output(['git','status','--porcelain'],cwd=R)
assert not D.exists();D.mkdir(mode=0o700)
source=(R/'examples/hia_bootstrap/selfhost.hiaasm').read_bytes();checked=assemble_program(source).as_dict();_,names=document()
functions={f['name']:f for f in checked['functions']}
M=z.Array('caller_bytes',z.BitVecSort(64),z.BitVecSort(8));at=z.BitVec('private_word_offset',64);value=z.BitVec('private_value',64)
u64=lambda n:z.BitVecVal(n&((1<<64)-1),64)
def evaluate(name,memory):
 f=functions[names[name]];assert len(f['blocks'])==1
 env={p['name']:arg for p,arg in zip(f['params'],[(None,u64(256)),at,value])}
 traps=[]
 for op in f['blocks'][0]['ops']:
  k=op['op'];a=[env[v] for v in op['args']];typ=op['out'][0]['type'] if op['out'] else None
  if k=='const':v=u64(op['attrs']['value'])
  elif k=='int.cast':
   assert op['attrs']['mode']=='wrap';bits={'u8':8,'u32':32,'usize':64,'u64':64}[typ];v=a[0]&u64((1<<bits)-1)
  elif k=='int.add.wrap':v=a[0]+a[1]
  elif k=='bit.and':v=a[0]&a[1]
  elif k=='bit.or':v=a[0]|a[1]
  elif k in ('int.shl.checked','int.shr.checked'):
   traps.append(z.UGE(a[1],u64(64)));v=a[0]<<a[1] if k=='int.shl.checked' else z.LShR(a[0],a[1])
  elif k=='buffer.load':
   traps.append(z.UGE(a[1],a[0][1]));v=z.ZeroExt(56,z.Select(memory,a[1]))
  elif k=='buffer.store':
   traps.append(z.UGE(a[1],a[0][1]));memory=z.Store(memory,a[1],z.Extract(7,0,a[2]));v=None
  else:raise AssertionError('unreviewed symbolic opcode '+k)
  if op['out']:env[op['out'][0]['name']]=v
 term=f['blocks'][0]['term'];assert term['op']=='ret'
 return env[term['values'][0]],memory,z.Or(*traps)
wide_get,_,wide_trap=evaluate('get',M);small_get,_,small_trap=evaluate('state_get32',M)
_,wide_memory,wide_store_trap=evaluate('put',M);_,small_memory,small_store_trap=evaluate('state_put32',M)
offsets=(0,8,24,40,56,80,88,96,104,112,120,136,224,240,248)
private=z.Or(*[at==u64(n) for n in offsets]);high_zero=z.And(*[z.Select(M,at+u64(i))==0 for i in range(4,8)])
rows=[]
def query(label,assumptions,violation,wanted):
 s=z.Solver();s.set(timeout=10000);s.add(*assumptions,violation)
 smt=s.to_smt2();(D/(label+'.smt2')).write_text(smt);observed=s.check();assert str(observed)==wanted,(label,observed)
 model=str(s.model()) if observed==z.sat else None
 if model:(D/(label+'.model.txt')).write_text(model)
 rows.append(dict(name=label,result=str(observed),query_sha256=sha256(smt.encode()).hexdigest(),counterexample_retained=model is not None))
query('get_equivalence_under_zero_high_bytes',[private,high_zero],z.Or(wide_get!=small_get,wide_trap,small_trap),'unsat')
query('put_full_memory_equivalence_for_u32_values',[private,high_zero,z.ULE(value,u64((1<<32)-1))],z.Or(wide_memory!=small_memory,wide_store_trap,small_store_trap),'unsat')
query('not_a_general_u64_store_replacement',[private,high_zero,value==u64(1<<32)],wide_memory!=small_memory,'sat')
query('header_clearing_is_necessary',[private],wide_get!=small_get,'sat')
report=dict(status='SCOPED_SYMBOLIC_HELPER_OBLIGATIONS_PASS',source_commit='79b53adaab0dd8d6869f6682e4a30810fc501156',
 actual_hia_source_sha256=sha256(source).hexdigest(),solver_version=z.get_version_string(),
 functions={n:dict(name=names[n],sha256=sha256(json.dumps(functions[names[n]],sort_keys=True).encode()).hexdigest()) for n in ('get','put','state_get32','state_put32')},
 obligations=rows,assumptions=dict(workspace_bytes=256,offsets=offsets,high_four_bytes_zero=True,private_store_value_max=(1<<32)-1),
 arbitrary_other_caller_bytes_preserved=True,private_invariant_reachability_proved=False,native_isa_or_compiler_equivalence_proved=False,whole_language_proof=False)
with (E/'core-private-state-words-smt-01.json').open('x') as f:json.dump(report,f,sort_keys=True,indent=2)
print(json.dumps(report))
