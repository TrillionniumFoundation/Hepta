"""Read actual Counted costs and literal HIA; never import or execute HIA code."""
from pathlib import Path
import ast,collections,hashlib,json,re,stat

ROOT=Path('/tmp/hia-r8-cross-cost-analysis-r1-dda7')
INPUTS={
 'counts':Path('/hia-r8-cross-counted-r1-dda7/diagnostic/STEP-COUNTS.json'),
 'original_HIA':Path('/dev/shm/hia-u32-r8-input-view-r3-dda7/inputs/other/0007/R8.hepta'),
 'inventory':Path('/tmp/hia-r8-fuel-successor-analysis-r1-dda7/WORD64-CAST-INVENTORY.json'),
 'actual_R9_generation_report':Path('/hia-r8-r9-execution-20261114-dda7/generation/generate/report.json'),
 'machine':Path('/tmp/hia-r8-source-recovery-20261114-r1/source/hepta/hia_program_runtime.py'),
 'state':Path('/hia-r8-cross-counted-r1-dda7/diagnostic/RAW-VM-STATE.json'),
 'exception':Path('/hia-r8-cross-counted-r1-dda7/diagnostic/EXCEPTION.txt'),
}

def pin(raw):return {'bytes':len(raw),'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),'sha256':hashlib.sha256(raw).hexdigest()}
def dump(name,value):
 with (ROOT/name).open('x') as f:json.dump(value,f,sort_keys=True,indent=2);f.write('\n')
def main():
 raw={name:path.read_bytes() for name,path in INPUTS.items()}
 assert pin(raw['original_HIA'])['sha256']=='83953e66677fa0cd7f63f3b1742276d954537df71487c3cd4a6eef9486e3e4de'
 costs=json.loads(raw['counts']);byname={r['function']:r for r in costs['rows']}
 assert costs['exclusive_step_sum']==costs['actual_machine_steps']==10000001
 assert sum(r['exclusive_steps'] for r in costs['rows'])==10000001 and costs['frames_after_unwind']==[]
 state=json.loads(raw['state']);assert state['status']=='budget_exceeded' and state['error']['code']=='steps'
 assert b'line 457, in invoke' in raw['exception'] and b'self.tick()' in raw['exception']
 generation=json.loads(raw['actual_R9_generation_report']);proof=generation['generated']['word64_projection']
 assert proof['whole_inverse_equal'] and proof['complete_original_Core_verifier_returned']
 assert proof['original_counts']=={'functions':107,'blocks':1456,'ops':6664}
 assert proof['after_counts']=={'functions':107,'blocks':1456,'ops':6347}
 removed=proof['removed_identity_casts'];assert len(removed)==317
 inventory=json.loads(raw['inventory']);assert inventory['removable_identity_wrap_casts']==317
 inv={(r['function'],r['out'],r['source']) for r in inventory['rows']}
 actual={(r['function'],r['operation']['out'][0]['name'],r['operation']['args'][0]) for r in removed}
 assert inv==actual and len(inv)==317
 # Literal line extraction only. This is not the project assembler or a VM.
 functions={}
 for m in re.finditer(r'^fn (f\d+)\([^\n]*\n.*?^end\n',raw['original_HIA'].decode(),re.M|re.S):
  text=m.group(0);blocks={};current=None
  for line in text.splitlines()[1:-1]:
   if line.startswith('block '):
    current=line.split('(',1)[0].split()[1];blocks[current]={'ops':[],'term':None}
   else:
    assert current is not None
    op=re.fullmatch(r'  (.+) = ([A-Za-z0-9_.]+)\(([^)]*)\)(?: (\{.*\}))?',line)
    if op:
     lhs,kind,args,attrs=op.groups()
     outs=[] if lhs=='_' else [{'name':v.split(':')[0],'type':v.split(':')[1]} for v in lhs.split(',')]
     blocks[current]['ops'].append({'out':outs,'op':kind,'args':args.split(',') if args else [],'attrs':json.loads(attrs) if attrs else {},'line':line})
    else:
     assert blocks[current]['term'] is None and line.strip().startswith(('ret(','branch ','jump ','trap(')),line
     blocks[current]['term']=line.strip()
  functions[m.group(1)]={'text':text,'blocks':blocks}
 assert len(functions)==107
 selected=('f25','f24','f91','f92','f23','f22');rows=[]
 for name in selected:
  fn=functions[name];cost=byname[name];casts=[r for r in removed if r['function']==name]
  for row in casts:
   op=fn['blocks'][row['block']]['ops'][row['original_op_index']]
   assert {k:v for k,v in op.items() if k!='line'}==row['operation']
  assert cost['inclusive_steps']==cost['exclusive_steps'],'selected leaf includes an actual child call'
  if name!='f92':
   assert list(fn['blocks'])==['b0'] and fn['blocks']['b0']['term'].startswith('ret(')
   assert not any(op['op']=='call' for op in fn['blocks']['b0']['ops'])
   normal_steps=len(fn['blocks']['b0']['ops'])+2
   if name=='f23':
    complete=cost['calls']-1;partial=cost['exclusive_steps']-complete*normal_steps
    assert normal_steps==61 and partial==6
    # One entry tick, four successful op ticks, then the fifth op's tick
    # refuses before its operation. There is no HIA exception recovery.
    successful_ops=partial-2
    partial_saving=sum(r['original_op_index']<successful_ops for r in casts)
    assert successful_ops==4 and partial_saving==1
    assert fn['blocks']['b0']['ops'][successful_ops]['op']=='int.add.wrap'
   else:
    assert cost['exclusive_steps']==normal_steps*cost['calls']
    complete=cost['calls'];partial=0;partial_saving=0
  else:
   assert list(fn['blocks'])==['b0','b1','b2']
   assert fn['blocks']['b0']['term'].startswith('branch ')
   assert [op['op'] for op in fn['blocks']['b0']['ops']]==['const','compare.gt']
   assert fn['blocks']['b1']['ops'][-1]['op']=='call'
   assert fn['blocks']['b1']['ops'][-1]['attrs']['function']=='f21'
   assert not any(op['op']=='call' for op in fn['blocks']['b2']['ops'])
   # No inclusive/exclusive difference proves zero actually charged child
   # calls, excluding b1. Global refusal is in leaf get, not cp16. Exact
   # 18-per-call accounting confirms every b2 path returned.
   normal_steps=1+len(fn['blocks']['b0']['ops'])+1+len(fn['blocks']['b2']['ops'])+1
   assert normal_steps==18 and cost['exclusive_steps']==normal_steps*cost['calls']
   complete=cost['calls'];partial=0;partial_saving=0
  saving=complete*len(casts)+partial_saving
  rows.append({'function':name,'source_function':cost['source_function'],'calls':cost['calls'],
   'actual_exclusive_steps':cost['exclusive_steps'],'normal_path_ticks':normal_steps,
   'proven_complete_calls':complete,'partial_charged_ticks':partial,
   'removed_static_cast_sites':len(casts),'removed_sites':casts,
   'proven_removed_dynamic_ticks_in_old_prefix':saving,
   'partial_successfully_executed_removed_casts':partial_saving})
 assert sum(r['proven_removed_dynamic_ticks_in_old_prefix'] for r in rows)==570519
 # Preserve the exact interpreter methods establishing step accounting.
 text=raw['machine'].decode();tree=ast.parse(text);machine=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='_Machine')
 methods={}
 for name in ('tick','invoke'):
  n=next(n for n in machine.body if isinstance(n,ast.FunctionDef) and n.name==name)
  methods[name]=''.join(text.splitlines(keepends=True)[n.lineno-1:n.end_lineno])
 dump('SOURCE-EXCERPTS.json',{'HIA':{n:functions[n] for n in selected},'original_Machine_methods':methods,
  'all_selected_cast_sites':sum(r['removed_static_cast_sites'] for r in rows)})
 dump('INPUT-PINS.json',{name:{'path':str(path),'identity':pin(raw[name]),'mode':stat.S_IMODE(path.stat().st_mode)} for name,path in INPUTS.items()})
 report={'schema':'hepta.r8.actual-cross-counted-word64-static-cost.v1','status':'SOURCE_AND_ACTUAL_COUNT_ANALYSIS_ONLY',
  'new_VM_Native_compile_generator_calls':0,'old_failed_prefix_steps':10000001,'old_product_status':'FAIL',
  'selected_functions':rows,'selected_static_cast_sites':28,'other_static_cast_sites_not_costed':289,
  'proven_removed_dynamic_ticks_in_observed_prefix':570519,'fraction_of_original_charged_prefix':570519/10000001,
  'selected_function_exclusive_sum':sum(r['actual_exclusive_steps'] for r in rows),
  'interpretation':'Exact dynamic count for these 28 sites in the observed old prefix; a lower bound for all 317 removed sites, not a full-run fuel prediction.',
  'no_per_function_static_count_times_calls_for_branched_loops':True,
  'phase_boundary':'Original final phase=0, signature phase=0. Phase1 remains unobserved; no whole-run step bound follows.',
  'unknowns':['dynamic counts of remaining 289 sites','work after the original stopped prefix','complete phase1 cost','R9 full-buffer semantic and 10M outcome'],
  'runtime_input_scope':'original frozen3180 plus executable/libpython two-file guards; not current-cold',
  'hotspots':costs['rows'][:12],
  'future_not_authored_or_adopted':[
    {'idea':'Eliminate redundant bit.and 255 immediately consumed only by int.cast wrap to u8 in original write helpers.',
     'constraint':'Keep every buffer.store and all bounds/order; keep cp16 upper-range compare and fail path. For any unsigned64 x, wrap_u8(x & 255) == wrap_u8(x). Full verifier/inverse and original size/controls remain required.',
     'not_done':'No code patch, generation, size estimate or fuel qualification.'},
    {'idea':'Share constant 1 in successive wrapping address increments within unrolled byte helpers.',
     'constraint':'Prove equal 64-bit modular addresses, retain each load/store and their order, preserve every original error/partial write. No assumed zero scratch or skipped read.',
     'not_done':'No second optimization added to frozen R9.'}],
  'no_fuel_PASS_claim':True,'original_failure_relabelled':False}
 dump('REPORT.json',report)
 print(json.dumps({'status':report['status'],'proven_removed_prefix_ticks':570519,'sites':28,
  'fraction':report['fraction_of_original_charged_prefix'],'rows':[{k:r[k] for k in ('source_function','calls','normal_path_ticks','proven_removed_dynamic_ticks_in_old_prefix')} for r in rows]},indent=2))

if __name__=='__main__':main()
