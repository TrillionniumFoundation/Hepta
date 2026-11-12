from pathlib import Path
import ast,hashlib,json,stat
S=Path(__file__).resolve().parent
def pin(raw):
 return {'bytes':len(raw),'gitsha':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),'sha256':hashlib.sha256(raw).hexdigest()}
def check(p,r):
 raw=p.read_bytes();z=pin(raw)
 assert z['gitsha']==r.get('gitsha',r.get('blob')) and z['bytes']==r['bytes'] and z['sha256']==r['sha256'],str(p)
 assert stat.S_IMODE(p.stat().st_mode)==int(r['mode'][-3:],8),str(p)
 return raw
D=json.loads((S/'unix-sourceDEL.json').read_bytes());rows=D['files'];prefix=D['suggested_prefix'];root=S/'overlay'/prefix
assert len(rows)==37 and D['files_count']==37 and sum(r['bytes'] for r in rows)==972430
for r in rows:check(S/'overlay'/r['path'],r)
proof=json.loads((root/'proof/propagated-pin-exact-inverses.json').read_bytes())
for key,old,new in [('builder','builder.py','build_actual_unixopen.py'),('CI','ci.py','ci_actual_unixopen.py')]:
 a=check(S/'unix-before'/old,proof[key]['old']).decode();b=check(root/new,proof[key]['new']).decode();c=a
 for before,after in proof[key]['edits']:
  assert c.count(before)==1;c=c.replace(before,after,1)
 assert c==b
 for before,after in reversed(proof[key]['edits']):
  assert c.count(after)==1;c=c.replace(after,before,1)
 assert c==a
old_i=(S/'unix-before/inputs.json').read_text();new_i=(root/'inputs.json').read_text();a=old_i
for r in proof['inputs']['changes']:
 for k in ('blob','bytes','sha256'):
  before=json.dumps(r['before'][k]);after=json.dumps(r['after'][k])
  if before!=after:
   assert a.count(before)==1;a=a.replace(before,after,1)
assert a==new_i
idx=json.loads(new_i);assert len(idx['inputs'])==28
for r in idx['inputs']:check(root/r['path'],r)
carrier=D['compatible_carrier_replacement'];before=S.parent/'follow56-source-stage/exact-source'/carrier['path'];after=S/'overlay'/carrier['path']
cp=json.loads((root/'proof/carrier-exact-inverse.json').read_bytes());a=check(before,cp['old']).decode();b=check(after,cp['new']).decode();c=a
for x,y in cp['edits']:
 assert c.count(x)==1;c=c.replace(x,y,1)
assert c==b
for x,y in reversed(cp['edits']):
 assert c.count(y)==1;c=c.replace(y,x,1)
assert c==a
prior=S/'active-selfbuild-only.json'
if not prior.exists():prior.write_bytes((S/'active.json').read_bytes())
active=json.loads(prior.read_bytes());assert len(active)==1128
lookup={r['path']:r for r in active};r=next(r for r in rows if r['path']==carrier['path']);lookup[r['path']]={k:r.get(k,r.get('blob') if k=='gitsha' else None) for k in ('path','mode','bytes','gitsha','sha256')}
assert len(D['active_python_paths'])==25
for path in D['active_python_paths']:
 assert path not in lookup;r=next(r for r in rows if r['path']==path);lookup[path]={k:r.get(k,r.get('blob') if k=='gitsha' else None) for k in ('path','mode','bytes','gitsha','sha256')}
active=sorted(lookup.values(),key=lambda r:r['path']);assert len(active)==1153
(S/'active.json').write_text(json.dumps(active,indent=2)+'\n')
manifest=json.loads((S/'manifest.json').read_bytes());manifest['files']=active;manifest['selection']='FOLLOW57: preserve all1110 prior active paths; update two existing carriers; add18 true-self-rebuild and25 Unix header-cache runtime source paths. Fourteen new self-rebuild stages and original Unix12+8+8 cases require fresh formal execution under unchanged stage budgets. Historical source paths and failures remain. Source syntax grants no native or whole-stack qualification.'
(S/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n')
source=(S/'check_source_and_workflow.py').read_text();edits=[('1128','1153'),('"updated_active_sources":1','"updated_active_sources":2'),('"added_active_sources":18','"added_active_sources":43'),('hia-follow57-root-source-workflow-check-r1','hia-follow57-root-source-workflow-check-r2'),('source-and-workflow-check.json','source-and-workflow-check-r2.json')]
bound=source
for a,b in edits:
 assert a in bound;bound=bound.replace(a,b)
for a,b in reversed(edits):bound=bound.replace(b,a)
assert bound==source
bound=source
for a,b in edits:bound=bound.replace(a,b)
exec(compile(bound,str(S/'check_source_and_workflow.py')+'[full1153_inventory_binding]', 'exec'),{'__name__':'__main__'})
report={'schema':'hia-follow57-Unix-headercache-root-source-check-r1','status':'PASS_SOURCE_ONLY','source_rows':37,'all_size_mode_SHA_Git_checked':True,'runtime_input_files':28,'only_issuer_and_builder_input_identities_changed':True,'builder_and_CI_complete_inverse':True,'carrier_three_pin_strings_complete_inverse':True,'old_fallback_and_selector_exact':True,'added_active_sources':25,'full_current_active_sources':1153,'target_executions':0,'full_unixOpen_closed':False}
(S/'unix-source-check.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,sort_keys=True))
