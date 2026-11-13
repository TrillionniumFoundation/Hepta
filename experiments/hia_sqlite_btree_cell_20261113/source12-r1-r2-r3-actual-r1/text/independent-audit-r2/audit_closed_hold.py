"""Independent read-only audit after the exact Source12 owner has closed.
No repository imports, generator calls, VM evaluation, C or native execution.
This reader preserves the actual nonzero qualification and independently audits its raw evidence.
"""
from pathlib import Path
import hashlib, json, math, os, stat, struct, traceback
PLAN=Path('/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-source-r1')
ACTUAL=Path('/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-source12-actual-r2')
OUT=Path('/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-source12-actual-audit-r2')
REQ_SHA='ebdb6023995fe43b21fe0bf8bd36b6c3966a30a8e8d2a75371c6b4e9b3d696e5'
OWNER_SHA='36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2'
COUNTS=[0,72,36,108,22,14,24,14,30,16,3,0]
REJECTIONS={0xfffffffd,0xfffffffe,0xfffffffc,0xfffffffb,0xfffffffa,0xfffffff9}
R={'schema':'hia.sqlite-btree-cell.source12-independent-actual-readback.v1','status':'HOLD','qualification_repeated':False,'checks':0,'errors':[]}
READS={}
def need(value,message):
 R['checks']+=1
 if not value:raise ValueError(message)
def ident(s):
 return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def pin_bytes(raw):
 return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
def read(p,maximum=64<<20):
 p=Path(p);need(p.is_absolute() and p.resolve(strict=True)==p,'absolute no-link file')
 before=p.lstat();need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size<=maximum,'bounded singleton regular input')
 with os.fdopen(os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC),'rb') as f:
  need(ident(os.fstat(f.fileno()))==ident(before),'fd matches name')
  raw=f.read();need(ident(os.fstat(f.fileno()))==ident(before),'fd stable during read')
 need(len(raw)==before.st_size and ident(p.lstat())==ident(before),'name stable after complete read')
 row={'path':str(p),**pin_bytes(raw),'identity':ident(before)}
 READS[str(p)]=row
 return raw,row
def js(p,maximum=64<<20):
 raw,pin=read(p,maximum)
 def pairs(values):
  d={}
  for k,v in values:
   if k in d:raise ValueError('duplicate JSON key')
   d[k]=v
  return d
 return json.loads(raw,object_pairs_hook=pairs),raw,pin
def bound(row):
 raw,p=read(row['path'])
 need(all(p[k]==row[k] for k in ('path','bytes','sha256','identity')),'frozen file binding: '+row['path'])
 return p
def walk_namespace(root):
 result={}
 for base,dirs,names in os.walk(root,followlinks=False):
  for n in dirs:need(stat.S_ISDIR((Path(base)/n).lstat().st_mode),'no linked directory')
  for n in names:
   path=Path(base)/n;raw,pin=read(path,64<<20)
   result[str(path.relative_to(root))]=(raw,pin)
 return result
def varint(raw,offset,end):
 x=0
 for j in range(9):
  need(offset<end,'complete successful varint');b=raw[offset];offset+=1
  if j==8:return (x<<8)|b,offset
  x=(x<<7)|(b&127)
  if b<128:return x,offset
 raise AssertionError('unreachable')
def expected_success(raw,control):
 need(len(control)==64,'successful command extent')
 magic,op,size,reserved,page,index,pages,zero=struct.unpack('<8Q',control)
 need(magic==int.from_bytes(b'HIABTC01','little') and op==1 and zero==0,'successful command constants')
 need(size in (512,1024,2048,4096,8192,16384,32768,65536) and len(raw)==size,'successful exact page size')
 need(0<=reserved<=255 and size-reserved>=480 and 1<=page<=pages<=4294967294,'successful page control bounds')
 usable=size-reserved
 def be(at,n):
  need(0<=at<=usable-n,'full big endian scalar span')
  return int.from_bytes(raw[at:at+n],'big')
 h=100 if page==1 else 0
 if page==1:
  need(raw[:16]==b'SQLite format 3\0','database magic')
  encoded=be(16,2);need((65536 if encoded==1 else encoded)==size and raw[20]==reserved,'database size and reserve')
  need(raw[18] in (1,2) and raw[19] in (1,2) and raw[21:24]==bytes((64,32,32)),'header versions and fractions')
  need(1<=be(44,4)<=4 and 1<=be(56,4)<=3 and raw[72:92]==bytes(20),'schema encoding reserved header')
  if be(24,4)==be(92,4) and be(28,4)!=0:need(be(28,4)==pages,'valid in-header database size')
 kind=raw[h];need(kind in (2,5,10,13) and (h!=100 or kind in (5,13)),'declared page kind')
 count,content=be(h+3,2),be(h+5,2);content=65536 if content==0 else content
 ptr=h+(12 if kind in (2,5) else 8)
 if kind in (2,5):need(1<=be(h+8,4)<=pages and be(h+8,4)!=page,'right child bound')
 need(content<=usable and ptr+count*2<=content and raw[h+7]<=60,'pointer-array geometry')
 free=be(h+1,2);need(free==0 or content<=free<=usable-4,'first freeblock position')
 need(index<count,'selected index')
 offset=be(ptr+index*2,2);need(content<=offset<=usable-4,'selected cell offset')
 at=offset;child=0
 if kind in (2,5):
  child=be(at,4);need(1<=child<=pages and child!=page,'left child bound');at+=4
 payload=0
 if kind!=5:
  payload,end=varint(raw,at,usable);need(end-at<=5 and payload<=2147483647,'payload width and numerical domain');at=end
 key=payload
 if kind in (5,13):key,at=varint(raw,at,usable)
 local=payload_at=overflow=overflow_at=overflow_pages=overflow_last=0
 end=at
 if kind!=5:
  payload_at=at;maxlocal=usable-35 if kind==13 else (usable-12)*64//255-23
  minlocal=(usable-12)*32//255-23
  local=payload
  if payload>maxlocal:
   surplus=minlocal+(payload-minlocal)%(usable-4);local=surplus if surplus<=maxlocal else minlocal
  need(local<=usable-at,'complete local payload')
  end=at+local
  if payload>local:
   overflow_at=end;overflow=be(end,4);need(1<=overflow<=pages and overflow!=page,'overflow page bound');end+=4
   overflow_pages,overflow_last=divmod(payload-local,usable-4)
   if overflow_last:overflow_pages+=1
   else:overflow_last=usable-4
  end=max(end,offset+4)
 need(end<=usable,'complete cell and padding')
 return struct.pack('<16Q',page,kind,usable,count,index,offset,end-offset,payload_at,payload,local,child,key,overflow,overflow_at,overflow_pages,overflow_last)

def inspect():
 q,qraw,qpin=js(PLAN/'REQUEST-r2.json')
 need(qpin['sha256']==REQ_SHA and q['qualification_seconds']==180 and q['cleanup_seconds']==3,'exact request and budget')
 need(q['actual_source12_runs']==0 and len(q['inputs'])==46 and len(q['expected_ids'])==12,'frozen request population')
 need(list(q['expected_vm_by_id'].values())==COUNTS and q['expected_vm_returns']==339,'frozen VM population')
 need(q['output_root']==str(ACTUAL),'exact actual namespace')
 old,oldraw,oldpin=js(PLAN/'REQUEST.json')
 need(oldpin['sha256']=='79cef7743537967dc89a325bb365636acfd914c6b8b91daa7f16dedce8fe1294','original R1 request preserved')
 need(q['inputs'][:43]==old['inputs'] and len(old['inputs'])==43,'all R1 physical inputs retained unchanged')
 differences={k for k in set(q)|set(old) if q.get(k)!=old.get(k)}
 need(differences=={'inputs','output_root','prior_pre_owner_failure'},'only explicit R2 request changes')
 R['r1_pre_owner_failure_preserved']=q['prior_pre_owner_failure']

 # Read only supervisor-produced receipt/request/wrapper until closure is proven.
 life,lraw,lp=js(ACTUAL/'owner.json',4<<20)
 req,rraw,rp=js(ACTUAL/'owner.json.request.json',4<<20)
 wrap,wraw,wp=js(ACTUAL/'OWNER-WRAPPER.json',4<<20)
 expected_cmd=[q['runtime']['executable'],'-I','-S','-B',str(PLAN/'control/source12_r2.py'),'--request',str(PLAN/'REQUEST-r2.json'),'--sha256',REQ_SHA,'--worker']
 need({k:v for k,v in wrap.items() if k not in ('supervisor_returncode','receipt_sha256')}==life,'full wrapper is original life plus two producer fields')
 need(wrap['receipt_sha256']==lp['sha256'] and life['request_sha256']==rp['sha256'],'original owner hashes')
 need(req['command']==expected_cmd and req['cwd']==str(PLAN) and req['env']==q['environment'],'exact worker argv/cwd/env')
 for k,n in [('stdout_path','stdout.log'),('stderr_path','stderr.log'),('receipt_path','owner.json')]:
  need(req[k]==str(ACTUAL/n),'exact original output path')
 need(req['schema']==life['schema']==wrap['schema']=='hepta.hia.selfhost-process-owner.v1','owner schemas')
 need(req['implementation_sha256']==life['implementation_sha256']==OWNER_SHA,'original owner implementation')
 need(req['qualification_seconds']==life['qualification_seconds']==180 and req['cleanup_seconds']==life['cleanup_seconds']==3,'owner original budgets')
 need(type(req['parent_pid']) is int and req['parent_pid']==life['parent_pid'] and req['parent_pid']>0,'actual owner parent PID')
 need(req['deadline_ns']-req['started_ns']==180000000000,'exact actual deadline')
 c=life['cleanup']
 closed=(life['subreaper_enabled'] is True and life['qualification_started'] is True
  and all(c.get(k) is True for k in ('attempted','complete','observed_echild','leader_reaped'))
  and c.get('deadline_exceeded') is False and c.get('remaining_direct_children')==[] and c.get('errors')==[])
 R['owner_closed']=closed
 need(closed,'ECHILD is required before child reads')
 # From here, full child evidence is closed and may be read regardless of status.
 original=walk_namespace(ACTUAL);R['actual_files']=len(original);R['actual_bytes']=sum(len(x[0]) for x in original.values())
 R['actual_inventory']=[{'name':n,**p} for n,(raw,p) in sorted(original.items())]
 events=life['events'];kinds=[e['kind'] for e in events]
 natural=(wrap['supervisor_returncode']==life['returncode']==1 and life['status']=='QUALIFICATION_FAILED'
  and life['timed_out'] is False and life['exit_observed_before_deadline'] is True
  and life['event_overflow'] is False and life['interrupted_signals']==[] and life.get('owner_error') is None
  and kinds==['qualification_started','owned_child_observed','qualification_exit_observed','owned_child_reaped'])
 R['owner_natural_exit_nonzero']=natural
 R['owner_success']=False
 need(natural,'source qualification ended naturally with the observed original nonzero result')
 pid=life['qualification_pid'];need(type(pid) is int and pid>0,'worker PID type')
 need(all(e['pid']==pid for e in events),'all four events bind same worker')
 need([e['monotonic_ns'] for e in events]==sorted(e['monotonic_ns'] for e in events),'ordered original events')
 need(req['started_ns']<=events[0]['monotonic_ns']<=events[2]['monotonic_ns']<req['deadline_ns'],'actual qualification inside deadline')
 need(events[1]['start_ticks']==events[3]['start_ticks'] and events[3]['returncode']==1 and events[2]['si_status']==1,'stable reaped leader')
 need(0<=c['elapsed_ns']<=3000000000,'actual cleanup bound')
 R['owner_start_to_exit_seconds']=(events[2]['monotonic_ns']-events[0]['monotonic_ns'])/1e9
 R['owner_start_to_reap_seconds']=(events[3]['monotonic_ns']-events[0]['monotonic_ns'])/1e9
 need(original['REQUEST.original.json'][0]==qraw,'actual original request full bytes')
 before=json.loads(original['INPUTS-BEFORE.json'][0]);after=json.loads(original['INPUTS-AFTER.json'][0])
 need(before==after==q['inputs'],'parent 46 input snapshots exact')
 fixed=[bound(row) for row in q['inputs']];R['fixed_inputs']=len(fixed)
 for n in ('tests/INPUTS-BEFORE.json','tests/INPUTS-AFTER.json'):
  need(json.loads(original[n][0])==q['inputs'],'worker 46 input snapshots exact')
 catalog=json.loads(read(q['source_catalog'])[0]);sb=json.loads(original['tests/SOURCE-BEFORE.json'][0]);sa=json.loads(original['tests/SOURCE-AFTER.json'][0])
 need(sb==sa==catalog and len(catalog)==1686,'source snapshots exact complete catalog')
 total=0
 for name,row in catalog.items():
  need(row['path']==str(Path(q['source_root'])/name) and '..' not in Path(name).parts and not name.startswith('/'),'source path binding')
  p=bound(row);need(p['git_blob']==row['git_blob'],'source full Git bytes');total+=p['bytes']
 need(total==40890650,'source bytes denominator')
 physical=set()
 for parent,dirs,names in os.walk(q['source_root'],followlinks=False):
  for n in dirs:need(stat.S_ISDIR((Path(parent)/n).lstat().st_mode),'source dir regular')
  for n in names:physical.add(str((Path(parent)/n).relative_to(q['source_root'])))
 need(physical==set(catalog),'complete physical source namespace')
 R['source']={'files':len(catalog),'bytes':total,'full_bytes_and_nine_field_identity_preserved':True}
 inv=json.loads(original['ORIGINALS.json'][0]);need(inv['after_bound_ECHILD'] is True,'original inventory closure flag')
 named={Path(r['path']).relative_to(ACTUAL).as_posix():r for r in inv['files']}
 need(set(named)==set(original)-{'ORIGINALS.json','FINAL.json'},'complete original output list')
 for name,row in named.items():
  p=original[name][1];need(all(p[k]==row[k] for k in ('path','bytes','sha256','identity')),'full original pin '+name)
 need(inv['bytes']==sum(len(original[n][0]) for n in named) and len(named)<=q['output_limits']['files'] and inv['bytes']<=q['output_limits']['bytes'],'original output quotas unchanged')
 final=json.loads(original['FINAL.json'][0]);report=json.loads(original['tests/REPORT.json'][0])
 need(final['schema']=='hia.sqlite-btree-cell.source12-final.v1' and final['status']==report['status']=='HOLD','final/worker actual scope')
 need(final['closed'] is True and final['natural'] is False and len(final['errors'])==1 and final['request_sha256']==REQ_SHA,'final closure request')
 need(all(original['ORIGINALS.json'][1][k]==final['originals'][k] for k in ('path','bytes','sha256','identity')),'final binds full originals')
 need(report['schema']=='hia.sqlite-btree-cell.source12-report.v1','worker schema')
 for k in ('expected_ids','loaded_ids','actual_ids'):need(report[k]==q['expected_ids'],'all twelve IDs '+k)
 need(report['success_ids']==q['expected_ids'][1:],'eleven successes preserve original first cap failure')
 need(len(report['failures'])==1 and report['failures'][0]['id']==q['expected_ids'][0] and 'AssertionError: 17 not less than or equal to 16' in report['failures'][0]['detail'],'original exact cap assertion')
 R['qualification_status']='HOLD'
 R['original_qualification_failures']=report['failures']
 R['original_final_errors']=final['errors']
 need(report['tests_run']==12 and report['inputs_unchanged'] is True and report['exception'] is None,'complete tests')
 for k in ('errors','skips','expected_failures','unexpected_successes','loader_errors','denied_effects','secondary_errors'):need(report[k]==[],'empty worker failures '+k)
 for k in ('native_executed','C_compiler_or_oracle_executed','database_opened','network_used'):need(report[k] is False,'limited scope '+k)
 expected_imports={r['path']:r for r in q['inputs']};expected_imports.update({r['path']:r for r in catalog.values()})
 need(any(r['module']==q['test_module'] for r in report['imports']),'exact test module imported')
 for mod in report['imports']:
  if mod.get('namespace_only') is True:need(mod['module']=='tools','only original tools namespace')
  else:
   p=mod['source'];need(p['path'] in expected_imports and all(p[k]==expected_imports[p['path']][k] for k in p),'bound imported project file')
 assembly=original['tests/sqlite_btree_cell.hiaasm'][0];document=json.loads(original['tests/CORE.json'][0]);fs=document['functions'];blocks=[b for f in fs for b in f['blocks']]
 argument_lists=[]
 def strings(value,path=''):
  if isinstance(value,dict):
   for k,v in value.items():
    if k in ('args','params') and isinstance(v,list):
     argument_lists.append({'path':path+'/'+k,'count':len(v),'items':v})
    yield from strings(v,path+'/'+k)
  elif isinstance(value,list):
   for i,v in enumerate(value):yield from strings(v,path+'/'+str(i))
  elif isinstance(value,str) and value.startswith('v') and value[1:].isdigit():yield int(value[1:])
 maximum_ssa=max(strings(document))
 metrics={'assembly_bytes':len(assembly),'assembly_lines':len(assembly.decode().split('\n')),'functions':len(fs),'total_blocks':len(blocks),'blocks_per_function':max(len(f['blocks']) for f in fs),'operations':sum(len(b['ops']) for b in blocks),'maximum_ssa':maximum_ssa,'arguments':max(r['count'] for r in argument_lists),'returns':max(len(f['returns']) for f in fs)}
 need(metrics['functions']==10,'ten exact authored functions')
 violations=[{'cap':k,'actual':v,'limit':q['original_caps'][k]} for k,v in metrics.items() if v>q['original_caps'][k]]
 R['actual_caps']=metrics;R['actual_cap_violations']=violations
 bad=[r for r in argument_lists if r['count']>q['original_caps']['arguments']]
 need(len(bad)==17 and metrics['arguments']==17 and all(x['path'].startswith('/functions/3/') for x in bad),'complete original seventeen arity violations')
 R['oversized_argument_or_parameter_lists']=bad
 need(violations==[{'cap':'arguments','actual':17,'limit':16}],'independent full caps preserve sole observed failure')

 raw=json.loads(original['tests/VM-RAW.json'][0]);calls=raw['calls']
 need(raw['schema']=='hia.sqlite-btree-cell.source-vm-raw.v1' and raw['native_executed'] is False and raw['compiler_executed'] is False,'VM-only raw scope')
 need(len(calls)==339,'all original VM returns')
 expected_order=[name for name,count in q['expected_vm_by_id'].items() for _ in range(count)]
 need([r['case'] for r in calls]==expected_order,'per-method actual order and counts')
 status_counts={};success=refusals=0;largest=0
 for row in calls:
  need(row['actual_returned'] is True and type(row['status']) is int and 'exception_type' not in row,'actual VM return')
  spans={}
  for k in ('source_before_hex','source_after_hex','output_before_hex','output_after_hex','control_before_hex','control_after_hex'):
   b=bytes.fromhex(row[k]);need(b.hex()==row[k],'canonical full raw span');spans[k]=b
  need(spans['source_before_hex']==spans['source_after_hex'] and spans['control_before_hex']==spans['control_after_hex'],'immutable VM input/control')
  a,b=spans['output_before_hex'],spans['output_after_hex'];need(len(a)==len(b),'output extent preserved')
  s=row['status'];status_counts[str(s)]=status_counts.get(str(s),0)+1;largest=max(largest,len(spans['source_before_hex']))
  if s in REJECTIONS:need(a==b,'refusal has zero output writes');refusals+=1
  else:
   need(s==128 and len(a)==128,'valid fixed success envelope')
   expected=expected_success(spans['source_before_hex'],spans['control_before_hex'])
   need(b==expected,'all sixteen independent selected-cell descriptor words')
   success+=1
 need(success==253 and refusals==86 and largest==65536,'complete selected-cell raw domain')
 need(status_counts=={'128':253,'4294967291':44,'4294967293':23,'4294967294':11,'4294967292':3,'4294967289':2,'4294967290':3},'all fixed fixture return classes')
 vm=report['VM'];need(vm['calls']==339 and vm['by_id']==q['expected_vm_by_id'] and vm['whole_raw_buffers_read'] is True,'worker VM declared population matches actual')
 need(all(original['tests/VM-RAW.json'][1][k]==vm['pin'][k] for k in ('path','bytes','sha256','identity')),'worker VM full raw pin')
 # A second read verifies the entire observed actual namespace remained unchanged.
 for name,(raw0,pin0) in original.items():
  raw1,pin1=read(ACTUAL/name,64<<20);need(raw1==raw0 and pin1==pin0,'actual immutable during independent audit')
 R['VM']={'calls':339,'successes':success,'refusals':refusals,'status_counts':status_counts,'full_spans_independently_read':True,'successful_cell_descriptors_independently_decoded':True,'refusals_have_zero_writes':True,'maximum_raw_input_bytes':largest}
 R['expected_ids']=q['expected_ids'];R['worker_seconds']=report['seconds'];R['status']='SOURCE12_BTREE_CELL_HOLD_ORIGINALS_VERIFIED'
 R['readback_complete']=True
 R['limits']='No native image, C oracle, SQL, pager, whole-page/tree integrity, default AgentStore, installation or whole-project qualification.'
def main():
 try:inspect()
 except BaseException as e:R['errors'].append({'type':type(e).__name__,'traceback':traceback.format_exc()})
 R['unique_files_read']=len(READS)
 raw=(json.dumps(R,sort_keys=True,indent=2)+'\n').encode()
 with (OUT/'AUDIT.json').open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
 print(json.dumps({'status':R['status'],'checks':R['checks'],'errors':R['errors'],'audit':pin_bytes(raw)}))
 return 0 if R.get('readback_complete') is True and R['errors']==[] else 1
if __name__=='__main__':raise SystemExit(main())
