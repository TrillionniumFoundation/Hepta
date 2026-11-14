"""Independent stdlib-only readback of one actual completed op13 binding.

No project import, binder, source copy, child, recovered binary, test or HIA/VM
execution. Actual BOUND/RESULT hashes are explicit inputs, never guessed.
"""
from __future__ import annotations
import argparse,ast,hashlib,json,os,stat,time,traceback
from pathlib import Path
AUTHOR=Path('/tmp/hia-op13-execution-author-r1-dda7')
SCOPE=Path('/dev/shm/hia-op13-execution-r1-dda7')
PLAN_PIN={'bytes':24783,'mode':'100644','git_blob':'30e3ad5c277b29164bfdef78d9963afd5e0d98b7','sha256':'9d4aae230b7dabda2e7e761f9454bdef11a4ed91b4c47729e0f5c9e423ab2ae1'}
TREE='821bb0ac9c4ce7a7648c1c34ef91406e3a45fbcb'
SCHEMA='hepta.hia.op13.post-reset.execution.v1'
FIELDS=('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_nlink')
LIMITS={'owner_seconds':180,'cleanup_seconds':3,'compile_seconds':20,'native_capacity':1048576,'vm_steps':10000000,'vm_heap':8388608,'vm_call_depth':128}
READS=[]
SEEN={}
def require(value,message):
 if not value:raise AssertionError(message)
def seven(value):return {k:getattr(value,k)for k in FIELDS}
def pin(raw,mode='100644'):
 return {'bytes':len(raw),'mode':mode,'sha256':hashlib.sha256(raw).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
def pairs(items):
 result={}
 for k,v in items:require(type(k)is str and k not in result,'duplicate/nonstring JSON key');result[k]=v
 return result
def decode(raw):
 def reject(value):raise ValueError('nonfinite JSON value: '+value)
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=reject)
def read(path,role,*,expected=None,expected_stat=None,maximum=None):
 path=Path(path);require(path.is_absolute()and'..'not in path.parts,'absolute input required');named=path.lstat()
 require(stat.S_ISREG(named.st_mode)and named.st_nlink==1,'ordinary unique input required: '+str(path))
 if expected_stat is not None:require(seven(named)==expected_stat,'before stat differs: '+str(path))
 if maximum is None:maximum=expected['bytes']if expected is not None else 16<<20
 require(0<=named.st_size<=maximum,'bounded metadata/input extent differs')
 fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  held=os.fstat(fd);require(seven(held)==seven(named)==seven(path.lstat())and stat.S_ISREG(held.st_mode),'held/named differs')
  parts=[];remaining=held.st_size+1
  while remaining:
   part=os.read(fd,min(1048576,remaining))
   if not part:break
   parts.append(part);remaining-=len(part)
  raw=b''.join(parts)
  require(len(raw)==held.st_size and seven(os.fstat(fd))==seven(held)==seven(path.lstat()),'complete read changed')
 finally:os.close(fd)
 actual=pin(raw,'100755'if held.st_mode&0o111 else'100644')
 if expected is not None:require(actual==expected,'full pin differs: '+str(path))
 row={'path':str(path),'pin':actual,'stat':seven(held)}
 if str(path)in SEEN:require(SEEN[str(path)]==row,'repeated input identity changed')
 SEEN[str(path)]=row;READS.append({'role':role,**row});return raw,row
def fixed(row,role):
 require(type(row)is dict and set(row)=={'path','pin','stat'}and set(row['stat'])==set(FIELDS),'complete descriptor required')
 return read(row['path'],role,expected=row['pin'],expected_stat=row['stat'])[0]
def inventory(root):
 root=Path(root);rows={'.':seven(root.lstat())};require(stat.S_ISDIR(rows['.']['st_mode']),'ordinary root required')
 def walk(directory,prefix):
  for e in sorted(os.scandir(directory),key=lambda e:e.name):
   n=prefix+e.name;s=e.stat(follow_symlinks=False)
   require(stat.S_ISDIR(s.st_mode)or(stat.S_ISREG(s.st_mode)and s.st_nlink==1),'unknown/aliased member: '+n)
   rows[n]=seven(s)
   if stat.S_ISDIR(s.st_mode):walk(Path(e.path),n+'/')
 walk(root,'');return rows
def parents(files):
 rows={'.'}
 for name in files:
  parts=name.split('/');require(all(p and p not in('.','..')for p in parts),'bad relative path')
  for i in range(1,len(parts)):rows.add('/'.join(parts[:i]))
 return rows
def tree(files):
 root={}
 for name,row in files.items():
  node=root;parts=name.split('/');require(all(p and p not in('.','..')for p in parts),'bad tree path')
  for part in parts[:-1]:node=node.setdefault(part,{})
  require(parts[-1]not in node,'duplicate tree path');node[parts[-1]]=row
 def visit(node):
  rows=[]
  for name,row in node.items():
   if'git_blob'in row:rows.append((name.encode(),row['mode'].encode(),bytes.fromhex(row['git_blob'])))
   else:rows.append(((name+'/').encode(),b'40000',visit(row)))
  raw=b''.join(m+b' '+n.rstrip(b'/')+b'\0'+s for n,m,s in sorted(rows))
  return hashlib.sha1(b'tree '+str(len(raw)).encode()+b'\0'+raw).digest()
 return visit(root).hex()
def directory_chain(path):
 rows=[]
 for node in reversed([Path(path),*Path(path).parents]):
  s=node.lstat();require(stat.S_ISDIR(s.st_mode),'ordinary directory ancestor required')
  rows.append({'path':str(node),'dev':s.st_dev,'ino':s.st_ino,'mode':s.st_mode,'uid':s.st_uid,'gid':s.st_gid})
 return rows
def guard_chain(rows):
 for row in rows:
  s=Path(row['path']).lstat()
  require(stat.S_ISDIR(s.st_mode)and row=={'path':row['path'],'dev':s.st_dev,'ino':s.st_ino,'mode':s.st_mode,'uid':s.st_uid,'gid':s.st_gid},'directory authority changed')
def runtime_record(row):
 s=row['stat'];p=row['pin']
 return {'path':row['path'],'bytes':p['bytes'],'sha256':p['sha256'],'mode':stat.S_IMODE(s['st_mode']),'device':s['st_dev'],'inode':s['st_ino'],'mtime_ns':s['st_mtime_ns'],'ctime_ns':s['st_ctime_ns']}
def write(path,value):
 raw=(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
 with Path(path).open('xb')as stream:stream.write(raw)
 require(Path(path).read_bytes()==raw,'reader evidence write differs')

def verify(bound_sha,result_sha,output):
 output=Path(output)
 require(output.is_absolute()and'..'not in output.parts and not os.path.lexists(output),'one new explicit reader output required')
 protected=(AUTHOR,SCOPE,Path('/tmp/hia-r8-source-recovery-20261114-r1'),Path('/tmp/hia-runtime-artifact-recovery-20261114-dda7'))
 require(all(output!=p and not output.is_relative_to(p)for p in protected),'reader output overlaps protected data')
 require(output.parent.is_dir(),'reader output parent must already exist')
 require(all(type(x)is str and len(x)==64 and all(c in'0123456789abcdef'for c in x)for x in(bound_sha,result_sha)),'actual result/plan SHA required')
 output.mkdir(mode=0o700)
 report={'schema':'hepta.hia.op13.independent-binding-readback.v1','status':'FAIL','started_ns':time.monotonic_ns(),'project_imports':0,'products':0,'source_copy':0,'binder_execution':0,'runtime_execution':0,'bound_plan_sha256':bound_sha,'binding_result_sha256':result_sha,'all_frames_retired':False,'whole':False,'current_cold':False}
 try:
  author_raw,author_desc=read(AUTHOR/'PREPARATION-PLAN.json','frozen-author-plan',expected=PLAN_PIN);author=decode(author_raw)
  require(author['schema']==SCHEMA+'.preparation'and author['state']=='AUTHORING_ONLY_AWAITING_ROOT_AUTHORIZATION'and author['scope']==str(SCOPE)and author['source_tree']==TREE and author['source_files']==3210 and author['limits']==LIMITS and author['storage_floor']==1073741824 and not author['missing_sources'],'original complete author scope/limits differ')
  for name,row in author['controls'].items():fixed(row,'control:'+name)
  for name,row in author['provenance'].items():fixed(row,'provenance:'+name)
  for name in('compiler','template'):fixed(author[name],name)
  require(author['compiler']['pin']=={'bytes':673413,'mode':'100644','git_blob':'315c6b5f36a1ec679deb68abdca24bd4d1bef9f8','sha256':'bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0'},'ordinary B3 changed')
  guard_chain(author['parent_ancestors']);guard_chain(author['author_ancestors'])
  scope_before=inventory(SCOPE);root=SCOPE/'source';source_before=inventory(root)
  require(stat.S_IMODE(scope_before['.']['st_mode'])==0o700 and not os.path.lexists(SCOPE/'attempt-r1'),'scope mode or absent product attempt differs')
  free=os.statvfs(SCOPE).f_bavail*os.statvfs(SCOPE).f_frsize;require(free>=1073741824,'original actual-filesystem 1GiB floor not met');report['current_free_before']=free
  bound_raw,bound_desc=read(SCOPE/'BOUND-PLAN.json','actual-bound-plan');result_raw,result_desc=read(SCOPE/'BINDING-RESULT.json','actual-binding-result')
  require(hashlib.sha256(bound_raw).hexdigest()==bound_sha and hashlib.sha256(result_raw).hexdigest()==result_sha,'independently supplied actual SHA differs')
  bound=decode(bound_raw);result=decode(result_raw)
  carry=('controls','provenance','compiler','runtime_map','limits','storage_floor','author_ancestors','template','component_sources','authority_names')
  additions={'schema','state','scope','source','source_tree','source_map','source_state','attempt','scope_ancestors','preparation_plan','copies','runtime'}
  require(set(bound)==set(carry)|additions and all(bound[k]==author[k]for k in carry),'BOUND plan changed frozen inputs or fields')
  require(bound['schema']==SCHEMA and bound['state']=='BOUND_AWAITING_ROOT_AUTHORIZATION'and bound['scope']==str(SCOPE)and bound['source']==str(root)and bound['attempt']==str(SCOPE/'attempt-r1')and bound['source_tree']==TREE,'actual bound source domain differs')
  require(bound['preparation_plan']==author_desc and fixed(bound['preparation_plan'],'bound-preparation-plan')==author_raw,'bound preparation authority differs')
  require(bound['scope_ancestors']==directory_chain(SCOPE),'new scope ancestor binding differs');guard_chain(bound['scope_ancestors'])
  require(result['schema']==SCHEMA+'.binding-result'and result['status']=='BOUND_NOT_EXECUTED'and result['products_executed']==0 and result['current_cold']is False and result['default']is False and result['whole']is False and result['copy_rows']==result['source_files']==3210 and result['source_tree']==TREE and result['free_bytes_before']>=1073741824 and result['next_launch_requires_root_review']is True and type(result['started_ns'])is int and type(result['finished_ns'])is int and result['finished_ns']>=result['started_ns']and not any(k in result for k in('traceback','terminal_guard_error','error')),'binding not a successful complete preparation')
  require(result['preparation_plan']==author_desc and result['plan']==bound_desc and fixed(result['plan'],'result-bound-plan')==bound_raw,'actual result plan authority differs')
  require(result['source_map']==bound['source_map']and result['source_state']==bound['source_state']and result['runtime']==bound['runtime'],'actual binding result fields differ')
  map_raw=fixed(bound['source_map'],'new-source-map');source_map=decode(map_raw)
  require(bound['source_map']['path']==str(SCOPE/'SOURCE-MAP.json')and map_raw==fixed(author['projected_source_map'],'projected-source-map')and len(source_map)==3210 and tree(source_map)==TREE,'complete source map/tree differ')
  state=decode(fixed(bound['source_state'],'new-source-state'))
  require(bound['source_state']['path']==str(SCOPE/'SOURCE-STATE.json')and state==source_before,'copied source state differs')
  require({n for n,s in state.items()if stat.S_ISREG(s['st_mode'])}==set(source_map)and {n for n,s in state.items()if stat.S_ISDIR(s['st_mode'])}==parents(source_map),'complete source file/directory pathset differs')
  require(stat.S_IMODE(state['.']['st_mode'])==0o700,'new source root mode differs')
  scope_files={n for n,s in scope_before.items()if stat.S_ISREG(s['st_mode'])};scope_dirs={n for n,s in scope_before.items()if stat.S_ISDIR(s['st_mode'])}
  root_files={'COPY-ROWS.jsonl','COPIES.json','SOURCE-MAP.json','SOURCE-STATE.json','BOUND-PLAN.json','BINDING-RESULT.json'}
  require(scope_files==root_files|{'source/'+n for n in source_map}and scope_dirs=={'.','source'}|{'source/'+n for n in parents(source_map)if n!='.'},'complete binding scope pathset differs')
  origins=decode(fixed(author['origin_rows'],'3210-original-source-authorities'));copies=decode(fixed(bound['copies'],'actual-complete-copies'))
  require(bound['copies']['path']==str(SCOPE/'COPIES.json')and len(origins)==len(copies)==3210,'copy inventory extent/path differs')
  journal_raw,_=read(SCOPE/'COPY-ROWS.jsonl','actual-copy-journal',maximum=16<<20)
  require(journal_raw.endswith(b'\n')and not any(not line for line in journal_raw.splitlines()),'copy journal incomplete')
  journal=[decode(line)for line in journal_raw.splitlines()]
  require(journal==copies and [r['relative']for r in origins]==[r['relative']for r in copies]==sorted(source_map),'actual copy order differs')
  old_inodes=set();new_inodes=set();source_rows=[]
  for origin,copy in zip(origins,copies,strict=True):
   name=origin['relative'];require(set(copy)=={'relative','origin','created'}and copy['origin']==origin['descriptor'],'copy origin differs')
   require(origin['expected']==origin['descriptor']['pin']==copy['created']['pin']==source_map[name],'copy expected/pin differs')
   require(copy['created']['path']==str(root/name)and copy['created']['stat']==state[name],'new copy path/stat differs')
   before=fixed(origin['descriptor'],'source-origin:'+name);after=fixed(copy['created'],'source-copy:'+name)
   require(before==after,'copied bytes not exactly original bytes')
   oldstat=origin['descriptor']['stat'];newstat=copy['created']['stat']
   require(stat.S_IMODE(oldstat['st_mode'])==stat.S_IMODE(newstat['st_mode'])==int(source_map[name]['mode'][-3:],8),'original/copied POSIX modes differ')
   old_inodes.add((oldstat['st_dev'],oldstat['st_ino']));new_inodes.add((newstat['st_dev'],newstat['st_ino']))
   source_rows.append({'relative':name,'original':origin['descriptor'],'actual':copy['created'],'complete_bytes_equal':True})
  require(len(old_inodes)==len(new_inodes)==3210 and not(old_inodes&new_inodes),'source inode independence failed')
  protected=author['protected_source'];oldroot=Path(protected['root']);oldmap=decode(fixed(protected['map'],'protected-R8-map'));oldstate=decode(fixed(protected['state'],'protected-R8-state'))
  require(len(oldmap)==3180 and inventory(oldroot)==oldstate and {n for n,s in oldstate.items()if stat.S_ISREG(s['st_mode'])}==set(oldmap),'protected full R8 state/pathset differs')
  oldtree={}
  for name,row in oldmap.items():
   ident=row['identity'];expected={k:ident[k]for k in('bytes','sha256','git_blob')};expected['mode']=ident['git_mode']
   stats=dict(zip(('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'),row['seven_stats']))
   require(oldstate[name]==stats and stat.S_IMODE(stats['st_mode'])==ident['mode'],'protected source original mode/stat differs')
   read(oldroot/name,'protected-R8-source:'+name,expected=expected,expected_stat=stats);oldtree[name]=expected
   require((stats['st_dev'],stats['st_ino'])not in new_inodes,'new source aliases protected R8')
  require(tree(oldtree)=='4c62be4ed66ff107fa6f88c6131313a354868bd9'and inventory(oldroot)==oldstate,'protected R8 bytes/state changed')
  old_guard={'files':3180,'all_bytes_read':True,'map':protected['map']['pin']}
  require(result['protected_source_before']==result['protected_source_after']==old_guard,'binding protected-source checks differ')
  rtmap=decode(fixed(author['runtime_map'],'complete-runtime-map'));rtroot=Path(rtmap['root']);rtbefore=inventory(rtroot);rtfiles={r['path']:r for r in rtmap['files']}
  require(len(rtfiles)==len(rtmap['files'])==2496 and {n for n,s in rtbefore.items()if stat.S_ISREG(s['st_mode'])}==set(rtfiles)and {n for n,s in rtbefore.items()if stat.S_ISDIR(s['st_mode'])}=={'.',*rtmap['new_directories']},'complete runtime pathset differs')
  for name,row in rtfiles.items():
   stats=dict(zip(('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'),row['new_file_seven_stat']))
   expected={**row['pin'],'mode':'100755'if row['mode']&0o111 else'100644'}
   require(rtbefore[name]==stats and stat.S_IMODE(stats['st_mode'])==row['mode'],'runtime mode/stat changed')
   read(rtroot/name,'complete-runtime:'+name,expected=expected,expected_stat=stats)
   require((stats['st_dev'],stats['st_ino'])not in new_inodes,'source aliases runtime')
  context=bound['runtime'];ready=decode(fixed(author['provenance']['runtime_readiness'],'Root-actual-stdlib-readiness'))
  require(ready['status']=='PASS_STDLIB_READINESS_ONLY'and ready['returncode']==0 and ready['observed_ECHILD']is True,'original readiness differs');observed=ready['observed']
  require(set(context)=={'schema','launch_executable','executable','python','version','prefix','base_prefix','sysconfig','library','library_directory'}and context['schema']=='hepta.hia.roundtrip-runtime-launch-context.v1'and context['version']==[3,14,4]and context['python']==observed['version']and context['prefix']==observed['prefix']and context['base_prefix']==observed['base_prefix'],'captured actual runtime version/prefix differs')
  for name in('executable','library'):
   expected=author['expected_runtime'][name];fixed(expected,'actual-runtime-'+name)
   require(context[name]==runtime_record(expected),'captured actual runtime file differs')
  require(context['launch_executable']==observed['executable']==author['expected_runtime']['executable']['path']and context['library_directory']==str(Path(context['library']['path']).parent),'actual launch/library path differs')
  require(set(context['sysconfig'])=={'Py_ENABLE_SHARED','LDLIBRARY','INSTSONAME'}and context['sysconfig']['Py_ENABLE_SHARED']==1,'shared interpreter config differs')
  configs=[n for n in rtfiles if Path(n).name.startswith('_sysconfigdata_')and n.endswith('.py')]
  require(len(configs)==1,'one frozen sysconfig data source required')
  cfgraw,_=read(rtroot/configs[0],'runtime-config-literal',expected={**rtfiles[configs[0]]['pin'],'mode':'100644'})
  assignments=[n for n in ast.parse(cfgraw).body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='build_time_vars'for t in n.targets)]
  require(len(assignments)==1,'literal build_time_vars absent');cfg=ast.literal_eval(assignments[0].value)
  require(context['sysconfig']=={k:cfg[k]for k in('Py_ENABLE_SHARED','LDLIBRARY','INSTSONAME')}and Path(context['library']['path']).name in(context['sysconfig']['LDLIBRARY'],context['sysconfig']['INSTSONAME']),'runtime config differs from exact restored literal')
  require(inventory(rtroot)==rtbefore and inventory(root)==source_before and inventory(SCOPE)==scope_before and inventory(oldroot)==oldstate,'terminal full paths/stats differ')
  for path,row in SEEN.items():require(seven(Path(path).lstat())==row['stat'],'terminal input stat differs: '+path)
  guard_chain(author['parent_ancestors']);guard_chain(author['author_ancestors']);guard_chain(bound['scope_ancestors'])
  require(not os.path.lexists(SCOPE/'attempt-r1'),'product attempt appeared')
  free_end=os.statvfs(SCOPE).f_bavail*os.statvfs(SCOPE).f_frsize;require(free_end>=1073741824,'original storage floor no longer met')
  write(output/'SOURCE-BYTE-READBACK.json',source_rows)
  write(output/'COMPLETE-STATE-READBACK.json',{'scope':scope_before,'source':source_before,'protected_R8':oldstate,'runtime':rtbefore})
  report.update(status='PASS_INDEPENDENT_BOUND_SOURCE_ONLY',actual_binding=result_desc,actual_bound_plan=bound_desc,source_files=3210,source_origin_full_reads=3210,source_copy_full_reads=3210,source_tree=tree(source_map),source_inode_disjoint=True,protected_R8_files_full_read=3180,protected_R8_unchanged=True,runtime_files_full_read=2496,runtime_unchanged=True,actual_runtime_report_matches_known_files_and_readiness=True,new_live_runtime_mapping_probe=False,scope_regular_files=3216,controls_full_read=len(author['controls']),provenance_full_read=len(author['provenance']),copy_rows=3210,complete_pathsets_and_modes_and_seven_stats_equal=True,attempt_absent=True,current_free_after=free_end,default=False,product_authorization_granted=False,legacy_retired=False,old_venv_restored=False)
 except BaseException:report['traceback']=traceback.format_exc()
 finally:
  report['finished_ns']=time.monotonic_ns();report['fresh_full_file_reads']=len(READS);report['unique_paths']=len(SEEN)
  write(output/'FULL-READ-LEDGER.json',READS);write(output/'RESULT.json',report)
 return 0 if report['status']=='PASS_INDEPENDENT_BOUND_SOURCE_ONLY'else 1

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--bound-plan-sha256',required=True);p.add_argument('--binding-result-sha256',required=True);p.add_argument('--output',required=True)
 a=p.parse_args();raise SystemExit(verify(a.bound_plan_sha256,a.binding_result_sha256,a.output))
