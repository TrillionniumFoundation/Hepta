"""Root fresh-byte review of the frozen op13 preparation; no project imports."""
from pathlib import Path
import hashlib,json,os,stat,time,traceback
ROOT=Path('/tmp/hia-progress-v148-20261114-dda7')
AUTHOR=Path('/tmp/hia-op13-execution-author-r2-dda7')
OUT=ROOT/'op13-preparation-admission-r2'
KEYS=('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
ROWS=[]
def require(ok,msg):
 if not ok:raise AssertionError(msg)
def pin(b):
 return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
def seven(s):return {k:getattr(s,k) for k in KEYS}
def read(p,expected=None,expected_stat=None):
 p=Path(p);fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
 try:
  before=os.fstat(fd);stamp=seven(before)
  require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<=before.st_size<=64<<20,'bounded independent regular file '+str(p))
  require(seven(p.lstat())==stamp and (expected_stat is None or expected_stat==stamp),'current file identity '+str(p))
  blocks=[];left=before.st_size+1
  while left:
   b=os.read(fd,min(left,1<<20))
   if not b:break
   blocks.append(b);left-=len(b)
  raw=b''.join(blocks);value=pin(raw)
  require(len(raw)==before.st_size and seven(os.fstat(fd))==stamp==seven(p.lstat()),'held/named bytes changed '+str(p))
 finally:os.close(fd)
 if expected is not None:
  require(all(value[k]==expected[k] for k in value),'full byte pin '+str(p))
  if 'mode' in expected:require(('100755' if before.st_mode&0o111 else '100644')==expected['mode'],'Git mode '+str(p))
 ROWS.append({'path':str(p),'identity':value,'new_seven_stats':stamp,'posix_mode':stat.S_IMODE(before.st_mode)})
 return raw
def checked(row):return read(row['path'],row['pin'],row['stat'])
def decode(b):return json.loads(b)
def snapshot(root):
 root=Path(root);out={'.':seven(root.lstat())}
 require(stat.S_ISDIR(out['.']['st_mode']),'root directory')
 for base,dirs,files in os.walk(root,followlinks=False):
  for n in dirs+files:
   p=Path(base)/n;s=p.lstat()
   require(stat.S_ISDIR(s.st_mode) or stat.S_ISREG(s.st_mode),'unknown node '+str(p))
   out[str(p.relative_to(root))]=seven(s)
 return out
def dump(p,d):
 b=(json.dumps(d,sort_keys=True,indent=2)+'\n').encode()
 with Path(p).open('xb')as f:f.write(b)
 require(Path(p).read_bytes()==b,'publication readback')
 return pin(b)
def tree(rows):
 top={}
 for name,row in rows.items():
  d=top;parts=name.split('/')
  for part in parts[:-1]:d=d.setdefault(part,{})
  d[parts[-1]]=row
 def walk(d):
  entries=[]
  for name,val in d.items():
   is_file='git_blob' in val
   mode=val['mode'] if is_file else '40000';digest=val['git_blob'] if is_file else walk(val)
   entries.append(((name+('' if is_file else '/')).encode(),mode.encode()+b' '+name.encode()+b'\0'+bytes.fromhex(digest)))
  b=b''.join(v for _,v in sorted(entries))
  return hashlib.sha1(b'tree '+str(len(b)).encode()+b'\0'+b).hexdigest()
 return walk(top)
def main():
 started=time.monotonic_ns();OUT.mkdir(mode=0o700)
 result={'schema':'hia.root.op13-preparation-admission.v1','status':'FAIL','products_executed':0,'project_imports':0,'source_copy_performed':False}
 try:
  hraw=read(AUTHOR/'HANDOFF.json');actual_h=decode(hraw)
  p2=decode(checked(actual_h['preparation_plan']))
  oldraw=read(Path('/tmp/hia-op13-execution-author-r1-dda7/PREPARATION-PLAN.json'))
  require(pin(oldraw)['git_blob']=='30e3ad5c277b29164bfdef78d9963afd5e0d98b7','original R1 preparation plan')
  oldp=decode(oldraw)
  require(set(p2)==set(oldp) and {k for k in oldp if oldp[k]!=p2[k]}=={'author_ancestors','controls','parent_ancestors','scope'},'only explicit R2 path-domain projection')
  require(p2['scope']=='/tmp/hia-op13-execution-r2-dda7' and set(oldp['controls'])==set(p2['controls']),'new independent stable scope')
  changed=[]
  for name in oldp['controls']:
   oldbody=checked(oldp['controls'][name]);newbody=checked(p2['controls'][name])
   if oldbody!=newbody:
    require(name in {'bind_execution.py','PARENT-CONTRACT.md'},'unexpected R2 control body change')
    a=b'/dev/shm/hia-op13-execution-r1-dda7';b=b'/tmp/hia-op13-execution-r2-dda7'
    require(oldbody.count(a)==newbody.count(b)==1 and oldbody.replace(a,b)==newbody and newbody.replace(b,a)==oldbody,'whole exact R2 scope projection')
    changed.append(name)
  require(set(changed)=={'bind_execution.py','PARENT-CONTRACT.md'},'exact two path-only body changes')
  h={'products_executed':actual_h['products'],'binder_executed':actual_h['binder_execution'],'whole':False,'source_files':actual_h['source_files'],'source_tree':actual_h['original_source_tree'],'limits':p2['limits'],'controls':p2['controls'],'entrypoint':p2['controls']['bind_execution.py'],'parent':p2['controls']['run_execution.py'],'files':{'PREPARATION-PLAN.json':actual_h['preparation_plan'],'PREPARATION-LAUNCH.json':actual_h['preparation_launch'],'OUTER-INVOCATION.json':actual_h['outer_invocation'],'PRODUCT-LAUNCH-TEMPLATE-FINAL.json':actual_h['product_template']}}
  result['R2_projection']={'only_top_fields':['author_ancestors','controls','parent_ancestors','scope'],'two_scope_literal_body_changes':changed,'all_other_product_bodies_guards_source_graphs_and_limits_unchanged':True,'old_R1_parent_guard_failure_retained':True}
  require(pin(hraw)['git_blob']=='335347b1345575f511cd34d139e1dbf64cf5a26d','frozen handoff')
  require(h['products_executed']==0 and not h['binder_executed'] and not h['whole'] and h['source_files']==3210,'author status')
  for row in h['files'].values():checked(row)
  for row in h['controls'].values():checked(row)
  checked(h['entrypoint']);checked(h['parent'])
  p=decode(checked(h['files']['PREPARATION-PLAN.json']))
  for family in ('controls','provenance'):
   for row in p[family].values():checked(row)
  for rows in ('author_ancestors','parent_ancestors'):
   for row in p[rows]:
    s=Path(row['path']).lstat()
    require(stat.S_ISDIR(s.st_mode) and row=={'path':row['path'],'dev':s.st_dev,'ino':s.st_ino,'mode':s.st_mode,'uid':s.st_uid,'gid':s.st_gid},'directory authority')
  limits={'cleanup_seconds':3,'compile_seconds':20,'native_capacity':1048576,'owner_seconds':180,'vm_call_depth':128,'vm_heap':8388608,'vm_steps':10000000}
  require(p['limits']==h['limits']==limits and p['storage_floor']==1073741824 and not p['missing_sources'],'budgets or source gaps')
  projected=decode(checked(p['projected_source_map']));origins=decode(checked(p['origin_rows']))
  require(len(projected)==len(origins)==3210 and [r['relative'] for r in origins]==sorted(projected),'3210 exact ordered source members')
  inodes=set()
  for row in origins:
   require(row['descriptor']['pin']==row['expected']==projected[row['relative']],'source authority relation')
   checked(row['descriptor']);s=row['descriptor']['stat'];inode=(s['st_dev'],s['st_ino'])
   require(inode not in inodes,'source authority shared inode');inodes.add(inode)
  require(tree(projected)==p['source_tree']==h['source_tree']=='821bb0ac9c4ce7a7648c1c34ef91406e3a45fbcb','projected exact tree')
  v=p['protected_source'];m=decode(checked(v['map']));state=decode(checked(v['state']))
  before=snapshot(v['root']);require(before==state and len(m)==3180,'protected source metadata')
  for name,row in m.items():
   identity=row['identity'];expected={k:identity[k] for k in ('bytes','git_blob','sha256')};expected['mode']=identity['git_mode']
   read(Path(v['root'])/name,expected,state[name])
  require(snapshot(v['root'])==before,'protected full source changed')
  runtime=decode(checked(p['runtime_map']));rbefore=snapshot(runtime['root'])
  names={r['path'] for r in runtime['files']}
  require(len(names)==2496 and {n for n,s in rbefore.items() if stat.S_ISREG(s['st_mode'])}==names,'runtime complete file set')
  require({n for n,s in rbefore.items() if stat.S_ISDIR(s['st_mode'])}=={'.',*runtime['new_directories']},'runtime complete directory set')
  for row in runtime['files']:
   s=dict(zip(KEYS,row['new_file_seven_stat']));require(stat.S_IMODE(s['st_mode'])==row['mode'],'runtime mode')
   read(Path(runtime['root'])/row['path'],row['pin'],s)
  require(snapshot(runtime['root'])==rbefore,'runtime changed during full read')
  for row in p['expected_runtime'].values():checked(row)
  checked(p['compiler']);checked(p['template'])
  invocation=decode(checked(h['files']['OUTER-INVOCATION.json']));launch=decode(checked(h['files']['PREPARATION-LAUNCH.json']))
  checked(invocation['outer_runner']);checked(invocation['outer_descriptor'])
  for row in launch['fixed_inputs'].values():checked(row)
  require(invocation['preparation_only'] is True and invocation['product_phase_not_authorized'] is True and launch['mode']=='preparation','preparation only')
  require(launch['argv'][3]==h['entrypoint']['path'] and launch['argv'][5]==h['files']['PREPARATION-PLAN.json']['path'],'real bound binder')
  for target in (p['scope'],launch['outer']):require(not os.path.lexists(target),'exclusive new target '+target)
  free=os.statvfs(Path(p['scope']).parent);available=free.f_bavail*free.f_frsize
  require(available>=1073741824,'original1GiB floor')
  reads_pin=dump(OUT/'FULL-FRESH-READBACK.json',ROWS)
  authorization={'schema':'hia.root.op13-preparation-authorization.v1','stage':'one metadata preparation and actual runtime capture','source_files':3210,'source_tree':p['source_tree'],'outer_invocation':h['files']['OUTER-INVOCATION.json'],'launch':h['files']['PREPARATION-LAUNCH.json'],'full_fresh_readback':reads_pin,'product_calls_authorized':0,'source_generation_authorized':0,'automatic_retry':False,'actual_binding_readback_required_before_any_product':True}
  auth_pin=dump(ROOT/'OP13-PREPARATION-AUTHORIZATION-R2.json',authorization)
  result.update(status='PASS_READY_FOR_ONE_METADATA_PREPARATION',full_fresh_reads=len(ROWS),fresh_bytes=sum(r['identity']['bytes'] for r in ROWS),original_source_authorities=3210,protected_source_files=3180,runtime_files=2496,new_source_copies=0,available_bytes=available,authorization=auth_pin,scope=p['scope'])
 except BaseException:result['error']=traceback.format_exc()
 result['elapsed_ns']=time.monotonic_ns()-started
 rp=dump(OUT/'RESULT.json',result);print(json.dumps({'result':result,'result_pin':rp},sort_keys=True))
 return 0 if result['status'].startswith('PASS_') else 1
if __name__=='__main__':raise SystemExit(main())
