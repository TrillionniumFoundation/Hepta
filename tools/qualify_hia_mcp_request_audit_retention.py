"""Run actual native audit retention cases against a supplied executable.

Usage: python -m tools.qualify_hia_mcp_request_audit_retention IMAGE FRESH_OUTPUT
No runtime mock, host policy fallback or original-test assertion edits.
"""
from pathlib import Path
from hashlib import sha256
import json,sys,os,signal,time,select
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tests.hia_request_audit_native_support import Audit,good,identity,write_json
image=Path(sys.argv[1]);out=Path(sys.argv[2]).resolve();out.mkdir(mode=0o700);rows=[]
def state(label):
 base=out/label;base.mkdir();root=base/'state'
 with Audit(root,image,base/'initialize') as a:good(a.prepare())
 return base,root

def record(index,owner='a'*64,accepted=None,state='completed',elapsed=1):
 return {'request_id':f'{index:064x}','owner':owner,'tool_name':'hia_describe','state':state,'accepted_unix_ms':index if accepted is None else accepted,'elapsed_ms':elapsed}
def seed(root,records,archive=True):
 for row in records:
  name=row['request_id']+'.json';write_json(root/'request-audit'/name,row)
  if archive:write_json(root/'request-archive-v11'/name,row)
def count(root):return len(list((root/'request-audit').glob('*.json')))
def read(root,rid,where='request-archive-v11'):return json.loads((root/where/(rid+'.json')).read_bytes())
def add(label,**data):rows.append({'case':label,'status':'PASS',**data});print('AUDIT_PASS',label,flush=True)

base,root=state('legacy-u128-and-missing-optional');row=record(1,accepted=(1<<128)-1,elapsed=None);row.pop('elapsed_ms');seed(root,[row],False)
with Audit(root,image,base/'actual') as a:good(a.prepare())
actual=read(root,row['request_id']);assert actual['accepted_unix_ms']==(1<<128)-1 and actual['elapsed_ms'] is None;add('legacy-u128-and-missing-optional',accepted=actual['accepted_unix_ms'])

for label,total,owners,owner in [('owner-128',128,1,'a'*64),('global-512',512,4,'f'*64)]:
 base,root=state(label);records=[record(i,owner=hex(10+i%owners)[2:]*64) for i in range(total)];seed(root,records)
 with Audit(root,image,base/'actual') as a:
  good(a.prepare());a.lease(0);beg=good(a.begin(owner=owner));assert beg['hot']==1 and count(root)==total;assert not (root/'request-audit'/(records[0]['request_id']+'.json')).exists();assert read(root,records[0]['request_id'])==records[0];good(a.finish(beg));a.release(0)
 add(label,hot_count=count(root),victim=records[0]['request_id'])

base,root=state('active-oldest-protected')
with Audit(root,image,base/'actual') as a:
 good(a.prepare());a.lease(0);old=good(a.begin());records=[record(i,accepted=old['accepted']+i) for i in range(1,128)];seed(root,records);a.lease(1);new=good(a.begin(1,2));assert (root/'request-audit'/(old['id']+'.json')).exists();assert not (root/'request-audit'/(records[0]['request_id']+'.json')).exists();good(a.finish(old));good(a.finish(new));a.release(0);a.release(1)
add('active-oldest-protected')

base,root=state('read-pin-owner-isolation');records=[record(i) for i in range(128)];seed(root,records)
with Audit(root,image,base/'actual') as a:
 good(a.prepare());a.lease(0);pin=good(a.begin(tool='request_status',target=records[0]['request_id']));assert (root/'request-audit'/(records[0]['request_id']+'.json')).exists();assert not (root/'request-audit'/(records[1]['request_id']+'.json')).exists();a.lease(1);second=good(a.begin(1,2));assert (root/'request-audit'/(records[0]['request_id']+'.json')).exists();assert not (root/'request-audit'/(records[2]['request_id']+'.json')).exists();a.lease(2);denied=a.begin(2,3,owner='b'*64,tool='request_result',target=records[0]['request_id']);assert denied['status']!=0 and denied['reason']==23,denied;good(a.finish(pin));good(a.finish(second));a.release(0);a.release(1);a.release(2)
add('read-pin-owner-isolation',denied=denied)

base,root=state('full-owner-bad-archive-preserves-hot');records=[record(i) for i in range(128)];seed(root,records,False)
for row in records:write_json(root/'request-archive-v11'/(row['request_id']+'.json'),{'wrong':'counterpart'})
original={p.name:sha256(p.read_bytes()).hexdigest() for p in (root/'request-archive-v11').iterdir()}
with Audit(root,image,base/'actual') as a:
 good(a.prepare());a.lease(0);beg=good(a.begin());assert beg['hot']==0 and count(root)==128;assert not (root/'request-audit'/(beg['id']+'.json')).exists();assert read(root,beg['id'])['state']=='unknown';good(a.finish(beg));a.release(0)
for name,digest in original.items():assert sha256((root/'request-archive-v11'/name).read_bytes()).hexdigest()==digest
add('full-owner-bad-archive-preserves-hot',hot_count=count(root))

base,root=state('real-worker-cancel-and-slot-reuse')
with Audit(root,image,base/'actual') as a:
 good(a.prepare());rd,wr=os.pipe();child=os.fork()
 if child==0:
  os.close(rd);a.evidence=base/'worker';a.evidence.mkdir();a.count=0
  try:
   a.lease(0);old=good(a.begin());os.write(wr,json.dumps(old).encode()+b'\n');os.close(wr)
   while True:signal.pause()
  except BaseException as e:
   os.write(wr,json.dumps({'error':repr(e)}).encode()+b'\n');os._exit(71)
 os.close(wr)
 try:
  assert select.select([rd],[],[],40)[0];old=json.loads(os.read(rd,4096));assert old.get('status')==0 and old.get('id'),old;os.kill(child,signal.SIGKILL);_,status=os.waitpid(child,0);assert os.WIFSIGNALED(status) and os.WTERMSIG(status)==signal.SIGKILL;child=0
  assert read(root,old['id'])['state']=='unknown' and read(root,old['id'])['elapsed_ms'] is None;a.lease(0);new=good(a.begin(0,2));assert new['id']!=old['id'];good(a.finish(new));assert read(root,old['id'])['state']=='unknown';a.release(0)
 finally:
  os.close(rd)
  if child:
   os.kill(child,signal.SIGKILL);os.waitpid(child,0)
add('real-worker-cancel-and-slot-reuse')

base,root=state('held-hot-directory-completion')
with Audit(root,image,base/'actual') as a:
 good(a.prepare());a.lease(0);beg=good(a.begin());oldhot=root/'held-hot';(root/'request-audit').rename(oldhot);(root/'request-audit').mkdir(mode=0o700);good(a.finish(beg));assert not list((root/'request-audit').iterdir());assert json.loads((oldhot/(beg['id']+'.json')).read_bytes())['state']=='completed' and read(root,beg['id'])['state']=='completed';a.release(0)
add('held-hot-directory-completion')

base,root=state('anchor-replacement-ticket-custody')
with Audit(root,image,base/'actual') as a:
 good(a.prepare());a.lease(0);beg=good(a.begin());anchor=root/'.request-archive-v11-anchor.json';raw=anchor.read_bytes();anchor.rename(root/'held-anchor');replacement=root/'replacement';write_json(replacement,json.loads(raw));replacement.rename(anchor);end=a.finish(beg);assert end['status']!=0 and read(root,beg['id'])['state']=='unknown',end
 # The old ticket has ended; the next independent open may capture the valid new anchor.
 next=good(a.begin(0,2));good(a.finish(next));a.release(0)
add('anchor-replacement-ticket-custody',old_finish=end)

base,root=state('terminal-archive-immutable')
with Audit(root,image,base/'actual') as a:
 good(a.prepare());a.lease(0);beg=good(a.begin());p=root/'request-archive-v11'/(beg['id']+'.json');terminal=json.loads(p.read_bytes());terminal.update(state='failed',elapsed_ms=123);p.unlink();write_json(p,terminal);end=a.finish(beg);assert end['status']!=0 and read(root,beg['id'])==terminal and read(root,beg['id'],'request-audit')['state']=='unknown';a.release(0)
add('terminal-archive-immutable',finish=end)

base,root=state('invalid-staging-no-descriptor-leak')
with Audit(root,image,base/'actual') as a:
 good(a.prepare());bad=root/'request-audit'/('.'+'c'*64+'-'+'d'*64+'.tmp');bad.write_bytes(b'{}');bad.chmod(0o644);a.lease(0);before=len(list(Path('/proc/'+str(a.proc.pid)+'/fd').iterdir()));responses=[]
 for i in range(32):
  r=a.begin(0,i+1);assert r['status']!=0 and r['reason']==16,r;responses.append(r)
 after=len(list(Path('/proc/'+str(a.proc.pid)+'/fd').iterdir()));assert after==before,(before,after);assert bad.exists();a.release(0)
add('invalid-staging-no-descriptor-leak',before=before,after=after,refusals=len(responses))

for label,change in [('unknown-record-field','unknown'),('duplicate-record-field','duplicate'),('symlink-hot-record','symlink'),('wrong-hot-mode','mode'),('excess-hot-records','count')]:
 base,root=state(label);row=record(1);seed(root,[row],False);p=root/'request-audit'/(row['request_id']+'.json')
 if change=='unknown':value={**row,'unrecognized':1};p.unlink();write_json(p,value)
 elif change=='duplicate':p.write_bytes(p.read_bytes()[:-1]+b',"owner":"'+b'a'*64+b'"}')
 elif change=='symlink':p.rename(root/'target');p.symlink_to('../target')
 elif change=='mode':p.chmod(0o644)
 elif change=='count':seed(root,[record(i+2) for i in range(512)],False)
 with Audit(root,image,base/'actual') as a:r=a.prepare();assert r['status']!=0,r
 add(label,refusal=r)
report={'status':'PASS','image':str(image),'image_sha256':sha256(image.read_bytes()).hexdigest(),'case_count':len(rows),'cases':rows,'scope':'Real native durable begin/finish, original retention/custody and live lease behavior; metadata query API not covered'}
(out/'report.json').write_text(json.dumps(report,indent=2)+'\n');print('RETENTION_CAMPAIGN_PASS',len(rows),flush=True)
