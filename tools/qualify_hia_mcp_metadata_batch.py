"""Real kernel controls for private metadata batching and original fences."""
from __future__ import annotations
import argparse,array,fcntl,gzip,hashlib,json,os,select,socket,struct,time
from pathlib import Path
from tests.hia_metadata_batch_native_support import MetadataAudit,NativeState,group
from tests.hia_request_audit_native_support import good
from tools.qualify_hia_mcp_request_archive import seed_archive,UNAVAILABLE,DEADLINE
from tools.qualify_hia_mcp_request_history import record

def refused(out,deadline=False):
 assert out['status']==1 and out['value'] is None,out
 assert out['text']==(DEADLINE if deadline else UNAVAILABLE),out
 if deadline:assert out['reason']==37,out

def page(out,rows,owner='a'*64,limit=32,after_id=None):
 value=good(out)['value'];owned=sorted([r for r in rows if r['owner']==owner],key=lambda r:(r['accepted_unix_ms'],r['request_id']))
 assert value['total']==len(owned)
 if after_id is not None:
  cursor=next(r for r in owned if r['request_id']==after_id);key=cursor['accepted_unix_ms'],cursor['request_id']
  owned=[r for r in owned if (r['accepted_unix_ms'],r['request_id'])>key]
 more=len(owned)>limit;selected=owned[:limit]
 assert [r['request_id'] for r in value['requests']]==[r['request_id'] for r in selected],out
 assert value['next_after_id']==(selected[-1]['request_id'] if more else None),out
 return value

def usage(out,rows,owner):
 value=good(out)['value'];owned=[r for r in rows if r['owner']==owner]
 expected={s:sum(r['state']==s for r in owned) for s in ['unknown','completed','failed']}
 assert value['total_requests']==len(owned) and value['active']==0
 for key,count in expected.items():assert value[key]==count,(key,value,expected)
 assert value['tool_counts']==({'hia_describe':len(owned)} if owned else {})
 assert value['first_accepted_unix_ms']==(min(r['accepted_unix_ms'] for r in owned) if owned else None)
 assert value['last_accepted_unix_ms']==(max(r['accepted_unix_ms'] for r in owned) if owned else None)
 return value

def qualify(image,output):
 output.mkdir(mode=0o700,parents=True,exist_ok=False);checks=[]
 report={'schema':'hepta.hia.metadata-batch-native.component.v3','passed':False,'checks':checks,'scope':'independent real native component','whole_runtime_qualified':False,'whole_cold_qualified':False,'audit_sha256':hashlib.sha256(image.read_bytes()).hexdigest(),'original_bounds':{'metadata_members':8,'usage_window_ns':1000000,'archive_window_ns':2000000,'query_budget_seconds':3}}
 def save():(output/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')
 def passed(label,**kw):
  checks.append(dict(case=label,passed=True,**kw));save();print('NATIVE_METADATA_BATCH_PASS',label,flush=True)
 try:
  with MetadataAudit(output/'protocol-root',image,output/'protocol-wire') as a:
   good(a.prepare())
   for i in range(32):a.lease(i)
   good(a.query('empty-archive'));good(a.query('empty-usage',kind=5));good(a.history())
   passed('private-v2-empty-both-kinds-and-original-history')
   baseline=len(list(Path(f'/proc/{a.proc.pid}/fd').iterdir()))
   # A malformed zero-byte datagram is distinct from a closed socket.
   assert a.client.send(b'')==0;good(a.query('after-empty-datagram'))
   passed('zero-datagram-does-not-terminate-live-audit-channel')
   # New private packets without a capability never contaminate legacy replies.
   assert a.client.send(a.frame_v2())>0;good(a.query('after-no-right'))
   assert not select.select([a.client],[],[],0)[0]
   good(a.history());passed('missing-reply-right-does-not-publish-on-common-channel')
   fcntl.lockf(a.fd,fcntl.LOCK_EX,1,1,os.SEEK_SET)
   try:good(a.query('metadata-while-legacy-exchange-locked'))
   finally:fcntl.lockf(a.fd,fcntl.LOCK_UN,1,1,os.SEEK_SET)
   passed('metadata-query-does-not-acquire-complete-exchange-lock')
   original=os.pread(a.fd,8,128);os.pwrite(a.fd,b'\0'*8,128)
   item=a.private('bad-shared-custody');a.send(item)
   try:
    answer=item['reader'].recv(65601)
    (a.evidence/(item['stem']+'.output.bin')).write_bytes(answer);assert not answer
    assert not select.select([a.client],[],[],0)[0]
   finally:
    os.pwrite(a.fd,original,128);item['reader'].close()
   good(a.query('after-shared-custody-refusal'))
   assert len(list(Path(f'/proc/{a.proc.pid}/fd').iterdir()))==baseline
   passed('shared-custody-refusal-closes-private-right-without-common-response')
   bads=[
    ('bad-version',lambda f:struct.pack_into('<Q',f,8,1)),
    ('bad-operation',lambda f:struct.pack_into('<Q',f,16,3)),
    ('bad-reserved',lambda f:struct.pack_into('<Q',f,288,1)),
    ('bad-slot',lambda f:struct.pack_into('<Q',f,48,32)),
    ('bad-generation',lambda f:struct.pack_into('<Q',f,64,0)),
    ('bad-worker',lambda f:struct.pack_into('<Q',f,56,os.getpid()+1000000)),
    ('bad-root',lambda f:struct.pack_into('<Q',f,32,999999)),
    ('bad-owner',lambda f:f.__setitem__(slice(128,192),b'A'*64)),
    ('bad-entered-nanoseconds',lambda f:struct.pack_into('<Q',f,280,1000000000)),
    ('body-truncation',lambda f:f.extend(b'x'*5000)),
   ]
   for label,mutate in bads:
    item=a.private(label);mutate(item['frame']);a.send(item)
    raw=item['reader'].recv(65601);item['reader'].close()
    (a.evidence/(item['stem']+'.output.bin')).write_bytes(raw);assert not raw,(label,raw)
    good(a.query(label+'-fresh'))
    assert len(list(Path(f'/proc/{a.proc.pid}/fd').iterdir()))==baseline,label
    passed(label+'-refused-and-owned-fds-closed')
   for label,count in [('multiple-rights',2),('ctrunc-rights',70)]:
    item=a.private(label);raw=item['frame']
    assert a.client.sendmsg([raw],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[item['writer'].fileno()]*count))])==len(raw)
    item['writer'].close();answer=item['reader'].recv(65601);item['reader'].close()
    (a.evidence/(item['stem']+'.input.bin')).write_bytes(raw);(a.evidence/(item['stem']+'.output.bin')).write_bytes(answer);assert not answer
    good(a.query(label+'-fresh'))
    assert len(list(Path(f'/proc/{a.proc.pid}/fd').iterdir()))==baseline
    passed(label+'-all-visible-descriptors-closed')
   entered=time.monotonic_ns()+100000000
   refused(a.query('future-entered',entered_ns=entered,deadline_ns=entered+3000000000))
   entered=time.monotonic_ns()
   refused(a.query('budget-extended',entered_ns=entered,deadline_ns=entered+3000000001))
   refused(a.query('already-expired',entered_ns=entered-4000000000,deadline_ns=entered-1),True)
   passed('entered-time-and-original-three-second-budget-not-rebased')
   good(a.query('normal-after-refusals'));good(a.history())
  assert a.proc.returncode==0;passed('real-peer-close-ends-daemon-normally')
  with MetadataAudit(output/'root',image,output/'wire') as a:
   good(a.prepare())
   for i in range(32):a.lease(i)
   state=NativeState(a)
   try:
    good(a.query('small-archive'));good(a.query('small-usage',kind=5))
    assert state.get()['archive_large']==state.get()['usage_large']==0
    passed('small-archives-do-not-collect')
    states=['completed','failed','unknown']
    rows=[record(i+1,accepted=i+1,owner=('b' if i%4==0 else 'a')*64,state=states[i%3],elapsed=None if i%3==2 else 1) for i in range(16385)]
    seed_archive(a.root,rows)
    (output/'original-fixture.json.gz').write_bytes(gzip.compress(json.dumps(rows,sort_keys=True,separators=(',',':')).encode(),mtime=0))
    began=time.monotonic();page(a.query('warm-archive'),rows);elapsed=time.monotonic()-began
    assert elapsed<3 and state.get()['archive_large']==1
    passed('large-hint-follows-complete-16385-original-observation',seconds=elapsed)
    selected=[r for r in rows if r['owner']=='a'*64]
    queries=[dict(slot=i,owner=('b' if i%3==0 else 'a')*64,limit=i+1) for i in range(8)];queries[2]['after_id']=selected[40]['request_id']
    items,snap=group(a,state,queries,'private-pages')
    for item,q in zip(items,queries):page(a.receive(item),rows,q['owner'],q['limit'],q.get('after_id'))
    passed('eight-private-page-projections-share-complete-observation',freeze=snap)
    queries=[dict(slot=i,owner='a'*64,limit=2) for i in range(8)];queries[3]['after_id']='f'*64
    items,snap=group(a,state,queries,'local-cursor')
    for i,item in enumerate(items):
     result=a.receive(item)
     if i==3:refused(result)
     else:page(result,rows,limit=2)
    passed('local-cursor-error-remains-private-until-common-fence',freeze=snap)
    usage(a.query('warm-usage',kind=5),rows,'a'*64);assert state.get()['usage_large']==1
    queries=[dict(slot=i,kind=5,owner=('b' if i%2 else 'a')*64) for i in range(8)]
    items,snap=group(a,state,queries,'private-usage')
    for item,q in zip(items,queries):usage(a.receive(item),rows,q['owner'])
    passed('eight-usage-projections-preserve-all-three-original-states',freeze=snap)
    queries=[dict(slot=i,owner='a'*64,limit=1) for i in range(7)]
    items=[a.private('seven-valid-'+str(i),**q) for i,q in enumerate(queries)]
    expired=a.private('expired-unregistered',slot=7)
    state.stop()
    try:
     entered=time.monotonic_ns()
     for item in items:
      struct.pack_into('<2Q',item['frame'],256,*divmod(entered+3000000000,1000000000))
      struct.pack_into('<2Q',item['frame'],272,*divmod(entered,1000000000))
      a.send(item,False)
     struct.pack_into('<2Q',expired['frame'],256,*divmod(entered-1000000000,1000000000))
     struct.pack_into('<2Q',expired['frame'],272,*divmod(entered-4000000000,1000000000))
     a.send(expired,False)
    finally:state.resume()
    for item in items+[expired]:(a.evidence/(item['stem']+'.input.bin')).write_bytes(item['frame'])
    snap=state.wait_scan(7)
    assert snap['deadline']==list(divmod(entered+3000000000,1000000000)),snap
    for item in items:page(a.receive(item),rows,limit=1)
    refused(a.receive(expired),True)
    passed('expired-unregistered-member-keeps-seven-valid-private-results',freeze=snap)
    # A real terminal publication is queued after this frozen observation.
    # The ninth caller must perform a new observation and see that completion.
    ticket=good(a.begin(slot=31))
    paths=list((a.root/'request-archive-v11').glob(ticket['id']+'.json'))
    paths+=list((a.root/'request-archive-v12').glob('*/'+ticket['id']+'.json'))
    assert len(paths)==1,paths
    original=json.loads(paths[0].read_bytes());assert original['state']=='unknown'
    before_rows=rows+[original]
    cursor=selected[-1]['request_id']
    queries=[dict(slot=i,owner='a'*64,limit=1,after_id=cursor) for i in range(8)]
    items,snap=group(a,state,queries,'ninth-fresh-observation');state.stop()
    ninth=a.private('ninth-after-completion',slot=8,owner='a'*64,limit=1,after_id=cursor)
    finish=bytearray(128);finish[:8]=b'HIAAUF01'
    struct.pack_into('<7Q',finish,8,1,2,128,1,ticket['slot'],ticket['generation'],os.getpid())
    finish[64:]=ticket['id'].encode()
    fcntl.lockf(a.fd,fcntl.LOCK_EX,1,1,os.SEEK_SET)
    try:
     assert a.client.send(finish)==128
     (a.evidence/'after-freeze-finish.input.bin').write_bytes(finish)
     a.send(ninth)
    finally:state.resume()
    try:
     for item in items:
      result=page(a.receive(item),before_rows,limit=1,after_id=cursor)
      assert result['requests'][0]['state']=='accepted',result
     reply=a.client.recv(513);(a.evidence/'after-freeze-finish.output.bin').write_bytes(reply)
     assert len(reply)==512 and reply[:8]==b'HIAAUO01'
     words=struct.unpack_from('<15Q',reply,8)
     assert words[1:4]==(2,0,0) and reply[128:192].decode()==ticket['id']
     completed=json.loads(paths[0].read_bytes());assert completed['state']=='completed'
     rows.append(completed)
     result=page(a.receive(ninth),rows,limit=1,after_id=cursor)
     assert result['requests'][0]['state']=='completed',result
    finally:fcntl.lockf(a.fd,fcntl.LOCK_UN,1,1,os.SEEK_SET)
    passed('ninth-private-request-sees-real-later-completion-without-result-reuse',freeze=snap)
    queries=[dict(slot=i,owner='a'*64,limit=1) for i in range(8)]
    for label,replacement in [('late-content-change',False),('late-inode-replacement',True)]:
     items,snap=group(a,state,queries,label);state.stop()
     foreign=next(r for r in reversed(rows) if r['owner']=='b'*64)
     target=a.root/'request-archive-v11'/(foreign['request_id']+'.json');before=target.read_bytes()
     try:
      if replacement:
       other=output/'replacement-original';other.write_bytes(before);other.chmod(0o600);os.replace(other,target)
      else:
       with target.open('wb') as f:f.write(b'{"changed":true}');f.flush();os.fsync(f.fileno())
      assert all(not select.select([item['reader']],[],[],0)[0] for item in items)
     finally:state.resume()
     for item in items:refused(a.receive(item))
     if not replacement:
      with target.open('wb') as f:f.write(before);f.flush();os.fsync(f.fileno())
     page(a.query(label+'-fresh'),rows)
     passed(label+'-discards-entire-group-and-fresh-read-recovers',freeze=snap)
    items,snap=group(a,state,queries,'cancelled-member');state.stop()
    try:
     items[0]['reader'].close()
     assert state.get()['active']==state.get()['frozen']==1
     assert all(not select.select([x['reader']],[],[],0)[0] for x in items[1:])
    finally:state.resume()
    for item in items[1:]:page(a.receive(item),rows,limit=1)
    page(a.query('after-cancel-fresh'),rows)
    passed('cancelled-member-does-not-release-original-custody-or-other-replies',freeze=snap)
    short=[dict(q) for q in queries];short[2]['budget_ns']=500000000
    items,snap=group(a,state,short,'minimum-deadline');state.stop()
    try:time.sleep(.6)
    finally:state.resume()
    for item in items:refused(a.receive(item),True)
    page(a.query('after-deadline-fresh'),rows)
    passed('earliest-original-member-deadline-refuses-whole-group',freeze=snap)
   finally:state.close()
  assert a.proc.returncode==0
  report.update(passed=True,passed_count=len(checks));save();return report
 finally:save()

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--audit',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 r=qualify(a.audit.resolve(),a.output.resolve());print(json.dumps({'passed':r['passed'],'passed_count':r.get('passed_count')}))

if __name__=='__main__':main()
