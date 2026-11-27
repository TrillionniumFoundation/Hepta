"""Native syscall continuations for private metadata capabilities and deadlines.

Only explicit syscall results are injected here. Real sockets, installed FD
cleanup, original mutations and process cancellation are exercised separately.
"""
from __future__ import annotations
import argparse,ctypes,json,mmap,struct
from hashlib import sha256
from pathlib import Path
from hepta.hia_json_preflight_native import NativeHiaJsonImage
from tools.qualify_hia_mcp_request_history_seed import HistorySeeds
from tools.generate_hia_mcp_request_audit_common import C as AC
from tools.generate_hia_mcp_service_owner_common import C as SC,SLOT
from tools.generate_hia_mcp_metadata_channel import C as MC

ROOT=Path(__file__).resolve().parents[1]
C={**SC,**AC,**MC}
NONE=(1<<64)-1
NEG4=NONE-3
NEG5=NONE-4
NEG11=NONE-10
STATE_BYTES=384<<20

def qualify(bootstrap,output):
 output.mkdir(mode=0o700,parents=True,exist_ok=False)
 seeds=HistorySeeds(ROOT,bootstrap,output/'seeds')
 report={'schema':'hepta.hia.metadata-batch-native-continuations.v1','passed':False,
         'whole_cold_qualified':False,'real_kernel_results_claimed':False,
         'sources':{},'checks':[]}
 arena=mmap.mmap(-1,STATE_BYTES)
 state=(ctypes.c_ubyte*STATE_BYTES).from_buffer(arena)
 request=ctypes.create_string_buffer(1);plan=ctypes.create_string_buffer(64);images={}
 def at(key):return C[key] if isinstance(key,str) else key
 def put(key,value):struct.pack_into('<Q',arena,at(key),value)
 def get(key):return struct.unpack_from('<Q',arena,at(key))[0]
 def reset(phase,result=0,module=17):
  for start,size in [(0,65536),(AC['INPUT'],8192),(AC['B_ACTIVE'],32768),
                     (SC['AUDIT_WIRE'],8192),(SC['HISTORY_REPLY'],65536)]:
   arena[start:start+size]=bytes(size)
  put(0,phase);put(8,result);put(16,module)
  put('B_PEER',NONE);put('B_RECEIVE_NEXT',11)
  put('MQ_SOCKET',NONE);put('MQ_PEER',NONE)
 def step(role,*,result=None):
  if result is not None:put(8,result)
  before={str(k):get(k) for k in [0,8,16,96,104,AC['B_MESSAGE_OK'],AC['B_PEER'],
    AC['B_COUNT'],AC['B_MIN_SEC'],AC['B_MIN_NS'],AC['B_CUT_SEC'],AC['B_CUT_NS'],
    MC['MQ_SOCKET'],MC['MQ_PEER'],MC['MQ_ACTIVE'],SC['ARCHIVE_DEADLINE_SEC'],
    SC['ARCHIVE_DEADLINE_NSEC']]}
  ctypes.memset(plan,0,64)
  status=images[role]._entry(request,0,plan,64,state,STATE_BYTES)
  actual=(status,tuple(struct.unpack('<8Q',plan.raw)))
  report['last_observation']={'role':role,'input_words':before,'status':status,
    'plan':list(actual[1]),'phase':get(0),'module':get(16),'message_ok':get('B_MESSAGE_OK')}
  return actual
 def record(label,actual,expected):
  assert actual==expected,(label,actual,expected,report['last_observation'])
  report['checks'].append({'case':label,'passed':True,**report['last_observation']})
 def transition(role,label,module,phase,result=None):
  actual=step(role,result=result);record(label,actual,(6,(0,)*8))
  assert (get(16),get(0))==(module,phase),(label,get(16),get(0))
 def syscall(role,label,wanted,result=None):
  record(label,step(role,result=result),(1,wanted))
 def member(index=0,slot=7,gen=9):
  base=AC['B_MEMBERS']+index*512
  for off,v in [(48,slot),(56,100),(64,gen),(256,103),(264,0),(272,100),(280,0)]:
   put(base+off,v)
 def rights(*fds,size=None,flags=0):
  reset(4,600);put('B_RECEIVE_NEXT',11)
  put(AC['B_MSG']+40,24 if size is None else size);put(AC['B_MSG']+48,flags)
  put('B_CONTROL',16+4*len(fds));put(AC['B_CONTROL']+8,4294967297)
  for i,fd in enumerate(fds):struct.pack_into('<I',arena,AC['B_CONTROL']+16+i*4,fd)
 def worker(phase,result=0):
  reset(phase,result,9)
  for key,value in [(1920,4),(1936,600),(1864,12),(1992,15),(2000,17),
                    ('MQ_ACTIVE',1),('MQ_SOCKET',44),('MQ_PEER',45),
                    ('ARCHIVE_DEADLINE_SEC',103),('ARCHIVE_DEADLINE_NSEC',0),
                    ('ARCHIVE_CLOCK',100),(432,7),(448,9)]:
   put(key,value)
 def recv_error(label,value):
  reset(4,value);transition('batch',label+'-preserves-full-ssize',0,11)
  assert get(8)==value and get('B_MESSAGE_OK')==1,(label,'lost receive failure',get(8),get('B_MESSAGE_OK'))
  syscall('session',label+'-terminates-original-channel',(60,74,0,0,0,0,0,0))
 try:
  for role,path in [('batch','mcp_request_audit_batch.hepta'),
                    ('session','mcp_request_audit_session.hepta'),
                    ('worker','mcp_service_audit_transport.hepta')]:
   file=ROOT/'examples/hia_bootstrap'/path;raw=file.read_bytes();flat=seeds.compile(raw,'div-word')
   (output/(role+'.flat')).write_bytes(flat)
   images[role]=NativeHiaJsonImage(flat,sha256(flat).hexdigest())
   report['sources'][str(file.relative_to(ROOT))]={'source_sha256':sha256(raw).hexdigest(),
     'source_bytes':len(raw),'image_sha256':sha256(flat).hexdigest(),'image_bytes':len(flat)}
  recv_error('recvmsg-eio',NEG5)
  recv_error('recvmsg-ebadf',NONE-8)
  reset(4,NEG11);put('B_RECEIVE_NEXT',17)
  transition('batch','recvmsg-eagain-keeps-signed-result',0,17);assert get(8)==NEG11
  transition('session','eagain-collection-keeps-original-cutoff',17,114)
  reset(4,NEG4);transition('batch','recvmsg-eintr-restarts-clean-message',17,0)
  reset(3);put('B_RECEIVE_FLAGS',64)
  syscall('batch','recvmsg-installs-cloexec-atomically',(47,0,AC['B_MSG'],1073741888,0,0,0,12))
  assert get(AC['B_MSG']+40)==256
  for flag,label in [(8,'ancillary-truncation'),(32,'body-truncation')]:
   rights(44,flags=flag)
   syscall('batch',label+'-closes-visible-right',(3,44,0,0,0,0,0,0))
   transition('batch',label+'-does-not-reuse-common-response',0,11,result=0)
   assert get('B_MESSAGE_OK')==0
  rights(44,45)
  syscall('batch','multiple-rights-close-first',(3,44,0,0,0,0,0,0))
  syscall('batch','multiple-rights-close-second',(3,45,0,0,0,0,0,0),result=0)
  transition('batch','multiple-rights-finish-private-refusal',0,11,result=0)
  assert get('B_MESSAGE_OK')==0
  rights(44,size=48)
  put(AC['B_CONTROL']+24,20);put(AC['B_CONTROL']+32,4294967297)
  struct.pack_into('<I',arena,AC['B_CONTROL']+40,45)
  syscall('batch','multiple-cmsgs-close-first',(3,44,0,0,0,0,0,0))
  syscall('batch','multiple-cmsgs-close-second',(3,45,0,0,0,0,0,0),result=0)
  transition('batch','multiple-cmsgs-remain-refused',0,11,result=0)
  assert get('B_MESSAGE_OK')==0
  rights(44,size=48);put(AC['B_CONTROL']+8,8589934593)
  put(AC['B_CONTROL']+24,20);put(AC['B_CONTROL']+32,4294967297)
  struct.pack_into('<I',arena,AC['B_CONTROL']+40,45)
  syscall('batch','unknown-cmsg-does-not-hide-later-right',(3,45,0,0,0,0,0,0))
  transition('batch','unknown-cmsg-refuses-after-visible-cleanup',0,11,result=0)
  for span in [0,15,25]:
   rights(size=24);put('B_CONTROL',span)
   transition('batch','invalid-cmsg-length-'+str(span),0,11)
   assert get('B_MESSAGE_OK')==0
  rights(44)
  syscall('batch','one-right-validates-socket-type',(55,44,1,3,AC['B_SOCKET_OPTION'],AC['B_SOCKET_OPTION']+8,0,960))
  put(AC['B_SOCKET_OPTION'],1);put(AC['B_SOCKET_OPTION']+8,4)
  syscall('batch','stream-socket-refused',(3,44,0,0,0,0,0,0),result=0)
  for phase,label in [(5,'type'),(6,'domain'),(7,'credentials'),(8,'lease')]:
   reset(phase,NEG5);put('B_PEER',44)
   syscall('batch',label+'-syscall-error-closes-right',(3,44,0,0,0,0,0,0))
  reset(4,0);put(AC['B_MSG']+40,0)
  syscall('batch','zero-byte-receive-checks-peer-close',(7,AC['B_POLL'],1,0,0,0,0,3))
  syscall('batch','zero-byte-poll-eintr-keeps-check',(7,AC['B_POLL'],1,0,0,0,0,3),result=NEG4)
  transition('batch','zero-datagram-remains-malformed',0,11,result=0)
  assert get('B_MESSAGE_OK')==0
  reset(10,1);put('B_RECEIVE_SIZE',0);struct.pack_into('<H',arena,AC['B_POLL']+6,16)
  transition('batch','closed-peer-publishes-eof',0,11)
  assert get('B_MESSAGE_OK')==1 and get(8)==0
  syscall('session','real-eof-exits-cleanly',(60,0,0,0,0,0,0,0))
  for kind,window in [(4,2000000),(5,1000000)]:
   reset(101);put('B_COUNT',1);put('B_ACTIVE',1);put('B_KIND',kind)
   put('B_MIN_SEC',103);put('B_MIN_NS',999500000)
   put('B_CLOCK',100);put(AC['B_CLOCK']+8,999700000)
   put(AC['B_MEMBERS']+272,100);put(AC['B_MEMBERS']+280,999500000)
   put('B_ARCHIVE_LARGE',1);put('B_USAGE_LARGE',1)
   transition('batch','fixed-window-carry-kind-'+str(kind),17,110)
   assert [get('B_CUT_SEC'),get('B_CUT_NS')]==[101,window-500000]
  reset(116);put('B_COUNT',7);put('B_MIN_SEC',103);put('B_CUT_SEC',101);put('B_CLOCK',100)
  put(AC['INPUT']+256,99);put(AC['INPUT']+264,0);put(AC['INPUT']+272,98)
  transition('batch','expired-unregistered-member-cannot-poison-group',17,115)
  assert get('B_COUNT')==7 and get('B_MIN_SEC')==103
  reset(116);put('B_COUNT',1);put('B_MIN_SEC',103);put('B_CUT_SEC',100);put('B_CUT_NS',2000000)
  put('B_CLOCK',100);put(AC['B_CLOCK']+8,2000000)
  transition('batch','cutoff-equality-defers-late-member',17,115)
  assert get('B_COUNT')==1 and get('B_CUT_NS')==2000000
  reset(111);put('B_COUNT',8);put('B_ACTIVE',1);put('B_MIN_SEC',103);put('B_CUT_SEC',101);put('B_CLOCK',100)
  member()
  syscall('batch','eighth-member-freezes-before-ninth-receive',(228,1,AC['FRAMES']+2048,0,0,0,0,12))
  assert get(16)==0 and get(0)==14 and get('B_FROZEN')==1
  for value,next_step,label in [(NEG4,1,'eintr'),(NEG11,3,'eagain')]:
   worker(204,value)
   syscall('worker','sendmsg-'+label+'-keeps-original-deadline',(228,1,SC['ARCHIVE_CLOCK'],0,0,0,0,12))
   assert get('MQ_NEXT')==next_step and get('ARCHIVE_DEADLINE_SEC')==103
  worker(204,599)
  syscall('worker','short-atomic-send-closes-peer',(3,45,0,0,0,0,0,0))
  syscall('worker','short-atomic-send-closes-private-receiver',(3,44,0,0,0,0,0,0),result=0)
  transition('worker','short-atomic-send-returns-failure',15,17,result=0)
  assert get('MQ_ACTIVE')==0 and get(2016)==1
  worker(204,600)
  syscall('worker','complete-send-drops-only-transferred-peer',(3,45,0,0,0,0,0,0))
  syscall('worker','private-receive-clock-follows-transfer',(228,1,SC['ARCHIVE_CLOCK'],0,0,0,0,12),result=0)
  assert get('MQ_NEXT')==2 and get('MQ_SOCKET')==44 and get('MQ_PEER')==NONE
  for value,next_step,label in [(NEG4,2,'eintr'),(NEG11,4,'eagain')]:
   worker(206,value);put('MQ_PEER',NONE)
   syscall('worker','receive-'+label+'-records-full-ssize',(228,1,SC['ARCHIVE_CLOCK'],0,0,0,0,12))
   assert get('MQ_RESULT')==value
   syscall('worker','receive-'+label+'-does-not-reset-budget',(228,1,SC['ARCHIVE_CLOCK'],0,0,0,0,12),result=0)
   assert get('MQ_NEXT')==next_step and get('ARCHIVE_DEADLINE_SEC')==103
  for label,slot,gen in [('correct',7,9),('old-generation',7,8),('wrong-slot',6,9)]:
   worker(210);put('MQ_PEER',NONE);put('MQ_NEXT',5);put('MQ_RESULT',66)
   arena[SC['HISTORY_REPLY']:SC['HISTORY_REPLY']+66]=struct.pack('<8Q',int.from_bytes(b'HIARQO02','little'),2,66,0,0,slot,gen,0)+b'{}'
   syscall('worker','private-reply-'+label+'-closes-channel',(3,44,0,0,0,0,0,0))
   assert get(2016)==(0 if label=='correct' else 1)
   transition('worker','private-reply-'+label+'-cannot-leak-to-reused-slot',15,17,result=0)
   assert get('MQ_ACTIVE')==0
  worker(210);put('ARCHIVE_CLOCK',103);put('MQ_NEXT',2)
  syscall('worker','private-query-at-original-deadline-closes-peer',(3,45,0,0,0,0,0,0))
  assert get('HISTORY_REASON')==37 and get('HISTORY_STATUS')==1
  syscall('worker','deadline-closes-receiver-once',(3,44,0,0,0,0,0,0),result=0)
  transition('worker','deadline-returns-after-capability-cleanup',15,17,result=0)
  assert get('MQ_ACTIVE')==0 and get(2016)==0
  worker(90);put(1904,123);put(32,100);put(424,99);put(384,19);put(416,20);put('HISTORY_LIMIT',4)
  arena[4000:4064]=b'a'*64;arena[4096:4102]=b'/state'
  for slot,offset,size in [('audit_owner',4000,64),('state_root',4096,6)]:
   put(SLOT[slot],offset);put(SLOT[slot]+8,size)
  syscall('worker','metadata-starts-private-channel-without-exchange-lock',(53,1,526341,0,MC['MQ_PAIR'],0,0,192))
  assert get('ARCHIVE_DEADLINE_SEC')==103 and get(SC['AUDIT_WIRE']+272)==100
  assert get(SC['AUDIT_WIRE'])==MC['MQ_ARCHIVE_IN'] and get(SC['AUDIT_WIRE']+8)==2
  report.update(passed=True,passed_checks=len(report['checks']))
  return report
 finally:
  seeds.save();del state;arena.close()
  (output/'qualification.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--bootstrap',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 r=qualify(a.bootstrap.resolve(),a.output.resolve());print(json.dumps({'passed':r['passed'],'checks':len(r['checks'])}))

if __name__=='__main__':main()
