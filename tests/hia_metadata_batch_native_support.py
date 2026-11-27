"""External observer for real native metadata groups; never edits native state."""
from pathlib import Path
import array,os,signal,socket,struct,time,json
from tests.hia_request_audit_native_support import Audit
from tools.generate_hia_mcp_request_audit_batch_common import C

class MetadataAudit(Audit):
 def frame_v2(self,kind=4,entered_ns=None,deadline_ns=None,**kw):
  if kind==5:kw['limit']=0
  raw=self.history_frame(**kw);raw[:8]=b'HIAUSQ02' if kind==5 else b'HIARQY02'
  struct.pack_into('<2Q',raw,8,2,kind)
  now=time.monotonic_ns() if entered_ns is None else entered_ns
  end=now+3_000_000_000 if deadline_ns is None else deadline_ns
  struct.pack_into('<2Q',raw,256,*divmod(end,1_000_000_000))
  struct.pack_into('<2Q',raw,272,*divmod(now,1_000_000_000))
  return raw
 def private(self,label,**kw):
  r,w=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET|socket.SOCK_CLOEXEC)
  r.settimeout(5);self.count+=1
  return {'reader':r,'writer':w,'frame':self.frame_v2(**kw),'stem':f'{self.count:04d}-{label}'}
 def send(self,item,save=True):
  raw=item['frame']
  assert self.client.sendmsg([raw],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[item['writer'].fileno()]))])==len(raw)
  item['writer'].close()
  if save:(self.evidence/(item['stem']+'.input.bin')).write_bytes(raw)
 def receive(self,item):
  raw=item['reader'].recv(65601);item['reader'].close()
  (self.evidence/(item['stem']+'.output.bin')).write_bytes(raw)
  assert 64<len(raw)<=65600,(item['stem'],len(raw),self.proc.poll())
  assert raw[:8]==(b'HIAUSO02' if item['frame'][:8]==b'HIAUSQ02' else b'HIARQO02')
  version,size,status,reason,slot,gen,reserved=struct.unpack_from('<7Q',raw,8)
  assert version==2 and size==len(raw) and reserved==0 and status in (0,1)
  assert (status==0)==(reason==0)
  assert slot==struct.unpack_from('<Q',item['frame'],48)[0] and gen==struct.unpack_from('<Q',item['frame'],64)[0]
  text=raw[64:].decode()
  out={'status':status,'reason':reason,'slot':slot,'generation':gen,'text':text,'value':json.loads(text) if not status else None}
  (self.evidence/(item['stem']+'.json')).write_text(json.dumps(out,indent=2)+'\n')
  return out
 def query(self,label='query',**kw):
  item=self.private(label,**kw);self.send(item);return self.receive(item)

class NativeState:
 def __init__(self,audit):
  self.audit=audit;maps=Path(f'/proc/{audit.proc.pid}/maps').read_text();found=[]
  for line in maps.splitlines():
   p=line.split();lo,hi=(int(x,16) for x in p[0].split('-'))
   if p[1]=='rw-p' and len(p)==5 and hi-lo==30<<20:found.append(lo)
  assert len(found)==1,maps
  self.base=found[0];self.fd=os.open(f'/proc/{audit.proc.pid}/mem',os.O_RDONLY|os.O_CLOEXEC)
 def get(self):
  raw=os.pread(self.fd,192,self.base+C['B_ACTIVE']);assert len(raw)==192
  w=struct.unpack('<24Q',raw)
  return dict(active=w[0],count=w[1],member=w[2],kind=w[3],deadline=[w[4],w[5]],cutoff=[w[6],w[7]],archive_large=w[8],usage_large=w[9],originals=w[10],frozen=w[11],sealed=w[23])
 def wait_scan(self,count=8):
  until=time.monotonic()+2;last=None
  while time.monotonic()<until:
   last=self.get()
   if last['active']==1 and last['frozen']==1 and last['count']==count and last['originals']>=32:return last
   assert self.audit.proc.poll() is None,('daemon exited',last)
   time.sleep(.0001)
  raise AssertionError(('actual bounded group not observed',last))
 def stop(self):
  os.kill(self.audit.proc.pid,signal.SIGSTOP);pid,status=os.waitpid(self.audit.proc.pid,os.WUNTRACED)
  assert pid==self.audit.proc.pid and os.WIFSTOPPED(status)
 def resume(self):os.kill(self.audit.proc.pid,signal.SIGCONT)
 def close(self):os.close(self.fd)

def group(a,state,queries,label):
 items=[a.private(label+'-'+str(i),**{k:v for k,v in q.items() if k!='budget_ns'}) for i,q in enumerate(queries)]
 state.stop()
 try:
  entered=time.monotonic_ns()
  for item,q in zip(items,queries):
   deadline=entered+q.get('budget_ns',3_000_000_000)
   struct.pack_into('<2Q',item['frame'],256,*divmod(deadline,1_000_000_000))
   struct.pack_into('<2Q',item['frame'],272,*divmod(entered,1_000_000_000))
   a.send(item,False)
 finally:state.resume()
 for item in items:(a.evidence/(item['stem']+'.input.bin')).write_bytes(item['frame'])
 observed=state.wait_scan()
 assert observed['cutoff']==list(divmod(entered+(1_000_000 if queries[0].get('kind',4)==5 else 2_000_000),1_000_000_000)),observed
 minimum=min(entered+q.get('budget_ns',3_000_000_000) for q in queries)
 assert observed['deadline']==list(divmod(minimum,1_000_000_000)),observed
 (a.evidence/(label+'.freeze.json')).write_text(json.dumps(observed,indent=2)+'\n')
 return items,observed
