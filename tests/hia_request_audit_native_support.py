"""External descriptor/socket observer for the real native audit executable."""
from pathlib import Path
import os,socket,fcntl,struct,subprocess,json
NONE=(1<<64)-1
# Linux UAPI value, also used by the native owner. Some Python builds omit the
# symbolic constant even though memfd and kernel sealing are available.
F_ADD_SEALS=getattr(fcntl,'F_ADD_SEALS',1033)
class Audit:
 def __init__(self,root,image,evidence):
  self.root=Path(root);self.root.mkdir(mode=0o700,parents=True,exist_ok=True);self.image=Path(image);self.evidence=Path(evidence);self.evidence.mkdir(parents=True,exist_ok=True);self.count=0
  self.rootfd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC);self.fd=os.memfd_create('native-audit-qualification',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING);os.fchmod(self.fd,0o600);os.ftruncate(self.fd,2<<20);fcntl.fcntl(self.fd,F_ADD_SEALS,7)
  self.client,server=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET|socket.SOCK_CLOEXEC);self.client.settimeout(40);self.controller=os.getpid();self.err=open(self.evidence/'stderr.log','wb')
  self.proc=subprocess.Popen([str(self.image)],stdin=server,stdout=server,stderr=self.err,env={'PATH':''},pass_fds=(self.rootfd,self.fd),start_new_session=True);server.close()
 def frame(self,op,slot=NONE,gen=0,worker=None,owner='a'*64,tool='hia_describe',target=''):
  worker=worker or os.getpid();path=os.fsencode(self.root);raw=bytearray(512+len(path));raw[:8]=b'HIAAUD01';tb=tool.encode() if op else b'';target=target.encode() if op else b''
  struct.pack_into('<12Q',raw,8,1,op,len(raw),self.rootfd,self.fd,slot,worker,gen,self.controller,len(path),len(tb),len(target))
  if op:raw[128:192]=owner.encode();raw[192:192+len(tb)]=tb;raw[256:256+len(target)]=target
  raw[512:]=path;return raw
 def exchange(self,label,frame):
  self.count+=1;stem=f'{self.count:04d}-{label}';(self.evidence/(stem+'.input.bin')).write_bytes(frame)
  fcntl.lockf(self.fd,fcntl.LOCK_EX,1,1,os.SEEK_SET)
  try:
   assert self.client.send(frame)==len(frame);raw=self.client.recv(513)
  finally:fcntl.lockf(self.fd,fcntl.LOCK_UN,1,1,os.SEEK_SET)
  (self.evidence/(stem+'.output.bin')).write_bytes(raw)
  assert len(raw)==512 and raw[:8]==b'HIAAUO01', (label,len(raw),self.proc.poll())
  words=struct.unpack_from('<15Q',raw,8);r={'phase':words[1],'status':words[2],'reason':words[3],'id':raw[128:192].decode() if words[4] else None,'hot':words[5],'accepted':words[6]+(words[7]<<64),'elapsed_present':words[8],'elapsed':words[9],'slot':words[10],'generation':words[11],'error':raw[192:192+words[12]].decode(),'daemon_rc':self.proc.poll() if os.getpid()==self.controller else None}
  (self.evidence/(stem+'.json')).write_text(json.dumps(r,indent=2)+'\n');return r
 def prepare(self):return self.exchange('prepare',self.frame(0))
 def lease(self,slot):fcntl.lockf(self.fd,fcntl.LOCK_EX,1,64+slot,os.SEEK_SET)
 def release(self,slot):fcntl.lockf(self.fd,fcntl.LOCK_UN,1,64+slot,os.SEEK_SET)
 def begin(self,slot=0,gen=1,**kw):return self.exchange('begin',self.frame(1,slot,gen,**kw))
 def finish(self,receipt,completion=1,worker=None):
  raw=bytearray(128);raw[:8]=b'HIAAUF01';struct.pack_into('<7Q',raw,8,1,2,128,completion,receipt['slot'],receipt['generation'],worker or os.getpid());raw[64:]=receipt['id'].encode();return self.exchange('finish',raw)
 def history_frame(self,slot=0,gen=1,worker=None,owner='a'*64,limit=32,after_id=None):
  path=os.fsencode(self.root);raw=bytearray(512+len(path));raw[:8]=b'HIAAHQ01';cursor=b'' if after_id is None else after_id.encode()
  struct.pack_into('<12Q',raw,8,1,3,len(raw),self.rootfd,self.fd,slot,worker or os.getpid(),gen,self.controller,len(path),limit,len(cursor))
  raw[128:192]=owner.encode();raw[192:192+len(cursor)]=cursor;raw[512:]=path;return raw
 def history_exchange(self,label,frame):
  self.count+=1;stem=f'{self.count:04d}-{label}';(self.evidence/(stem+'.input.bin')).write_bytes(frame)
  fcntl.lockf(self.fd,fcntl.LOCK_EX,1,1,os.SEEK_SET)
  try:
   assert self.client.send(frame)==len(frame);raw=self.client.recv(64+65536+1)
  finally:fcntl.lockf(self.fd,fcntl.LOCK_UN,1,1,os.SEEK_SET)
  (self.evidence/(stem+'.output.bin')).write_bytes(raw)
  assert 64<=len(raw)<=64+65536 and raw[:8]==b'HIAAHO01',(label,len(raw),self.proc.poll())
  version,size,status,reason,slot,generation,reserved=struct.unpack_from('<7Q',raw,8)
  assert version==1 and size==len(raw) and status in (0,1) and reserved==0
  text=raw[64:].decode();r={'status':status,'reason':reason,'slot':slot,'generation':generation,'text':text,'value':json.loads(text) if status==0 else None}
  assert (status==0)==(reason==0)
  (self.evidence/(stem+'.json')).write_text(json.dumps(r,indent=2)+'\n');return r
 def history(self,**kw):return self.history_exchange('history',self.history_frame(**kw))
 def close(self):
  self.client.close()
  try:self.proc.wait(timeout=3)
  except subprocess.TimeoutExpired:self.proc.kill();self.proc.wait(timeout=3)
  self.err.close();os.close(self.rootfd);os.close(self.fd)
 def __enter__(self):return self
 def __exit__(self,*exc):self.close()
def good(row):
 assert row['status']==0,row
 return row

def identity(path):
 s=Path(path).stat();return [s.st_dev,s.st_ino]
def write_json(path,value):
 p=Path(path);data=json.dumps(value,separators=(',',':')).encode();fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC,0o600)
 try:assert os.write(fd,data)==len(data);os.fsync(fd)
 finally:os.close(fd)
