"""Lossless alternate transport of the already completed original seal; zero target calls."""
from pathlib import Path
import hashlib,json,lzma,resource,signal,time
ROOT=Path(__file__).resolve().parent
def pin(p):
 b=p.read_bytes();return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest(),gitsha=hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest(),mode=p.stat().st_mode&0o777)
def save(p,v):
 b=(json.dumps(v,sort_keys=True,indent=2)+"\n").encode();p.write_bytes(b);assert p.read_bytes()==b
def main():
 start=time.monotonic_ns();resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
 def timeout(*_):raise TimeoutError("repack180")
 signal.signal(signal.SIGALRM,timeout);signal.setitimer(signal.ITIMER_REAL,180)
 source=ROOT/"complete-header-cache-evidence.tar.xz";target=ROOT/"complete-header-cache-evidence-dict8-r2.tar.xz"
 before=pin(source);assert before["gitsha"]=="1a2c3caccec96a486e9227b8ea7de6ebaa3b6958"
 assert not target.exists();primary=None;report=dict(status="INCOMPLETE",scope="LOSSLESS_ARCHIVE_TRANSPORT_REENCODING_ZERO_TARGET",input=before,B3=0,VM=0,native=0)
 try:
  h=hashlib.sha256();n=0
  with lzma.open(source,"rb") as src,lzma.open(target,"wb",preset=6) as dst:
   while b:=src.read(1<<20):dst.write(b);h.update(b);n+=len(b)
  after=hashlib.sha256();m=0
  with lzma.open(target,"rb") as src:
   while b:=src.read(1<<20):after.update(b);m+=len(b)
  assert (m,after.hexdigest())==(n,h.hexdigest()) and pin(source)==before
  report.update(status="PASS",output=pin(target),uncompressed_tar_bytes=n,uncompressed_tar_sha256=h.hexdigest(),complete_tar_stream_byte_equivalent=True,original_compressed_seal_retained_unchanged=True,source_custody=pin(ROOT/"custody.json"),member_index=pin(ROOT/"members.json"))
 except BaseException as exc:primary=exc;report.update(status="FAIL",error=repr(exc))
 finally:
  try:
   save(ROOT/"transport-reencode-r2.json",report);print(json.dumps(report,sort_keys=True),flush=True)
   assert time.process_time_ns()<90_000_000_000 and time.monotonic_ns()-start<180_000_000_000
  except BaseException as exc:
   if primary is None:primary=exc
   else:primary.add_note(repr(exc))
  if primary is not None:report.update(status="FAIL",error=repr(primary));save(ROOT/"transport-reencode-r2.json",report)
  signal.setitimer(signal.ITIMER_REAL,0)
 if primary is not None:raise primary
if __name__=="__main__":main()
