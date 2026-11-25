from pathlib import Path
import importlib.util,json,time,sys,os,random,unicodedata,hashlib
T=Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125');Q=T/'multiversion-runtime-snapshot-qa'
from tools import qualify_hia_multiversion_runtime_snapshot as h
Q=h.Q;T=h.T
D=Q/'unicode-v1';D.mkdir();n=h.Native(Q/'native-v4/snapshot.flat')
count=0;points=0;digest=hashlib.sha256();started=time.monotonic_ns()
def verify(path,label):
 global count
 wi,ex=h.oserror(13,path);expected=h.jbytes(ex);raw=h.packet(wi)
 got,out,w,elapsed=n.run(raw,len(expected),65536)
 if got!=len(expected)or out!=expected:
  (D/'failed.input').write_bytes(raw);(D/'failed.expected.json').write_bytes(expected);(D/'failed.actual.bin').write_bytes(out)
  raise AssertionError((label,got,len(expected),out,expected))
 digest.update(len(expected).to_bytes(8,'little'));digest.update(expected);count+=1
for start in range(0,0x110000,64):
 string=''.join(chr(cp)for cp in range(start,min(start+64,0x110000)))
 verify(string.encode('utf-8','surrogatepass'),'codepoints-'+str(start));points+=len(string)
 if count%4096==0:print('UNICODE_PROGRESS',count,points,flush=True)
for b in range(256):verify(bytes([b])*8,'byte-'+str(b))
rng=random.Random(3164)
for i in range(256):
 raw=bytes(rng.getrandbits(8)for _ in range(rng.randrange(0,1600)));verify(raw,'invalid-random-'+str(i))
for i,string in enumerate(["'","\"","'\"","\\","\n\t\r\x00\udc00","🙂"*1024,"'*'*"*1000,"\U000e0001"*1024]):
 verify(string.encode('utf-8','surrogatepass'),'boundary-'+str(i))
report={'status':'PASS','native_sha256':h.sha(n.raw),'python':sys.version,'unicode_version':unicodedata.unidata_version,'codepoints_examined':points,'actual_native_calls':count,'expected_output_stream_sha256':digest.hexdigest(),'elapsed_ns':time.monotonic_ns()-started,'errors_match_actual_oserror_str_and_repr':True}
(D/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report),flush=True)
