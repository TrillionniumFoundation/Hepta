"""Actual native strict UTF-8 bounds against the original Python decoder."""
from pathlib import Path
import argparse,json,struct,hashlib,traceback,random,ctypes as C
from tools.qualify_hia_generation_lease_owner import old
p=argparse.ArgumentParser();p.add_argument('--flat',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(mode=0o700)
raw=a.flat.read_bytes();image=old.Image(raw);out=C.create_string_buffer(80);work=C.create_string_buffer(1)
count=0;failures=0;valid=0;digest=hashlib.sha256();groups=[]
reason={'invalid start byte':1,'invalid continuation byte':2,'unexpected end of data':3}
def run(data):
 global count,failures,valid
 src=C.create_string_buffer(data);C.memset(out,0xa5,80)
 rc=image.entry(src,len(data),out,64,work,0);got=struct.unpack('<8Q',bytes(out)[:64])
 assert rc==0 and bytes(out)[:8]==b'HIAU8ER1' and bytes(out)[64:]==b'\xa5'*16,(rc,got)
 try:data.decode('utf-8');want=(0,0,0,0);valid+=1
 except UnicodeDecodeError as e:want=(1,e.start,e.end,reason[e.reason]);failures+=1
 assert got[1:5]==want and got[5:]==(len(data),0,0),(data,got,want)
 digest.update(struct.pack('<Q',len(data))+data+bytes(out)[:64]);count+=1
report={'schema':'hia.native-utf8-error-qualification.v1','passed':False,'product':{'path':str(a.flat),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()},'groups':groups,'whole_public_runtime_qualified':False}
try:
 for n in range(256):run(bytes([n]))
 groups.append({'case':'all-single-bytes','cases':256})
 for n in range(65536):run(n.to_bytes(2,'little'))
 groups.append({'case':'all-two-byte-sequences','cases':65536})
 boundaries=[0,0x41,0x7f,0x80,0x8f,0x90,0x9f,0xa0,0xbf,0xc0,0xff]
 n=count
 for lead in range(0xe0,0xf0):
  for b in range(256):
   for c in boundaries:run(bytes([lead,b,c]))
 groups.append({'case':'all-three-byte-lead-and-second-with-third-boundaries','cases':count-n})
 n=count
 for lead in range(0xf0,0xf5):
  for b in range(256):
   for c in boundaries:
    for d in boundaries:run(bytes([lead,b,c,d]))
 groups.append({'case':'all-four-byte-lead-and-second-with-third-fourth-boundaries','cases':count-n})
 n=count;codepoints=0
 for start in range(0,0x110000,4096):
  text=''.join(chr(cp)for cp in range(start,min(start+4096,0x110000))if not 0xd800<=cp<=0xdfff)
  codepoints+=len(text);run(text.encode())
 groups.append({'case':'every-valid-Unicode-codepoint','cases':count-n,'codepoints':codepoints})
 n=count;rng=random.Random(72831103)
 for i in range(5000):
  prefix='aé世界😀'.encode()*rng.randrange(5)
  data=prefix+bytes(rng.randrange(256)for _ in range(rng.randrange(33)));run(data)
 for lead in range(0xc2,0xf5):
  for tail in [b'',b'\x80',b'\xa0',b'\x80\x80',b'\x90\x80']:
   run(b'prefix'+bytes([lead])+tail)
 groups.append({'case':'random-and-incomplete-after-valid-prefix','cases':count-n})
 src=C.create_string_buffer(b'x');C.memset(out,0xa5,80);assert image.entry(src,1,out,63,work,0)==0xfffffffe and bytes(out)==b'\xa5'*80
 report.update(passed=True,cases=count,valid=valid,errors=failures,comparison_sha256=digest.hexdigest(),actual_native_execution=True)
 print('NATIVE_UTF8_ERROR_PASS',count,valid,failures,flush=True)
except BaseException as e:report.update(failure=repr(e),traceback=traceback.format_exc());raise
finally:(a.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
