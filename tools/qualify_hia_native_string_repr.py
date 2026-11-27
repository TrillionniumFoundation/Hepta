"""Qualify the native string/bytes repr policy against the original runtime."""
from pathlib import Path
import argparse,json,struct,hashlib,traceback,random,mmap,ctypes as C,unicodedata
from tools.qualify_hia_generation_lease_owner import old
p=argparse.ArgumentParser()
p.add_argument('--flat',type=Path,required=True)
p.add_argument('--output',type=Path,required=True)
args=p.parse_args();o=args.output;o.mkdir(mode=0o700)
flat=args.flat.read_bytes();image=old.Image(flat)
out=mmap.mmap(-1,1<<20);work=mmap.mmap(-1,8192)
op=C.addressof(C.c_char.from_buffer(out));wp=C.addressof(C.c_char.from_buffer(work))
cases=[];counts={'codepoints':0,'bytes':0,'malformed':0,'bounds':0}
def add(value,mode,label,capacity=None):
 raw=value if mode==1 else value.encode('utf-8','surrogatepass')
 wire=b'HIAREPR1'+struct.pack('<Q',mode)+raw
 want=(ascii(value) if mode==2 else repr(value)).encode('utf-8','surrogatepass')
 inp=C.create_string_buffer(wire);cap=len(out) if capacity is None else capacity
 assert len(want)+16<len(out)
 out[:len(want)+16]=b'\xa5'*(len(want)+16)
 n=image.entry(inp,len(wire),op,cap,wp,len(work))
 if cap<len(want):
  assert n==0xfffffffe and out[:len(want)+16]==b'\xa5'*(len(want)+16),(label,'capacity',n)
 else:
  got=bytes(out[:n])if n<len(out)else b''
  assert got==want,(label,n,repr(got[:1000]),repr(want[:1000]))
  assert out[n:n+16]==b'\xa5'*16,(label,'output overrun')
 cases.append({'label':label,'mode':mode,'input_bytes':len(wire),'output_bytes':len(want),'capacity':cap,'passed':True})
 return len(want)
def invalid(wire,expect=0xfffffffd,wn=8192):
 inp=C.create_string_buffer(wire);out[:64]=b'\xa5'*64
 n=image.entry(inp,len(wire),op,len(out),wp,wn)
 assert n==expect and out[:64]==b'\xa5'*64,(wire,n,expect)
 counts['malformed' if expect==0xfffffffd else 'bounds']+=1
report={'schema':'hia.native-string-repr-qualification.v1','passed':False,'product':{'path':str(args.flat),'bytes':len(flat),'sha256':hashlib.sha256(flat).hexdigest()},'oracle_unicode':unicodedata.unidata_version,'cases':cases,'counts':counts,'whole_public_runtime_qualified':False}
try:
 assert unicodedata.unidata_version=='16.0.0'
 fixtures=['',"'",'"',"a'b",'a"b','a\'"b','\\','\0\t\n\r\a\b\f\v\x7f\x80\x85\xa0','hello 世界','😀\u200d👨','\ud800\udcff\udfff','\ufdd0\uffff\U0010ffff','a'*20000,'é'*12000]
 for i,value in enumerate(fixtures):
  for mode in [0,2]:add(value,mode,'fixture-'+str(i))
 for start in range(0,0x110000,1024):
  value=''.join(map(chr,range(start,min(start+1024,0x110000))))
  for mode in [0,2]:add(value,mode,'all-unicode-'+str(start))
  counts['codepoints']+=len(value)
 for n in range(256):
  add(bytes([n]),1,'byte-'+str(n));counts['bytes']+=1
 for i,value in enumerate([b'',bytes(range(256)),bytes(range(256))*100,b"a'b",b'a"b',b'a\'"b',b'\t\n\r\\\0']):
  add(value,1,'bytes-fixture-'+str(i))
 rng=random.Random(17702219)
 for i in range(512):
  mode=i%3
  value=bytes(rng.randrange(256)for _ in range(rng.randrange(256)))if mode==1 else ''.join(chr(rng.randrange(0x110000))for _ in range(rng.randrange(256)))
  n=add(value,mode,'random-'+str(i));add(value,mode,'exact-'+str(i),n);add(value,mode,'short-'+str(i),n-1)
 for mode in [0,2]:
  for raw in [b'\x80',b'\xc0\x80',b'\xc1\xbf',b'\xc2',b'\xe0\x80\x80',b'\xe2\x80',b'\xf0\x80\x80\x80',b'\xf4\x90\x80\x80',b'\xf5\x80\x80\x80',b'\xff',b'a\xe2b\x80']:
   invalid(b'HIAREPR1'+struct.pack('<Q',mode)+raw)
 for wire in [b'',b'HIAREPR1',b'HIAREPR2'+bytes(8),b'HIAREPR1'+struct.pack('<Q',3),b'HIAREPR1'+struct.pack('<Q',2**64-1)]:
  invalid(wire)
 invalid(b'HIAREPR1'+bytes(8),0xfffffffe,8191)
 report.update(passed=True,groups=len(cases),actual_native_execution=True,all_unicode_codepoints_covered=True,all_byte_values_covered=True,no_output_on_malformed_or_insufficient_capacity=True)
 print('NATIVE_STRING_REPR_PASS',len(cases),counts,flush=True)
except BaseException as e:report.update(failure=repr(e),traceback=traceback.format_exc());raise
finally:(o/'report.json').write_text(json.dumps(report,indent=2)+'\n');out.close();work.close()
