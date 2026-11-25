"""Fresh native CPython string-repr and KeyError messages, not Rust Debug."""
from pathlib import Path
from hashlib import sha256
import argparse,ctypes as C,json,random,struct,sys,time,unicodedata
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from tools.qualify_hia_background_optimizer_structure import Flat
def main():
 p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 D=a.output;D.mkdir(exist_ok=False);flat=Flat(a.directory/'background_optimizer_string_repr.flat')
 rows=[];report={'passed':False,'whole_background_qualified':False,'scope':__doc__,'native_flat_sha256':flat.sha,'python':sys.version,'unicode_database_version':unicodedata.unidata_version,'cases':rows}
 def frame(text,kind,mode=0):raw=text.encode('utf-8','surrogatepass');return struct.pack('<8s7Q',b'HIABRP01',mode,kind,len(raw),0,0,0,0)+raw
 def call(raw,n):
  s=C.create_string_buffer(raw);o=C.create_string_buffer(n+32);w=C.create_string_buffer(16384+32)
  C.memset(o,0xdb,len(o));C.memset(w,0xa5,len(w))
  t=time.monotonic_ns();rc=flat.entry(s,len(raw),C.addressof(o)+16,n,C.addressof(w)+16,16384);elapsed=time.monotonic_ns()-t
  assert s.raw==raw+b'\0'and o.raw[:16]+o.raw[-16:]==b'\xdb'*32 and w.raw[:16]+w.raw[-16:]==b'\xa5'*32
  return rc,o.raw[16:16+n],elapsed
 def expected(text,kind):
  if kind==0:return repr(text).encode()
  if kind==1:return json.dumps(repr(text),ensure_ascii=False,separators=(',',':')).encode()
  return json.dumps({'type':'KeyError','message':str(KeyError(text))},sort_keys=True,ensure_ascii=False,separators=(',',':')).encode()
 def run(name,text,kinds=(0,1,2),short=False):
  for kind in kinds:
   want=expected(text,kind);raw=frame(text,kind);rc,out,e1=call(raw,64)
   try:
    assert rc==0,(rc,name,kind)
    h=struct.unpack('<8s7Q',out);assert h[0]==b'HIABRR01'and h[1]==kind and h[2]==len(want)and h[3]==len(text)and h[4]in(34,39)and h[5:]==(0,0,0),(h,len(want),len(text))
    rc,full,e2=call(frame(text,kind,1),64+len(want))
    assert rc==0 and full[:64]==out and full[64:]==want,(name,kind,rc,full[64:200],want[:136])
    if short:
     rc,small,_=call(frame(text,kind,1),63+len(want));assert rc==4294967294 and small==b'\xdb'*len(small)
   except BaseException:
    (D/'failure.input').write_bytes(raw);(D/'failure.json').write_text(json.dumps({'name':name,'kind':kind,'rc':rc,'expected_sha256':sha256(want).hexdigest(),'completed':len(rows)},indent=2)+'\n');raise
   rows.append({'name':name,'kind':kind,'codepoints':len(text),'raw_bytes':len(raw)-64,'result_bytes':len(want),'input_sha256':sha256(raw).hexdigest(),'output_sha256':sha256(want).hexdigest(),'native_elapsed_ns':e1+e2,'short_atomic':short,'passed':True})
  if len(rows)%150==0 or len(text)>100000:
   (D/'qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('BG_REPR_CASE',len(rows),name,flush=True)
 for text in ['',"'","\"","'\"","a'b",'a"b','a\'"b','\\','\x00\b\f\t\n\r\x7f','中😀é','\ud800','\ud800\udfff','\ufeff\u2028\u2029\u200d','a\nb\rc\td']:
  run('explicit-'+str(len(rows)),text,short=True)
 for cp in range(256):run('byte-'+str(cp),chr(cp))
 rng=random.Random(0xBF314)
 for i in range(1000):
  s=''.join(chr(rng.randrange(0x110000))for _ in range(rng.randrange(80)))
  if i%3==0:s="'"+s
  if i%7==0:s+='"'
  run('random-'+str(i),s,kinds=(i%3,),short=i%53==0)
 # Every Unicode scalar and surrogate code point passes the actual repr path.
 allpoints=''.join(map(chr,range(0x110000)))
 run('all-1114112-codepoints',allpoints,kinds=(0,2))
 run('no-new-8m-string-limit','x'*8388609,kinds=(0,),short=True)
 invalid=[b'\x80',b'\xc0\x80',b'\xc1\xbf',b'\xc2',b'\xc2 ',b'\xe0\x80\x80',b'\xe0\xa0',b'\xe1\x80 ',b'\xf0\x80\x80\x80',b'\xf0\x90\x80',b'\xf4\x90\x80\x80',b'\xf5\x80\x80\x80',b'\xff']
 guards=[]
 for raw in invalid:
  packet=struct.pack('<8s7Q',b'HIABRP01',0,0,len(raw),0,0,0,0)+raw
  rc,out,_=call(packet,64);assert rc==4294967293 and out==b'\xdb'*64
  guards.append({'case':'invalid-wtf8','input_hex':raw.hex(),'rc':rc,'atomic':True})
 good=frame('x',0)
 for at in [0,8,16,24,32,40,48,56]:
  raw=bytearray(good);struct.pack_into('<Q',raw,at,(1<<64)-1)
  rc,out,_=call(bytes(raw),64);assert rc==4294967293 and out==b'\xdb'*64
  guards.append({'offset':at,'rc':rc,'atomic':True})
 rc,out,_=call(good,63);assert rc==4294967294 and out==b'\xdb'*63;guards.append({'short_header':63,'rc':rc,'atomic':True})
 table=ROOT/'tools/hia_cli_unicode_tables.json'
 report.update(passed=True,total=len(rows),guards=guards,guard_count=len(guards),all_codepoints=0x110000,embedded_table_input_sha256=sha256(table.read_bytes()).hexdigest(),no_aggregate_8m_cap=True)
 (D/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')
 print('BG_REPR_QUALIFIED',len(rows),len(guards),flat.sha,flush=True)
if __name__=='__main__':main()
