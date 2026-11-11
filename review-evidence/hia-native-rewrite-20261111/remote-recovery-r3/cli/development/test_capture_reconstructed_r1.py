"""New reconstruction verification. Actual HIA image; Python is independent oracle only."""
from pathlib import Path
from hashlib import sha256
import ctypes as C,json,os,random,struct,sys,zlib,traceback,unicodedata
BASE=Path('/var/tmp/hia9acdfa-native-resume-a3c61136-20261111')
PROJECT=BASE/'cli-recovery/workspace/native-hia-cli-next'
sys.path.insert(0,str(BASE/'source'));sys.dont_write_bytecode=True
from hepta.hia_json_preflight_native import NativeHiaJsonImage
MANIFEST=PROJECT/'development/capture-reconstructed-compile-r1/cli-capture.manifest.json'
OUT=PROJECT/'development/capture-reconstructed-native-r1'
OUT.mkdir(exist_ok=False);(OUT/'cas').mkdir()
assert sys.version_info[:3]==(3,12,14) and unicodedata.unidata_version=='15.0.0'
mraw=MANIFEST.read_bytes();m=json.loads(mraw)
source=Path(m['source']);image=Path(m['image']);sraw=source.read_bytes();iraw=image.read_bytes()
assert sha256(sraw).hexdigest()==m['source_sha256'] and sha256(iraw).hexdigest()==m['image_sha256']
pins={str(p):sha256(raw).hexdigest() for p,raw in [(MANIFEST,mraw),(source,sraw),(image,iraw),(Path(__file__),Path(__file__).read_bytes())]}
(OUT/'source-before.json').write_text(json.dumps(pins,sort_keys=True,indent=2)+'\n')
native=NativeHiaJsonImage(iraw,expected_sha256=m['image_sha256'])
magic=lambda x:int.from_bytes(x,'little')
IMM=magic(b'HIACOS01');ARG=magic(b'HIACLA01');EVENT=magic(b'HIACOE01')
BAD=0xfffffffd;GROW=0xfffffffe;MASK=(1<<64)-1
GUARD=b'CAPTURE-CANARY-FIXED-32-BYTES!!!'
assert len(GUARD)==32
entries=0;cases=[];ledger=(OUT/'entries.jsonl').open('w')
def cas(raw):
 raw=bytes(raw);h=sha256(raw).hexdigest();p=OUT/'cas'/(h+'.zlib')
 if not p.exists():p.write_bytes(zlib.compress(raw,6))
 assert zlib.decompress(p.read_bytes())==raw
 return {'sha256':h,'bytes':len(raw),'compression':'zlib','path':'cas/'+p.name}
def invoke(raw,work,label):
 global entries
 a=C.create_string_buffer(raw+GUARD);o=C.create_string_buffer(bytes(128)+GUARD);w=C.create_string_buffer(bytes(work)+GUARD)
 entries+=1;record={'entry':entries,'label':label,'input':cas(raw),'output_before':cas(bytes(128)),'workspace_before':cas(work),'state':'ENTER'}
 ledger.write(json.dumps(record,sort_keys=True)+'\n');ledger.flush()
 ret=int(native._entry(C.addressof(a),len(raw),C.addressof(o),128,C.addressof(w),len(work)))
 assert a.raw[:len(raw)]==raw and a.raw[len(raw):len(raw)+32]==GUARD
 assert o.raw[128:160]==GUARD and w.raw[len(work):len(work)+32]==GUARD
 result=w.raw[:len(work)]
 record.update(state='RETURN',ret=ret,output_after=cas(o.raw[:128]),workspace_after=cas(result))
 ledger.write(json.dumps(record,sort_keys=True)+'\n');ledger.flush()
 return ret,result
def packet(argv,env=(),tty=(0,0,25)):
 rows=[];values=list(argv)+list(env);at=96+16*len(values);raw=bytearray(struct.pack('<12Q',IMM,1,len(argv),len(env),96,at,at+sum(map(len,values)),*tty,0,0))
 for value in values:raw+=struct.pack('<2Q',at,len(value));at+=len(value)
 return bytes(raw)+b''.join(values)
def expected(argv,env,tty):
 width=None
 for raw in env:
  if raw.startswith(b'COLUMNS='):
   try:
    x=int(os.fsdecode(raw[8:]));width=min(x,MASK) if x>0 else None
   except (ValueError,UnicodeError):pass
   break
 if width is None:width=tty[0] if tty[2]==0 and tty[0]>0 else 80
 args=[os.fsdecode(x).encode('utf-8','surrogatepass') for x in argv[1:]]
 at=64+16*len(args);head=struct.pack('<8Q',ARG,1,len(args),64,at,at+sum(map(len,args)),width,0)
 rows=b''
 for value in args:rows+=struct.pack('<2Q',at,len(value));at+=len(value)
 return head+rows+b''.join(args)
def run_case(label,argv,env=(),tty=(0,0,25)):
 raw=packet(argv,env,tty);work=bytes(1024);steps=0
 while True:
  ret,work=invoke(raw,work,label);steps+=1;e=struct.unpack_from('<16Q',work,256)
  assert e[0]==EVENT
  if ret==GROW:
   assert e[1]==1 and e[6]>len(work);work+=bytes(e[6]-len(work));continue
  assert ret==128 and e[1]==0,(label,ret,e)
  got=work[e[2]:e[2]+e[3]];want=expected(argv,env,tty)
  assert got==want,(label,got.hex(),want.hex())
  cases.append({'label':label,'actual':cas(got),'expected':cas(want),'entries':steps});return
def bad_case(label,raw,after_growth=False,mutate=None):
 work=bytes(1024)
 if after_growth:
  ret,work=invoke(packet([b'hia',b'help']),work,label+'-prefix');assert ret==GROW
  e=struct.unpack_from('<16Q',work,256);work+=bytes(e[6]-len(work))
 if mutate is not None:raw=mutate(raw)
 ret,work=invoke(raw,work,label);assert ret==BAD,(label,ret)
 ret,work=invoke(packet([b'hia',b'--help']),work,label+'-followup');assert ret==BAD
 cases.append({'label':label,'private_protocol':'BAD_AND_PERMANENT','input':cas(raw)})
try:
 rawcases=[[],[b'hia'],[b'hia',b'--help'],[b'hia',b'\xff'],[b'hia',b'\xed\xa0\x80\xed\xbf\xbf'],[b'hia',b'\xf4\x90\x80\x80'],[b'hia',bytes(range(1,256))],[b'hia',b'\xc0\x80\xe0\x80\x80\xf0\x80\x80\x80']]
 for i,v in enumerate(rawcases):run_case('raw-'+str(i),v)
 rng=random.Random(0x43415054555245)
 for i in range(240):
  values=[b'hia']+[bytes(rng.randrange(1,256) for _ in range(rng.randrange(0,96))) for _ in range(rng.randrange(0,9))]
  run_case('random-'+str(i),values)
 widths=['','0','-0','-1','+1','80','1_000','1__0','_1','1_',' 80 ','\x1c80','\x8580\x85','\u200380\u2003','\u300080','\u00a080','18446744073709551615','18446744073709551616','9'*4300,'9'*4301]
 widths+=[''.join(chr(cp+j) for j in (1,2,3)) for cp in range(0x110000) if unicodedata.category(chr(cp))=='Nd' and unicodedata.decimal(chr(cp))==0]
 for i,value in enumerate(widths):run_case('columns-'+str(i),[b'hia',b'--help'],[b'COLUMNS='+value.encode('utf-8')])
 run_case('columns-invalid-utf8',[b'hia'],[b'COLUMNS=\xff'])
 run_case('columns-duplicate-first',[b'hia'],[b'COLUMNS=20',b'COLUMNS=30'])
 run_case('columns-duplicate-invalid-first',[b'hia'],[b'COLUMNS=bad',b'COLUMNS=30'],(91,30,0))
 for i,tty in enumerate([(0,0,0),(1,24,0),(131,41,0),(131,41,25)]):run_case('tty-'+str(i),[b'hia'],[],tty)
 run_case('ten-thousand-argv',[b'hia']+[b'x']*10000)
 good=packet([b'hia',b'--help'])
 mutations=[(0,0),(8,2),(16,MASK),(24,MASK),(32,0),(40,97),(48,len(good)-1),(80,1),(88,1),(96,0),(104,MASK)]
 for i,(at,value) in enumerate(mutations):
  raw=bytearray(good);struct.pack_into('<Q',raw,at,value);bad_case('header-'+str(i),bytes(raw))
 bad_case('truncated',good[:20]);bad_case('nul',packet([b'hia',b'\x00']))
 old=packet([b'hia',b'help']);changed=bytearray(old);struct.pack_into('<Q',changed,56,81)
 bad_case('grow-changed-header',bytes(changed),True)
 summary={'status':'PASS','scope':'NEW_RECONSTRUCTION_ACTUAL_IMAGE_NOT_OLD_RUN_NOT_COLD','cases':len(cases),'public_cases':sum('private_protocol' not in x for x in cases),'private_controls':sum('private_protocol' in x for x in cases),'actual_entries':entries,'source_manifest':str(MANIFEST),'cases_detail':cases,'python':sys.version,'unicode_version':unicodedata.unidata_version}
 (OUT/'summary.json').write_text(json.dumps(summary,sort_keys=True,indent=2)+'\n')
 print(json.dumps({k:v for k,v in summary.items() if k!='cases_detail'},sort_keys=True))
except BaseException:
 (OUT/'failure.txt').write_text(traceback.format_exc());raise
finally:
 ledger.close()
 after={p:sha256(Path(p).read_bytes()).hexdigest() for p in pins}
 (OUT/'source-after.json').write_text(json.dumps(after,sort_keys=True,indent=2)+'\n');assert pins==after
