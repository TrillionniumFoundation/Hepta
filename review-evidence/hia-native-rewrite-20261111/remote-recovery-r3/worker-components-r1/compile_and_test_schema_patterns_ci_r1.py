"""Fresh bounded compiler and actual HIA proof for the five installed patterns.

This is a complete published-pattern component, not a full schema validator.
It deliberately retains Python re.search '$' semantics before a final LF.
"""
from __future__ import annotations
import ast,ctypes,importlib.util,json,os,random,re,resource,stat,struct,subprocess,sys,time,traceback,zlib
from hashlib import sha1,sha256
from pathlib import Path
from unittest.mock import patch
WORK=Path(sys.argv[1]).resolve();REPO=Path(sys.argv[2]).resolve();OUT=Path(sys.argv[3]).resolve()
ROOT=WORK/'native-agent-schema-next';REFERENCE=WORK/'Hepta-agent-edit-native'
COMPILER=WORK/'dependencies/f50-B3.image.bin'
PINS=[
  {
    "path": "tools/agent_schema_patterns.py",
    "bytes": 4116,
    "sha256": "f8a41b688db6e405fd0ca77ad0406ec561bbb2e3d16fee76a5e1fcadb54244a8",
    "gitsha": "162a0c6971d8eed9569102f878aa13231d9985c0"
  },
  {
    "path": "tools/generate_hia_agent_schema_patterns.py",
    "bytes": 4435,
    "sha256": "22fb5f5e8b190f638fc2be3aa13c2e47cc8024e7dbd2fcebeb50112453ed3eee",
    "gitsha": "eb2921eb86c6e916ea08f68e8f8c4037a07f298c"
  }
]
REFERENCE_PINS=[
  {
    "path": "hepta/hia_agent_contract.py",
    "bytes": 18464,
    "sha256": "5878c0b188cb4a31f486e4a2b6f261a30fb20c06da810cd5f079746956abb2f7"
  },
  {
    "path": "docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json",
    "bytes": 226542,
    "sha256": "61325aadc2fa6740c84037227c9410f5e299267d908cfbbd0be6b05eedfbfbf8"
  }
]
M=lambda s:int.from_bytes(s,'little')
pack=lambda *v:struct.pack('<'+'Q'*len(v),*v)
BAD=0xfffffffd;CANARY=bytes(range(64))
def digest(raw):return sha256(raw).hexdigest()
def gitsha(raw):return sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
def save_json(path,v):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(v,indent=2,sort_keys=True,ensure_ascii=True)+'\n')
def disabled(*args,**kwargs):raise AssertionError('host regex/validator entered actual image interval')
class Buffer:
    def __init__(self,size,raw=b''):
        assert 0<=len(raw)<=size
        self.size=size;self.buf=ctypes.create_string_buffer(size+64)
        if raw:ctypes.memmove(self.address,raw,len(raw))
        ctypes.memmove(self.address+size,CANARY,64)
    @property
    def address(self):return ctypes.addressof(self.buf)
    def raw(self):return ctypes.string_at(self.address,self.size)
    def guard(self):assert ctypes.string_at(self.address+self.size,64)==CANARY
OUT.mkdir(parents=True,exist_ok=False)
ROOT.mkdir(parents=True,exist_ok=False);(ROOT/'tools').mkdir();(ROOT/'examples/hia_bootstrap').mkdir(parents=True)
(OUT/'cas').mkdir()
pins={};saved=set();entries=0;cases=0;status='FAIL';failure=None;manifest=None
started=time.monotonic_ns()
ledger=(OUT/'entries.jsonl').open('w');results=(OUT/'cases.jsonl').open('w')
def read(path):
    p=Path(path).resolve();raw=p.read_bytes()
    if p in pins:assert pins[p]==raw
    pins[p]=raw;return raw
def pinrows():
    return [dict(path=str(p),bytes=len(b),sha256=digest(b),mode=stat.S_IMODE(p.stat().st_mode)) for p,b in pins.items()]
def check():
    for p,b in pins.items():assert p.read_bytes()==b,str(p)
def cas(raw):
    key=digest(raw)
    if key not in saved:
        path=OUT/'cas'/(key+'.zlib');path.write_bytes(zlib.compress(raw,1))
        assert zlib.decompress(path.read_bytes())==raw
        saved.add(key)
    return dict(bytes=len(raw),sha256=key)
def invoke(image,raw,output=64,workspace=4096,label='value'):
    global entries
    sb=Buffer(len(raw),raw);ob=Buffer(output);wb=Buffer(workspace)
    with patch('re.search',new=disabled),patch('hepta.hia_agent_contract.validate',new=disabled):
        value=int(image._entry(sb.address,sb.size,ob.address,ob.size,wb.address,wb.size))
    assert sb.raw()==raw
    for b in (sb,ob,wb):b.guard()
    entries+=1
    ledger.write(json.dumps(dict(entry=entries,label=label,status=value,input=cas(raw),
        output=cas(ob.raw()),workspace=cas(wb.raw())),sort_keys=True)+'\n');ledger.flush()
    return value,ob.raw()
def values():
    result=['','\n','\n\n','0','00','01','1','a','a\n','a\r\n',' a','a ','a~','a/._:-',
            'hia://artifacts/a','hia://artifacts/a\n','hia://artifacts/a/','hia://artifacts/_a',
            'f'*64,'f'*64+'\n','F'*64,'ff','ff\n','fff','0'*20,'1'+'0'*19,'1'+'0'*20]
    cps=[*range(256),0x3b1,0x660,0x200d,0x2028,0x2029,0xd7ff,0xd800,0xdfff,0xe000,0xfffd,0xffff,0x10000,0x1f600,0x10ffff]
    for cp in cps:
        ch=chr(cp);result.extend((ch,'a'+ch,ch+'a','hia://artifacts/'+ch,'f'*31+ch+'f'*32))
    for n in (0,1,19,20,21,63,64,65,190,191,192,193):
        for seed in ('a','0','f'):
            result.extend((seed*n,seed*n+'\n','hia://artifacts/'+seed*n,'hia://artifacts/'+seed*n+'\n'))
    rng=random.Random(20261111)
    alphabet='abcXYZ019fF_~:./-\n\r'+'éΩ😀'
    for _ in range(200):result.append(''.join(rng.choice(alphabet) for _ in range(rng.randrange(0,50))))
    return list(dict.fromkeys(result))
try:
    assert len(read(COMPILER))==668608 and digest(read(COMPILER))=='0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8'
    for row in REFERENCE_PINS:
        raw=read(REFERENCE/row['path'])
        assert (len(raw),digest(raw))==(row['bytes'],row['sha256'])
    for row in PINS:
        raw=subprocess.check_output(['/usr/bin/git','cat-file','blob',row['gitsha']],cwd=REPO)
        assert (len(raw),digest(raw),gitsha(raw))==(row['bytes'],row['sha256'],row['gitsha'])
        ast.parse(raw);p=ROOT/row['path'];p.write_bytes(raw);read(p)
    read(Path(__file__))
    for path in ('tools/qualify_hia_selfhost.py','tools/generate_hia_selfhost.py',
                 'hepta/hia_agent_assembly.py','hepta/hia_program.py','hepta/hia_json_preflight_native.py'):
        read(REFERENCE/path)
    save_json(OUT/'source-before.json',pinrows());check()
    sys.path[:0]=[str(ROOT/'tools'),str(REFERENCE)]
    from generate_hia_agent_schema_patterns import document,inventory
    from agent_schema_patterns import PATTERNS
    from hepta.hia_agent_assembly import render_assembly,assemble_program
    from tools.qualify_hia_selfhost import compile_stage
    from hepta.hia_json_preflight_native import NativeHiaJsonImage
    doc=document();fs=doc['functions']
    counts=dict(functions=len(fs),blocks=sum(len(f['blocks']) for f in fs),
        instructions=sum(len(b['ops']) for f in fs for b in f['blocks']),
        max_function_blocks=max(len(f['blocks']) for f in fs),
        max_block_parameters=max(len(b['params']) for f in fs for b in f['blocks']))
    raw=render_assembly(doc).encode();assemble_program(raw)
    src=ROOT/'examples/hia_bootstrap/agent_schema_patterns.hiaasm';src.write_bytes(raw);read(src)
    image_path,receipt=compile_stage(OUT,'agent-schema-patterns',COMPILER,raw)
    image_bytes=read(image_path);receipt_path=OUT/'agent-schema-patterns.receipt.json'
    actual=json.loads(read(receipt_path))
    assert (actual['input_sha256'],actual['produced_sha256'],actual['image_sha256'])==(digest(raw),digest(image_bytes),digest(read(COMPILER)))
    manifest=dict(schema='hepta.hia.agent-schema-patterns-development.v1',source_path=str(src),source_bytes=len(raw),
       source_sha256=digest(raw),image_path=str(image_path),image_bytes=len(image_bytes),image_sha256=digest(image_bytes),
       compiler_path=str(COMPILER),compiler_sha256=digest(read(COMPILER)),receipt_path=str(receipt_path),inventory=inventory())
    save_json(OUT/'patterns.manifest.json',manifest)
    check()
    resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    image=NativeHiaJsonImage(image_bytes,digest(image_bytes))
    for pat_id,pat in enumerate(PATTERNS,1):
        p=pat.encode('ascii')
        for value in values():
            expected=re.search(pat,value) is not None
            vb=value.encode('utf-8','surrogatepass')
            command=pack(M(b'HIARXC01'),1,cases+1,len(p),len(vb),64+len(p)+len(vb),0,0)+p+vb
            status_code,out=invoke(image,command,label='pattern-'+str(pat_id))
            assert status_code==64
            frame=struct.unpack('<8Q',out)
            assert frame==(M(b'HIARXR01'),1,cases+1,int(expected),pat_id,len(vb),0,0),(pat_id,repr(value),expected,frame)
            results.write(json.dumps(dict(case=cases+1,pattern=pat_id,value=value,matched=expected),ensure_ascii=True)+'\n')
            cases+=1
    for value in ('a'*2097152,'ab'*1048576,('ab'*1048576)+'\n',('ab'*1048576)+'f'):
        pat=PATTERNS[4];pb=pat.encode();vb=value.encode()
        expected=re.search(pat,value) is not None
        command=pack(M(b'HIARXC01'),1,cases+1,len(pb),len(vb),64+len(pb)+len(vb),0,0)+pb+vb
        rc,out=invoke(image,command,label='full-published-buffer-pattern')
        assert rc==64 and struct.unpack('<8Q',out)==(M(b'HIARXR01'),1,cases+1,int(expected),5,len(vb),0,0)
        results.write(json.dumps(dict(case=cases+1,pattern=5,value_bytes=len(vb),value_sha256=digest(vb),matched=expected))+'\n')
        cases+=1
    pb=PATTERNS[0].encode();vb=b'a'
    header=[M(b'HIARXC01'),7,8,len(pb),len(vb),64+len(pb)+len(vb),0,0]
    for index,new in ((0,0),(1,0),(2,0),(3,1<<63),(4,2),(5,1),(6,1),(7,1)):
        h=header.copy();h[index]=new;raw=pack(*h)+pb+vb
        rc,out=invoke(image,raw,label='invalid-header-'+str(index))
        assert rc==BAD and out==bytes(64);cases+=1
    unknown=b'.*';raw=pack(M(b'HIARXC01'),7,8,len(unknown),1,65+len(unknown),0,0)+unknown+b'a'
    rc,out=invoke(image,raw,label='unsupported-schema-is-private')
    assert rc==BAD and out==bytes(64);cases+=1
    rc,out=invoke(image,pack(*header)+pb+vb,output=63,label='short-output')
    assert rc==BAD and out==bytes(63);cases+=1
    rc,out=invoke(image,b'\0'*63,label='short-input')
    assert rc==BAD and out==bytes(64);cases+=1
    check();status='PASS'
except BaseException as exc:
    failure=dict(error_class=type(exc).__name__,error=str(exc));traceback.print_exc()
finally:
    ledger.close();results.close()
    try:check();unchanged=True
    except BaseException:unchanged=False;status='FAIL';traceback.print_exc()
    save_json(OUT/'source-after.json',pinrows())
    summary=dict(status=status,scope='FIVE_PUBLISHED_PATTERNS_ONLY_NOT_COMPLETE_SCHEMA',
        cases=cases,entries=entries,source_unchanged=unchanged,manifest=manifest,failure=failure,
        original_limits_unchanged=True,whole_worker_closed=False,complete_schema_validator=False,
        elapsed_ns=time.monotonic_ns()-started)
    save_json(OUT/'summary.json',summary);print(json.dumps(summary,sort_keys=True),flush=True)
if status!='PASS':raise SystemExit(1)
