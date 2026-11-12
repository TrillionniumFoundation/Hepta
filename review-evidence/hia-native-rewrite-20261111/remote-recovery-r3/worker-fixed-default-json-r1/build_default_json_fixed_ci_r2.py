"""Fresh bounded generation, B3 compilation and actual HIA ELF packing.

New fixed default-DataJSON component, not an ordinary Worker activation.
All original peer images must have been compiled in this same independent run.
"""
from __future__ import annotations
import ast,ctypes,json,os,resource,stat,struct,subprocess,sys,time,traceback,zlib
from hashlib import sha1,sha256
from pathlib import Path
sys.dont_write_bytecode=True
WORK=Path(sys.argv[1]).resolve();REPO=Path(sys.argv[2]).resolve()
PEERS=Path(sys.argv[3]).resolve();OUT=Path(sys.argv[4]).resolve()
ROOT=WORK/'native-agent-default-json-fixed-next';REFERENCE=WORK/'Hepta-agent-edit-native'
COMPILER=WORK/'dependencies/f50-B3.image.bin'
PINS=[
  {
    "path": "tools/agent_default_json_fixed_common.py",
    "bytes": 9004,
    "sha256": "b43072d63f1c64b638e351cf199e0533cf3031ac18d3b803598d024661f415cb",
    "gitsha": "671c92a6dea7f065a3036e88e5c93470c50a1ae5"
  },
  {
    "path": "tools/agent_default_json_fixed_flow.py",
    "bytes": 18838,
    "sha256": "0d332f4a1d398fd0674cc22af27484f88ab72e2d25c0eea7b463878aafb132e0",
    "gitsha": "f4048e45e8d0db3fc2a6b3e567464d10a9c38294"
  },
  {
    "path": "tools/generate_hia_agent_default_json_fixed.py",
    "bytes": 4509,
    "sha256": "e3c03556257af6a30f8cc92db6f4988c6174ab51e97724c77960825bba14fdb0",
    "gitsha": "3e0aba2c9f2a0dcf21e8a7fc06a18303c5c5cebe"
  },
  {
    "path": "tools/agent_default_json_fixed_executor.S",
    "bytes": 10943,
    "sha256": "8fb44dd5be96f24b8a9e79a46029405bc8cad86a9a042e4b2d623aeca4120a0f",
    "gitsha": "31830b86bbfa60f396c66e1d1be59b7d0f243350"
  },
  {
    "path": "tools/generate_hia_agent_default_json_fixed_packer.py",
    "bytes": 6218,
    "sha256": "cfb015f85f019789e7bdabc7253809838f7dca9284a748864a99b046203ccd28",
    "gitsha": "99fd3313b1f0c379dcf003821672c2f07e1c6c95"
  },
  {
    "path": "tools/agent_fixed_authoring.py",
    "bytes": 2467,
    "sha256": "e86be00d7ab84c6b54c0ea9f4d8e4dc3284b9a3cf27925c07309ec668756876a",
    "gitsha": "10708685e352f517c403bccc79f420234a00f0ac"
  },
  {
    "path": "docs/HIA_DEFAULT_JSON_FIXED_COMPONENT_R1.md",
    "bytes": 9976,
    "sha256": "9209ec700e0b20220ce317b676825a1b5db2f56d8871814923ff135337de20e8",
    "gitsha": "7846eac071b948d8b69243ed63bb35770db1c615"
  }
]
COMPILER_SHA='0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8'
ROLE_NAMES=('default_json_raw','default_json_services','default_json_late',
            'preflight','decoder','data_graph','binary64')
BAD=0xfffffffd;CAPACITY=0xfffffffe;CANARY=bytes(range(64))
resource.setrlimit(resource.RLIMIT_CPU,(90,90))
resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
OUT.mkdir(parents=True,exist_ok=False);ROOT.mkdir(parents=True,exist_ok=False)
(ROOT/'tools').mkdir();(ROOT/'examples/hia_bootstrap').mkdir(parents=True)
(OUT/'cas').mkdir()
pins={};modes={};saved=set();rows={};entries=0;status='FAIL';failure=None
ledger=(OUT/'packer-entries.jsonl').open('w')
start=time.monotonic_ns()
def digest(raw):return sha256(raw).hexdigest()
def gitsha(raw):return sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def read(path):
    path=Path(path).resolve();raw=path.read_bytes();mode=stat.S_IMODE(path.stat().st_mode)
    if path in pins:assert pins[path]==raw and modes[path]==mode
    pins[path]=raw;modes[path]=mode;return raw
def pinrows():
    return [dict(path=str(p),bytes=len(raw),sha256=digest(raw),mode=modes[p])
        for p,raw in pins.items()]
def unchanged():
    return all(p.is_file() and p.read_bytes()==raw and stat.S_IMODE(p.stat().st_mode)==modes[p]
        for p,raw in pins.items())
def cas(raw):
    raw=bytes(raw);h=digest(raw)
    if h not in saved:
        path=OUT/'cas'/(h+'.zlib')
        path.write_bytes(zlib.compress(raw,1))
        assert zlib.decompress(path.read_bytes())==raw
        saved.add(h)
    return dict(sha256=h,bytes=len(raw))
class Buffer:
    def __init__(self,n,raw=b'',fill=0):
        assert len(raw)<=n
        self.n=n;self.buf=ctypes.create_string_buffer(n+128)
        self.base=ctypes.addressof(self.buf);self.p=self.base+64
        ctypes.memmove(self.base,CANARY,64)
        ctypes.memmove(self.p+n,CANARY,64)
        if n:ctypes.memset(self.p,fill,n)
        if raw:ctypes.memmove(self.p,raw,len(raw))
    def raw(self):return ctypes.string_at(self.p,self.n)
    def guard(self):
        assert ctypes.string_at(self.base,64)==CANARY
        assert ctypes.string_at(self.p+self.n,64)==CANARY
def bounded_compile(role,path,counts):
    source=read(path)
    image,_=compile_stage(OUT,role,COMPILER,source)
    image=Path(image).resolve();raw=read(image)
    receipt_path=OUT/(role+'.receipt.json');receipt=json.loads(read(receipt_path))
    assert receipt['input_sha256']==digest(source)
    assert receipt['produced_sha256']==digest(raw)
    assert receipt['image_sha256']==COMPILER_SHA
    row=dict(role=role,source_path=str(path),source_bytes=len(source),
        source_sha256=digest(source),image_path=str(image),image_bytes=len(raw),
        image_sha256=digest(raw),receipt_path=str(receipt_path),
        compiler_sha256=COMPILER_SHA,counts=counts)
    rows[role]=row;save(OUT/(role+'.manifest.json'),row)
    return row
def pack_call(image,label,raw,capacity,expected):
    global entries
    s=Buffer(len(raw),raw);o=Buffer(capacity,fill=0xa5);w=Buffer(64)
    before=(s.raw(),o.raw(),w.raw())
    save(OUT/'pending-packer-entry.json',dict(label=label,ordinal=entries+1,
        source=cas(before[0]),output_before=cas(before[1]),workspace_before=cas(before[2])))
    returned=int(image._entry(s.p,s.n,o.p,o.n,w.p,w.n))
    entries+=1
    assert s.raw()==before[0]
    for b in (s,o,w):b.guard()
    after=(o.raw(),w.raw())
    ledger.write(json.dumps(dict(label=label,entry=entries,returned=returned,
        source=cas(before[0]),output_before=cas(before[1]),workspace_before=cas(before[2]),
        output_after=cas(after[0]),workspace_after=cas(after[1]),
        readonly_input_and_canaries_unchanged=True),sort_keys=True)+'\n');ledger.flush()
    assert returned==expected,(label,returned,expected)
    if expected in (BAD,CAPACITY):assert after==before[1:],label
    return after[0]
try:
    assert (len(read(COMPILER)),digest(read(COMPILER)))==(668608,COMPILER_SHA)
    read(__file__)
    for row in PINS:
        raw=subprocess.check_output(['/usr/bin/git','cat-file','blob',row['gitsha']],cwd=REPO)
        assert (len(raw),digest(raw),gitsha(raw))==(row['bytes'],row['sha256'],row['gitsha'])
        target=ROOT/row['path'];target.parent.mkdir(parents=True,exist_ok=True)
        if target.suffix=='.py':ast.parse(raw,filename=str(target))
        target.write_bytes(raw);read(target)
    for relative in ('tools/generate_hia_selfhost.py','tools/hia_agent_edit_source_views.py',
        'tools/qualify_hia_selfhost.py','hepta/hia_program.py',
        'hepta/hia_agent_assembly.py','hepta/hia_json_preflight_native.py'):
        read(REFERENCE/relative)
    bundle=json.loads(read(PEERS/'bundle.json'))
    assert bundle['schema']=='hia-agent-default-json-development-bundle-v1' and bundle['status']=='PASS'
    assert set(bundle['components'])==set(ROLE_NAMES)
    images=[]
    for role in ROLE_NAMES:
        row=bundle['components'][role]
        assert row['role']==role and row['compiler_sha256']==COMPILER_SHA
        raw=read(row['source_path']);image=read(row['image_path'])
        receipt=json.loads(read(row['receipt_path']))
        assert (len(raw),digest(raw))==(row['source_bytes'],row['source_sha256'])
        assert (len(image),digest(image))==(row['image_bytes'],row['image_sha256'])
        assert receipt['input_sha256']==digest(raw) and receipt['produced_sha256']==digest(image)
        assert receipt['image_sha256']==COMPILER_SHA
        # Role manifests must point into this run's fresh compile outputs.
        assert Path(row['image_path']).resolve().parent==PEERS
        assert 0<len(image)<=1048576
        images.append(image);rows[role]=row
    sys.path[:0]=[str(ROOT/'tools'),str(REFERENCE)]
    from hepta.hia_agent_assembly import render_assembly,assemble_program
    from hepta.hia_json_preflight_native import NativeHiaJsonImage
    from tools.qualify_hia_selfhost import compile_stage
    import generate_hia_agent_default_json_fixed as gen
    import generate_hia_agent_default_json_fixed_packer as packer
    from agent_fixed_authoring import document,profile
    (OUT/'driver.expanded-authoring.py').write_text(gen.source_program())
    doc=gen.document();raw=render_assembly(doc).encode('utf-8');assemble_program(raw)
    path=ROOT/'examples/hia_bootstrap/agent_default_json_fixed_driver.hiaasm'
    path.write_bytes(raw);driver=bounded_compile('fixed_default_driver',path,profile(doc))
    images.append(read(driver['image_path']))
    assert len(images)==8 and all(0<len(image)<=1048576 for image in images)
    template_out=OUT/'template';template_out.mkdir()
    prefix,table,original=packer.template(ROOT/'tools/agent_default_json_fixed_executor.S',template_out)
    (template_out/'prefix.bin').write_bytes(prefix)
    authored=packer.source(prefix,table);(OUT/'packer.expanded-authoring.py').write_text(authored)
    doc=document(authored,'agent_default_json_fixed_packer')
    raw=render_assembly(doc).encode('utf-8');assemble_program(raw)
    path=ROOT/'examples/hia_bootstrap/agent_default_json_fixed_packer.hiaasm'
    path.write_bytes(raw);packed_row=bounded_compile('fixed_default_packer',path,profile(doc))
    expected=bytearray(prefix)
    for role,image in enumerate(images,1):
        expected.extend(bytes((-len(expected))%16))
        struct.pack_into('<Q',expected,table+role*8,0x400000+len(expected))
        expected.extend(image)
    struct.pack_into('<QQ',expected,96,len(expected),len(expected))
    expected=bytes(expected)
    packet=struct.pack('<16Q',int.from_bytes(b'HIAGFP01','little'),1,8,
        128+sum(map(len,images)),64,0,0,0,*map(len,images))+b''.join(images)
    (OUT/'packer-input.bin').write_bytes(packet)
    save(OUT/'layout.json',dict(prefix_bytes=len(prefix),prefix_sha256=digest(prefix),
        image_table=table,roles=list(ROLE_NAMES)+['fixed_default_driver'],
        expected_bytes=len(expected),expected_sha256=digest(expected)))
    assert unchanged()
    save(OUT/'source-before-native.json',pinrows())
    actual_packer=NativeHiaJsonImage(read(packed_row['image_path']),packed_row['image_sha256'])
    actual=pack_call(actual_packer,'complete-ELF',packet,len(expected),len(expected))
    assert actual==expected
    executable=OUT/'hia-default-json';executable.write_bytes(actual);executable.chmod(0o755)
    read(executable)
    pack_call(actual_packer,'output-minus-one',packet,len(expected)-1,CAPACITY)
    for word,value in ((0,0),(1,2),(2,7),(3,len(packet)+1),(4,65),(5,1),(6,1),(7,1),
                       (8,0),(15,1048577)):
        changed=bytearray(packet);struct.pack_into('<Q',changed,word*8,value)
        pack_call(actual_packer,'invalid-header-'+str(word),bytes(changed),len(expected),BAD)
    pack_call(actual_packer,'truncated-header',packet[:127],len(expected),BAD)
    pack_call(actual_packer,'trailing-payload',packet+b'\0',len(expected),BAD)
    save(OUT/'bundle.json',dict(schema='hia-default-json-fixed-development-bundle-v1',
        status='PASS',roles={str(i+1):rows[role] for i,role in enumerate((*ROLE_NAMES,'fixed_default_driver'))},
        packer=packed_row,executable_path=str(executable),executable_bytes=len(actual),
        executable_sha256=digest(actual),executor_path=str(ROOT/'tools/agent_default_json_fixed_executor.S'),
        executor_sha256=digest(original),compiler_sha256=COMPILER_SHA,
        runtime_python_dispatch=False,whole_worker_closed=False,production_activation=False))
    status='PASS'
except BaseException as exc:
    failure=dict(error_class=type(exc).__name__,error=str(exc));traceback.print_exc()
finally:
    ledger.close()
    same=unchanged()
    if not same:status='FAIL'
    for i,(path,raw) in enumerate(pins.items()):
        frozen=OUT/'frozen-inputs'/str(i)/path.name
        frozen.parent.mkdir(parents=True,exist_ok=True);frozen.write_bytes(raw)
        frozen.chmod(modes[path])
    save(OUT/'source-after.json',pinrows())
    summary=dict(status=status,scope='NEW_FIXED_DEFAULT_JSON_BUILD_AND_ACTUAL_HIA_PACK',
        failure=failure,source_unchanged=same,new_compiler_roles=[x for x in rows if x.startswith('fixed_')],
        packer_actual_entries=entries,elapsed_ns=time.monotonic_ns()-start,
        executable_semantics_tested=False,old_default_component_tests_inherited=False,
        compiler_limits=dict(cpu_seconds=10,wall_seconds=20,address_space_bytes=256<<20),
        packer_test_limits=dict(cpu_seconds=90,address_space_bytes=1<<30),
        whole_worker_closed=False,production_activation=False)
    save(OUT/'summary.json',summary);print(json.dumps(summary,sort_keys=True),flush=True)
if status!='PASS':raise SystemExit(1)
