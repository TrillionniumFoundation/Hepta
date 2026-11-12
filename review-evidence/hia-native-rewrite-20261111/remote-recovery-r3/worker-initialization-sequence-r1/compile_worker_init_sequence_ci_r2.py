"""Fresh original-limit B3 compilation of the complete initializer sequence."""
from __future__ import annotations
import ast,json,stat,subprocess,sys,time,traceback
from hashlib import sha1,sha256
from pathlib import Path
sys.dont_write_bytecode=True
WORK=Path(sys.argv[1]).resolve();REPO=Path(sys.argv[2]).resolve();OUT=Path(sys.argv[3]).resolve()
ROOT=WORK/'native-agent-initialization-sequence-next';REFERENCE=WORK/'Hepta-agent-edit-native'
COMPILER=WORK/'dependencies/f50-B3.image.bin'
COMPILER_SHA='0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8'
PINS=[
  {
    "path": "tools/generate_hia_agent_worker_init_sequence.py",
    "bytes": 34300,
    "sha256": "fad447d45d40494f04280ca100f1ce1abf5e5651bce4feba8cedcfcdbdae06ef",
    "gitsha": "f9cd612bad5707d95acef736afe03b6600724d9b"
  },
  {
    "path": "docs/HIA_WORKER_INITIALIZATION_SEQUENCE_ABI_R3.md",
    "bytes": 14808,
    "sha256": "376d43332395f7fada5f1a8b289bd7cedc475bb0ee6147b3a5fbc91f8df04c01",
    "gitsha": "5b6ddbb6176760f0ceff587c69de6ea6deda82f6"
  },
  {
    "path": "development/value_mechanics_source.py",
    "bytes": 27233,
    "sha256": "1602df39c9dd982e42ece64379e76fc9ca123b7ca407e84d7f4ded767bebf753",
    "gitsha": "b12248a7ad4aa4875e78af33922182b3fffc1636"
  }
]
OUT.mkdir(parents=True,exist_ok=False);ROOT.mkdir(parents=True,exist_ok=False)
(ROOT/'tools').mkdir();(ROOT/'examples/hia_bootstrap').mkdir(parents=True)
pins={};modes={};components={};status='FAIL';failure=None;counts=None;started=time.monotonic_ns()
def digest(raw):return sha256(raw).hexdigest()
def gitsha(raw):return sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def read(path):
    path=Path(path).resolve();raw=path.read_bytes();mode=stat.S_IMODE(path.stat().st_mode)
    if path in pins:assert pins[path]==raw and modes[path]==mode
    pins[path]=raw;modes[path]=mode;return raw
def rows():
    return [dict(path=str(path),bytes=len(raw),sha256=digest(raw),mode=modes[path])
        for path,raw in pins.items()]
def same():
    return all(path.is_file() and path.read_bytes()==raw
        and stat.S_IMODE(path.stat().st_mode)==modes[path] for path,raw in pins.items())
try:
    read(__file__)
    assert (len(read(COMPILER)),digest(read(COMPILER)))==(668608,COMPILER_SHA)
    for row in PINS:
        raw=subprocess.check_output(['/usr/bin/git','cat-file','blob',row['gitsha']],cwd=REPO)
        assert (len(raw),digest(raw),gitsha(raw))==(row['bytes'],row['sha256'],row['gitsha'])
        path=ROOT/row['path'];path.parent.mkdir(parents=True,exist_ok=True)
        if path.suffix=='.py':ast.parse(raw,filename=str(path))
        with path.open('xb') as out:out.write(raw)
        read(path)
    for name in ('tools/generate_hia_selfhost.py','tools/hia_agent_edit_source_views.py',
        'tools/qualify_hia_selfhost.py','hepta/hia_program.py','hepta/hia_agent_assembly.py',
        'hepta/hia_agent_service.py','hepta/hia_agent_store.py','hepta/hia_json_preflight_native.py'):
        read(REFERENCE/name)
    assert digest(read(REFERENCE/'hepta/hia_agent_service.py'))=='684caf496de7e3e7c8db1fd80ef616139cf13717aa5879bbd2d6ebf834df9330'
    sys.path[:0]=[str(ROOT/'tools'),str(REFERENCE)]
    import generate_hia_agent_worker_init_sequence as generation
    from hepta.hia_agent_assembly import assemble_program,render_assembly
    from tools.qualify_hia_selfhost import compile_stage
    (OUT/'sequence.expanded-authoring.py').write_text(generation.source_program())
    value=generation.document();fs=value['functions']
    counts=dict(functions=len(fs),blocks=sum(len(f['blocks']) for f in fs),
        instructions=sum(len(b['ops']) for f in fs for b in f['blocks']),
        max_function_blocks=max(len(f['blocks']) for f in fs),
        max_block_parameters=max(len(b['params']) for f in fs for b in f['blocks']))
    assert all(a<=b for a,b in zip(counts.values(),(128,1536,8192,256,16))),counts
    raw=render_assembly(value).encode();assemble_program(raw)
    path=ROOT/'examples/hia_bootstrap/agent_worker_initialization_sequence.hiaasm'
    path.write_bytes(raw);source=read(path)
    image,_=compile_stage(OUT,'sequence',COMPILER,source)
    image=Path(image).resolve();image_raw=read(image)
    receipt_path=OUT/'sequence.receipt.json';receipt=json.loads(read(receipt_path))
    assert receipt['input_sha256']==digest(source) and receipt['produced_sha256']==digest(image_raw)
    assert receipt['image_sha256']==COMPILER_SHA
    row=dict(role='sequence',source_path=str(path),source_bytes=len(source),source_sha256=digest(source),
        image_path=str(image),image_bytes=len(image_raw),image_sha256=digest(image_raw),
        receipt_path=str(receipt_path),compiler_sha256=COMPILER_SHA,counts=counts)
    components['sequence']=row;save(OUT/'sequence.manifest.json',row)
    for module in tuple(sys.modules.values()):
        file=getattr(module,'__file__',None)
        if file:
            candidate=Path(file).resolve()
            if candidate.suffix=='.py' and candidate.is_relative_to(REFERENCE):read(candidate)
    assert same()
    save(OUT/'bundle.json',dict(schema='hia-worker-initialization-sequence-development-v1',
        status='PASS',components=components,original_compiler_sha256=COMPILER_SHA,
        actual_semantic_peer_joins=0,ordinary_initialization=False,whole_worker_closed=False))
    status='PASS'
except BaseException as exc:
    failure=dict(error_class=type(exc).__name__,error=str(exc));traceback.print_exc()
finally:
    unchanged=same()
    if not unchanged:status='FAIL'
    save(OUT/'source-after.json',rows())
    for index,(path,raw) in enumerate(pins.items()):
        target=OUT/'frozen-inputs'/str(index)/path.name
        target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw);target.chmod(modes[path])
    summary=dict(status=status,scope='INITIALIZER_SEQUENCE_FRESH_ORIGINAL_LIMIT_COMPILE',
        components=components,counts=counts,actual_compiles=len(components),
        failure=failure,source_unchanged=unchanged,elapsed_ns=time.monotonic_ns()-started,
        original_compiler_limits=dict(cpu_seconds=10,wall_seconds=20,address_space_bytes=256<<20),
        runtime_entries=0,actual_semantic_peer_joins=0,ordinary_initialization=False,
        whole_worker_closed=False,production_activation=False)
    save(OUT/'summary.json',summary);print(json.dumps(summary,sort_keys=True),flush=True)
if status!='PASS':raise SystemExit(1)
