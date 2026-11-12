"""Fresh original-limit B3 compilation of native initializer map operations."""
from __future__ import annotations
import ast,json,stat,subprocess,sys,time,traceback
from hashlib import sha1,sha256
from pathlib import Path
sys.dont_write_bytecode=True
WORK=Path(sys.argv[1]).resolve();REPO=Path(sys.argv[2]).resolve();OUT=Path(sys.argv[3]).resolve()
ROOT=WORK/'native-agent-initialization-maps-next';REFERENCE=WORK/'Hepta-agent-edit-native'
COMPILER=WORK/'dependencies/f50-B3.image.bin'
COMPILER_SHA='0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8'
PINS=[
  {
    "path": "tools/generate_hia_agent_worker_init_maps.py",
    "bytes": 19560,
    "sha256": "8a837ae4acaf11a68054c030c51d6d667d93dee4c825c8fee5bb324b9a6fc2fb",
    "gitsha": "275a8c3a5d63a94241d0651adf425ae2530d2380"
  },
  {
    "path": "docs/HIA_WORKER_INITIALIZATION_MAPS_ABI_R2.md",
    "bytes": 7521,
    "sha256": "49c2c7a8538c1ffe36254c8a85bc2abef0d50d6ebf91378c97813a5fd9d052c9",
    "gitsha": "9c093feaeb159c7bab749c39683e61a77fb78459"
  },
  {
    "path": "dependencies/generate_hia_agent_worker_init_values.py",
    "bytes": 22197,
    "sha256": "9a786c3d3982b736bd068eb522b8b8d7649da80bd4813f9c235e2c83461a95ac",
    "gitsha": "a0bdd8d99238cb52c6669be09463a57b9fdd0c78"
  },
  {
    "path": "development/value_mechanics_source.py",
    "bytes": 27233,
    "sha256": "1602df39c9dd982e42ece64379e76fc9ca123b7ca407e84d7f4ded767bebf753",
    "gitsha": "b12248a7ad4aa4875e78af33922182b3fffc1636"
  },
  {
    "path": "dependencies/HIA_AGENT_NATIVE_TOOL_CATALOG.json",
    "bytes": 226542,
    "sha256": "61325aadc2fa6740c84037227c9410f5e299267d908cfbbd0be6b05eedfbfbf8",
    "gitsha": "9b6ff8f96518a50b7d348ec732981610aa4c9ed1"
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
    import generate_hia_agent_worker_init_maps as generation
    from hepta.hia_agent_assembly import assemble_program,render_assembly
    from tools.qualify_hia_selfhost import compile_stage
    (OUT/'maps.expanded-authoring.py').write_text(generation.source_program())
    value=generation.document();fs=value['functions']
    counts=dict(functions=len(fs),blocks=sum(len(f['blocks']) for f in fs),
        instructions=sum(len(b['ops']) for f in fs for b in f['blocks']),
        max_function_blocks=max(len(f['blocks']) for f in fs),
        max_block_parameters=max(len(b['params']) for f in fs for b in f['blocks']))
    assert all(a<=b for a,b in zip(counts.values(),(128,1536,8192,256,16))),counts
    raw=render_assembly(value).encode();assemble_program(raw)
    path=ROOT/'examples/hia_bootstrap/agent_worker_initialization_maps.hiaasm'
    path.write_bytes(raw);source=read(path)
    image,_=compile_stage(OUT,'maps',COMPILER,source)
    image=Path(image).resolve();image_raw=read(image)
    receipt_path=OUT/'maps.receipt.json';receipt=json.loads(read(receipt_path))
    assert receipt['input_sha256']==digest(source) and receipt['produced_sha256']==digest(image_raw)
    assert receipt['image_sha256']==COMPILER_SHA
    row=dict(role='maps',source_path=str(path),source_bytes=len(source),source_sha256=digest(source),
        image_path=str(image),image_bytes=len(image_raw),image_sha256=digest(image_raw),
        receipt_path=str(receipt_path),compiler_sha256=COMPILER_SHA,counts=counts)
    components['maps']=row;save(OUT/'maps.manifest.json',row)
    for module in tuple(sys.modules.values()):
        file=getattr(module,'__file__',None)
        if file:
            candidate=Path(file).resolve()
            if candidate.suffix=='.py' and candidate.is_relative_to(REFERENCE):read(candidate)
    assert same()
    save(OUT/'bundle.json',dict(schema='hia-worker-initialization-maps-development-v1',
        status='PASS',components=components,original_compiler_sha256=COMPILER_SHA,
        actual_native_map_operations=0,ordinary_initialization=False,whole_worker_closed=False))
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
    summary=dict(status=status,scope='INITIALIZER_MAPS_FRESH_ORIGINAL_LIMIT_COMPILE',
        components=components,counts=counts,actual_compiles=len(components),
        failure=failure,source_unchanged=unchanged,elapsed_ns=time.monotonic_ns()-started,
        original_compiler_limits=dict(cpu_seconds=10,wall_seconds=20,address_space_bytes=256<<20),
        runtime_entries=0,actual_semantic_peer_joins=0,ordinary_initialization=False,
        whole_worker_closed=False,production_activation=False)
    save(OUT/'summary.json',summary);print(json.dumps(summary,sort_keys=True),flush=True)
if status!='PASS':raise SystemExit(1)
