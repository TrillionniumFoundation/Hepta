"""Fresh bounded compile for complete native Worker initialization values."""
from __future__ import annotations
import ast,json,stat,subprocess,sys,time,traceback
from hashlib import sha1,sha256
from pathlib import Path
sys.dont_write_bytecode=True
WORK=Path(sys.argv[1]).resolve();REPO=Path(sys.argv[2]).resolve();OUT=Path(sys.argv[3]).resolve()
ROOT=WORK/'native-agent-initialization-next';REFERENCE=WORK/'Hepta-agent-edit-native'
RENDER=WORK/'native-agent-edit-render-next'
COMPILER=WORK/'dependencies/f50-B3.image.bin'
PINS=[
  {
    "path": "tools/agent_worker_init_templates.py",
    "bytes": 13155,
    "sha256": "65d048c0eb027cbbe83be4d20f1708b96b40415c760322f1c79c4c7d3d1e93d0",
    "gitsha": "fe96d796fe71120ddef15707d6add729f96c7aec"
  },
  {
    "path": "tools/generate_hia_agent_worker_init_values.py",
    "bytes": 22197,
    "sha256": "9a786c3d3982b736bd068eb522b8b8d7649da80bd4813f9c235e2c83461a95ac",
    "gitsha": "a0bdd8d99238cb52c6669be09463a57b9fdd0c78"
  },
  {
    "path": "docs/HIA_WORKER_INITIALIZATION_VALUES_ABI_R1.md",
    "bytes": 7041,
    "sha256": "83db85c5c75bf4d64d92439d45a726bebf6ba27122cca56712ac1a9d6f931319",
    "gitsha": "6a4e0a2e1b06802dabf38ffae969a3e05c4f2577"
  }
]
COMPILER_SHA='0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8'
WIRE_PINS={
 'scan':('graph_json_wire_scan.hiaasm',147822,'c1cb49c1df3c4c653dfd37beebba12b3baf57a28a7d77c257157d2cc7e58cde3'),
 'emit':('graph_json_wire_emit.hiaasm',173680,'9ad72bddb7eaa3d9118155a056e4c5faa7ff3e015e45fbc2d09dae14e2cfb7a2'),
}
OUT.mkdir(parents=True,exist_ok=False);ROOT.mkdir(parents=True,exist_ok=False)
(ROOT/'tools').mkdir();(ROOT/'examples/hia_bootstrap').mkdir(parents=True)
pins={};modes={};components={};status='FAIL';failure=None;started=time.monotonic_ns()
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
    return [dict(path=str(path),bytes=len(raw),sha256=digest(raw),mode=modes[path])
        for path,raw in pins.items()]
def unchanged():
    return all(path.is_file() and path.read_bytes()==raw and stat.S_IMODE(path.stat().st_mode)==modes[path]
        for path,raw in pins.items())
def compile(role,path,counts):
    source=read(path)
    image,_=compile_stage(OUT,role,COMPILER,source)
    image=Path(image).resolve();raw=read(image)
    receipt_path=OUT/(role+'.receipt.json');receipt=json.loads(read(receipt_path))
    assert receipt['image_sha256']==COMPILER_SHA
    assert receipt['input_sha256']==digest(source) and receipt['produced_sha256']==digest(raw)
    row=dict(role=role,source_path=str(path),source_bytes=len(source),source_sha256=digest(source),
        image_path=str(image),image_bytes=len(raw),image_sha256=digest(raw),
        receipt_path=str(receipt_path),compiler_sha256=COMPILER_SHA,counts=counts)
    components[role]=row;save(OUT/(role+'.manifest.json'),row)
try:
    assert (len(read(COMPILER)),digest(read(COMPILER)))==(668608,COMPILER_SHA)
    read(__file__)
    for row in PINS:
        raw=subprocess.check_output(['/usr/bin/git','cat-file','blob',row['gitsha']],cwd=REPO)
        assert (len(raw),digest(raw),gitsha(raw))==(row['bytes'],row['sha256'],row['gitsha'])
        path=ROOT/row['path'];path.parent.mkdir(parents=True,exist_ok=True)
        if path.suffix=='.py':ast.parse(raw,filename=str(path))
        with path.open('xb') as out:out.write(raw)
        read(path)
    sys.path[:0]=[str(ROOT/'tools'),str(REFERENCE)]
    from hepta.hia_agent_assembly import assemble_program,render_assembly
    from tools.qualify_hia_selfhost import compile_stage
    import agent_worker_init_templates as templates
    import generate_hia_agent_worker_init_values as generation
    template_manifest=templates.build(REFERENCE,OUT/'static-templates')
    for row in template_manifest['dependencies']:
        assert digest(read(row['path']))==row['sha256']
    template_path=Path(template_manifest['packet']['path'])
    template=read(template_path)
    assert digest(template)==template_manifest['packet']['sha256']
    (OUT/'values.expanded-authoring.py').write_text(generation.source_program())
    document=generation.document()
    raw=render_assembly(document).encode('utf-8');assemble_program(raw)
    path=ROOT/'examples/hia_bootstrap/agent_worker_initialization_values.hiaasm'
    path.write_bytes(raw)
    fs=document['functions']
    counts=dict(functions=len(fs),blocks=sum(len(fn['blocks']) for fn in fs),
        instructions=sum(len(block['ops']) for fn in fs for block in fn['blocks']),
        max_function_blocks=max(len(fn['blocks']) for fn in fs),
        max_block_parameters=max(len(block['params']) for fn in fs for block in fn['blocks']))
    compile('values',path,counts)
    for role,(name,size,identity) in WIRE_PINS.items():
        path=RENDER/'examples/hia_bootstrap'/name
        assert (len(read(path)),digest(read(path)))==(size,identity)
        compile(role,path,None)
    assert unchanged()
    save(OUT/'bundle.json',dict(schema='hia-worker-initialization-values-development-v1',
        status='PASS',components=components,template_path=str(template_path),
        template_bytes=len(template),template_sha256=digest(template),
        template_manifest=str(OUT/'static-templates/manifest.json'),
        original_compiler_sha256=COMPILER_SHA,
        ordinary_initialization=False,namespace_effects=False,whole_worker_closed=False))
    status='PASS'
except BaseException as exc:
    failure=dict(error_class=type(exc).__name__,error=str(exc));traceback.print_exc()
finally:
    same=unchanged()
    if not same:status='FAIL'
    save(OUT/'source-after.json',pinrows())
    for index,(path,raw) in enumerate(pins.items()):
        dest=OUT/'frozen-inputs'/str(index)/path.name
        dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(raw);dest.chmod(modes[path])
    summary=dict(status=status,scope='NEW_INITIALIZATION_VALUE_TEMPLATE_AND_HIA_COMPILE',
        components=components,actual_compiles=len(components),failure=failure,
        source_unchanged=same,elapsed_ns=time.monotonic_ns()-started,
        original_compiler_limits=dict(cpu_seconds=10,wall_seconds=20,address_space_bytes=256<<20),
        runtime_application_entries=0,ordinary_initialization=False,whole_worker_closed=False)
    save(OUT/'summary.json',summary);print(json.dumps(summary,sort_keys=True),flush=True)
if status!='PASS':raise SystemExit(1)
