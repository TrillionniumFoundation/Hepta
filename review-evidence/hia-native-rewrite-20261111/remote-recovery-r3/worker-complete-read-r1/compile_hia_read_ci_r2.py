"""Generate the complete read business kernels and compile five real images.

The namespace ABI is an exact immutable authoring input. A successful compile
does not claim any execution of the high-level namespace or the ordinary Worker.
"""
from __future__ import annotations
import ast,json,stat,subprocess,sys,time,traceback
from hashlib import sha1,sha256
from pathlib import Path
WORK=Path(sys.argv[1]).resolve();REPO=Path(sys.argv[2]).resolve()
OUT=Path(sys.argv[3]).resolve();ABI=Path(sys.argv[4]).resolve()
ROOT=WORK/'native-agent-read-next';REFERENCE=WORK/'Hepta-agent-edit-native'
COMPILER=WORK/'dependencies/f50-B3.image.bin'
PINS=[
  {
    "path": "tools/agent_read_common.py",
    "bytes": 13642,
    "sha256": "3b8cbc0082fea459b5b29667a73fc29a74bcac0962e55df92e523ee6e9cba513",
    "gitsha": "9e28e8fdb60741420b27b0c247a1e073cc6d39db"
  },
  {
    "path": "tools/agent_read_graph.py",
    "bytes": 12519,
    "sha256": "f2bf6993bd1a44f15cae6e1d37bd9fffddee671e7ce4aa6c4470a6bd19e8ccfe",
    "gitsha": "5db985a5e428f43c36c12faabb3fc9e376012d39"
  },
  {
    "path": "tools/agent_read_values.py",
    "bytes": 8364,
    "sha256": "bfae2a7195187190a4547e907c5527411cb89a11de385bfd392348c72a4b576e",
    "gitsha": "e7042f139e4f64496e0f1d136476f9209a3e2afc"
  },
  {
    "path": "tools/agent_read_flow.py",
    "bytes": 8361,
    "sha256": "8aead3f3eb111287a27b3157e58a07d35e080069766745b75c29dce536273031",
    "gitsha": "d4e48b654c3fe7133b89901a4cd7d8020bbd6ffd"
  },
  {
    "path": "tools/generate_hia_agent_read.py",
    "bytes": 10173,
    "sha256": "e0d8594044ec12ee3214dd7b97d35bb683d7ebf3cb7d9ec8e4ce919a399a7738",
    "gitsha": "cb70f909d8c6da0575fe32a21ebe44b5ab75cfba"
  },
  {
    "path": "docs/HIA_AGENT_READ_NATIVE_DEVELOPMENT_R1.md",
    "bytes": 13298,
    "sha256": "cde0b239a8b6bab2350f7b9d6a6c04f884ae6cfd94aa3cc23c6e24e1015608b4",
    "gitsha": "9559bb2b56a92f1380a0b265abec49e98a1262e5"
  },
  {
    "path": "tools/graph_harness_frozen_original.py",
    "bytes": 9783,
    "sha256": "75fe54554a93e19e30251073ac225deff944d6673d87ccc2b597e47a19e8be7c",
    "gitsha": "eaf060c8c6870cad0a85a23f6b94ffa39308c45c"
  }
]


WIRE_PINS=[
 dict(role='scan',path='graph_json_wire_scan.hiaasm',bytes=147822,sha256='c1cb49c1df3c4c653dfd37beebba12b3baf57a28a7d77c257157d2cc7e58cde3'),
 dict(role='emit',path='graph_json_wire_emit.hiaasm',bytes=173680,sha256='9ad72bddb7eaa3d9118155a056e4c5faa7ff3e015e45fbc2d09dae14e2cfb7a2')]
def digest(raw):return sha256(raw).hexdigest()
def gitsha(raw):return sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
OUT.mkdir(parents=True,exist_ok=False);ROOT.mkdir(parents=True,exist_ok=False)
(ROOT/'tools').mkdir();(ROOT/'examples/hia_bootstrap').mkdir(parents=True)
pins={};components={};attempts=[];failures=[];binding=None
summary=dict(status='INCOMPLETE',scope='COMPLETE_HIA_READ_WITH_PENDING_NAMESPACE_DEVELOPMENT',
    actual_compiles=0,native_entries=0,whole_worker_closed=False,ordinary_namespace_closed=False,
    production_activation=False,compiler_limits=dict(cpu_seconds=10,wall_seconds=20,address_space_bytes=256<<20))
started=time.monotonic_ns()
def read(path):
    p=Path(path).resolve();raw=p.read_bytes()
    if p in pins:assert pins[p]==raw
    pins[p]=raw;return raw
def rows():
    return [dict(path=str(p),bytes=len(raw),sha256=digest(raw),mode=stat.S_IMODE(p.stat().st_mode)) for p,raw in pins.items()]
def counts(value):
    fs=value['functions'];row=dict(functions=len(fs),blocks=sum(len(f['blocks']) for f in fs),
        instructions=sum(len(b['ops']) for f in fs for b in f['blocks']),
        max_function_blocks=max(len(f['blocks']) for f in fs),
        max_block_parameters=max(len(b['params']) for f in fs for b in f['blocks']))
    assert all(a<=b for a,b in zip(row.values(),(128,1536,8192,256,16))),row
    return row
def compile_one(role,source,profile=None):
    raw=read(source);image,receipt=compile_stage(OUT,role,COMPILER,raw)
    image=Path(image).resolve();image_raw=read(image)
    receipt_path=OUT/(role+'.receipt.json');actual=json.loads(read(receipt_path))
    assert actual['input_sha256']==digest(raw)
    assert actual['produced_sha256']==digest(image_raw)
    assert actual['image_sha256']==digest(read(COMPILER))
    row=dict(role=role,source_path=str(source),source_bytes=len(raw),source_sha256=digest(raw),
        image_path=str(image),image_bytes=len(image_raw),image_sha256=digest(image_raw),
        receipt_path=str(receipt_path),compiler_sha256=digest(read(COMPILER)),counts=profile)
    save(OUT/(role+'.manifest.json'),row);components[role]=row
    attempts.append(dict(role=role,status='PASS',manifest=row));summary['actual_compiles']+=1
def failed(role):
    exc=sys.exception();trace=traceback.format_exc()
    (OUT/(role+'.failure.log')).write_text(trace);traceback.print_exc()
    row=dict(role=role,status='FAIL',error_class=type(exc).__name__,error=str(exc))
    failures.append(row);attempts.append(row)
try:
    raw=read(COMPILER)
    assert (len(raw),digest(raw))==(668608,'0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8')
    for row in PINS:
        raw=subprocess.check_output(['/usr/bin/git','cat-file','blob',row['gitsha']],cwd=REPO)
        assert (len(raw),digest(raw),gitsha(raw))==(row['bytes'],row['sha256'],row['gitsha'])
        path=ROOT/row['path'];path.parent.mkdir(parents=True,exist_ok=True)
        if path.suffix=='.py':ast.parse(raw,filename=str(path))
        path.write_bytes(raw);read(path)
    for path in ('tools/generate_hia_selfhost.py','tools/hia_agent_edit_source_views.py',
        'tools/qualify_hia_selfhost.py','hepta/hia_program.py','hepta/hia_agent_assembly.py',
        'hepta/hia_agent_contract.py','hepta/hia_agent_store.py','hepta/hia_agent_service.py',
        'hepta/hia_program_tools.py','hepta/hia_json_preflight_native.py'):
        read(REFERENCE/path)
    service=read(REFERENCE/'hepta/hia_agent_service.py')
    assert (len(service),digest(service),gitsha(service))==(100742,
        '684caf496de7e3e7c8db1fd80ef616139cf13717aa5879bbd2d6ebf834df9330',
        '2f56a5b4b02c54b9e56e53882db5cbd5687e4b4e')
    read(__file__);read(ABI)
    save(OUT/'source-before.json',rows())
    sys.path[:0]=[str(ROOT/'tools'),str(REFERENCE)]
    import generate_hia_agent_read as generator
    from hepta.hia_agent_assembly import render_assembly,assemble_program
    from tools.qualify_hia_selfhost import compile_stage
    opcodes,binding=generator.namespace_bindings(read(ABI))
    save(OUT/'namespace-binding.json',binding)
    for role,(name,_) in generator.ROLES.items():
        try:
            (OUT/(name+'.expanded-authoring.py')).write_text(generator.source_program(role,opcodes))
            value=generator.document(role,opcodes);profile=counts(value)
            raw=render_assembly(value).encode();assemble_program(raw)
            path=ROOT/'examples/hia_bootstrap'/(name+'.hiaasm');path.write_bytes(raw)
            compile_one(name,path,profile)
        except BaseException:failed(name)
    for row in WIRE_PINS:
        try:
            path=WORK/'native-agent-edit-render-next/examples/hia_bootstrap'/row['path']
            raw=read(path);assert (len(raw),digest(raw))==(row['bytes'],row['sha256'])
            compile_one(row['role'],path)
        except BaseException:failed(row['role'])
    try:
        path=REFERENCE/'examples/hia_bootstrap/sha256_stream.hiaasm';raw=read(path)
        assert (len(raw),digest(raw),gitsha(raw))==(30784,
            '7fdc436867514b3d1dd741e3c3d86c0b95cc19d5b69907d5df9febf29639cb68',
            '909c1a87627b998bc3f7a6610bb1a7ef2f572145')
        compile_one('sha256_stream',path)
    except BaseException:failed('sha256_stream')
    if not failures:
        assert set(components)=={'agent_read_flow','agent_read_values','scan','emit','sha256_stream'}
        bundle=dict(schema='hia-agent-read-development-bundle-v1',status='PASS',
            scope=summary['scope'],components=components,namespace_binding=binding,
            compiler_sha256=digest(read(COMPILER)),whole_worker_closed=False,
            ordinary_namespace_closed=False)
        save(OUT/'bundle.json',bundle);summary.update(status='PASS',bundle=bundle)
except BaseException:failed('generation-driver')
finally:
    unchanged=all(p.is_file() and p.read_bytes()==raw for p,raw in pins.items())
    if failures or not unchanged:summary['status']='FAIL'
    for i,(path,raw) in enumerate(pins.items()):
        frozen=OUT/'frozen-inputs'/str(i)/path.name;frozen.parent.mkdir(parents=True,exist_ok=True)
        frozen.write_bytes(raw);frozen.chmod(stat.S_IMODE(path.stat().st_mode))
    summary.update(source_unchanged=unchanged,attempts=attempts,failures=failures,
        namespace_binding=binding,elapsed_ns=time.monotonic_ns()-started)
    save(OUT/'source-after.json',rows());save(OUT/'summary.json',summary)
    print(json.dumps(summary,sort_keys=True),flush=True)
if summary['status']!='PASS':raise SystemExit(1)
