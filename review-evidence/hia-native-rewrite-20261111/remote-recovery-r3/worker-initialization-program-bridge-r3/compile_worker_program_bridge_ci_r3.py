"""Fresh four-image initializer program bridge, original historical B3 gate.

Only the two new bridge owners and exact existing decoder/DataGraph compile.
No program service semantic result or prior test success is inherited.
"""
from __future__ import annotations
import ast,ctypes,importlib.util,json,os,resource,stat,subprocess,sys,time,traceback
from hashlib import sha1,sha256
from pathlib import Path
sys.dont_write_bytecode=True
WORK=Path(sys.argv[1]).resolve();REPO=Path(sys.argv[2]).resolve();PROJECT=Path(sys.argv[3]).resolve()
REFERENCE=WORK/'Hepta-agent-edit-native';COMPILER=WORK/'dependencies/f50-B3.image.bin'
OUT=PROJECT/'development/compile-r1'
COMPILER_SHA='0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8'
PINS=[
  {
    "path": "tools/worker_initializer_program_bridge_common.py",
    "mode": "100644",
    "bytes": 10034,
    "sha256": "31451df01b02736b069b71010b1b81132bbe3a549d6fe21df5aca493c1a723a5",
    "gitsha": "ce434ec5f3eee25d77dbd8881268b0b95fd5d3d3"
  },
  {
    "path": "tools/worker_initializer_program_bridge_input.py",
    "mode": "100644",
    "bytes": 22169,
    "sha256": "44bddb83b5888e223865d15a7befe438525048cf3cfa971667d0eba6cb81d332",
    "gitsha": "e9b520e8a4451fc3e0d5a205d12ecc256d163931"
  },
  {
    "path": "tools/worker_initializer_program_bridge_output.py",
    "mode": "100644",
    "bytes": 14756,
    "sha256": "034925ae38747908e948c6e584dd76991d3a56a4a037c5694086393bbe9eaeeb",
    "gitsha": "8b290480e88e57c9ccfe4dd92c9017dfd2a81cba",
    "classification": "NEW_R3_0_AST_0_GENERATION_0_B3_0_NATIVE"
  },
  {
    "path": "tools/generate_hia_worker_initializer_program_bridge.py",
    "mode": "100644",
    "bytes": 11048,
    "sha256": "6c7ba7d63e24425f028f73dbcf8b677efbf91f4efb557521258ce8d37231e98a",
    "gitsha": "108d662ee8638566764bcded29118f6484f465b4",
    "classification": "NEW_R3_0_AST_0_GENERATION_0_B3_0_NATIVE"
  },
  {
    "path": "dependencies/generate_hia_agent_worker_init_values.py",
    "mode": "100644",
    "bytes": 22197,
    "sha256": "9a786c3d3982b736bd068eb522b8b8d7649da80bd4813f9c235e2c83461a95ac",
    "gitsha": "a0bdd8d99238cb52c6669be09463a57b9fdd0c78"
  },
  {
    "path": "dependencies/generate_hia_agent_worker_init_sequence.py",
    "mode": "100644",
    "bytes": 34300,
    "sha256": "fad447d45d40494f04280ca100f1ce1abf5e5651bce4feba8cedcfcdbdae06ef",
    "gitsha": "f9cd612bad5707d95acef736afe03b6600724d9b"
  },
  {
    "path": "dependencies/worker_init_resources_front.py",
    "mode": "100644",
    "bytes": 14894,
    "sha256": "f88b58c8471e16636c2c780b25ee8a1dce278b598a4ab4ce2575c1fb9a78c9bc",
    "gitsha": "465dd6843bca67008d030db7303513d96abddee8"
  },
  {
    "path": "dependencies/worker_init_resources_result.py",
    "mode": "100644",
    "bytes": 12297,
    "sha256": "0d5c0185c897ff34431caf6e2912661d01131b3cc363b138bec38a64f525e272",
    "gitsha": "2d4e00ebedef26766e6f52c63fae8fabe4ec72b4"
  },
  {
    "path": "dependencies/agent_data_graph_values.py",
    "mode": "100644",
    "bytes": 12677,
    "sha256": "4b005ea341992084ce60355c7112dcd47c7544dc3f24b2eccd4b8966b2734421",
    "gitsha": "308b0cc5a962bf9a74b4b87101fee815143c0ae8"
  },
  {
    "path": "tools/agent_data_graph_common.py",
    "mode": "100644",
    "bytes": 13039,
    "sha256": "192366d8ad7934e78e3e31617ccde4591d69af428779d65d449d30a5a581af8b",
    "gitsha": "bd05a2344399c4b7f2028c407e49bb43ecd48335"
  },
  {
    "path": "tools/agent_data_graph_values.py",
    "mode": "100644",
    "bytes": 12677,
    "sha256": "4b005ea341992084ce60355c7112dcd47c7544dc3f24b2eccd4b8966b2734421",
    "gitsha": "308b0cc5a962bf9a74b4b87101fee815143c0ae8"
  },
  {
    "path": "tools/generate_hia_agent_data_graph.py",
    "mode": "100644",
    "bytes": 4528,
    "sha256": "7bd7aaa02358acf599931338994ed9c7e6746dc7202f9195c81d92d82427eb7b",
    "gitsha": "323595d0596e55e4317ea4c017aaae7dd7f32e9e"
  },
  {
    "path": "examples/hia_bootstrap/frozen_agent_data_json.hiaasm",
    "mode": "100644",
    "bytes": 92926,
    "sha256": "bfb36b20e6e2def7a484c794b71f6ff7a202ecdc5452605bc0ad63251b03308e",
    "gitsha": "3129bb348bc8edfbd4398f69f30fd1b20b70497b"
  }
]
resource.setrlimit(resource.RLIMIT_CPU,(90,90))
resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
libc=ctypes.CDLL(None,use_errno=True)
libc.prctl.argtypes=[ctypes.c_int]+[ctypes.c_ulong]*4;libc.prctl.restype=ctypes.c_int
assert libc.prctl(4,0,0,0,0)==0 and libc.prctl(3,0,0,0,0)==0
OUT.mkdir(parents=True,exist_ok=False)
pins={};components={};status='FAIL';failure=None;started=time.monotonic_ns();attempts=[]
def digest(raw):return sha256(raw).hexdigest()
def gitsha(raw):return sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def read(path):
    path=Path(path).resolve();raw=path.read_bytes()
    row=dict(path=str(path),bytes=len(raw),sha256=digest(raw),mode=stat.S_IMODE(path.stat().st_mode))
    if path in pins:assert pins[path]==row,path
    pins[path]=row;return raw
def materialize(row):
    raw=subprocess.check_output(['/usr/bin/git','cat-file','blob',row['gitsha']],cwd=REPO)
    assert (len(raw),digest(raw),gitsha(raw))==(row['bytes'],row['sha256'],row['gitsha']),row['path']
    relative=Path(row['path']);assert not relative.is_absolute() and '..' not in relative.parts
    target=PROJECT/relative;target.parent.mkdir(parents=True,exist_ok=True)
    if target.suffix=='.py':ast.parse(raw,filename=str(target))
    with target.open('xb') as stream:stream.write(raw)
    target.chmod(0o644);read(target)
def load(name,path):
    raw=read(path);ast.parse(raw,filename=str(path))
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module)
    return module
def compile_image(role,path,profile=None):
    source=read(path)
    assert 0<len(source)<=1048576
    attempts.append(dict(role=role,path=str(path),source_bytes=len(source),source_sha256=digest(source),
        compiler_sha256=COMPILER_SHA))
    save(OUT/'compile-attempts.json',attempts)
    image,receipt=compile_stage(OUT,role,COMPILER,source)
    raw=read(image);receipt_path=OUT/(role+'.receipt.json')
    original=json.loads(read(receipt_path));assert original==receipt
    assert receipt['image_sha256']==COMPILER_SHA
    assert receipt['input_sha256']==digest(source) and receipt['produced_sha256']==digest(raw)
    assert 0<len(raw)<=1048576
    components[role]=dict(role=role,source_path=str(path),source_bytes=len(source),source_sha256=digest(source),
        image_path=str(image),image_bytes=len(raw),image_sha256=digest(raw),receipt_path=str(receipt_path),
        compiler_sha256=COMPILER_SHA,profile=profile)
    save(OUT/(role+'.manifest.json'),components[role])
    print('HIA_WORKER_PROGRAM_BRIDGE_COMPILE '+json.dumps(components[role],sort_keys=True),flush=True)
try:
    read(__file__)
    for row in PINS:materialize(row)
    assert (len(read(COMPILER)),digest(COMPILER.read_bytes()))==(668608,COMPILER_SHA)
    assert digest(read(REFERENCE/'tools/hia_agent_edit_source_views.py'))=='555472263213f15deb239fcf3bf8e5b273a28caf3a67bb29ffd037f171d7ae5c'
    os.environ['HIA_WORKER_REFERENCE']=str(REFERENCE)
    sys.path[:0]=[str(PROJECT/'tools'),str(REFERENCE)]
    from tools.qualify_hia_selfhost import compile_stage
    from hepta.hia_agent_assembly import render_assembly,assemble_program
    generator=load('worker_program_bridge_generator',PROJECT/'tools/generate_hia_worker_initializer_program_bridge.py')
    for which in ('input','output'):
        document,authoring,metadata=generator.document(which)
        raw=render_assembly(document).encode('utf-8')
        assemble_program(raw)
        path=PROJECT/'examples/hia_bootstrap'/('worker_initializer_program_'+which+'.hiaasm')
        with path.open('xb') as stream:stream.write(raw)
        (PROJECT/'development'/(which+'-authoring-r1.py')).write_text(authoring)
        save(PROJECT/'development'/(which+'-source-r1.json'),metadata)
        save(OUT/(which+'-document.json'),document)
        for source,row in metadata['source_dependencies'].items():
            actual=read(source)
            assert (len(actual),digest(actual),stat.S_IMODE(Path(source).stat().st_mode))==(
                row['bytes'],row['sha256'],row['mode'])
        compile_image('program-'+which,path,metadata['profile'])
    data=load('worker_program_complete_datagraph',PROJECT/'tools/generate_hia_agent_data_graph.py')
    document=data.document();profile=generator.measured(document)
    authoring=data.source_program();raw=render_assembly(document).encode('utf-8')
    assemble_program(raw)
    path=PROJECT/'examples/hia_bootstrap/program_core_data_graph.hiaasm'
    path.write_bytes(raw);(PROJECT/'development/datagraph-authoring-r1.py').write_text(authoring)
    save(OUT/'datagraph-profile.json',profile);save(OUT/'datagraph-document.json',document)
    compile_image('program-datagraph',path,profile)
    compile_image('program-decoder',PROJECT/'examples/hia_bootstrap/frozen_agent_data_json.hiaasm')
    for module in tuple(sys.modules.values()):
        path=getattr(module,'__file__',None)
        if path:
            path=Path(path).resolve()
            if path.suffix=='.py' and any(path.is_relative_to(root) for root in (REFERENCE,PROJECT)):
                read(path)
    assert len(components)==4
    assert all(Path(path).is_file() and Path(path).stat().st_size==row['bytes']
        and digest(Path(path).read_bytes())==row['sha256']
        and stat.S_IMODE(Path(path).stat().st_mode)==row['mode'] for path,row in pins.items())
    save(OUT/'bundle.json',dict(schema='hia-worker-initializer-program-bridge-v1',status='PASS',
        components=components,compiler_sha256=COMPILER_SHA,actual_compiles=4,
        scope='COMPILED_PRIVATE_BRIDGE_NOT_INITIALIZER_EXECUTION',ordinary_worker_closed=False,
        actual_namespace_entries=0))
    status='PASS'
except BaseException as exc:
    failure=dict(error_class=type(exc).__name__,error=str(exc),traceback=traceback.format_exc())
    traceback.print_exc()
finally:
    unchanged=all(Path(path).is_file() and Path(path).stat().st_size==row['bytes']
        and digest(Path(path).read_bytes())==row['sha256']
        and stat.S_IMODE(Path(path).stat().st_mode)==row['mode'] for path,row in pins.items())
    if not unchanged:status='FAIL'
    save(OUT/'source-pins.json',list(pins.values()))
    summary=dict(status=status,actual_compiles=len(components),attempts=attempts,components=components,
        failure=failure,source_unchanged=unchanged,elapsed_ns=time.monotonic_ns()-started,
        semantic_entries=0,whole_worker_closed=False,compiler_sha256=COMPILER_SHA,
        original_compile_limits=dict(cpu_seconds=10,wall_seconds=20,address_space_bytes=268435456))
    save(OUT/'summary.json',summary)
    print('HIA_WORKER_PROGRAM_BRIDGE_BUILD '+json.dumps(summary,sort_keys=True),flush=True)
if status!='PASS':raise SystemExit(1)
