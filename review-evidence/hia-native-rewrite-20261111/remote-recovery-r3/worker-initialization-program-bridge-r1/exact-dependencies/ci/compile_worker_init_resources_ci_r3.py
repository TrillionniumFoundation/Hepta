"""Compile P12 r3 exact previous-owner admission and unchanged metadata."""
from __future__ import annotations
import ast,ctypes,importlib.util,json,os,resource,stat,subprocess,sys
from pathlib import Path
from hashlib import sha256

WORK=Path(sys.argv[1]).resolve();REPO=Path(sys.argv[2]).resolve()
PROJECT=Path(sys.argv[3]).resolve();ROOT_WORK=Path(sys.argv[4]).resolve()
REFERENCE=WORK/'Hepta-agent-edit-native'
sys.path.insert(0,str(REFERENCE))
from tools.qualify_hia_selfhost import compile_stage
COMPILER=WORK/'dependencies/f50-B3.image.bin'
COMPILER_SHA='0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8'
PINS={
 "tools/worker_init_resources_front.py":("465dd6843bca67008d030db7303513d96abddee8",14894,"f88b58c8471e16636c2c780b25ee8a1dce278b598a4ab4ce2575c1fb9a78c9bc"),
 "tools/worker_init_resources_result.py":("2d4e00ebedef26766e6f52c63fae8fabe4ec72b4",12297,"0d5c0185c897ff34431caf6e2912661d01131b3cc363b138bec38a64f525e272"),
 "tools/generate_hia_worker_init_resources.py":("d3a5204ea0600ae811ffe05cd40850fc7c57fd20",14257,"c313bf97147c9e13fd1681cc5344beb729d12508b3c64680a36f9da17e44a361"),
 "dependencies/generate_hia_agent_worker_init_values.py":("a0bdd8d99238cb52c6669be09463a57b9fdd0c78",22197,"9a786c3d3982b736bd068eb522b8b8d7649da80bd4813f9c235e2c83461a95ac"),
 "dependencies/generate_hia_agent_worker_init_sequence.py":("f9cd612bad5707d95acef736afe03b6600724d9b",34300,"fad447d45d40494f04280ca100f1ce1abf5e5651bce4feba8cedcfcdbdae06ef"),
 "dependencies/generate_hia_metadata.py":("67939394696bc44daeb3a7643571f80fe84a59c2",18431,"3f14f5b921a9d584944f8d5cee44587f336a4321ffb0be1cb6c0385b4dd50138"),
 "dependencies/graph_harness_r3.py":("eaf060c8c6870cad0a85a23f6b94ffa39308c45c",9783,"75fe54554a93e19e30251073ac225deff944d6673d87ccc2b597e47a19e8be7c"),
 "dependencies/generate_hia_sha256.py":("b59c2259f038eab830c16bf498b14a5d15556ee4",5474,"4114a26ff0ea47229bccbedadcb40efdd9715a8dd0739d2fcb55c98f8ddbdf97"),
}
def generation_limits():
 resource.setrlimit(resource.RLIMIT_CPU,(90,90))
 resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
 resource.setrlimit(resource.RLIMIT_CORE,(0,0))
 libc=ctypes.CDLL(None,use_errno=True);libc.prctl.argtypes=[ctypes.c_int]+[ctypes.c_ulong]*4;libc.prctl.restype=ctypes.c_int
 assert libc.prctl(4,0,0,0,0)==0 and libc.prctl(3,0,0,0,0)==0

def save(path,value):
 path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
pins={};status='FAIL';components={};failure=None
def fixed(path):
 raw=path.read_bytes()
 row=dict(path=str(path),bytes=len(raw),sha256=sha256(raw).hexdigest(),mode=stat.S_IMODE(path.stat().st_mode))
 if str(path) in pins:assert pins[str(path)]==row
 pins[str(path)]=row;return raw
def materialize(relative,row):
 gitsha,size,identity=row
 raw=subprocess.check_output(['/usr/bin/git','cat-file','blob',gitsha],cwd=REPO)
 assert (len(raw),sha256(raw).hexdigest())==(size,identity),relative
 if relative.endswith('.py'):ast.parse(raw,filename=relative)
 path=PROJECT/relative;path.parent.mkdir(parents=True,exist_ok=True)
 with path.open('xb') as stream:stream.write(raw)
 fixed(path);return path
OUT=PROJECT/'development/compile-r2';OUT.mkdir(parents=True,exist_ok=False)
try:
 for relative,row in PINS.items():materialize(relative,row)
 assert (len(fixed(COMPILER)),sha256(COMPILER.read_bytes()).hexdigest())==(668608,COMPILER_SHA)
 helper=REFERENCE/'tools/hia_agent_edit_source_views.py'
 assert sha256(fixed(helper)).hexdigest()=='555472263213f15deb239fcf3bf8e5b273a28caf3a67bb29ffd037f171d7ae5c'
 generator=PROJECT/'tools/generate_hia_worker_init_resources.py'
 env=dict(os.environ,HIA_WORKER_REFERENCE=str(REFERENCE),PYTHONDONTWRITEBYTECODE='1')
 with (OUT/'generation.stdout.log').open('xb') as stdout,(OUT/'generation.stderr.log').open('xb') as stderr:
  completed=subprocess.run([sys.executable,'-B',str(generator)],cwd='/',env=env,stdout=stdout,stderr=stderr,timeout=180,preexec_fn=generation_limits)
 save(OUT/'generation.process.json',dict(returncode=completed.returncode,timeout_seconds=180))
 assert completed.returncode==0,'resource authoring failed; preserve generation stderr'
 spec=json.loads(fixed(PROJECT/'development/resources-source-r2.json'))
 assert all(spec['profile'][key]<=limit for key,limit in
  {'functions':128,'blocks':1536,'instructions':8192,'max_function_blocks':256,'max_block_parameters':16}.items())
 assert spec['profile']['max_ssa_index']<2048
 fixed(PROJECT/'development/resources-pool-r2.bin')
 metadata_source=ROOT_WORK/'native-program-service-next/examples/hia_bootstrap/agent_program_metadata.hiaasm'
 raw=fixed(metadata_source)
 assert (len(raw),sha256(raw).hexdigest())==(169517,'394b864a5e1f92f544fdc5de89a1f000bf778fbaf3de83ab584069d4a5f727da')
 metadata_target=PROJECT/'examples/hia_bootstrap/frozen_program_metadata.hiaasm'
 with metadata_target.open('xb') as stream:stream.write(raw)
 targets={'resources':PROJECT/'examples/hia_bootstrap/worker_initializer_resources.hiaasm',
          'metadata':metadata_target}
 for role,path in targets.items():
  source=fixed(path)
  image,receipt=compile_stage(OUT,role,COMPILER,source)
  image_raw=fixed(image);receipt_path=OUT/(role+'.receipt.json');fixed(receipt_path)
  assert receipt['image_sha256']==COMPILER_SHA
  assert receipt['input_sha256']==sha256(source).hexdigest()
  assert receipt['produced_sha256']==sha256(image_raw).hexdigest()
  components[role]=dict(role=role,source_path=str(path),source_bytes=len(source),source_sha256=sha256(source).hexdigest(),
    image_path=str(image),image_bytes=len(image_raw),image_sha256=sha256(image_raw).hexdigest(),
    receipt_path=str(receipt_path),compiler_sha256=COMPILER_SHA)
 for path,row in pins.items():
  raw=Path(path).read_bytes()
  assert (len(raw),sha256(raw).hexdigest(),stat.S_IMODE(Path(path).stat().st_mode))==(row['bytes'],row['sha256'],row['mode'])
 save(OUT/'bundle.json',dict(schema='hia-worker-resource-peer-development-v2',status='PASS',
  compiler_sha256=COMPILER_SHA,components=components,whole_worker_closed=False,actual_namespace_entries=0))
 status='PASS'
except BaseException as exc:
 import traceback
 failure=dict(error_class=type(exc).__name__,error=str(exc));traceback.print_exc()
finally:
 save(OUT/'source-pins.json',list(pins.values()))
 summary=dict(status=status,actual_compiles=len(components),components=components,failure=failure,
  scope='TWO_FRESH_RESOURCE_METADATA_IMAGES_NOT_WHOLE_WORKER',
  compiler_sha256=COMPILER_SHA,limits=dict(cpu_seconds=10,wall_seconds=20,address_space_bytes=268435456))
 save(OUT/'summary.json',summary);print(json.dumps(summary,sort_keys=True),flush=True)
if status!='PASS':raise SystemExit(1)
