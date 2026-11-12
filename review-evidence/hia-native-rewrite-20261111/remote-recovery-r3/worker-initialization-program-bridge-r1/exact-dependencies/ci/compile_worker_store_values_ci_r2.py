"""Fresh exact compiler Store.json/profile HIA component, no inherited result."""
from __future__ import annotations
import ast,importlib.util,json,os,stat,subprocess,sys,time,traceback
from hashlib import sha1,sha256
from pathlib import Path
sys.dont_write_bytecode=True
WORK=Path(sys.argv[1]).resolve();REPO=Path(sys.argv[2]).resolve()
ROOT=Path(sys.argv[3]).resolve();REG=Path(sys.argv[4]).resolve();FULL_REFERENCE=Path(sys.argv[5]).resolve()
REFERENCE=WORK/'Hepta-agent-edit-native';COMPILER=WORK/'dependencies/f50-B3.image.bin'
COMPILER_SHA='0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8'
PINS=[
  {
    "path": "tools/worker_store_values_front.py",
    "bytes": 16296,
    "sha256": "5bb3e5d3de54d1e7fb3223abcf5eebf86e8dbee8a691fce72ceb6ae0c6bcebf3",
    "gitsha": "77513aee9a8b7e32b13fabed94a9d81047862ad0"
  },
  {
    "path": "tools/worker_store_values_result.py",
    "bytes": 17172,
    "sha256": "6b581bd60da75d897e5bfc99fb47bbd932c6c99d569393fc1537d140081816dd",
    "gitsha": "9356f0f3b12184cde9c0f2f30339eea3bc3f0f21"
  },
  {
    "path": "tools/generate_hia_agent_worker_store_values.py",
    "bytes": 10025,
    "sha256": "48959dac55d58a9f618a678ed63dad392c3fabd2371e4edbf99ba2b9b13bc4f8",
    "gitsha": "d6422061126662dbb52a4be7d45009258416aa9e"
  },
  {
    "path": "dependencies/generate_hia_agent_worker_init_values.py",
    "bytes": 22197,
    "sha256": "9a786c3d3982b736bd068eb522b8b8d7649da80bd4813f9c235e2c83461a95ac",
    "gitsha": "a0bdd8d99238cb52c6669be09463a57b9fdd0c78"
  },
  {
    "path": "dependencies/generate_hia_agent_worker_initialization_sequence.py",
    "bytes": 34300,
    "sha256": "fad447d45d40494f04280ca100f1ce1abf5e5651bce4feba8cedcfcdbdae06ef",
    "gitsha": "f9cd612bad5707d95acef736afe03b6600724d9b"
  },
  {
    "path": "dependencies/worker_digest_result.py",
    "bytes": 11421,
    "sha256": "e998c82865c3ac5adc6da87d27c0484be08ce8b6b4f64ac045cd363f90ae3d4d",
    "gitsha": "9fc8a73fb39822cae52bf93162aca37463a34773"
  },
  {
    "path": "dependencies/graph_harness_r3.py",
    "bytes": 9783,
    "sha256": "75fe54554a93e19e30251073ac225deff944d6673d87ccc2b597e47a19e8be7c",
    "gitsha": "eaf060c8c6870cad0a85a23f6b94ffa39308c45c"
  },
  {
    "path": "dependencies/value_mechanics_source.py",
    "bytes": 27233,
    "sha256": "1602df39c9dd982e42ece64379e76fc9ca123b7ca407e84d7f4ded767bebf753",
    "gitsha": "b12248a7ad4aa4875e78af33922182b3fffc1636"
  },
  {
    "path": "dependencies/HIA_AGENT_NAMESPACE_STORE_ABI.json",
    "bytes": 51264,
    "sha256": "c15222c99cb04ef8bc6a7f13108a7e90adb0bc908876d663eb4329fd14563c04",
    "gitsha": "2cb6092f730298252943830a38b2864fce2597cd"
  },
  {
    "path": "dependencies/hia_agent_store.py",
    "bytes": 20250,
    "sha256": "fae25d48a6de7187ed465287c1491af74214ac8bf3eae2af921bd100a247b822",
    "gitsha": "ce939c30102a16d0c0d9736774dca3c50d91f879"
  }
]
ROOT.mkdir(parents=True,exist_ok=False)
OUT=ROOT/'development/compile-r1';OUT.mkdir(parents=True)
pins={};components={};counts={};status='FAIL';failure=None;started=time.monotonic_ns()
def digest(raw):return sha256(raw).hexdigest()
def gitsha(raw):return sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
def save(path,value):
 path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def read(path):
 path=Path(path).resolve();raw=path.read_bytes();mode=stat.S_IMODE(path.stat().st_mode)
 if path in pins:assert pins[path]==(raw,mode)
 pins[path]=(raw,mode);return raw
def same():
 return all(p.is_file() and p.read_bytes()==raw and stat.S_IMODE(p.stat().st_mode)==mode for p,(raw,mode) in pins.items())
def rows():
 return [dict(path=str(p),bytes=len(raw),sha256=digest(raw),gitsha=gitsha(raw),mode=mode) for p,(raw,mode) in pins.items()]
def put(path,raw):
 path.parent.mkdir(parents=True,exist_ok=True)
 with path.open('xb') as stream:stream.write(raw)
 read(path)
def load_module(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
 sys.modules[name]=module;spec.loader.exec_module(module);return module
try:
 read(__file__)
 assert (len(read(COMPILER)),digest(read(COMPILER)))==(668608,COMPILER_SHA)
 for row in PINS:
  raw=subprocess.check_output(['/usr/bin/git','cat-file','blob',row['gitsha']],cwd=REPO)
  assert (len(raw),digest(raw),gitsha(raw))==(row['bytes'],row['sha256'],row['gitsha'])
  path=ROOT/row['path']
  if path.suffix=='.py':ast.parse(raw,filename=str(path))
  elif path.suffix=='.json':json.loads(raw)
  put(path,raw)
 helper=read(REFERENCE/'tools/hia_agent_edit_source_views.py')
 assert (len(helper),digest(helper))==(23950,'555472263213f15deb239fcf3bf8e5b273a28caf3a67bb29ffd037f171d7ae5c')
 put(ROOT/'dependency-overlay/tools/hia_agent_edit_source_views.py',helper)
 assert read(REFERENCE/'hepta/hia_agent_store.py')==read(ROOT/'dependencies/hia_agent_store.py')
 bundle=json.loads(read(REG/'bundle.json'));summary=json.loads(read(REG/'summary.json'))
 assert bundle['status']=='PASS' and summary['status']=='PASS' and summary['actual_compiles']==8
 assert summary['source_unchanged'] and bundle['original_compiler_sha256']==COMPILER_SHA
 put(ROOT/'dependencies/recovered-registry/bundle.json',read(REG/'bundle.json'))
 for role,row in bundle['components'].items():
  assert role in ('sequence','pure','maps','values','registry','merge','scan','emit')
  for suffix in ('.image.bin','.input.bin','.receipt.json'):
   put(ROOT/'dependencies/recovered-registry'/(role+suffix),read(REG/(role+suffix)))
  assert digest(read(REG/(role+'.input.bin')))==row['source_sha256']
  assert digest(read(REG/(role+'.image.bin')))==row['image_sha256']
  receipt=json.loads(read(REG/(role+'.receipt.json')))
  assert receipt['image_sha256']==COMPILER_SHA and receipt['produced_sha256']==row['image_sha256']
  assert receipt['input_sha256']==row['source_sha256']
 os.environ['HIA_WORKER_REFERENCE']=str(REFERENCE)
 sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'dependencies'),str(REFERENCE),str(FULL_REFERENCE)]
 from hepta.hia_agent_assembly import assemble_program,render_assembly
 from tools.qualify_hia_selfhost import compile_stage
 generation=load_module('worker_store_values_current_generation',ROOT/'tools/generate_hia_agent_worker_store_values.py')
 expanded=generation.source_program()
 put(OUT/'expanded-authoring.py',expanded.encode())
 value=generation.document();fs=value['functions']
 counts=dict(functions=len(fs),blocks=sum(len(f['blocks']) for f in fs),
  instructions=sum(len(b['ops']) for f in fs for b in f['blocks']),
  max_function_blocks=max(len(f['blocks']) for f in fs),
  max_block_parameters=max(len(b['params']) for f in fs for b in f['blocks']))
 assert all(a<=b for a,b in zip(counts.values(),(128,1536,8192,256,16))),counts
 # This is the existing bounded compiler's numeric SSA-index profile, not an
 # additional operation/block quota. Check every emitted definition after
 # compact_authoring_cfg; original verify_program also checks all uses.
 ssa_names=[p['name'] for f in fs for p in f['params']]
 ssa_names.extend(p['name'] for f in fs for b in f['blocks'] for p in b['params'])
 ssa_names.extend(p['name'] for f in fs for b in f['blocks'] for op in b['ops'] for p in op['out'])
 assert ssa_names and all(name.startswith('v') and name[1:].isascii()
  and name[1:].isdigit() for name in ssa_names),ssa_names
 counts['max_ssa_index']=max(int(name[1:]) for name in ssa_names)
 save(OUT/'generated-profile.json',dict(counts=counts,numeric_ssa_index_exclusive_limit=2048))
 assert counts['max_ssa_index']<2048,counts
 source=render_assembly(value).encode();assemble_program(source)
 current=ROOT/'examples/hia_bootstrap/agent_worker_store_json_profile.hiaasm'
 put(current,source)
 image,receipt=compile_stage(OUT,'worker-store-json-profile',COMPILER,source)
 actual=read(image);receipt=json.loads(read(OUT/'worker-store-json-profile.receipt.json'))
 assert receipt['image_sha256']==COMPILER_SHA and receipt['input_sha256']==digest(source)
 assert receipt['produced_sha256']==digest(actual)
 row=dict(role='storevalues',source_path=str(current),source_sha256=digest(source),source_bytes=len(source),
  image_sha256=digest(actual),image_bytes=len(actual),image_path=str(image),
  receipt_path=str(OUT/'worker-store-json-profile.receipt.json'),compiler_sha256=COMPILER_SHA,counts=counts)
 components['storevalues']=row
 save(OUT/'worker-store-json-profile.manifest.json',row)
 for module in tuple(sys.modules.values()):
  name=getattr(module,'__file__',None)
  if name:
   path=Path(name).resolve()
   if path.suffix=='.py' and any(path.is_relative_to(base) for base in (ROOT,REFERENCE,FULL_REFERENCE)):read(path)
 assert same();status='PASS'
except BaseException as exc:
 failure=dict(error_class=type(exc).__name__,error=str(exc));traceback.print_exc()
finally:
 unchanged=same()
 if not unchanged:status='FAIL'
 for index,(path,(raw,mode)) in enumerate(pins.items()):
  target=OUT/'frozen-inputs'/str(index)/path.name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw);target.chmod(mode)
 save(OUT/'source-after.json',rows())
 summary=dict(status=status,scope='NEW_STORE_JSON_PROFILE_FRESH_B3_AFTER_ORIGINAL_EIGHT_FRESH_PEERS',
  actual_compiles=len(components),components=components,counts=counts,failure=failure,source_unchanged=unchanged,
  elapsed_ns=time.monotonic_ns()-started,compiler_sha256=COMPILER_SHA,
  original_limits=dict(cpu_seconds=10,wall_seconds=20,address_space_bytes=268435456),
  semantic_entries=0,actual_physical_namespace_entries=0,whole_worker_closed=False)
 save(OUT/'summary.json',summary);print(json.dumps(summary,sort_keys=True),flush=True)
if status!='PASS':raise SystemExit(1)
