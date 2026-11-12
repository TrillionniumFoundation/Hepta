"""Fresh original-limit SHA and digest compilation after eight real registry compiles."""
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
    "path": "tools/worker_digest_common.py",
    "bytes": 11607,
    "sha256": "29a33404037ea950e36bbb14a5220f707bec5831925d20cf17dc0dda9393fac9",
    "gitsha": "6d56f0b6302fc359e95c2d75acea1b481e018528"
  },
  {
    "path": "tools/worker_digest_result.py",
    "bytes": 11421,
    "sha256": "e998c82865c3ac5adc6da87d27c0484be08ce8b6b4f64ac045cd363f90ae3d4d",
    "gitsha": "9fc8a73fb39822cae52bf93162aca37463a34773"
  },
  {
    "path": "tools/generate_hia_agent_worker_digest.py",
    "bytes": 7219,
    "sha256": "7c8b432e2582f0feab7d0629ffc9ceae03a173d7f9dca627d012e71c9368502b",
    "gitsha": "9ef895047c622c2886f212c4bc80bf0f723cd2d4"
  },
  {
    "path": "dependencies/generate_hia_agent_worker_init_values.py",
    "bytes": 22197,
    "sha256": "9a786c3d3982b736bd068eb522b8b8d7649da80bd4813f9c235e2c83461a95ac",
    "gitsha": "a0bdd8d99238cb52c6669be09463a57b9fdd0c78"
  },
  {
    "path": "dependencies/graph_harness_r3.py",
    "bytes": 9783,
    "sha256": "75fe54554a93e19e30251073ac225deff944d6673d87ccc2b597e47a19e8be7c",
    "gitsha": "eaf060c8c6870cad0a85a23f6b94ffa39308c45c"
  },
  {
    "path": "dependencies/generate_hia_sha256_stream.py",
    "bytes": 4420,
    "sha256": "247816be2a50d384a6dd86a1d8cad909a48fbcdef54444f2394a7789fb137238",
    "gitsha": "80167acbcc4c4f162deaf436aab95fffefb9947a"
  }
]
ROOT.mkdir(parents=True,exist_ok=False)
OUT=ROOT/'development/compile-r2';OUT.mkdir(parents=True)
pins={};components={};status='FAIL';failure=None;started=time.monotonic_ns()
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
  path=ROOT/row['path'];ast.parse(raw,filename=str(path));put(path,raw)
 helper=read(REFERENCE/'tools/hia_agent_edit_source_views.py')
 assert (len(helper),digest(helper))==(23950,'555472263213f15deb239fcf3bf8e5b273a28caf3a67bb29ffd037f171d7ae5c')
 put(ROOT/'dependency-overlay/tools/hia_agent_edit_source_views.py',helper)
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
 import tools
 # The independently verified full exact-0ef source contributes only the
 # SHA author's constants/helpers if that tracked module was not in the
 # historical small Worker reference. No runtime peer is replaced.
 tools.__path__=list(tools.__path__)+[str(FULL_REFERENCE/'tools')]
 read(FULL_REFERENCE/'tools/generate_hia_sha256.py')
 sha_generation=load_module('worker_digest_exact_sha_generation',ROOT/'dependencies/generate_hia_sha256_stream.py')
 generation=load_module('worker_digest_current_generation',ROOT/'tools/generate_hia_agent_worker_digest.py')
 for role,module,label,expected_source,expected_image in (
  ('sha',sha_generation,'sha256_stream','7fdc436867514b3d1dd741e3c3d86c0b95cc19d5b69907d5df9febf29639cb68','e9b0c18a52518af8d9e9909451d8174a02b7d6adc2910f8ca68d1b284a7093cb'),
  ('digest',generation,'worker-store-wire-digest','2830a5819ab19a6201076aeed0e7f65801ea5f1276b9910ea4602aa89ef0e71a','2f47d44fce6ac6c9fd2fa7453265b906642ff4dfe8d9117b8f89f41255f8f1c2')):
  (OUT/(role+'.expanded-authoring.py')).write_text(module.source_program())
  value=module.document();fs=value['functions']
  counts=dict(functions=len(fs),blocks=sum(len(f['blocks']) for f in fs),
    instructions=sum(len(b['ops']) for f in fs for b in f['blocks']),
    max_function_blocks=max(len(f['blocks']) for f in fs),max_block_parameters=max(len(b['params']) for f in fs for b in f['blocks']))
  assert all(a<=b for a,b in zip(counts.values(),(128,1536,8192,256,16))),counts
  source=render_assembly(value).encode();assemble_program(source)
  assert digest(source)==expected_source
  put(OUT/(role+'.hiaasm'),source)
  image,receipt=compile_stage(OUT,label,COMPILER,source)
  actual=read(image);receipt=json.loads(read(OUT/(label+'.receipt.json')))
  assert receipt['image_sha256']==COMPILER_SHA and receipt['input_sha256']==expected_source
  assert receipt['produced_sha256']==digest(actual)==expected_image
  components[role]=dict(source_sha256=expected_source,source_bytes=len(source),image_sha256=digest(actual),
   image_bytes=len(actual),image_path=str(image),receipt=receipt,counts=counts)
  if role=='sha':
   for suffix in ('.image.bin','.input.bin','.receipt.json'):
    put(ROOT/'dependencies/recovered-storage'/('sha256_stream'+suffix),read(OUT/(label+suffix)))
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
 summary=dict(status=status,scope='NEW_DIGEST_CI_TWO_FRESH_B3_AFTER_ORIGINAL_EIGHT_FRESH_PEERS',
  actual_compiles=len(components),components=components,failure=failure,source_unchanged=unchanged,
  elapsed_ns=time.monotonic_ns()-started,compiler_sha256=COMPILER_SHA,
  original_limits=dict(cpu_seconds=10,wall_seconds=20,address_space_bytes=268435456),
  semantic_entries=0,whole_worker_closed=False)
 save(OUT/'summary.json',summary);print(json.dumps(summary,sort_keys=True),flush=True)
if status!='PASS':raise SystemExit(1)
