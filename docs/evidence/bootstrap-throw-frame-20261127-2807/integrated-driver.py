from pathlib import Path
import sys,os,json,time,hashlib,subprocess,ast
spec=json.load(sys.stdin)
scope=Path('/home/qian-qi/hia-bootstrap-throw-frame-20261127-2807')
root=scope/'src';out=scope/'controls-v3'
def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
prior=(scope/'controls-v2/result.json').read_bytes();assert pin(prior)==spec['prior_result']
assert json.loads(prior)['status']=='PASS_REAL_VM_MECHANICAL_LIFETIME_CONTROLS_ONLY'
for name,expected in spec['source_before'].items():assert pin((root/name).read_bytes())==expected,name
for name,expected in spec['original_test_pins'].items():assert pin((root/name).read_bytes())==expected,name
out.mkdir(mode=0o700)
(out/'invocation.json').write_text(json.dumps(spec,sort_keys=True)+'\n')
for name,text in spec['product_files'].items():
 raw=text.encode();expected=spec['product_pins'][name]
 assert pin(raw)=={k:expected[k] for k in ('bytes','sha256')},name
 target=root/name
 if name not in spec['source_before']:assert not target.exists(),name
 if name!='hepta/hia_service_bootstrap_native.py':target.write_bytes(raw)
 else:assert target.read_bytes()==raw
before_class=ast.parse((scope/'controls-v2/frame-lifetime-control.py').read_bytes())
after_class=ast.parse((root/'tests/test_hia_bootstrap_generator_frame_lifetime.py').read_bytes())
a=next(x for x in before_class.body if isinstance(x,ast.ClassDef) and x.name=='GeneratorMechanicalLifetimeTests')
b=next(x for x in after_class.body if isinstance(x,ast.ClassDef) and x.name=='GeneratorMechanicalLifetimeTests')
assert ast.dump(a,include_attributes=False)==ast.dump(b,include_attributes=False)
for key in list(os.environ):
 if key.startswith(('HEPTA_HIA_','PYTHON','HIA_BOOTSTRAP_DIAG_')) or key=='LD_PRELOAD':del os.environ[key]
temporary=out/'temporary';temporary.mkdir(mode=0o700);os.environ['TMPDIR']=str(temporary)
if os.getpriority(os.PRIO_PROCESS,0)<10:os.setpriority(os.PRIO_PROCESS,0,10)
os.chdir(root);sys.path.insert(0,str(root))
from tests import hia_service_bootstrap_support as s
before=s.source_snapshot()
expected={**spec['source_before'],**{name:pin(text.encode()) for name,text in spec['product_files'].items()}}
assert before==expected and len(before)==160
command=['/usr/bin/python3','-I','-B','tools/run_hia_unittest_gate.py',
 'tests.test_hia_bootstrap_terminal_business.BootstrapTerminalBusinessTests',
 'tests.test_hia_service_bootstrap_sources.ServiceBootstrapStaticSourceTests',
 'tests.test_hia_service_bootstrap_fixed_words.ServiceBootstrapFixedWordSourceTests',
 'tests.test_hia_service_bootstrap_word.ServiceBootstrapWordSourceTests',
 'tests.test_hia_bootstrap_observer_source_custody.BootstrapObserverSourceCustodyTests',
 'tests.test_hia_bootstrap_generator_frame_lifetime.GeneratorMechanicalLifetimeTests']
started=time.monotonic()
with (out/'tests.stdout').open('xb') as a,(out/'tests.stderr').open('xb') as b:
 result=subprocess.run(command,cwd=root,env=os.environ.copy(),stdout=a,stderr=b,timeout=180)
after=s.source_snapshot();assert after==before
for name,expected in spec['original_test_pins'].items():assert pin((root/name).read_bytes())==expected,name
text=(out/'tests.stderr').read_text()
assert 'Ran 38 tests in ' in text
record={'schema':'hepta.hia.bootstrap-throw-frame-integrated-controls.v1',
 'status':'PASS_38_CONTROLS_ONLY' if result.returncode==0 else 'HOLD',
 'whole_native_stack_qualified':False,'source8_qualified':False,
 'command':command,'returncode':result.returncode,'timeout_seconds':180,'seconds':time.monotonic()-started,
 'source_before':before,'source_after':after,'original_test_pins':spec['original_test_pins'],
 'stdout':s.file_pin(out/'tests.stdout'),'stderr':s.file_pin(out/'tests.stderr'),
 'control_class_AST_unchanged_from_actual_before_after':True}
s.write_json(out/'result.json',record)
print(json.dumps({'status':record['status'],'returncode':result.returncode,'seconds':record['seconds'],
 'source_count':len(before),'record':s.file_pin(out/'result.json')},sort_keys=True),flush=True)
sys.exit(result.returncode)
