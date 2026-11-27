from pathlib import Path
import sys,os,json,time,hashlib,traceback
spec=json.load(sys.stdin)
scope=Path('/home/qian-qi/hia-bootstrap-closure-20261127-2807');root=scope/'src'
out=Path('/run/media/qian-qi/TOSHIBA_DEV_1TB/hia-bootstrap-closure-20261127-2807/current-owned-dispatch-v1')
for name,pin in spec['source_pins'].items():
 raw=(root/name).read_bytes();assert len(raw)==pin['bytes'] and hashlib.sha256(raw).hexdigest()==pin['sha256'],name
compiler=scope/'development-B3-acb6478.flat'
assert len(compiler.read_bytes())==641344 and hashlib.sha256(compiler.read_bytes()).hexdigest()=='acb6478d1a466d17210611c5fcbbd5aeec3109b0813e917f0bb5c8419f3c33a9'
for key in list(os.environ):
 if key.startswith(('HEPTA_HIA_','PYTHON','HIA_BOOTSTRAP_DIAG_')) or key=='LD_PRELOAD':del os.environ[key]
os.environ['TMPDIR']=str(scope/'temporary');os.chdir(root);sys.path.insert(0,str(root))
from tests import hia_service_bootstrap_support as s
from tools.build_hia_service_bootstrap import build
from tools.qualify_hia_service_bootstrap_finite import current_dispatch_child
from tools.read_hia_service_bootstrap import _read_current_dispatch_control
from tools.hia_bootstrap_source_history import code_bindings,SOURCE
out.mkdir(mode=0o700)
before=s.source_snapshot();assert before==spec['source_pins']
s.write_json(out/'invocation.json',spec)
record={'schema':'hepta.hia.bootstrap-current-owned-dispatch-observation.v1',
 'scope':'CURRENT_PUBLIC_DOMAIN_ONLY','whole_native_stack_qualified':False,
 'original_source_suite_executed':False,'matching_source_cold_qualified':False,
 'source_before':before,'lanes':{}}
started=time.monotonic()
try:
 manifest=build(scope/'current-owned-dispatch-component-v1',compiler,development=True)
 record['manifest']={'path':str(manifest),**s.file_pin(manifest)}
 bindings=code_bindings((root/SOURCE).read_bytes())
 for lane in ('unselected','vm','native'):
  laneout=out/lane;laneout.mkdir(mode=0o700)
  entry,captures=current_dispatch_child(laneout,lane,before,manifest=manifest if lane=='native' else None)
  raw,report,pin=s.capture_json(laneout/'current-dispatch/report.json',entry['report'])
  _read_current_dispatch_control(report['current_dispatch'],bindings,lane)
  for path,content in captures:s.exact_reread(path,content)
  result=json.loads((laneout/'current-dispatch.result.json').read_bytes())
  assert result['timeout_seconds']==60 and result['cleanup_seconds']==3
  assert result['timeout'] is False and result['returncode']==0 and result['stderr']['bytes']==0 and result['stdout']['bytes']==0
  assert result['cleanup']['signals']==[] and result['cleanup']['after']==[]
  record['lanes'][lane]={'owned_entry':entry,'proof':report['current_dispatch'],
    'elapsed_seconds':result['elapsed_seconds'],'runtime':report['runtime']}
  print(json.dumps({'event':'current_owned_dispatch_lane_terminal','lane':lane,'seconds':result['elapsed_seconds'],'report':pin},sort_keys=True),flush=True)
 record['status']='PASS_CURRENT_PUBLIC_8_INIT_12_PROGRAM_THREE_OWNED_LANES_ONLY'
except BaseException as error:
 record.update({'status':'HOLD','error':{'type':type(error).__name__,'message':str(error)}});traceback.print_exc()
finally:
 record['source_after']=s.source_snapshot();assert record['source_after']==before
 record['seconds']=time.monotonic()-started
 s.write_json(out/'observation.json',record)
 print(json.dumps({'event':'current_owned_dispatch_terminal','status':record['status'],'seconds':record['seconds'],'error':record.get('error'),'report':s.file_pin(out/'observation.json')},sort_keys=True),flush=True)
sys.exit(0 if record['status'].startswith('PASS_CURRENT_PUBLIC_') else 1)
