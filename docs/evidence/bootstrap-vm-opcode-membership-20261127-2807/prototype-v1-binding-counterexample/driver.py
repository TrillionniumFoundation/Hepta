from pathlib import Path
import sys,os,json,hashlib,ast,types,unittest,io,time
root=Path('/home/qian-qi/hia-bootstrap-opcode-membership-20261127-2807/src')
out=root.parent/'type-name-before-control-v1'
spec=json.load(sys.stdin)
def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
for name,expected in spec['source_pins'].items():assert pin((root/name).read_bytes())==expected,name
raw=Path(spec['control_path']).read_bytes();assert pin(raw)==spec['control_pin']
out.mkdir(mode=0o700)
for key in list(os.environ):
 if key.startswith(('HEPTA_HIA_','PYTHON','HIA_BOOTSTRAP_DIAG_')) or key=='LD_PRELOAD':del os.environ[key]
os.chdir(root);sys.path.insert(0,str(root))
from tests import test_hia_program_runtime_opcode_membership as admitted
from tests import hia_service_bootstrap_support as support
before=support.source_snapshot();assert before==spec['source_pins']
tree=ast.parse(raw)
cls=next(node for node in tree.body if isinstance(node,ast.ClassDef) and node.name=='OpcodeMembershipSourceTests')
name='test_replaced_type_names_after_private_instruction_read_keep_original_effects'
method=next(node for node in cls.body if isinstance(node,ast.FunctionDef) and node.name==name)
namespace=dict(vars(admitted))
exec(compile(ast.Module(body=[method],type_ignores=[]),spec['control_path'],'exec'),namespace)
class V1TypeBindingControl(unittest.TestCase):
 def setUp(self):self.previous=admitted.previous_machine()
setattr(V1TypeBindingControl,name,namespace[name])
start=time.perf_counter()
with (out/'control.stderr').open('w') as stream:
 result=unittest.TextTestRunner(stream=stream,verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(V1TypeBindingControl))
after=support.source_snapshot();assert before==after
record={'schema':'hepta.hia.bootstrap-opcode-type-names-before-control.v1',
 'source_before':before,'source_after':after,'control_pin':spec['control_pin'],
 'method_AST':ast.dump(method,include_attributes=False),'control_methods':result.testsRun,
 'failures':len(result.failures),'errors':len(result.errors),'skips':len(result.skipped),
 'seconds':time.perf_counter()-start,'stderr':pin((out/'control.stderr').read_bytes()),
 'status':'EXPECTED_PREDECESSOR_EFFECT_MISMATCH' if result.testsRun==1 and result.failures and not result.errors and not result.skipped else 'HOLD',
 'source8_qualified':False,'whole_native_stack_qualified':False}
support.write_json(out/'observation.json',record)
print(json.dumps({'status':record['status'],'failures':record['failures'],'errors':record['errors'],
 'report':pin((out/'observation.json').read_bytes()),'stderr':record['stderr']},sort_keys=True),flush=True)
sys.exit(0 if record['status']=='EXPECTED_PREDECESSOR_EFFECT_MISMATCH' else 1)
