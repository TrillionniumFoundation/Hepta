from pathlib import Path
import sys,os,json,time,hashlib,subprocess,stat,ast,traceback
spec=json.load(sys.stdin)
old=Path('/home/qian-qi/hia-bootstrap-terminal-comparison-20261127-2807/src')
scope=Path('/home/qian-qi/hia-bootstrap-admission-lifetime-20261127-2807')
root=scope/'src'
data=Path('/run/media/qian-qi/TOSHIBA_DEV_1TB/hia-bootstrap-admission-lifetime-20261127-2807')
observer_name='tests/hia_service_bootstrap_observer.py'
def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
for name,expected in spec['source_before'].items():assert pin((old/name).read_bytes())==expected,name
assert pin(spec['observer'].encode())==spec['observer_pin']
assert pin(spec['preliminary_child'].encode())==spec['preliminary_child_pin']
before_text=(old/observer_name).read_text()
before_ast=ast.parse(before_text);after_ast=ast.parse(spec['observer'])
before_functions={node.name:ast.dump(node,include_attributes=False) for node in before_ast.body if isinstance(node,(ast.FunctionDef,ast.ClassDef))}
after_functions={node.name:ast.dump(node,include_attributes=False) for node in after_ast.body if isinstance(node,(ast.FunctionDef,ast.ClassDef))}
assert set(before_functions)==set(after_functions)
assert [name for name in before_functions if before_functions[name]!=after_functions[name]]==['run']
def business_loop(tree):
 run=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='run')
 return next(node for node in ast.walk(run) if isinstance(node,ast.For) and ast.unparse(node.target)=='(ordinal, case)')
assert ast.dump(business_loop(before_ast),include_attributes=False)==ast.dump(business_loop(after_ast),include_attributes=False)
scope.mkdir(mode=0o700);root.mkdir(mode=0o700);data.mkdir(mode=0o700)
names=set(spec['source_before'])
for prefix in ('hepta','tools','tests'):
 for path in (old/prefix).rglob('*'):
  if path.is_file() and (path.suffix=='.py' or str(path.relative_to(old)).startswith('tests/fixtures/')):
   names.add(str(path.relative_to(old)))
for name in ('pyproject.toml','setup.py','README.md'):
 if (old/name).is_file():names.add(name)
total=sum((old/name).stat().st_size for name in names)
assert total<512_000_000
assert os.statvfs(scope).f_bavail*os.statvfs(scope).f_frsize>total+500_000_000
copied={}
for name in sorted(names):
 source=old/name;st=source.lstat()
 assert stat.S_ISREG(st.st_mode) and not source.is_symlink(),name
 raw=source.read_bytes();target=root/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
 assert target.read_bytes()==raw and source.read_bytes()==raw,name
 copied[name]=pin(raw)
for name,expected in spec['source_before'].items():assert pin((root/name).read_bytes())==expected,name
before_test={name:(root/name).read_bytes() for name in spec['unchanged_test_pins']}
for name,expected in spec['unchanged_test_pins'].items():assert pin(before_test[name])==expected
(root/observer_name).write_text(spec['observer'])
assert pin((root/observer_name).read_bytes())==spec['observer_pin']
for name,raw in before_test.items():assert (root/name).read_bytes()==raw
(scope/'preliminary.py').write_text(spec['preliminary_child'])
(data/'reconstruction.json').write_text(json.dumps({'source_origin':str(old),
 'public_product_base':spec['base_commit'],'independent_source_snapshot_not_git_checkout':True,
 'copied_files':copied,'proposal_pin':spec['observer_pin'],'original_test_pins':spec['unchanged_test_pins'],
 'total_copied_bytes':total,'only_changed_definition':'run','entire_business_loop_ast_unchanged':True,
 'admit_originals_and_seal_record_ast_unchanged':True},sort_keys=True,indent=2)+'\n')
(data/'invocation.json').write_text(json.dumps(spec,sort_keys=True,indent=2)+'\n')
for key in list(os.environ):
 if key.startswith(('HEPTA_HIA_','PYTHON','HIA_BOOTSTRAP_DIAG_')) or key=='LD_PRELOAD':del os.environ[key]
tmp=scope/'temporary';tmp.mkdir(mode=0o700)
os.environ['TMPDIR']=str(tmp);os.chdir(root);sys.path.insert(0,str(root))
from tests import hia_service_bootstrap_support as s
source=s.source_snapshot()
expected_source={**spec['source_before'],observer_name:spec['observer_pin']}
assert source==expected_source and len(source)==103
control=['/usr/bin/python3','-I','-B','tools/run_hia_unittest_gate.py',
 'tests.test_hia_bootstrap_terminal_business.BootstrapTerminalBusinessTests',
 'tests.test_hia_service_bootstrap_sources.ServiceBootstrapStaticSourceTests',
 'tests.test_hia_service_bootstrap_fixed_words.ServiceBootstrapFixedWordSourceTests',
 'tests.test_hia_service_bootstrap_word.ServiceBootstrapWordSourceTests']
started=time.monotonic()
with (data/'controls.stdout').open('xb') as stdout,(data/'controls.stderr').open('xb') as stderr:
 result=subprocess.run(control,cwd=root,env=os.environ.copy(),stdout=stdout,stderr=stderr,timeout=180)
s.write_json(data/'controls.result.json',{'command':control,'returncode':result.returncode,
 'seconds':time.monotonic()-started,'stdout':s.file_pin(data/'controls.stdout'),'stderr':s.file_pin(data/'controls.stderr')})
print(json.dumps({'event':'admission_lifetime_controls','returncode':result.returncode,
 'seconds':time.monotonic()-started,'source_count':len(source),'copied_bytes':total},sort_keys=True),flush=True)
if result.returncode:raise RuntimeError('strict terminal-comparison controls failed')
record={'schema':'hepta.hia.bootstrap-admission-lifetime-owned-observation.v1','source_before':source,
 'whole_native_stack_qualified':False,'original_source_suite_executed':False,
 'outer_seconds':1800,'cleanup_seconds':3}
try:
 receipt,report,raw=s.run_child(data,'preliminary-unselected',
   [sys.executable,'-I','-B',str(scope/'preliminary.py'),str(data/'preliminary-unselected')],seconds=1800)
 record['status']='PASS_UNSELECTED_FINITE_AND_READBACK_ONLY'
 record['report']=s.bytes_pin(raw);record['receipt']=s.file_pin(data/'preliminary-unselected.result.json')
except BaseException as error:
 record.update({'status':'HOLD','error':{'type':type(error).__name__,'message':str(error)}});traceback.print_exc()
finally:
 record['source_after']=s.source_snapshot();assert record['source_after']==source
 s.write_json(data/'observation.json',record)
 print(json.dumps({'event':'admission_lifetime_preliminary_outer','status':record['status'],
 'error':record.get('error'),'report':s.file_pin(data/'observation.json')},sort_keys=True),flush=True)
sys.exit(0 if record['status'].startswith('PASS_') else 1)
