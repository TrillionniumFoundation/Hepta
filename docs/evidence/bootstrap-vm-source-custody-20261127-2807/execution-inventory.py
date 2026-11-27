from pathlib import Path
import sys,os,json,hashlib,stat,time,runpy,traceback
root=Path('/home/qian-qi/hia-bootstrap-admission-lifetime-20261127-2807/src')
out=Path('/run/media/qian-qi/TOSHIBA_DEV_1TB/hia-bootstrap-vm-execution-inventory-20261127-2807-v1')
out.mkdir(mode=0o700);tmp=out/'temporary';tmp.mkdir(mode=0o700)
for key in list(os.environ):
 if key.startswith(('HEPTA_HIA_','PYTHON','HIA_BOOTSTRAP_DIAG_')) or key=='LD_PRELOAD':del os.environ[key]
os.environ['TMPDIR']=str(tmp);os.chdir(root);sys.path.insert(0,str(root))
def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
before={}
for prefix in ('hepta','tools','tests'):
 for path in (root/prefix).rglob('*.py'):
  st=path.lstat();assert stat.S_ISREG(st.st_mode) and not path.is_symlink()
  before[str(path.relative_to(root))]=pin(path.read_bytes())
assert not list((root/'hepta').rglob('*.pyc'))
from tests import hia_service_bootstrap_support as support
source_before=support.source_snapshot()
expected=json.load(sys.stdin);assert source_before==expected
calls={};virtual=set()
prefix=str(root)+'/'
def profile(frame,event,arg):
 if event=='call':
  code=frame.f_code;filename=code.co_filename
  if filename.startswith(prefix):
   name=filename[len(prefix):]
   if name in before:
    key=(code.co_name,code.co_firstlineno,hashlib.sha256(code.co_code).hexdigest())
    table=calls.setdefault(name,{})
    table[key]=table.get(key,0)+1
   else:virtual.add(name)
scopes=[
 'tests.test_hia_bootstrap_terminal_business.BootstrapTerminalBusinessTests',
 'tests.test_hia_service_bootstrap_sources.ServiceBootstrapStaticSourceTests',
 'tests.test_hia_service_bootstrap_fixed_words.ServiceBootstrapFixedWordSourceTests',
 'tests.test_hia_service_bootstrap_word.ServiceBootstrapWordSourceTests']
command=['/usr/bin/python3','-I','-B','tools/run_hia_unittest_gate.py',*scopes]
sys.argv=['tools/run_hia_unittest_gate.py',*scopes]
old_profile=sys.getprofile();assert old_profile is None
started=time.monotonic();exit_code=0;failure=None
with (out/'tests.stdout').open('x') as stdout,(out/'tests.stderr').open('x') as stderr:
 previous_out,previous_err=sys.stdout,sys.stderr
 try:
  sys.stdout,sys.stderr=stdout,stderr
  sys.setprofile(profile)
  try:runpy.run_path(str(root/'tools/run_hia_unittest_gate.py'),run_name='__main__')
  except SystemExit as error:
   exit_code=0 if error.code is None else error.code
 except BaseException as error:
  exit_code=1;failure={'type':type(error).__name__,'message':str(error)};traceback.print_exc()
 finally:
  sys.setprofile(old_profile);sys.stdout,sys.stderr=previous_out,previous_err
loaded={}
for name,module in list(sys.modules.items()):
 if module is None:continue
 path=vars(module).get('__file__')
 if not isinstance(path,str) or not path.startswith(prefix):continue
 relative=path[len(prefix):]
 if relative in before:loaded[name]=relative
used=set(calls)|set(loaded.values())
for name in before:assert pin((root/name).read_bytes())==before[name],name
assert support.source_snapshot()==source_before
record={'schema':'hepta.hia.bootstrap-vm-execution-source-inventory.v1',
 'status':'DIAGNOSTIC_SOURCE_INVENTORY_ONLY','qualification_claim':False,
 'profiling_can_perturb_execution':True,'source_root':str(root),'source_before':source_before,
 'command':command,'exit_code':exit_code,'error':failure,'seconds':time.monotonic()-started,
 'loaded_modules':loaded,'called_functions':{name:[{'name':key[0],'line':key[1],
 'bytecode_sha256':key[2],'calls':count} for key,count in sorted(table.items())] for name,table in sorted(calls.items())},
 'virtual_code_filenames':sorted(virtual),'used_source_pins':{name:before[name] for name in sorted(used)},
 'missing_from_component_inputs':{name:before[name] for name in sorted(used) if name not in source_before},
 'all_python_source_before_after_equal':True,'runtime':sys.version,
 'stdout':pin((out/'tests.stdout').read_bytes()),'stderr':pin((out/'tests.stderr').read_bytes())}
raw=json.dumps(record,sort_keys=True,indent=2)+'\n';(out/'inventory.json').write_text(raw)
print(json.dumps({'exit_code':exit_code,'seconds':record['seconds'],'captured_python_files':len(before),
 'loaded_modules':len(loaded),'called_source_files':len(calls),'missing_count':len(record['missing_from_component_inputs']),
 'missing_paths':list(record['missing_from_component_inputs']),'path':str(out/'inventory.json'),'record':pin(raw.encode())},sort_keys=True))
sys.exit(0 if exit_code==0 else 1)
