"""Run only isolated synthetic reader/source checks, never a native product."""
from pathlib import Path
import argparse,ast,hashlib,json,shutil,sys,time,traceback,unittest
from unittest.mock import patch

p=argparse.ArgumentParser();p.add_argument('--base',type=Path,required=True);p.add_argument('--evidence',type=Path,required=True)
a=p.parse_args();draft=Path(__file__).resolve().parents[1];out=a.evidence.resolve();out.mkdir(mode=0o700,parents=True,exist_ok=False)
started=time.monotonic()
def pin(path):
 raw=path.read_bytes();return {'path':str(path),'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
 'git_blob_sha1':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
def write(name,value):
 with (out/name).open('x') as f:json.dump(value,f,indent=2,sort_keys=True);f.write('\n')
inputs=sorted((draft/'inputs').rglob('*'));inputs=[x for x in inputs if x.is_file()]
before=[pin(x) for x in inputs];write('inputs-before.json',before)
validation=out/'validation-root';validation.mkdir()
for path in inputs:
 target=validation/path.relative_to(draft/'inputs');target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(path.read_bytes())
references=('experiments/hia_native_successor_runner_20261111/run_hia_qualification_v9.py','tools/qualify_hia_core_lowering_callers.py')
refs=[]
for name in references:
 source=a.base/name;target=validation/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(source.read_bytes());refs.append(pin(source))
write('references.json',refs)
report={'schema':'hia.core-unpack-matching-gates-source-controls.v1','status':'HOLD','runtime':sys.version,
 'scope':'SOURCE_ONLY_SYNTHETIC_READER_CONTROL','native_or_compile_or_cold_executed':False,
 'product18_executed':False,'original116_executed':False,'expected_ids':[],'loaded_ids':[],'executed_ids':[]}
try:
 for path in inputs:
  if path.suffix=='.py':ast.parse(path.read_bytes(),filename=str(path))
 sys.path.insert(0,str(a.base))
 import tools,tests
 tools.__path__=[str(validation/'tools'),*list(tools.__path__)];tests.__path__=[str(validation/'tests'),*list(tests.__path__)]
 from tools import hia_core_unpack_gates as gates
 from tests import test_hia_core_unpack_gates as module
 from hepta.hia_json_preflight_native import NativeHiaJsonImage
 from hepta.hia_core_unpack_native import CpythonLeaves,UnpackSession
 loader=unittest.TestLoader();suite=loader.loadTestsFromModule(module)
 def flatten(x):
  for y in x:
   if isinstance(y,unittest.TestSuite):yield from flatten(y)
   else:yield y
 ids=[x.id() for x in flatten(suite)];report['loaded_ids']=ids
 source=ast.parse((validation/'tests/test_hia_core_unpack_gates.py').read_bytes())
 cls=next(x for x in source.body if isinstance(x,ast.ClassDef) and x.name=='CoreUnpackGateSourceTests')
 expected=['tests.test_hia_core_unpack_gates.CoreUnpackGateSourceTests.'+name for name in sorted(x.name for x in cls.body if isinstance(x,ast.FunctionDef) and x.name.startswith('test_'))]
 report['expected_ids']=expected
 assert len(expected)==14 and ids==expected and len(set(ids))==len(ids) and not loader.errors
 executed=[]
 class Result(unittest.TextTestResult):
  def startTest(self,test):executed.append(test.id());super().startTest(test)
 def forbidden(*args,**kwargs):raise AssertionError('native execution forbidden in source-only controls')
 with (out/'unittest.log').open('x') as log,patch.object(NativeHiaJsonImage,'__init__',forbidden),patch.object(CpythonLeaves,'__init__',forbidden),patch.object(UnpackSession,'_step',forbidden):
  result=unittest.TextTestRunner(stream=log,verbosity=2,resultclass=Result).run(suite)
 report.update(executed_ids=executed,tests_run=result.testsRun,loader_errors=list(loader.errors),successful=result.wasSuccessful())
 for name in ('errors','failures','skipped','expectedFailures','unexpectedSuccesses'):
  report[name]=[(item[0].id(),item[1]) if isinstance(item,tuple) else item.id() for item in getattr(result,name)]
 if (result.wasSuccessful() and ids==executed and result.testsRun==14
     and not any(report[x] for x in ('loader_errors','errors','failures','skipped','expectedFailures','unexpectedSuccesses'))):report['status']='SOURCE_CONTROL_PASS'
except BaseException:
 report['status']='HOLD';report['error']=traceback.format_exc()
finally:
 after=[pin(x) for x in inputs];write('inputs-after.json',after)
 report['source_preserved']=before==after
 if before!=after:report['status']='HOLD'
 report['seconds']=time.monotonic()-started;write('report.json',report)
 print(json.dumps({key:report.get(key) for key in ('status','tests_run','seconds','source_preserved','error')}),flush=True)
raise SystemExit(0 if report['status']=='SOURCE_CONTROL_PASS' else 1)
