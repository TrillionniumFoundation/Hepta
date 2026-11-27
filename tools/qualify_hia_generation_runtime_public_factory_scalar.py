"""Actual scalar admission errors through the public native Runtime factory."""
from pathlib import Path
import argparse,ctypes as C,json,os,traceback
from tools import qualify_hia_generation_runtime_public_factory as factory
from tools import qualify_hia_generation_runtime_directory as directory
from tools.qualify_hia_clang_capture_faults import isolated
from hepta.hia_multiversion import ScalarMultiversionRuntime
from hepta.hia_program import verify_program
from tests import test_hia_scalar_profile_native as samples
q=factory.q
CASES=('version-8','hidden-export','unit-signature','too-many-parameters',
 'trap-effect-default','unreachable-cycle','unit-block-parameter','checked-cast',
 'division-u32','division-i8','functions-17','blocks-65','operations-2049')
def fixture(name):
 table={n:(doc,total)for n,doc,total in samples.witnesses()}
 if name=='functions-17':
  doc=samples.basic('f0')
  doc['functions']=[samples.basic('f'+str(i))['functions'][0]for i in range(17)]
  return doc,False
 if name=='blocks-65':return samples.chain(65),False
 if name=='operations-2049':return samples.repeated_operations(2049),False
 return table[name]
def one(path,out,name):
 f=factory.installed.InstalledFixture(path,out);v=factory.Values(q.ValueTransport(f.owner))
 before=q.get(v.raw(47),48);cwd=os.getcwd();os.chdir(out)
 report=dict(name=name,passed=False)
 def save():(out/'case.json').write_text(json.dumps(report,indent=2,sort_keys=True,default=repr)+'\n')
 try:
  doc,total=fixture(name);checked=verify_program(doc)
  expected=None
  try:ScalarMultiversionRuntime(doc,None,clang=None,prove_total=total)
  except BaseException as error:expected=(type(error).__name__,error.args)
  assert expected is not None and expected[0]=='MultiversionRejected',expected
  marker=v.lst([]);cls=v.cls('AdmissionOrderPathLike',[])
  v.attr(cls,'__fspath__',directory.callable_value(v,marker,directory.marker_body()))
  body=json.dumps(doc,sort_keys=True,separators=(',',':')).encode()
  caps=[v.scalar(body),v.instance(cls),v.scalar(None),(0,0,0),(0,0,0),v.scalar(total)]
  rc,row,raw=factory.construct(f,caps);report.update(rc=rc,result=row,expected=expected)
  save()
  assert rc==0 and raw[:8]==b'HIARTCR1',(rc,row)
  assert row['known']==1 and row['pending']==0 and row['retired']==1 and row['state']==3,row
  assert row['status']!=0 and row['disposition']==2 and row['delivered']==1 and all(row['cap']),row
  error=v.keep(raw);actual=factory.exception_data(v,error);report['actual']=actual;save()
  assert actual==expected,(actual,expected)
  assert q.get(v.raw(17,a=marker),48)==0,'directory callback preceded the original scalar admission'
  f.guard(0)
  while v.held:v.drop(next(iter(v.held)))
  assert q.get(v.raw(47),48)==before,(before,q.get(v.raw(47),48))
  report.update(passed=True,**f.finish());save();return report
 except BaseException as error:
  report.update(error=repr(error),traceback=traceback.format_exc());save();raise
 finally:os.chdir(cwd)
def main():
 p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--cases',nargs='*',choices=CASES)
 a=p.parse_args();spec=json.loads((a.build/'build.json').read_bytes());path=a.build/'install/hia-generation-component-root.so'
 assert directory.custody.pin(path.read_bytes())==spec['products']['hia-generation-component-root.so']
 a.output.mkdir(parents=True,exist_ok=False);rows=[]
 for name in a.cases or CASES:
  here=a.output/name;here.mkdir()
  rows.append(isolated(name,lambda name=name,here=here:one(path,here,name)))
  (a.output/'partial.json').write_text(json.dumps(rows,indent=2,sort_keys=True,default=repr)+'\n')
  print('PUBLIC_RUNTIME_SCALAR_ERROR_PASS',name,flush=True)
 report=dict(passed=True,groups=len(rows),cases=rows,owner=directory.custody.pin(path.read_bytes()),construction=directory.custody.pin((a.build/'build.json').read_bytes()),qualifier=directory.custody.pin(Path(__file__).read_bytes()),public_constructor_qualified=False,whole_runtime_qualified=False)
 (a.output/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True,default=repr)+'\n')
 print('PUBLIC_RUNTIME_SCALAR_ERRORS_ACTUAL_PASS',len(rows),flush=True)
if __name__=='__main__':main()
