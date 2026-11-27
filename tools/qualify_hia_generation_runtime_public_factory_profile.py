"""The original Runtime rejects freshly valid structured profiles before paths/Clang."""
from pathlib import Path
import argparse,json,traceback
from tools import qualify_hia_generation_runtime_public_factory as factory
from tools import qualify_hia_generation_runtime_directory as directory
from tools.qualify_hia_clang_capture_faults import isolated
from hepta.hia_multiversion import ScalarMultiversionRuntime
from hepta.hia_program import verify_program
from tests.test_hia_program_composite import module
q=factory.q;ZERO=(0,0,0)
CASES=('structured-raw','structured-verified','structured-before-path','structured-before-clang','invalid-structured')
def one(path,out,name):
 f=factory.installed.InstalledFixture(path,out);v=factory.Values(q.ValueTransport(f.owner));baseline=q.get(v.raw(47),48)
 report=dict(passed=False,name=name)
 def save():(out/'case.json').write_text(json.dumps(report,indent=2,sort_keys=True,default=repr)+'\n')
 try:
  doc=module([],*json.loads(directory.current_core())['functions'])
  oracle=doc
  if name=='invalid-structured':doc={'schema':doc['schema']};oracle=doc
  marker=None
  if name=='structured-verified':
   oracle=verify_program(doc)
   can=v.scalar(oracle.canonical_bytes);original=v.scalar(oracle.structured_bytes)
   base=v.keep(v.raw(67,a=can,b=original))
  else:base=v.scalar(json.dumps(doc,indent=2).encode())
  folder=v.scalar(str(f.parent));caps=[base,folder]
  if name=='structured-before-path':
   marker=v.lst([]);cls=v.cls('StructuredMustPrecedePath',[])
   v.attr(cls,'__fspath__',directory.callable_value(v,marker,directory.marker_body()))
   caps[1]=v.instance(cls)
  elif name=='structured-before-clang':caps+=[v.scalar(None)]
  try:ScalarMultiversionRuntime(oracle,None)
  except BaseException as e:expected=type(e).__name__,e.args
  else:raise AssertionError('original profile admitted structured input')
  rc,row,raw=factory.construct(f,caps)
  report.update(rc=rc,row=row,expected=expected,factory_header=f.front.raw[524288:525312].hex());save()
  assert rc==0 and raw[:8]==b'HIARTCR1'
  assert row['status']!=0 and row['disposition']==2 and row['known']==row['delivered']==row['retired']==1 and row['pending']==0 and row['state']==3,row
  exc=v.keep(raw);actual=factory.exception_data(v,exc);report['actual']=actual;save();assert actual==expected,(actual,expected)
  if name!='invalid-structured':assert row['profile']==1,row
  if marker is not None:assert q.get(v.raw(17,a=marker),48)==0
  f.guard(0)
  while v.held:v.drop(next(iter(v.held)))
  assert q.get(v.raw(47),48)==baseline
  report.update(passed=True,**f.finish());save();return report
 except BaseException as e:
  report.update(error=repr(e),traceback=traceback.format_exc());save();raise
def main():
 p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--cases',nargs='*',choices=CASES);a=p.parse_args()
 spec=json.loads((a.build/'build.json').read_bytes());path=a.build/'install/hia-generation-component-root.so'
 assert directory.custody.pin(path.read_bytes())==spec['products']['hia-generation-component-root.so']
 a.output.mkdir(parents=True,exist_ok=False);rows=[]
 for name in a.cases or CASES:
  here=a.output/name;here.mkdir();rows.append(isolated(name,lambda name=name,here=here:one(path,here,name)))
  (a.output/'partial.json').write_text(json.dumps(rows,indent=2,sort_keys=True,default=repr)+'\n');print('PUBLIC_FACTORY_PROFILE_PASS',name,flush=True)
 report=dict(passed=True,groups=len(rows),cases=rows,owner=directory.custody.pin(path.read_bytes()),construction=directory.custody.pin((a.build/'build.json').read_bytes()),qualifier=directory.custody.pin(Path(__file__).read_bytes()),actual_original_structured_rejection=True,public_constructor_qualified=False,whole_runtime_qualified=False)
 (a.output/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True,default=repr)+'\n');print('PUBLIC_FACTORY_PROFILE_ACTUAL_PASS',len(rows),flush=True)
if __name__=='__main__':main()
