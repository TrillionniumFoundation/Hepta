"""Original public Runtime ordering and native Value identity through the factory."""
from pathlib import Path,PurePosixPath
import argparse,ctypes as C,json,os,struct,traceback
from tools import qualify_hia_generation_runtime_public_factory as factory
from tools import qualify_hia_generation_runtime_directory as directory
from tools.qualify_hia_clang_capture_faults import isolated
from hepta.hia_multiversion import ScalarMultiversionRuntime
from hepta.hia_program import verify_program
q=factory.q
ZERO=(0,0,0)
OPTION_CASES={
 'timeout-zero':{'validation_timeout_ms':0},
 'timeout-high':{'validation_timeout_ms':30001},
 'timeout-float':{'validation_timeout_ms':2.0},
 'max-low':{'max_live_generations':1},
 'max-high':{'max_live_generations':65},
 'max-bool':{'max_live_generations':True},
 'prove-int':{'prove_total':0},
 'prove-none':{'prove_total':None},
 'timeout-first':{'validation_timeout_ms':False,'max_live_generations':False,'prove_total':0},
 'max-before-prove':{'max_live_generations':False,'prove_total':0},
}
CASES=tuple(OPTION_CASES)+('baseline-invalid','baseline-before-path','directory-none','directory-relative','directory-string-subclass','directory-posix-subclass','directory-pathlike','directory-raise','directory-parts-ignore-fspath','clang-string-subclass','explicit-defaults','repeat-factory','clang-missing','clang-none','clang-raise','clang-pathlike')
def oracle_error(baseline,directory,**kw):
 try:
  result=ScalarMultiversionRuntime(baseline,directory,**kw)
 except BaseException as error:return type(error).__name__,error.args
 else:
  result.close();raise AssertionError('original operation did not raise')
def one(path,out,name):
 f=factory.installed.InstalledFixture(path,out);v=factory.Values(q.ValueTransport(f.owner))
 baseline=q.get(v.raw(47),48);cwd=os.getcwd();os.chdir(out)
 report=dict(name=name,passed=False,calls=[])
 def save():(out/'case.json').write_text(json.dumps(report,indent=2,sort_keys=True,default=repr)+'\n')
 try:
  program=directory.current_core();original=program
  base=v.scalar(program);folder=v.scalar(str(f.parent));caps=[base,folder]
  expected=None;expected_identity=None;marker=None
  if name in OPTION_CASES:
   kw=OPTION_CASES[name];args=[ZERO]*7;args[0]=base;args[1]=folder
   for key,index in [('validation_timeout_ms',3),('max_live_generations',4),('prove_total',5)]:
    if key in kw:args[index]=v.scalar(kw[key])
   caps=args;expected=oracle_error(None,None,**kw)
  elif name in ('baseline-invalid','baseline-before-path'):
   original=b'{}';base=v.scalar(original);caps[0]=base
   expected=oracle_error(original,None)
   if name=='baseline-before-path':
    marker=v.lst([]);cls=v.cls('ActualOrderPathLike',[])
    v.attr(cls,'__fspath__',directory.callable_value(v,marker,directory.marker_body()))
    caps[1]=v.instance(cls)
  elif name=='directory-none':caps[1]=v.scalar(None)
  elif name=='directory-relative':caps[1]=v.scalar('artifacts/./../artifacts')
  elif name=='directory-string-subclass':
   cls=v.cls('ActualDirectoryStr',[v.builtin(6)])
   caps[1]=v.instance(cls,base=v.scalar('artifacts/./../artifacts'))
  elif name in ('directory-posix-subclass','directory-parts-ignore-fspath'):
   cls=v.cls('ActualDirectoryPath',[v.builtin(18)])
   if name=='directory-parts-ignore-fspath':
    marker=v.lst([]);v.attr(cls,'__fspath__',directory.callable_value(v,marker,directory.marker_body()))
   caps[1]=v.instance(cls,base=v.lst([v.scalar(x)for x in ['artifacts','.','..','artifacts']]))
  elif name in ('directory-pathlike','directory-raise'):
   cls=v.cls('ActualRuntimeDirectoryLike',[])
   if name=='directory-raise':
    expected_identity=directory.raised_value(v)
    fn=directory.callable_value(v,expected_identity,directory.inv.echo_field(1,2))
   else:fn=directory.callable_value(v,v.scalar(str(f.parent)),directory.inv.echo_field(1))
   v.attr(cls,'__fspath__',fn);caps[1]=v.instance(cls)
  elif name=='clang-string-subclass':
   cls=v.cls('ActualClangStr',[v.builtin(6)]);caps+=[v.instance(cls,base=v.scalar('clang'))]
  elif name in ('clang-raise','clang-pathlike'):
   cls=v.cls('ActualRuntimeClangLike',[])
   if name=='clang-raise':
    expected_identity=directory.raised_value(v)
    fn=directory.callable_value(v,expected_identity,directory.inv.echo_field(1,2))
   else:fn=directory.callable_value(v,v.scalar('clang'),directory.inv.echo_field(1))
   v.attr(cls,'__fspath__',fn);caps+=[v.instance(cls)]
  elif name=='explicit-defaults':caps+=[v.scalar('clang'),v.scalar(2000),v.scalar(8),v.scalar(False)]
  elif name=='clang-missing':
   caps+=[v.scalar('/nonexistent/hia-runtime-constructor-clang')]
   expected=oracle_error(original,str(f.parent),clang='/nonexistent/hia-runtime-constructor-clang')
  elif name=='clang-none':
   caps+=[v.scalar(None)]
   expected=oracle_error(original,str(f.parent),clang=None)
  elif name!='repeat-factory':raise AssertionError(name)
  for index in range(2 if name=='repeat-factory'else 1):
   rc,row,raw=factory.construct(f,caps);report['calls'].append(dict(rc=rc,**row));report['factory_header']=f.front.raw[524288:524800].hex();save()
   assert rc==0 and raw[:8]==b'HIARTCR1',(rc,row,raw[:128].hex())
   assert row['known']==1 and row['pending']==0 and row['retired']==1 and row['state']==3,row
   assert row['delivered']==1 and all(row['cap']),row
   primary=v.keep(raw)
   if expected is not None or expected_identity is not None:
    assert row['status']!=0 and row['disposition']==2,row
    if expected_identity is not None:assert v.same(primary,expected_identity)
    else:
     actual=factory.exception_data(v,primary);report['oracle']=expected;report['actual']=actual;save()
     assert actual==expected,(actual,expected)
    f.guard(0)
   else:
    assert row['status']==0 and row['disposition']==1,row
    cls=v.keep(v.raw(36,a=primary));canonical=v.builtin(20);assert v.same(cls,canonical)
    f.guard(1);rawcap=factory.private_value(f.owner,49,primary,1)
    assert q.get(rawcap,8)==0
    carrier=struct.unpack_from('<3Q',rawcap,24);lease=q.old.lease(f.c,carrier)
    f.c.call(lease,51);v.drop(primary);f.guard(1);f.c.call(lease,53)
    q.old.ok(f.api.call(6,lease));f.guard(0)
   if marker is not None:assert q.get(v.raw(17,a=marker),48)==0,'__fspath__ called outside original order'
  while v.held:v.drop(next(iter(v.held)))
  assert q.get(v.raw(47),48)==baseline,(baseline,q.get(v.raw(47),48))
  report.update(passed=True,**f.finish());save();return report
 except BaseException as e:
  report.update(error=repr(e),traceback=traceback.format_exc());save();raise
 finally:os.chdir(cwd)
def main():
 p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--cases',nargs='*',choices=CASES);a=p.parse_args()
 spec=json.loads((a.build/'build.json').read_bytes());path=a.build/'install/hia-generation-component-root.so'
 assert directory.custody.pin(path.read_bytes())==spec['products']['hia-generation-component-root.so']
 a.output.mkdir(parents=True,exist_ok=False);rows=[]
 for name in a.cases or CASES:
  here=a.output/name;here.mkdir()
  rows.append(isolated(name,lambda name=name,here=here:one(path,here,name)))
  (a.output/'partial.json').write_text(json.dumps(rows,indent=2,sort_keys=True,default=repr)+'\n')
  print('PUBLIC_FACTORY_CONTRACT_PASS',name,flush=True)
 report=dict(passed=True,groups=len(rows),cases=rows,owner=directory.custody.pin(path.read_bytes()),construction=directory.custody.pin((a.build/'build.json').read_bytes()),qualifier=directory.custody.pin(Path(__file__).read_bytes()),public_constructor_qualified=False,whole_runtime_qualified=False)
 (a.output/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True,default=repr)+'\n')
 print('PUBLIC_FACTORY_CONTRACT_ACTUAL_PASS',len(rows),flush=True)
if __name__=='__main__':main()
