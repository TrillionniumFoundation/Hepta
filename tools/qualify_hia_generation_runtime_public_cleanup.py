"""Actual failed Runtime construction preserves exception identity and cleanup facts.

All dynamic timestamps, directory names and inode numbers are captured from the
two independent executions. Only those measured identity fields are normalized
for the recursive original-Python comparison; every cleanup key and other
value is compared. The actual cleanup dictionary then outlives the exception.
"""
from pathlib import Path
import argparse,json,os,traceback
from tools import qualify_hia_generation_runtime_public_factory as factory
from tools import qualify_hia_generation_runtime_directory as directory
from tools.qualify_hia_clang_capture_faults import isolated
from hepta.hia_multiversion import ScalarMultiversionRuntime
q=factory.q
ZERO=(0,0,0)
CASES=('clang-missing','clang-none','clang-raise','clang-overwrite','directory-raise','baseline-invalid','timeout-before-baseline','repeat-failed-construct')
def observation(value,parent):
 root=value['directory_identity_pin']['path']
 assert type(root)is str and Path(root).parent==parent and Path(root).name.startswith('hia-multiversion-'),root
 assert not Path(root).exists(),root
 inode=value['directory_identity_pin']['inode']
 assert type(inode)is list and len(inode)==2 and all(type(v)is int and v>=0 for v in inode),inode
 assert value['directory_cleanup']['identity_pin']==value['directory_identity_pin']
 assert value['directory_cleanup']['before']['actual_inode']==inode
 assert value['directory_cleanup']['path']==value['directory_observation']['path']==root
 for row in value['recent_attempts']:
  assert row['artifact']==root+'/generation-'+str(row['generation'])+'.so'
  assert row['artifact_identity_pin']['path']==row['artifact']
  assert row['native']['attempted_ns']<=row['native']['finished_ns']
  assert row['disk']['attempted_ns']<=row['disk']['before']['observed_ns']
 close=value['directory_identity_pin']['close']
 assert close['attempted_ns']<=close['finished_ns']
 d=value['directory_cleanup']
 assert d['before']['observed_ns']<=d['attempted_ns']<=d['after']['observed_ns']<=value['directory_observation']['observed_ns']
 def normalized(item,key=''):
  if key.endswith('_ns'):
   assert type(item)is int and item>0,(key,item)
   return '<actual-monotonic-time>'
  if key in('inode','actual_inode')and item is not None:
   assert item==inode,(key,item,inode)
   return [item[0],'<actual-inode>']
  if isinstance(item,dict):return {k:normalized(v,k)for k,v in item.items()}
  if isinstance(item,list):return [normalized(v)for v in item]
  if isinstance(item,str)and(item==root or item.startswith(root+'/')):return '<actual-runtime-directory>'+item[len(root):]
  return item
 return normalized(value)
def oracle(program,folder,clang,timeout,marker=None):
 class ThrowingPath:
  def __fspath__(self):raise marker
 if folder=='raise':folder=ThrowingPath()
 if clang=='raise':clang=ThrowingPath()
 kw={}
 if clang!='default':kw['clang']=clang
 if timeout is not None:kw['validation_timeout_ms']=timeout
 try:result=ScalarMultiversionRuntime(program,folder,**kw)
 except BaseException as error:
  if marker is not None:assert error is marker
  return type(error).__name__,error.args,getattr(error,'hia_cleanup',None)
 else:
  result.close();raise AssertionError('original failed-constructor case succeeded')
def one(path,out,name):
 f=factory.installed.InstalledFixture(path,out);v=factory.Values(q.ValueTransport(f.owner))
 baseline=q.get(v.raw(47),48);report=dict(passed=False,name=name,iterations=[])
 def save():(out/'case.json').write_text(json.dumps(report,indent=2,sort_keys=True,default=repr)+'\n')
 try:
  program=directory.current_core();base=v.scalar(program);folder=v.scalar(str(f.parent));caps=[base,folder]
  clang='default';timeout=None;pyfolder=str(f.parent);marker=None;actualmarker=None
  if name in('clang-missing','repeat-failed-construct'):
   clang='/nonexistent/hia-runtime-constructor-clang';caps+=[v.scalar(clang)]
  elif name=='clang-none':
   clang=None;caps+=[v.scalar(None)]
  elif name in('clang-raise','clang-overwrite','directory-raise'):
   marker=TypeError('actual native directory callback exception')
   actualmarker=directory.raised_value(v)
   if name=='clang-overwrite':
    marker.hia_cleanup={'old':True}
    ns,args,typename=v.parts(actualmarker)
    v.raw(10,a=ns,b=v.scalar('hia_cleanup'),c=v.keep(v.raw(1,tail=b'{"old":true}')))
    for item in(ns,args,typename):v.drop(item)
   cls=v.cls('ActualCleanupThrowingPath',[])
   fn=directory.callable_value(v,actualmarker,directory.inv.echo_field(1,2));v.attr(cls,'__fspath__',fn)
   obj=v.instance(cls)
   if name=='directory-raise':caps[1]=obj;pyfolder='raise'
   else:caps+=[obj];clang='raise'
  elif name=='baseline-invalid':
   program=b'{}';caps[0]=v.scalar(program)
  elif name=='timeout-before-baseline':
   program=None;caps=[v.scalar(None),v.scalar(None),ZERO,v.scalar(True)];pyfolder=None;timeout=True
  else:raise AssertionError(name)
  retained_cleanup=[]
  for iteration in range(2 if name=='repeat-failed-construct'else 1):
   expected_type,expected_args,expected_cleanup=oracle(program,pyfolder,clang,timeout,marker)
   rc,row,raw=factory.construct(f,caps)
   item=dict(rc=rc,native=row,expected_type=expected_type,expected_args=expected_args,expected_cleanup=expected_cleanup)
   report['iterations'].append(item);save()
   assert rc==0 and raw[:8]==b'HIARTCR1',(rc,row)
   assert row['known']==row['delivered']==row['retired']==1 and row['pending']==0 and row['state']==3,row
   assert row['status']!=0 and row['disposition']==2,row
   primary=v.keep(raw)
   assert factory.exception_data(v,primary)==(expected_type,expected_args)
   if actualmarker is not None:assert v.same(primary,actualmarker)
   ns,args,typename=v.parts(primary);namespace=v.python_value(ns);item['actual_namespace']=namespace;save()
   if expected_cleanup is None:
    assert 'hia_cleanup'not in namespace,namespace
   else:
    actual=namespace['hia_cleanup']
    assert observation(actual,f.parent)==observation(expected_cleanup,f.parent),(actual,expected_cleanup)
    key=v.scalar('hia_cleanup');cleanup=v.keep(v.raw(9,a=ns,b=key));v.drop(key)
    retained_cleanup.append((cleanup,actual))
    item['actual_cleanup_fields_original_equal']=True
   for part in(ns,args,typename):v.drop(part)
   v.drop(primary);f.guard(0)
  held_cleanup={cap for cap,_ in retained_cleanup}
  while any(cap not in held_cleanup for cap in v.held):
   v.drop(next(cap for cap in v.held if cap not in held_cleanup))
  for cap,expected in retained_cleanup:
   assert v.python_value(cap)==expected,'cleanup dictionary did not survive all other references'
   v.drop(cap)
  assert q.get(v.raw(47),48)==baseline,(baseline,q.get(v.raw(47),48))
  report.update(passed=True,actual_original_exception_identity=True,actual_cleanup_reference_lifetime=True,**f.finish());save();return report
 except BaseException as error:
  report.update(error=repr(error),traceback=traceback.format_exc());save();raise
def main():
 p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--cases',nargs='*',choices=CASES);a=p.parse_args()
 path=a.build/'install/hia-generation-component-root.so';spec=json.loads((a.build/'build.json').read_bytes())
 assert directory.custody.pin(path.read_bytes())==spec['products']['hia-generation-component-root.so']
 a.output.mkdir(parents=True,exist_ok=False);rows=[]
 for name in a.cases or CASES:
  here=a.output/name;here.mkdir()
  rows.append(isolated(name,lambda name=name,here=here:one(path,here,name)))
  (a.output/'partial.json').write_text(json.dumps(rows,indent=2,sort_keys=True,default=repr)+'\n')
  print('PUBLIC_CLEANUP_FACTORY_PASS',name,flush=True)
 report=dict(passed=True,groups=len(rows),cases=rows,owner=directory.custody.pin(path.read_bytes()),construction=directory.custody.pin((a.build/'build.json').read_bytes()),qualifier=directory.custody.pin(Path(__file__).read_bytes()),public_constructor_qualified=False,whole_runtime_qualified=False)
 (a.output/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True,default=repr)+'\n')
 print('PUBLIC_CLEANUP_FACTORY_ACTUAL_PASS',len(rows),flush=True)
if __name__=='__main__':main()
