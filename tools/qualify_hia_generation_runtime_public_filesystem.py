"""Real early filesystem errors and cleanup against selected native Python custody.

The oracle uses the actual frozen retirement_state image and documented selector.
Only actual per-execution random directory names and monotonic timestamps differ.
No exception factory, native context, mask, return value or syscall is substituted.
"""
from pathlib import Path
import argparse,hashlib,json,os,traceback
from tools import qualify_hia_generation_runtime_public_factory as factory
from tools import qualify_hia_generation_runtime_directory as directory
from tools.qualify_hia_clang_capture_faults import isolated
from hepta.hia_multiversion import ScalarMultiversionRuntime
from hepta import hia_retirement_state_native as retirement
q=factory.q
CASES=('missing-parent','file-parent','dangling-parent','symlink-loop','no-search-parent',
       'unicode-missing','surrogate-missing','relative-missing','repeat-missing')
def pin(raw):
 return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def oracle_manifest(build,out):
 image=build/'role-inputs/17-gen_prepare_retirement_state.flat'
 actual=pin(image.read_bytes())
 assert actual==dict(bytes=193481,sha256='144173a1ba12c72f540f165eeedfbfcf313ea76888c22ef89f7a06f87289c893')
 source=retirement.SOURCE.read_bytes()
 assert hashlib.sha256(source).hexdigest()=='a2d2ece149725327602a9e2b62ae863cbcc80f5986086902d133c8227c130512'
 result=dict(schema=retirement.SCHEMA,source_sha256=hashlib.sha256(source).hexdigest(),
  image_path=str(image),image_sha256=actual['sha256'],
  compiler_sha256='494833999e25ac74ea6ad1de41235c01bfa036951f212604026cb8be686c78af')
 path=out/'native-retirement-manifest.json';path.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
 return path,result
def original(program,folder,manifest):
 old=os.environ.get(retirement.SELECTOR)
 os.environ[retirement.SELECTOR]=str(manifest)
 try:
  assert retirement.selected_retirement_state()is not None
  try:instance=ScalarMultiversionRuntime(program,folder)
  except BaseException as error:
   return dict(type=type(error).__name__,args=error.args,errno=getattr(error,'errno',None),
    strerror=getattr(error,'strerror',None),filename=getattr(error,'filename',None),
    filename2=getattr(error,'filename2',None),cleanup=getattr(error,'hia_cleanup',None))
  else:
   instance.close();raise AssertionError('original filesystem error missing')
 finally:
  if old is None:os.environ.pop(retirement.SELECTOR,None)
  else:os.environ[retirement.SELECTOR]=old
def normalize(value,folder):
 assert type(value)is dict,value
 root=value['directory_identity_pin']['path']
 assert Path(root).parent==Path(folder).absolute(),(root,folder)
 name=Path(root).name
 assert name.startswith('hia-multiversion-')and len(name)==49 and all(c in '0123456789abcdef'for c in name[17:]),name
 assert value['attempts']==0 and value['recent_attempts']==[] and value['pending']==[] and value['pending_identity_releases']==[]
 assert value['pending_resource_count']==0
 identity=value['directory_identity_pin']
 assert identity['inode']is None and identity['acquisition_attempted']is False and identity['identity_fd_held']is False
 assert value['directory_cleanup']['identity_pin']==identity
 assert value['directory_cleanup']['path']==value['directory_observation']['path']==root
 before=value['directory_cleanup']['before']['observed_ns']
 attempted=value['directory_cleanup']['attempted_ns']
 after=value['directory_cleanup']['after']['observed_ns']
 observed=value['directory_observation']['observed_ns']
 assert 0<before<=attempted<=after<=observed,(before,attempted,after,observed)
 def walk(item,key=''):
  if key.endswith('_ns'):
   assert type(item)is int and item>0,(key,item)
   return '<actual-monotonic-time>'
  if isinstance(item,dict):return {k:walk(v,k)for k,v in item.items()}
  if isinstance(item,list):return [walk(v)for v in item]
  if isinstance(item,str):return item.replace(root,'<actual-runtime-directory>')
  return item
 return root,walk(value)
def one(build,out,name,manifest):
 path=build/'install/hia-generation-component-root.so'
 f=factory.installed.InstalledFixture(path,out);v=factory.Values(q.ValueTransport(f.owner))
 baseline=q.get(v.raw(47),48);report=dict(passed=False,name=name,iterations=[])
 fixtures=[]
 def save():(out/'case.json').write_text(json.dumps(report,indent=2,sort_keys=True,default=repr)+'\n')
 try:
  folder=f.parent/'missing'/'parent'
  if name=='file-parent':
   folder=f.parent/'ordinary-file';folder.write_bytes(b'fixture');fixtures.append(('file',folder))
  elif name=='dangling-parent':
   folder=f.parent/'dangling';folder.symlink_to('not-present',target_is_directory=True);fixtures.append(('file',folder))
  elif name=='symlink-loop':
   folder=f.parent/'loop';folder.symlink_to('loop',target_is_directory=True);fixtures.append(('file',folder))
  elif name=='no-search-parent':
   assert os.geteuid()!=0,'real PermissionError requires unprivileged fixture'
   folder=f.parent/'unsearchable';folder.mkdir(mode=0o700);folder.chmod(0);fixtures.append(('dir',folder))
  elif name=='unicode-missing':folder=f.parent/'目录-δ-😀'/'不存在'
  elif name=='surrogate-missing':folder=f.parent/'missing-\udcff'/'parent'
  arg=os.path.relpath(folder,Path.cwd())if name=='relative-missing'else str(folder)
  program=directory.current_core();caps=[v.scalar(program),v.scalar(arg)]
  retained=[]
  for iteration in range(2 if name=='repeat-missing'else 1):
   expected=original(program,arg,manifest)
   rc,row,raw=factory.construct(f,caps)
   item=dict(iteration=iteration,rc=rc,native=row,expected=expected);report['iterations'].append(item);save()
   assert rc==0 and raw[:8]==b'HIARTCR1',(rc,row)
   assert row['known']==row['delivered']==row['retired']==1 and row['pending']==0 and row['state']==3,row
   assert row['status']!=0 and row['disposition']==2,row
   primary=v.keep(raw);kind,args=factory.exception_data(v,primary)
   assert (kind,args)==(expected['type'],expected['args']),((kind,args),expected)
   actual=dict(type=kind,args=args)
   for index,field in enumerate(('errno','strerror','filename','filename2')):
    fieldcap=v.keep(factory.private_value(f.owner,105,primary,index))
    actual[field]=v.python_value(fieldcap);v.drop(fieldcap)
   ns,arguments,typename=v.parts(primary)
   namespace=v.python_value(ns);actual['cleanup']=namespace['hia_cleanup'];item['actual']=actual;save()
   assert actual['errno']==expected['errno'] and actual['strerror']==expected['strerror']
   assert actual['filename2']==expected['filename2']is None
   ownroot,own=normalize(actual['cleanup'],arg);oldroot,old=normalize(expected['cleanup'],arg)
   assert actual['filename']==ownroot and expected['filename']==oldroot
   assert own==old,(own,old)
   key=v.scalar('hia_cleanup');cleanup=v.keep(v.raw(9,a=ns,b=key));v.drop(key)
   retained.append((cleanup,actual['cleanup']))
   for cap in(ns,arguments,typename,primary):v.drop(cap)
   f.guard(0);item['all_cleanup_fields_original_equal']=True;save()
  kept={cap for cap,_ in retained}
  while any(cap not in kept for cap in v.held):
   v.drop(next(cap for cap in v.held if cap not in kept))
  for cap,expected in retained:
   assert v.python_value(cap)==expected
   v.drop(cap)
  assert q.get(v.raw(47),48)==baseline,(baseline,q.get(v.raw(47),48))
  for kind,path in reversed(fixtures):
   if kind=='dir':path.chmod(0o700);path.rmdir()
   else:path.unlink()
  report.update(passed=True,native_retirement_oracle=True,actual_os_fields=True,actual_cleanup_lifetime=True,**f.finish())
  save();return report
 except BaseException as error:
  report.update(error=repr(error),traceback=traceback.format_exc());save();raise
def main():
 p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--cases',nargs='*',choices=CASES);a=p.parse_args()
 path=a.build/'install/hia-generation-component-root.so';spec=json.loads((a.build/'build.json').read_bytes())
 assert pin(path.read_bytes())==spec['products']['hia-generation-component-root.so']
 a.output.mkdir(parents=True,exist_ok=False);manifest,oracle=oracle_manifest(a.build,a.output);rows=[]
 for name in a.cases or CASES:
  here=a.output/name;here.mkdir()
  rows.append(isolated(name,lambda name=name,here=here:one(a.build,here,name,manifest)))
  (a.output/'partial.json').write_text(json.dumps(rows,indent=2,sort_keys=True,default=repr)+'\n')
  print('PUBLIC_RUNTIME_FILESYSTEM_PASS',name,flush=True)
 report=dict(passed=True,groups=len(rows),cases=rows,owner=pin(path.read_bytes()),construction=pin((a.build/'build.json').read_bytes()),qualifier=pin(Path(__file__).read_bytes()),
  original_selected_native_retirement=oracle,public_constructor_qualified=False,whole_runtime_qualified=False)
 (a.output/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True,default=repr)+'\n')
 print('PUBLIC_RUNTIME_FILESYSTEM_ACTUAL_PASS',len(rows),flush=True)
if __name__=='__main__':main()
