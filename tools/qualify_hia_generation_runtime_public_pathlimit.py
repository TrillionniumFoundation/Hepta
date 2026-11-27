"""Exact selected-native retirement path boundary through public Runtime construction."""
from pathlib import Path
import argparse,json,os,traceback
from tools import qualify_hia_generation_runtime_public_filesystem as filesystem
factory=filesystem.factory
directory=filesystem.directory
q=factory.q
CASES=('root-4095','root-4096','root-4097','root-over-profile','component-256',
       'unicode-root-4096','surrogate-root-4096')
def at_bytes(parent,n,prefix=''):
 value=str(parent)+'/'+prefix
 left=n-len(os.fsencode(value))
 assert left>0
 while left>100:
  value+='x'*99+'/'
  left-=100
 value+='y'*left
 assert len(os.fsencode(value))==n and str(Path(value))==value
 return value
def normalize_cleanup(value,folder):
 assert type(value)is dict,value
 root=value['directory_identity_pin']['path']
 assert Path(root).parent==Path(folder).absolute(),(root,folder)
 name=Path(root).name
 assert len(name)==49 and name.startswith('hia-multiversion-')
 assert all(c in '0123456789abcdef'for c in name[17:])
 def walk(item,key=''):
  if key.endswith('_ns')and item is not None:
   assert type(item)is int and item>0,(key,item)
   return '<actual-monotonic-time>'
  if isinstance(item,dict):return {k:walk(v,k)for k,v in item.items()}
  if isinstance(item,list):return [walk(v)for v in item]
  if isinstance(item,str):return item.replace(root,'<actual-runtime-directory>')
  return item
 return root,walk(value)
def one(build,out,name,manifest):
 f=factory.installed.InstalledFixture(build/'install/hia-generation-component-root.so',out)
 v=factory.Values(q.ValueTransport(f.owner))
 baseline=q.get(v.raw(47),48)
 report=dict(name=name,passed=False)
 def save():(out/'case.json').write_text(json.dumps(report,indent=2,sort_keys=True,default=repr)+'\n')
 try:
  n={'root-4095':4045,'root-4096':4046,'root-4097':4047,
     'root-over-profile':4251,'unicode-root-4096':4046,'surrogate-root-4096':4046}.get(name)
  prefix='目录-δ-😀/'if name.startswith('unicode-')else('missing-\udcff/'if name.startswith('surrogate-')else'')
  folder=at_bytes(f.parent,n,prefix)if n else str(f.parent/('x'*256))
  program=directory.current_core()
  expected=filesystem.original(program,folder,manifest)
  rc,row,raw=factory.construct(f,[v.scalar(program),v.scalar(folder)])
  report.update(directory_bytes=len(os.fsencode(folder)),expected=expected,rc=rc,native=row);save()
  assert rc==0 and raw[:8]==b'HIARTCR1',(rc,row)
  assert row['known']==row['delivered']==row['retired']==1 and row['pending']==0 and row['state']==3,row
  assert row['status']!=0 and row['disposition']==2,row
  primary=v.keep(raw);kind,args=factory.exception_data(v,primary)
  assert (kind,args)==(expected['type'],expected['args']),((kind,args),expected)
  ns,arguments,typename=v.parts(primary);namespace=v.python_value(ns)
  report.update(actual=dict(type=kind,args=args,namespace=namespace));save()
  retained=None
  if expected['cleanup']is None:
   assert kind=='ValueError'and args==('native retirement path exceeds the Linux 4096-byte profile',)
   assert 'hia_cleanup'not in namespace,namespace
  else:
   assert 'hia_cleanup'in namespace,namespace
   actual=namespace['hia_cleanup'];ownroot,own=normalize_cleanup(actual,folder);oldroot,old=normalize_cleanup(expected['cleanup'],folder)
   assert own==old,(own,old)
   for index,field in enumerate(('errno','strerror','filename','filename2')):
    cap=v.keep(factory.private_value(f.owner,105,primary,index));value=v.python_value(cap);v.drop(cap)
    if field=='filename':assert value==ownroot and expected[field]==oldroot,(value,expected[field])
    else:assert value==expected[field],(field,value,expected[field])
   key=v.scalar('hia_cleanup');retained=v.keep(v.raw(9,a=ns,b=key));v.drop(key)
   if name in ('root-4096','unicode-root-4096','surrogate-root-4096'):assert len(os.fsencode(ownroot))==4096
  for cap in(ns,arguments,typename,primary):v.drop(cap)
  while any(cap!=retained for cap in v.held):v.drop(next(cap for cap in v.held if cap!=retained))
  if retained:
   assert v.python_value(retained)==namespace['hia_cleanup'];v.drop(retained)
  f.guard(0);assert q.get(v.raw(47),48)==baseline,(baseline,q.get(v.raw(47),48))
  report.update(passed=True,original_exact_exception_and_cleanup=True,**f.finish());save();return report
 except BaseException as error:
  report.update(error=repr(error),traceback=traceback.format_exc());save();raise
def main():
 p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--cases',nargs='*',choices=CASES);a=p.parse_args()
 spec=json.loads((a.build/'build.json').read_text());so=a.build/'install/hia-generation-component-root.so'
 assert filesystem.pin(so.read_bytes())==spec['products']['hia-generation-component-root.so']
 a.output.mkdir(parents=True,exist_ok=False);manifest,oracle=filesystem.oracle_manifest(a.build,a.output);rows=[]
 for name in a.cases or CASES:
  here=a.output/name;here.mkdir()
  rows.append(filesystem.isolated(name,lambda name=name,here=here:one(a.build,here,name,manifest)))
  (a.output/'partial.json').write_text(json.dumps(rows,indent=2,sort_keys=True,default=repr)+'\n')
  print('PUBLIC_RUNTIME_PATHLIMIT_PASS',name,flush=True)
 report=dict(passed=True,groups=len(rows),cases=rows,owner=filesystem.pin(so.read_bytes()),construction=filesystem.pin((a.build/'build.json').read_bytes()),qualifier=filesystem.pin(Path(__file__).read_bytes()),original_selected_native_retirement=oracle,public_constructor_qualified=False,whole_runtime_qualified=False)
 (a.output/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True,default=repr)+'\n')
 print('PUBLIC_RUNTIME_PATHLIMIT_ACTUAL_PASS',len(rows),flush=True)
if __name__=='__main__':main()
