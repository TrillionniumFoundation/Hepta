import sys,os,json,pathlib,hashlib,stat,importlib,importlib.metadata,time
started=time.monotonic_ns()
root=pathlib.Path('/home/qian-qi')
expected={
'/home/qian-qi/hia-e26e-python314-linux-r1/install/bin/python3.14':'b2d6bc2ad950753c5ea407a30788165d8f59c110ca4e90fbad14c8c75376a493',
'/home/qian-qi/hia-e26e-python314-linux-completion-r2/python-linux-preparation.json':'f834e072227ed59f06d347772b8db126c1910c574e660d66f9d15c1c1ec43967',
'/home/qian-qi/hia-e26e-python314-linux-completion-r2/guard/guardian.json':'f4115e59f8a6eb22db8a002960fbca83e248e071e5694d89e93371b2262b036d',
'/home/qian-qi/he26v65r2/q/QUALIFICATION.json':'d91d279d192a9fe6b6a7521d8732197bdc37f4af3a03a694cfccb15929748b60',
'/home/qian-qi/he26v65r2/q/cold.json':'938b9331e28e53442a21796acb319f3c9683fc26748cad49893b56873bf02ad4',
'/home/qian-qi/he26v65r2/q/source-tests.json':'a2a84183bbca9df57ee352524e874420c446cb472bba34a5abd04551556593de',
'/home/qian-qi/he26v65r2/guard/guardian.json':'ae721abf9b428acedb43fe99d5b072fed1de3299fd331b457410fdb5858519f1',
'/home/qian-qi/he26v66r1/preparation.json':'c02e412c2251060e390571e4f1746c141360afdf362ecc35ca87025e6b7e9824',
'/home/qian-qi/he26v66r1/guard/guardian.json':'c843ea8a9c841ebc0d9fa3102056dc061709a1dd9ae81282f54116b810303077',
'/home/qian-qi/hia-native-closure-evidence/4161e8d12d87906fde144f039da07908ad52d98a/desktop-full-hold-r2-preservation-r3/PRESERVATION.json':'6edd6d762f9ca2f95c1b3c0b40d1cd543c83e030fa0ecba1a72a2c26507644de'
}
def info(path,expected_sha=None):
 p=pathlib.Path(path); result={'path':str(p)}
 try:
  s=p.lstat()
  if not stat.S_ISREG(s.st_mode):return dict(result,regular=False,mode=oct(s.st_mode))
  h=hashlib.sha256()
  with p.open('rb')as f:
   while True:
    b=f.read(1<<20)
    if not b:break
    h.update(b)
  after=p.stat()
  result.update(regular=True,bytes=s.st_size,mode=oct(s.st_mode),uid=s.st_uid,nlink=s.st_nlink,sha256=h.hexdigest(),stable=(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns))
  if expected_sha is not None:result.update(expected_sha256=expected_sha,pin_matches=h.hexdigest()==expected_sha)
 except BaseException as e:result.update(error_type=type(e).__name__,error=str(e))
 return result
pins=[info(k,v)for k,v in expected.items()]
dependencies={}
for module,distribution in [('z3','z3-solver'),('jsonschema','jsonschema'),('setuptools','setuptools'),('wheel','wheel'),('zstandard','zstandard')]:
 try:
  value=importlib.import_module(module);dependencies[module]={'imported':True,'version':importlib.metadata.version(distribution),'file':getattr(value,'__file__',None)}
  if module=='z3':dependencies[module]['native_library_version']=value.get_version_string()
 except BaseException as e:dependencies[module]={'imported':False,'error_type':type(e).__name__,'error':str(e)}
memory={}
for line in pathlib.Path('/proc/meminfo').read_text().splitlines():
 name,_,value=line.partition(':')
 if name in ('MemTotal','MemAvailable','Shmem'):memory[name]=value.strip()
v=os.statvfs(root)
space={'path':str(root),'device':root.stat().st_dev,'available_bytes':v.f_bavail*v.f_frsize,'free_inodes':v.f_favail}
report_paths=[pathlib.Path('/home/qian-qi/he26v65r2/q/cold.json'),pathlib.Path('/home/qian-qi/he26v65r2/q/QUALIFICATION.json')]
references=[]
def inspect(v,where):
 if type(v)is dict:
  for k,x in v.items():inspect(x,where+[str(k)])
 elif type(v)is list:
  for i,x in enumerate(v):inspect(x,where+[str(i)])
 elif type(v)is str and v.startswith('/home/qian-qi/he26v65r2/') and ('compiler' in '/'.join(where).lower() or 'b3' in '/'.join(where).lower() or any(t in pathlib.Path(v).name.lower()for t in ['compiler','stage3','stage-3','b3'])) and not v.endswith(('.py','.hiaasm','.json')):
  references.append({'field':'.'.join(where),'path':v})
report_keys={}
for p in report_paths:
 try:
  x=json.loads(p.read_bytes());report_keys[str(p)]=list(x);inspect(x,[p.name])
 except BaseException as e:report_keys[str(p)]={'error':repr(e)}
candidates=set(x['path']for x in references);walk_roots=[]
for p in [pathlib.Path('/home/qian-qi/he26v65r2/q'),pathlib.Path('/home/qian-qi/he26v65r2/t')]:
 if p.is_dir():
  seen=0
  for d,ds,fs in os.walk(p,followlinks=False):
   rel=pathlib.Path(d).relative_to(p)
   ds[:]=[n for n in ds if n not in ('.git','__pycache__','site-packages') and not(pathlib.Path(d)/n).is_symlink()]
   if len(rel.parts)>=7:ds[:]=[]
   seen+=len(ds)+len(fs)
   if seen>15000:break
   for n in fs:
    low=n.lower()
    if (low in ('b3','b3.bin','stage3.bin','stage-3.bin','compiler.bin')or ('compiler'in low and low.endswith(('.bin','.elf','.image')))):
     candidates.add(str(pathlib.Path(d)/n))
  walk_roots.append({'root':str(p),'entries_seen':seen,'bounded_limit':15000,'depth_limit':7})
compiler_candidates=[info(p)for p in sorted(candidates)][:32]
layout={}
for p in ['/home/qian-qi/he26v65r2/s/.git/HEAD','/home/qian-qi/he26v66devr1','/home/qian-qi/he26v66r2']:
 path=pathlib.Path(p)
 try:
  s=path.lstat();layout[p]={'exists':True,'mode':oct(s.st_mode),'uid':s.st_uid}
  if p.endswith('/.git/HEAD')and stat.S_ISREG(s.st_mode):layout[p]['head_text']=path.read_text().strip()
 except FileNotFoundError:layout[p]={'exists':False}
 except BaseException as e:layout[p]={'error':repr(e)}
prefix=pathlib.Path('/home/qian-qi/hia-e26e-v64-prerequisites')
tools={}
for name,relative in [('clang','llvm-20.1.8/LLVM-20.1.8-Linux-X64/bin/clang'),('clangxx','llvm-20.1.8/LLVM-20.1.8-Linux-X64/bin/clang++'),('qemu_x86_64','verification-tools/qemu-8.2.2-complete/qemu-x86_64-static'),('lean','verification-tools/lean-4.19.0/bin/lean')]:
 p=prefix/relative
 try:
  actual=p.resolve(strict=True);s=actual.stat();tools[name]={'requested':str(p),'resolved':str(actual),'regular':stat.S_ISREG(s.st_mode),'executable':os.access(actual,os.X_OK),'bytes':s.st_size}
 except BaseException as e:tools[name]={'requested':str(p),'error':repr(e)}
print(json.dumps({'schema':'hia.desktop-v66-development-readonly-environment.v1','scope':'READ_ONLY_FACTS_NOT_PREPARATION_OR_QUALIFICATION','python':{'requested':sys.executable,'resolved':str(pathlib.Path(sys.executable).resolve()),'version':sys.version},'dependencies':dependencies,'space':space,'memory':memory,'cpu_affinity_count':len(os.sched_getaffinity(0)),'load_average':os.getloadavg(),'pins':pins,'all_requested_pins_match':all(x.get('pin_matches')is True and x.get('stable')is True for x in pins),'compiler_report_references':references[:32],'compiler_candidates':compiler_candidates,'report_top_keys':report_keys,'bounded_task_walks':walk_roots,'layout':layout,'existing_tools_existence_only':tools,'files_created_or_modified':False,'whole_native_delivery_qualified':False,'elapsed_ns':time.monotonic_ns()-started},sort_keys=True),flush=True)
