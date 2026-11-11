import pathlib,os,json,hashlib,stat,time
start=time.monotonic_ns();root=pathlib.Path('/home/qian-qi/he26v65r2');q=root/'q';cold=q/'cold.json';raw=cold.read_bytes()
assert hashlib.sha256(raw).hexdigest()=='938b9331e28e53442a21796acb319f3c9683fc26748cad49893b56873bf02ad4'
value=json.loads(raw);facts=[];candidate=set();loaded=[]
def inspect(v,where):
 if type(v)is dict:
  for k,x in v.items():
   if k.lower()not in ('source_manifest','sources','source_hashes','environment','env'):inspect(x,where+[str(k)])
 elif type(v)is list:
  for i,x in enumerate(v):inspect(x,where+[str(i)])
 elif type(v)is str and len(v)<4096:
  context='/'.join(where).lower();name=pathlib.Path(v).name.lower()
  if any(t in context or t in name for t in ('b3','stage3','stage_3','stage-3','compiler','bootstrap','artifact_dir','output_dir','nested_report')):
   if len(facts)<100:facts.append({'field':'.'.join(where),'value':v})
  if v.startswith(str(root)+'/') and not v.endswith(('.py','.json','.hiaasm','.md','.log')) and any(t in context or t in name for t in ('b3','stage3','stage_3','stage-3','compiler')):
   candidate.add(v)
inspect(value,['cold.json'])
nested=value.get('nested_report')
if type(nested)is str:
 path=pathlib.Path(nested)
 if not path.is_absolute():path=cold.parent/path
 if str(path.resolve()).startswith(str(root)+'/') and path.is_file() and path.stat().st_size<16777216:
  raw2=path.read_bytes();n=json.loads(raw2);loaded.append({'path':str(path),'bytes':len(raw2),'sha256':hashlib.sha256(raw2).hexdigest(),'keys':list(n)});inspect(n,[path.name])
seen=0;depth=12;limit=20000
for d,ds,fs in os.walk(q,followlinks=False):
 rel=pathlib.Path(d).relative_to(q);ds[:]=[n for n in ds if n not in ('.git','__pycache__','site-packages') and not(pathlib.Path(d)/n).is_symlink()]
 if len(rel.parts)>=depth:ds[:]=[]
 seen+=len(ds)+len(fs)
 if seen>limit:break
 for name in fs:
  low=name.lower();context=str(rel).lower()
  matched=any(t in low for t in ('b3','stage3','stage_3','stage-3'))
  matched=matched or (any(t in context for t in ('b3','stage3','stage_3','stage-3','compiler'))and low.endswith(('.bin','.elf','.native','.image','.code')))
  if matched and not low.endswith(('.json','.log','.py','.hiaasm','.md','.sha256')):candidate.add(str(pathlib.Path(d)/name))
records=[]
for x in sorted(candidate)[:32]:
 p=pathlib.Path(x);r={'path':x}
 try:
  a=p.lstat();r.update(bytes=a.st_size,regular=stat.S_ISREG(a.st_mode),mode=oct(a.st_mode),uid=a.st_uid,nlink=a.st_nlink)
  if stat.S_ISREG(a.st_mode) and a.st_size<=67108864:
   h=hashlib.sha256()
   with p.open('rb')as f:
    while True:
     b=f.read(1048576)
     if not b:break
     h.update(b)
   z=p.stat();r.update(sha256=h.hexdigest(),stable=(a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(z.st_dev,z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns))
 except BaseException as e:r.update(error_type=type(e).__name__,error=str(e))
 records.append(r)
print(json.dumps({'schema':'hia.desktop-retained-compiler-readonly-location.v1','scope':'READ_ONLY_DEVELOPMENT_INPUTS_NOT_QUALIFICATION','old_cold_pin_matches':True,'nested_report_type':type(nested).__name__,'loaded_nested_reports':loaded,'relevant_report_fields':facts,'q_direct_children':[x.name for x in list(q.iterdir())[:40]],'task_walk_entries':seen,'depth_limit':depth,'entry_limit':limit,'compiler_candidates':records,'files_created_or_modified':False,'whole_native_delivery_qualified':False,'elapsed_ns':time.monotonic_ns()-start},sort_keys=True),flush=True)
