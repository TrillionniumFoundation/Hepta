"""Full lossless custody of three frozen actual outcomes; no products."""
import base64,gzip,hashlib,io,json,os,stat,tarfile,time
from pathlib import Path
OUT=Path('/tmp/hia-root-v145-capsules-dda7');OUT.mkdir(mode=0o700)
D=Path('/tmp/hia-root-v141-dda7')
def pin(raw):return {'bytes':len(raw),'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),'sha256':hashlib.sha256(raw).hexdigest()}
def seven(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def enc(v):return (json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def write(name,raw):
 with (OUT/name).open('xb') as f:f.write(raw)
 return {'path':str(OUT/name),**pin(raw)}
packages={
 'patch-r4-generation':{
  'trees':{'generation':Path('/dev/shm/hia-patch-result-generation-r4-dda7'),'root-outer':Path('/tmp/hia-root-patch-generation-r4-2-dda7'),'author-r4':Path('/tmp/hia-patch-result-owner-r4-dda7')},
  'exclude':{'generation/source'},
  'extra':['verify_patch_generation_r4_2_preflight.py','patch-generation-r4-2-root-preflight.json','patch-generation-r4-2-root-authorization.json','launch_patch_generation_r4_2_once.py','verify_patch_generation_r4_2_terminal.py','patch-generation-r4-2-root-terminal.json','patch-generation-r4-2-root-inventory.json']},
 'u32-r8-actual-size-pack':{
  'trees':{'actual':Path('/tmp/hia-u32-r8-size-pack-r1-dda7/evidence/attempt-r1'),'root-outer':Path('/tmp/hia-root-u32-r8-size-pack-dda7')},'exclude':set(),
  'extra':['verify_u32_r8_size_pack_preflight.py','u32-r8-size-pack-root-preflight.json','u32-r8-size-pack-root-authorization.json','launch_u32_r8_size_pack_once.py','verify_u32_r8_size_pack_terminal.py','u32-r8-size-pack-root-terminal.json','u32-r8-size-pack-root-inventory.json']},
 'inspect-cli-r4-actual-failure':{
  'trees':{'attempt':Path('/dev/shm/hia-inspect-cli-controls-r4-dda7/attempt-r1'),'launch':Path('/tmp/hia-root-inspect-cli-r4-execution-dda7'),'binding':Path('/dev/shm/hia-inspect-cli-controls-r4-dda7'),'binding-outer':Path('/tmp/hia-root-inspect-cli-r4-preparation-dda7')},
  'exclude':{'binding/source','binding/attempt-r1'},
  'extra':['verify_inspect_cli_r4_preflight.py','inspect-cli-r4-root-preflight.json','inspect-cli-r4-preparation-root-authorization.json','launch_inspect_cli_r4_preparation_once.py','verify_inspect_cli_r4_binding_terminal.py','inspect-cli-r4-binding-root-terminal.json','inspect-cli-r4-binding-root-inventory.json','inspect-cli-r4-product-root-authorization.json','launch_inspect_cli_r4_product_once.py','verify_inspect_cli_r4_product_failure.py','inspect-cli-r4-product-failure-root-terminal.json','inspect-cli-r4-product-failure-root-inventory.json']}}
summary={}
for label,config in packages.items():
 start=time.monotonic_ns();files={};directories={};pathsets={}
 def add(path,name):
  s=path.lstat();assert stat.S_ISREG(s.st_mode)
  raw=path.read_bytes();assert seven(path.lstat())==seven(s)
  assert name not in files
  files[name]={'origin':str(path),'pin':pin(raw),'posix_mode':stat.S_IMODE(s.st_mode),'seven_stats':seven(s),'raw':raw}
 for prefix,root in config['trees'].items():
  paths=[]
  for folder,dirs,names in os.walk(root,followlinks=False):
   relative=Path(folder).relative_to(root).as_posix()
   logical=prefix if relative=='.' else prefix+'/'+relative
   dirs[:]=[name for name in dirs if logical+'/'+name not in config['exclude']]
   directories[logical]=stat.S_IMODE(Path(folder).lstat().st_mode)
   paths.append((logical,'directory'))
   for name in dirs:assert stat.S_ISDIR((Path(folder)/name).lstat().st_mode)
   for name in names:add(Path(folder)/name,logical+'/'+name);paths.append((logical+'/'+name,'file'))
  pathsets[prefix]=set(paths)
 if config['extra']:directories['root']=0o755
 for name in config['extra']:add(D/name,'root/'+name)
 stream=io.BytesIO()
 with tarfile.open(fileobj=stream,mode='w',format=tarfile.USTAR_FORMAT) as tar:
  for name,mode in sorted(directories.items()):
   info=tarfile.TarInfo(name);info.type=tarfile.DIRTYPE;info.mode=mode;info.mtime=0;tar.addfile(info)
  for name,row in sorted(files.items()):
   info=tarfile.TarInfo(name);info.mode=row['posix_mode'];info.size=len(row['raw']);info.mtime=0;tar.addfile(info,io.BytesIO(row['raw']))
 archive=gzip.compress(stream.getvalue(),compresslevel=6,mtime=0)
 decoded=gzip.decompress(archive)
 assert decoded==stream.getvalue()
 with tarfile.open(fileobj=io.BytesIO(decoded),mode='r:') as tar:
  ms=tar.getmembers();fs={m.name:m for m in ms if m.isfile()};ds={m.name:m for m in ms if m.isdir()}
  assert len(ms)==len(fs)+len(ds)==len(files)+len(directories) and set(fs)==set(files) and set(ds)==set(directories)
  for name,m in fs.items():assert m.mode==files[name]['posix_mode'] and tar.extractfile(m).read()==files[name]['raw']
  for name,m in ds.items():assert m.mode==directories[name]
 for row in files.values():assert seven(Path(row['origin']).lstat())==row['seven_stats']
 for prefix,root in config['trees'].items():
  now=set()
  for folder,dirs,names in os.walk(root,followlinks=False):
   rel=Path(folder).relative_to(root).as_posix();logical=prefix if rel=='.' else prefix+'/'+rel
   dirs[:]=[name for name in dirs if logical+'/'+name not in config['exclude']]
   now.add((logical,'directory'))
   for name in names:now.add((logical+'/'+name,'file'))
  assert now==pathsets[prefix]
 manifest={name:{k:v for k,v in row.items() if k!='raw'} for name,row in files.items()}
 total=sum(row['pin']['bytes'] for row in files.values())
 capsule={'schema':'hepta.root.lossless-custody.v1','label':label,'encoding':'gzip-ustar+base64','archive':pin(archive),'files':len(files),'directories':len(directories),'logical_bytes':total,'data_base64':base64.b64encode(archive).decode(),'qualification':'Frozen actual result only; all original scope limits remain; no new product execution'}
 refs={}
 refs['capsule']=write(label+'-CAPSULE.json',enc(capsule))
 refs['manifest']=write(label+'-MANIFEST.json',enc({'schema':'hepta.root.lossless-custody-manifest.v1','label':label,'files':manifest,'directories':directories,'excluded_complete_source_trees_bound_separately':sorted(config['exclude'])}))
 proof={'schema':'hepta.root.lossless-custody-readback.v1','status':'PASS_FULL_ROUNDTRIP','label':label,'capsule':refs['capsule'],'manifest':refs['manifest'],'archive':pin(archive),'files':len(files),'directories':len(directories),'logical_bytes':total,'all_full_bytes_modes_pathsets_current_seven_stats':True,'all_original_paths_unchanged':True,'product_executions':0,'whole_native':False,'production_legacy_retired':False,'elapsed_ns':time.monotonic_ns()-start}
 refs['proof']=write(label+'-READBACK.json',enc(proof));summary[label]=refs
write('SUMMARY.json',enc(summary));print(json.dumps(summary,sort_keys=True))
