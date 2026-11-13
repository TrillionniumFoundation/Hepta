import ast,hashlib,json,os,stat,subprocess,sys
from pathlib import Path
cfg=json.load(sys.stdin)
repo=Path(cfg['repository'])
base=Path(cfg['directory'])
def require(c,m):
 if not c: raise RuntimeError(m)
def sha(b):return hashlib.sha256(b).hexdigest()
def blob(b):return hashlib.sha1(('blob '+str(len(b))+'\0').encode()+b).hexdigest()
def write(p,b):
 p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  with os.fdopen(fd,'wb') as f:f.write(b);f.flush();os.fsync(f.fileno())
 except BaseException:raise
 require(p.read_bytes()==b,'write readback '+str(p))
def git(args):
 r=subprocess.run(['/usr/bin/git','-C',str(repo),*args],capture_output=True,check=True)
 return r.stdout
require(str(repo.resolve())==str(repo),'repository alias')
require(git(['rev-parse','HEAD']).decode().strip()==cfg['base_commit'],'base commit')
require(git(['rev-parse','HEAD^{tree}']).decode().strip()==cfg['base_tree'],'base tree')
require(git(['status','--porcelain=v1'])==b'','base dirty')
if base.exists():
 st=base.lstat();require(stat.S_ISDIR(st.st_mode) and st.st_uid==os.geteuid() and not any(base.iterdir()),'fresh exclusive directory')
else:base.mkdir(mode=0o700)
for entry in cfg['files']:
 raw=entry['content'].encode()
 require(len(raw)==entry['bytes'] and sha(raw)==entry['sha256'] and blob(raw)==entry['git_blob_sha1'],'transport bytes')
 write(base/entry['relative'],raw)
index={}
for record in git(['ls-files','--stage','-z']).split(b'\0'):
 if not record:continue
 head,name=record.split(b'\t',1);mode,oid,stage=head.decode().split()
 require(stage=='0','unmerged index')
 index[name.decode()]={'git_mode':mode,'git_blob_sha1':oid}
contract=ast.parse((repo/'tools/hia_selfhost_contract.py').read_bytes())
node=next(n.value for n in contract.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='SOURCE_FILES' for t in n.targets))
declared=ast.literal_eval(node)
require(type(declared) is tuple and all(type(x) is str for x in declared),'literal source list')
chosen=set(declared)|{'tools/hia_selfhost_contract.py','setup.py','pyproject.toml','MANIFEST.in'}
for name in index:
 if name.startswith(('hepta/','docs/','examples/','tests/fixtures/')) or (name.startswith(('tools/','tests/')) and name.endswith('.py')):
  chosen.add(name)
source=base/'source';source.mkdir(mode=0o700)
rows=[]
for name in sorted(chosen):
 require(name in index,'untracked dependency '+name)
 path=repo/name
 fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW)
 try:
  before=os.fstat(fd)
  require(stat.S_ISREG(before.st_mode) and before.st_nlink==1,'nonregular dependency '+name)
  with os.fdopen(fd,'rb',closefd=False) as f:raw=f.read()
  after=os.fstat(fd)
 finally:os.close(fd)
 require((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),'input changed')
 require(blob(raw)==index[name]['git_blob_sha1'],'base object differs '+name)
 original={'bytes':len(raw),'sha256':sha(raw),'git_blob_sha1':blob(raw)}
 if name==cfg['changed_path']:
  require(original['git_blob_sha1']==cfg['old_generator_blob'],'old generator')
  raw=(base/'canonical/generator/generate_hia_core_lowering.py').read_bytes()
 dest=source/name;write(dest,raw)
 st=dest.stat()
 rows.append({'path':name,**index[name],'original':original,'candidate':{'bytes':len(raw),'sha256':sha(raw),'git_blob_sha1':blob(raw)},'physical':{'mode':stat.S_IMODE(st.st_mode),'uid':st.st_uid,'gid':st.st_gid,'dev':st.st_dev,'ino':st.st_ino,'nlink':st.st_nlink,'size':st.st_size,'mtime_ns':st.st_mtime_ns,'ctime_ns':st.st_ctime_ns}})
require(git(['status','--porcelain=v1'])==b'','shared base changed')
report={'schema':'hia.pc-forwarding.source-materialization.v1','status':'SOURCE_COPIED_NOT_EXECUTED','base_commit':cfg['base_commit'],'base_tree':cfg['base_tree'],'repository':str(repo),'directory':str(base),'source_root':str(source),'files':rows,'file_count':len(rows),'source_bytes':sum(r['candidate']['bytes'] for r in rows),'changed':[r['path'] for r in rows if r['candidate']!=r['original']],'declaration_paths':len(declared),'generator_ran':False,'tests_ran':False,'native_ran':False}
raw=(json.dumps(report,sort_keys=True,indent=2)+'\n').encode();write(base/'SOURCE-MATERIALIZATION.json',raw)
print(json.dumps({'status':report['status'],'file_count':report['file_count'],'source_bytes':report['source_bytes'],'changed':report['changed'],'manifest_bytes':len(raw),'manifest_sha256':sha(raw),'manifest_path':str(base/'SOURCE-MATERIALIZATION.json')},sort_keys=True))
