"""Offline source restoration at its recorded real shallow boundary; no experiment."""
from pathlib import Path
import argparse,gzip,hashlib,json,os,subprocess,tempfile
def req(v,m):
 if not v:raise ValueError(m)
def digest(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
a=argparse.ArgumentParser();a.add_argument('--package',type=Path,required=True);a.add_argument('--output',type=Path,required=True);x=a.parse_args()
p=x.package.resolve();m=json.loads((p/'MANIFEST.json').read_bytes());x.output.mkdir(parents=True,exist_ok=False);o=x.output.resolve();repo=o/'restored.git'
env={k:v for k,v in os.environ.items() if not k.startswith('GIT_')};env.update(GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null',GIT_NO_REPLACE_OBJECTS='1',GIT_NO_LAZY_FETCH='1',GIT_OPTIONAL_LOCKS='0',GIT_TERMINAL_PROMPT='0')
def run(*args,input=None,check=True):
 c=subprocess.run(['git',*args],env=env,input=input,capture_output=True,timeout=120)
 if check:req(c.returncode==0,c.stderr.decode('utf-8','replace'))
 return c
run('init','--bare','--initial-branch=original',str(repo))
req(run('-C',str(repo),'cat-file','-e',m['source']['commit'],check=False).returncode!=0,'original commit existed before import')
pack=o/'objects.pack';h=hashlib.sha256();n=0
with pack.open('xb') as f:
 for part in m['pack']['parts']:
  b=(p/part['name']).read_bytes();req(len(b)==part['bytes'] and hashlib.sha256(b).hexdigest()==part['sha256'],'part drift');f.write(b);h.update(b);n+=len(b)
req(n==m['pack']['bytes'] and h.hexdigest()==m['pack']['sha256'],'whole pack drift')
with pack.open('rb') as f:
 c=subprocess.run(['git','-C',str(repo),'index-pack','--stdin'],env=env,stdin=f,capture_output=True,timeout=120)
 req(c.returncode==0,c.stderr.decode('utf-8','replace'))
shallow=(p/'RESTORED_SHALLOW_BOUNDARIES.txt').read_bytes();req(hashlib.sha256(shallow).hexdigest()==m['normalized_shallow_sha256'],'shallow drift');(repo/'shallow').open('xb').write(shallow)
run('-C',str(repo),'update-ref','refs/heads/original',m['source']['commit'])
req(run('-C',str(repo),'rev-parse','HEAD','HEAD^{tree}').stdout.decode().splitlines()==[m['source']['commit'],m['source']['tree']],'source identity')
expected=(p/'REACHABLE_OBJECT_IDS.txt').read_bytes();req(hashlib.sha256(expected).hexdigest()==m['object_ids_sha256'],'object inventory drift');wanted=set(expected.decode().split())
got=set(run('-C',str(repo),'cat-file','--batch-all-objects','--batch-check=%(objectname)').stdout.decode().split());req(got==wanted,'object set differs')
for f in (repo/'objects').rglob('*'):
 req(not f.is_symlink(),'object symlink')
 if f.is_file():req(f.stat().st_nlink==1 and not f.name.endswith('.promisor'),'linked or partial object')
req(not (repo/'objects/info/alternates').exists(),'alternate object store')
fsck=run('-C',str(repo),'fsck','--full','--strict');(o/'fsck.stdout').write_bytes(fsck.stdout);(o/'fsck.stderr').write_bytes(fsck.stderr)
raw=gzip.decompress((p/'TRACKED_INVENTORY.json.gz').read_bytes());req(hashlib.sha256(raw).hexdigest()==m['tracked_inventory_sha256'],'tracked manifest drift');rows=json.loads(raw)
tree=run('-C',str(repo),'ls-tree','-rz','HEAD').stdout;req(hashlib.sha256(tree).hexdigest()==m['original_tree_sha256'],'tree records drift')
c=subprocess.Popen(['git','-C',str(repo),'cat-file','--batch'],env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
total=0
try:
 for r in rows:
  c.stdin.write((r['git_blob']+'\n').encode());c.stdin.flush();hdr=c.stdout.readline().decode().split();req(hdr==[r['git_blob'],'blob',str(r['bytes'])],'blob header')
  left=r['bytes'];s=hashlib.sha256()
  while left:
   b=c.stdout.read(min(left,1024*1024));req(bool(b),'short blob');s.update(b);left-=len(b)
  req(c.stdout.read(1)==b'\n' and s.hexdigest()==r['sha256'],'restored blob bytes');total+=r['bytes']
 c.stdin.close();err=c.stderr.read();req(c.wait(timeout=30)==0,'cat-file exit')
finally:
 if c.poll() is None:c.kill();c.wait()
print(json.dumps({'passed':True,'source':m['source'],'tracked_paths':len(rows),'tracked_bytes':total,'objects':len(got),'full_public_ancestry_present':False,'real_shallow_boundaries':shallow.decode().split(),'preimport_original_commit_absent':True,'all_tree_and_blob_hashes_verified':True,'object_store_independent':True,'pack_sha256':h.hexdigest(),'no_experiments_executed':True},sort_keys=True))
