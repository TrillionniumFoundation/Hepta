from pathlib import Path
import os,sys,json,hashlib,stat,tarfile,time,subprocess
base=Path('/home/qq/hia-kernel-expanded18-union-20261128-2ac5');source=base/'source';out=base/'linux-authors-complete-capture-v1';out.mkdir(mode=0o700,exist_ok=False)
(out/'driver.py').write_text(sys.argv[1]);sha=lambda b:hashlib.sha256(b).hexdigest()
generation=json.loads((base/'linux-authors-v5/generation.json').read_bytes());assert generation['status']=='ALL_FOUR_LINUX_AUTHORS_COMPLETED'
assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=source,text=True).strip()==generation['head']=='d5f853cabeb7bed4102e2033415e699e8c100d4f'
assert set(subprocess.check_output(['git','diff','--name-only'],cwd=source,text=True).splitlines())==set(generation['generated'])
actual=[]
for name,pin in generation['generated'].items():
 p=source/name;raw=p.read_bytes();assert len(raw)==pin['bytes']and sha(raw)==pin['sha256']and p.stat().st_mode&0o777==pin['mode']
 assert raw==(base/'linux-authors-v5/generated'/name).read_bytes();actual.append(name)
original=json.loads((base/'linux-authors-v1/existing-preservation-before.json').read_bytes());existing=Path('/home/qq/hia-final-native-cold-20261128-2ac5/source')
assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=existing,text=True).strip()==original['head']
assert subprocess.check_output(['git','status','--porcelain=v1'],cwd=existing,text=True)==original['status']
for n,pin in original['files'].items():
 p=existing/n;raw=p.read_bytes();assert len(raw)==pin['bytes']and sha(raw)==pin['sha256']and p.stat().st_mode&0o777==pin['mode']
before=json.loads((base/'linux-authors-v5/complete-physical-source-before.json').read_bytes())
for n,pin in before.items():
 p=source/n;assert p.is_file()and not p.is_symlink()and p.stat().st_nlink==1
 with p.open('rb')as f:h=hashlib.file_digest(f,'sha256').hexdigest()
 assert p.stat().st_size==pin['bytes']and h==pin['sha256']and p.stat().st_mode&0o777==pin['mode'],n
(out/'all-physical-sources-after.json').write_text(json.dumps(before,sort_keys=True,indent=2)+'\n')
members={}
for top in sorted(base.iterdir()):
 if (top.name.startswith('linux-authors-v')or top.name=='original393-expanded18-v1')and top.is_dir():
  for p in sorted(top.rglob('*')):
   if p.is_dir():continue
   assert p.is_file()and not p.is_symlink()
   members[str(p.relative_to(base))]=p
members['linux-authors-complete-capture-v1/all-physical-sources-after.json']=out/'all-physical-sources-after.json'
members['linux-authors-complete-capture-v1/driver.py']=out/'driver.py'
pins={n:{'bytes':p.stat().st_size,'sha256':sha(p.read_bytes()),'mode':p.stat().st_mode&0o777}for n,p in members.items()}
(out/'all-original-members.json').write_text(json.dumps(pins,sort_keys=True,indent=2)+'\n')
archive=out/'complete-linux-authors-and-generation-failure.tar.gz'
with tarfile.open(archive,'w:gz')as tar:
 for n,p in sorted(members.items()):tar.add(p,arcname=n,recursive=False)
 tar.add(out/'all-original-members.json',arcname='all-original-members.json',recursive=False)
with tarfile.open(archive,'r:gz')as tar:
 assert set(tar.getnames())==set(pins)|{'all-original-members.json'}
 for m in tar:
  raw=tar.extractfile(m).read()
  if m.name=='all-original-members.json':assert raw==(out/'all-original-members.json').read_bytes();continue
  p=pins[m.name];assert m.isfile()and m.mode==p['mode']and len(raw)==p['bytes']and sha(raw)==p['sha256']and members[m.name].read_bytes()==raw
report={'status':'FOUR_LINUX_AUTHORS_GENERATED_AND_ALL_FAILURES_CAPTURED','head':generation['head'],'generated_files':generation['generated'],'physical_sources':len(before),'original393_setup_failure_retained':True,'current10_and47_not_yet_executed':True,'original_existing_worktree_preserved':True,'archive_bytes':archive.stat().st_size,'archive_sha256':sha(archive.read_bytes()),'members':len(pins),'whole_cold_qualified':False}
(out/'terminal.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n');print(json.dumps(report,sort_keys=True))
