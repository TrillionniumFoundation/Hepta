from pathlib import Path
import os,sys,json,hashlib,subprocess,tarfile,time,traceback,stat
os.umask(0o022)
source=Path('/Users/qianqi/work/hia-root-unified-cold-20261127-2ac5/kernel-generic-integration-v1/source');out=source.parent/'expanded18-linux-generation-integration-v1';out.mkdir(mode=0o700,exist_ok=False)
(out/'driver.py').write_text(sys.argv[1]);start=time.monotonic();rows=[];sha=lambda b:hashlib.sha256(b).hexdigest()
def run(label,argv,cwd=out,timeout=120):
 tick=time.monotonic();p=subprocess.run(argv,cwd=cwd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
 (out/(label+'.stdout')).write_bytes(p.stdout);(out/(label+'.stderr')).write_bytes(p.stderr)
 row={'label':label,'returncode':p.returncode,'seconds':time.monotonic()-tick};rows.append(row);print(json.dumps(row),flush=True)
 assert p.returncode==0,p.stderr.decode(errors='replace')
 return p.stdout
try:
 head=run('initial-head',['git','rev-parse','HEAD'],source).decode().strip();assert head=='d5f853cabeb7bed4102e2033415e699e8c100d4f'
 assert run('initial-status',['git','status','--porcelain=v1'],source)==b''
 archive=out/'complete-linux-authors-and-generation-failure.tar.gz'
 remote='ai395:/home/qq/hia-kernel-expanded18-union-20261128-2ac5/linux-authors-complete-capture-v1/'
 run('copy-archive',['/usr/bin/scp',remote+archive.name,str(archive)])
 assert archive.stat().st_size==1702786 and sha(archive.read_bytes())=='2e2a9753ac036b937656665b950ac1aedca953f9d1273ad32e2323af7971c496'
 run('copy-capture-terminal',['/usr/bin/scp',remote+'terminal.json',str(out/'capture-terminal.json')])
 capture=json.loads((out/'capture-terminal.json').read_bytes());assert capture['archive_sha256']==sha(archive.read_bytes())and capture['status']=='FOUR_LINUX_AUTHORS_GENERATED_AND_ALL_FAILURES_CAPTURED'
 dest=out/'originals';dest.mkdir(mode=0o700)
 with tarfile.open(archive,'r:gz')as tar:
  pins=json.loads(tar.extractfile('all-original-members.json').read());assert len(pins)==65 and set(tar.getnames())==set(pins)|{'all-original-members.json'}
  for m in tar:
   assert m.isfile()and not Path(m.name).is_absolute()and '..'not in Path(m.name).parts
   raw=tar.extractfile(m).read()
   if m.name in pins:
    p=pins[m.name];assert len(raw)==p['bytes']and sha(raw)==p['sha256']and m.mode==p['mode']
   target=dest/m.name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw);target.chmod(m.mode)
 generation=json.loads((dest/'linux-authors-v5/generation.json').read_bytes());assert generation['generated']==capture['generated_files']and generation['head']==head
 for n,pin in generation['generated'].items():
  raw=(dest/'linux-authors-v5/generated'/n).read_bytes();assert len(raw)==pin['bytes']and sha(raw)==pin['sha256']
  previous=source/n;saved=out/'previous-source'/n;saved.parent.mkdir(parents=True,exist_ok=True);saved.write_bytes(previous.read_bytes())
  assert previous.read_bytes()==run('read-before-'+str(len(rows)),['git','show',head+':'+n],source)
  previous.write_bytes(raw);previous.chmod(pin['mode'])
 protected={'tools/hia_frozen_component_sources.py':'60a30ab07d6c58ef0523531636a3250cc9e75402bffe75a07115012efa5d0774','tools/hia_evaluation_window_history.py':'08054cf59af6e93453fc370d08c64d1b14e9072012f69652cfae747083346cfa','hepta/hia_program_runtime.py':'76f184195ffc37dab2e327a2170e0999aa51349b9e1f62475084719d675686f4'}
 for n,h in protected.items():assert sha((source/n).read_bytes())==h
 proof=source/'review-evidence/root-expanded18-linux-native-generation-20261128-2ac5';proof.mkdir(parents=True,exist_ok=False)
 import shutil
 for source_file,name in [(archive,archive.name),(out/'capture-terminal.json','capture-terminal.json'),(dest/'all-original-members.json','all-original-members.json'),(dest/'linux-authors-complete-capture-v1/driver.py','capture-driver.py'),(out/'driver.py','integration-driver.py')]:shutil.copy2(source_file,proof/name)
 report={'schema':'hepta.expanded18-linux-source-generation-integration.v1','base':head,'actual_linux_authors':4,'generated':generation['generated'],'independent_full_archive_members':len(pins),'archive_sha256':sha(archive.read_bytes()),'retained_failed_setup':'Original393 preparation rejects the Source8 builder INPUTS successor not yet present in the fixed generation relation. No test body or fixed authority is changed.','source_controls_complete':False,'whole_cold_qualified':False}
 (proof/'integration.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
 expected=set(generation['generated'])|{str(p.relative_to(source))for p in proof.iterdir()}
 run('stage-source-and-proof',['git','add','--',*sorted(expected)],source)
 changed=set(run('staged-paths',['git','diff','--cached','--name-only'],source).decode().splitlines());assert changed==expected
 run('diff-check',['git','diff','--cached','--check'],source)
 run('commit',['git','commit','-m','Generate expanded native worker sources on Linux and retain complete author custody'],source)
 newhead=run('committed-head',['git','rev-parse','HEAD'],source).decode().strip();tree=run('committed-tree',['git','rev-parse','HEAD^{tree}'],source).decode().strip();assert run('terminal-status',['git','status','--porcelain=v1'],source)==b''
 report.update(status='COMMITTED_LINUX_SOURCE_GENERATION',head=newhead,tree=tree,paths=len(changed),seconds=time.monotonic()-start,rows=rows)
except BaseException as e:
 report={'status':'FAILED','error':repr(e),'traceback':traceback.format_exc(),'rows':rows,'whole_cold_qualified':False}
 (out/'terminal.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n');print(json.dumps(report),flush=True);raise
(out/'terminal.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n');print(json.dumps(report,sort_keys=True),flush=True)
