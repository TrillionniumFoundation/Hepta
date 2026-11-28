from pathlib import Path
import sys,json,hashlib,subprocess,time,traceback
base=Path('/Users/qianqi/work/hia-root-unified-cold-20261127-2ac5/kernel-generic-integration-v1')
root=base/'source';out=base/'ndu-expanded18-catalog-authority-v1';out.mkdir(mode=0o700,exist_ok=False)
(out/'driver.py').write_text(sys.argv[1])
head='7a8a97db149e688cb5e4e6f9e1c7844fcb96d6d0'
def git(*argv):return subprocess.check_output(['git','-C',str(root),*argv])
assert git('rev-parse','HEAD').decode().strip()==head and git('status','--porcelain=v1')==b''
sys.dont_write_bytecode=True;sys.path.insert(0,str(root))
from tools.hia_native_worker_source_authority import checked_paths,load_native_source_authority
from tools.hia_native_release_dependencies import TABLE
from tools.generate_hia_source_release_cold_admit import CONTRACT_PATH
authority=root/'docs/HIA_NATIVE_SOURCE_AUTHORITY.json';sourcefiles=root/'docs/HIA_COLD_NATIVE_SOURCE_FILES.json'
old_authority=authority.read_bytes();old_paths=load_native_source_authority(authority)
regpath=root/'review-evidence/hia-ndu-native-rank-20261128-2ac5/source-registration.json';regraw=regpath.read_bytes();assert hashlib.sha256(regraw).hexdigest()=='8e82a385af07971de45f3af3af59b067f06e25da87f472f7167d133eb065fe14'
registration=json.loads(regraw)
for name,pin in registration['changed_source'].items():
 raw=(root/name).read_bytes();assert len(raw)==pin['bytes'] and hashlib.sha256(raw).hexdigest()==pin['sha256'],name
required=set(registration['native_registration_additions'])|set(registration['declared_rank_component_inputs'])|set(registration['complete_recipe_native_inputs'])
for name in required:
 raw=(root/name).read_bytes();assert not(root/name).is_symlink() and(root/name).stat().st_nlink==1
 assert Path(name).suffix not in('.py','.rs','.elf','.so','.o','.bin','.pyc') and not raw.startswith(b'\x7fELF')
 if name in registration['complete_recipe_native_inputs']:
  p=registration['complete_recipe_native_inputs'][name];assert len(raw)==p['bytes'] and hashlib.sha256(raw).hexdigest()==p['sha256']
 assert raw==git('show',head+':'+name),name
new_paths=list(checked_paths(sorted(set(old_paths)|required)))
before_files=['docs/HIA_NATIVE_SOURCE_AUTHORITY.json','docs/HIA_COLD_NATIVE_SOURCE_FILES.json',TABLE,'examples/hia_bootstrap/release_stage_ndu_evaluator.hiastd','docs/HIA_NATIVE_NDU_EVALUATOR_RECIPE.json']
before={}
for name in before_files:
 p=root/name
 if p.exists():
  data=p.read_bytes();before[name]={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()};target=out/'before'/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
protected={n:hashlib.sha256((root/n).read_bytes()).hexdigest() for n in ['tools/hia_frozen_component_sources.py','tools/hia_evaluation_window_history.py','hepta/hia_program_runtime.py']}
authority.write_text(json.dumps({'schema':'hepta.hia.native-source-authority.v1','paths':new_paths},indent=2)+'\n')
sourcefiles.write_text(json.dumps({'schema':'hepta.hia.native-source-files.v1','mode':'native_only','files':[n for n in new_paths if n!=CONTRACT_PATH]},indent=2)+'\n')
rows=[]
def run(label,argv):
 start=time.monotonic();p=subprocess.run(argv,cwd=root,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120)
 (out/(label+'.stdout')).write_bytes(p.stdout);(out/(label+'.stderr')).write_bytes(p.stderr)
 row={'label':label,'argv':argv,'returncode':p.returncode,'seconds':time.monotonic()-start};rows.append(row);(out/'progress.json').write_text(json.dumps(rows,sort_keys=True,indent=2)+'\n')
 print(json.dumps(row),flush=True);print(p.stdout.decode(errors='replace')[-8000:]+p.stderr.decode(errors='replace')[-8000:],flush=True)
 assert p.returncode==0,label
try:
 run('ndu-current-recipe',[sys.executable,'-B','-m','tools.generate_hia_ndu_evaluator_recipe'])
 assert hashlib.sha256((root/registration['recipe']).read_bytes()).hexdigest()==registration['recipe_sha256']
 run('release-extension-catalog',[sys.executable,'-B','-m','tools.generate_hia_release_extension_catalog','--source',str(root)])
 run('release-dependency-check',[sys.executable,'-B','-m','tools.hia_native_release_dependencies','--check-source-files'])
 assert {n:hashlib.sha256((root/n).read_bytes()).hexdigest() for n in protected}==protected
 catalog=json.loads((out/'release-extension-catalog.stdout').read_bytes())
 assert len(catalog['registered_dags'])==14 and catalog['stages']==20 and catalog['publications']==122 and catalog['original_fourteen_groups_unchanged']
 changes=git('diff','--name-only').decode().splitlines()
 changed={n:{'bytes':(root/n).stat().st_size,'sha256':hashlib.sha256((root/n).read_bytes()).hexdigest()} for n in changes}
 report={'status':'CATALOG_AND_EXPLICIT_NATIVE_AUTHORITY_GENERATED','head':head,'rows':rows,'original_authority_count':len(old_paths),'native_authority_count':len(new_paths),'actual_added_paths':sorted(set(new_paths)-set(old_paths)),'registration_sha256':hashlib.sha256(regraw).hexdigest(),'source_changes':changed,'catalog':catalog,'native_sources_only':True,'old_authority_paths_preserved':True,'linux_authors_complete':False,'whole_cold_qualified':False}
except BaseException as e:
 report={'status':'FAILED','rows':rows,'error':repr(e),'traceback':traceback.format_exc(),'whole_cold_qualified':False}
 (out/'terminal.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n');print(json.dumps(report,sort_keys=True),flush=True);raise
(out/'terminal.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items()if k not in['actual_added_paths','source_changes']},sort_keys=True),flush=True)
