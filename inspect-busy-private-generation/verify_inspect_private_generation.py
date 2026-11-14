import ast,hashlib,json,shutil,stat
from pathlib import Path
R=Path('/workspace/scratch/dda74a4fae35');B=R/'v132-inspect-machine-entry-r1/successor-r2/generation-stage-r1'
ns={};t=ast.parse((R/'v95-audit-mount-r1/v139-progress/verify_inspect_r3_terminal.py').read_text())
exec(compile(ast.Module(body=[n for n in t.body if isinstance(n,(ast.Import,ast.ImportFrom)) or isinstance(n,ast.FunctionDef) and n.name=='pin'],type_ignores=[]),'<root-pin-helper>','exec'),ns)
pin=ns['pin'];load=lambda p:json.loads(p.read_bytes())
p=load(B/'PLAN.json');l=load(B/'LAUNCH.json');s=load(B/'STATIC-PROOF.json')
for name,sha in [('PLAN.json','04d6db7d206317a564c582d1e757737fee642b4d'),('run_generation.py','80b3c87b4ca7c1ff90ff902e4b56f9ca28ea6abd'),('LAUNCH.json','3bc34256bc90c567a31100527b5718bf40da6bfd')]:assert pin(B/name)[0]['git_blob']==sha
for row in p['inputs'].values():assert pin(Path(row['path']))==(row['pin'],row['posix_mode'])
assert p['limits']=={'assembly_source_bytes':1048576,'cleanup_seconds':3,'minimum_free_bytes':1073741824,'qualification_seconds':180}
assert p['stage_order']==['generation-1','generation-2','generation-check'] and l['owner_count']==3
old=Path(p['inputs']['original_generation_runner']['path']).read_text();new=(B/'run_generation.py').read_text()
defs=lambda x:{n.name:n for n in ast.parse(x).body if isinstance(n,ast.FunctionDef)}
a,b=defs(old),defs(new);retained=s['whole_function_bytes_and_ast_retained'];assert len(retained)==19
for k in retained:assert ast.get_source_segment(old,a[k])==ast.get_source_segment(new,b[k]) and ast.dump(a[k],include_attributes=False)==ast.dump(b[k],include_attributes=False)
maps={};ins={}
for role,n in [('base',3187),('source',3188)]:
 c=load(Path(p['inputs'][role+'_capture']['path']));maps[role]=c['files'];ins[role]=set()
 assert not c['errors'] and len(c['files'])==len(c['stat'])==n
 for name,v in c['files'].items():
  f=Path(p[role])/name;actual,mode=pin(f);q=f.lstat();m={'device':q.st_dev,'inode':q.st_ino,'bytes':q.st_size,'mode':mode,'nlink':q.st_nlink,'mtime_ns':q.st_mtime_ns,'ctime_ns':q.st_ctime_ns}
  assert actual==v and m==c['stat'][name],role+'/'+name
  ins[role].add((q.st_dev,q.st_ino))
  if role=='source':assert q.st_nlink==1
assert len(ins['source'])==3188 and not ins['base']&ins['source']
assert sorted(k for k in set(maps['source'])|set(maps['base']) if maps['source'].get(k)!=maps['base'].get(k))==['hepta/hia_inspect_program_native.py','tests/test_hia_inspect_program_machine_entry.py']
assert all(maps['source'][k]==maps['base'][k] for k in p['generated_paths'])
runtime=p['runtime'];assert runtime==load(Path(p['inputs']['runtime_capture']['path'])) and runtime['version']==[3,14,4]
for k in ('executable','library'):
 v=runtime[k];f=Path(v['path']);actual,mode=pin(f);q=f.lstat()
 assert all(actual[x]==v[x] for x in ('bytes','sha256')) and mode==v['mode']
 assert all(getattr(q,sk)==v[k2] for sk,k2 in [('st_dev','device'),('st_ino','inode'),('st_mtime_ns','mtime_ns'),('st_ctime_ns','ctime_ns')])
expected=['/usr/bin/env','-i','PATH=/usr/local/bin:/usr/bin:/bin','HOME='+p['attempt'],'LANG=C.UTF-8','LC_ALL=C.UTF-8','PYTHONDONTWRITEBYTECODE=1','LD_LIBRARY_PATH='+runtime['library_directory'],runtime['launch_executable'],'-I','-B',str(B/'run_generation.py'),'--execute-generation-only','--plan',str(B/'PLAN.json'),'--plan-sha256',pin(B/'PLAN.json')[0]['sha256'],'--attempt',p['attempt']]
assert l['argv']==expected and not Path(p['attempt']).exists() and not Path(l['outer_directory']).exists()
free=shutil.disk_usage(R).free;assert free>=1073741824
report={'schema':'hepta.root-inspect-private-generation-static.v1','status':'PASS_STATIC_READBACK','source_files':3188,'base_files':3187,'all_bytes_modes_seven_stats_unchanged':True,'all_private_inodes_disjoint_and_nlink1':True,'retained_19_helpers_full_bytes_AST':retained,'plan':pin(B/'PLAN.json')[0],'runner':pin(B/'run_generation.py')[0],'launch':pin(B/'LAUNCH.json')[0],'runtime_full_file_identity_verified':True,'free_bytes':free,'unique_outputs_absent':True,'new_product_execution':False,'authorizes_execution':False,'whole_native':False}
out=R/'v95-audit-mount-r1/v140-progress/ROOT-INSPECT-PRIVATE-GENERATION-STATIC.json'
with out.open('x') as f:f.write(json.dumps(report,sort_keys=True,indent=2)+'\n')
print(json.dumps({'status':report['status'],'report':str(out),'pin':pin(out)[0],'free_bytes':free}))
