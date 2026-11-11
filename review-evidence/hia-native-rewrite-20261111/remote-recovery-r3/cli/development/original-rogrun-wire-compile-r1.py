from pathlib import Path
from hashlib import sha256
import json,sys,subprocess,ast,traceback
base=Path('/var/tmp/hia9acdfa-native-resume-a3c61136-20261111');root=base/'cli-recovery/workspace/native-hia-cli-next';original=base/'cli-recovery/r6-exact-original'
stage=root/'development/cli-wire-reconstructed-compile-r1';stage.mkdir(exist_ok=False)
for name,text in json.loads(sys.stdin.read())['files'].items():
 target=root/name;assert not target.exists();target.write_text(text);assert target.read_text()==text
copy={
 'checkpoints/source-r3/tools/generate_hia_graph_wire_scan.py':'tools/cli_graph_wire_scan.py',
 'dependencies/base/tools/generate_hia_agent_binary64_format.py':'tools/generate_hia_agent_binary64_format.py',
 'dependencies/base/tools/generate_hia_agent_binary64.py':'tools/generate_hia_agent_binary64.py'}
for name,target in copy.items():
 raw=(original/name).read_bytes();p=root/target;assert not p.exists();p.write_bytes(raw);assert p.read_bytes()==raw
sources=[root/'tools'/x for x in ('cli_graph_wire_common.py','cli_graph_wire_scan.py','cli_graph_wire_emit.py','generate_hia_cli_graph_wire.py','generate_hia_agent_binary64_format.py','generate_hia_agent_binary64.py')]
def pin(p):return {'path':str(p),'bytes':p.stat().st_size,'sha256':sha256(p.read_bytes()).hexdigest()}
before=[pin(p) for p in sources];(stage/'source-before.json').write_text(json.dumps(before,sort_keys=True,indent=2)+'\n')
def body(path,name):
 tree=ast.parse(path.read_text())
 return ast.literal_eval(next(n.value for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id==name for t in n.targets)))
def defs(text):return {x.name:ast.dump(x,include_attributes=False) for x in ast.parse(text).body}
checks={}
for owner in ('common','scan','emit'):
 symbol='COMMON' if owner=='common' else 'BODY'
 old=defs(body(original/'checkpoints/source-r3/tools'/('generate_hia_graph_wire_'+owner+'.py'),symbol))
 new=defs(body(root/'tools'/('cli_graph_wire_'+owner+'.py'),symbol))
 changed=[k for k in old if old[k]!=new[k]];added=sorted(set(new)-set(old));checks[owner]={'changed':changed,'added':added,'original_count':len(old)}
 assert changed==({'common':['graph'],'scan':[],'emit':['emit','append']}[owner]),checks
 assert added==({'common':[],'scan':[],'emit':['cli_emit','cli_start']}[owner]),checks
(stage/'ast-scope.json').write_text(json.dumps(checks,sort_keys=True,indent=2)+'\n')
try:
 env=dict(__import__('os').environ,PYTHONDONTWRITEBYTECODE='1',PYTHONPATH=str(root)+':'+str(base/'source'))
 run=subprocess.run([sys.executable,str(root/'tools/generate_hia_cli_graph_wire.py')],cwd=root,env=env,capture_output=True,timeout=90)
 (stage/'generation.stdout').write_bytes(run.stdout);(stage/'generation.stderr').write_bytes(run.stderr);assert run.returncode==0,run.stderr.decode()
 compiler=base/'root-recovery/workspace/native-edit-candidate-next/development/build-r1/source/1/B3.image.bin';craw=compiler.read_bytes()
 assert sha256(craw).hexdigest()=='35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b'
 frozen=stage/'B3.image.bin';frozen.write_bytes(craw);sys.path.insert(0,str(base/'source'))
 from tools.qualify_hia_selfhost import compile_stage
 components={}
 for role in ('scan','emit'):
  source=root/('examples/hia_bootstrap/cli_graph_json_wire_'+role+'.hiaasm');raw=source.read_bytes();(stage/(role+'.hiaasm')).write_bytes(raw)
  image,receipt=compile_stage(stage,'cli-graph-wire-'+role,frozen,raw);image=Path(image);iraw=image.read_bytes()
  assert receipt['input_sha256']==sha256(raw).hexdigest()==receipt['source_sha256'] and receipt['image_sha256']==sha256(craw).hexdigest()==receipt['artifact_sha256'] and receipt['produced_sha256']==sha256(iraw).hexdigest() and receipt['produced_bytes']==len(iraw)
  row={'schema':'hepta.hia.cli-graph-wire-'+role+'-development.v1','source_path':str(source),'source_sha256':sha256(raw).hexdigest(),'source_bytes':len(raw),'image_path':str(image),'image_sha256':sha256(iraw).hexdigest(),'image_bytes':len(iraw),'compiler_sha256':sha256(craw).hexdigest(),'receipt':receipt}
  assert source.read_bytes()==raw and image.read_bytes()==iraw
  (stage/(role+'.manifest.json')).write_text(json.dumps(row,sort_keys=True,indent=2)+'\n');components[role]=row
 assert compiler.read_bytes()==craw and frozen.read_bytes()==craw
 bundle={'status':'PASS_COMPILE_ONLY','scope':'NEW_CLI_GRAPH_WIRE_RECONSTRUCTION_DEVELOPMENT_NOT_COLD','components':components,'ast_scope':checks,'python':sys.version}
 (stage/'bundle.json').write_text(json.dumps(bundle,sort_keys=True,indent=2)+'\n')
 print(json.dumps({'status':'PASS_ACTUAL_COMPILE_ONLY','bundle':str(stage/'bundle.json'),'components':{k:{a:v for a,v in row.items() if a not in ('receipt',)} for k,row in components.items()},'generation':run.stdout.decode()},sort_keys=True))
except BaseException:
 (stage/'failure.txt').write_text(traceback.format_exc());raise
finally:
 after=[pin(p) for p in sources];(stage/'source-after.json').write_text(json.dumps(after,sort_keys=True,indent=2)+'\n');assert after==before
