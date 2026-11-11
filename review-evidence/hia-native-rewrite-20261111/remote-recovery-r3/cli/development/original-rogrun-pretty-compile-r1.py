from pathlib import Path
from hashlib import sha256
import json,sys,subprocess,traceback
base=Path('/var/tmp/hia9acdfa-native-resume-a3c61136-20261111');root=base/'cli-recovery/workspace/native-hia-cli-next';stage=root/'development/pretty-reconstructed-compile-r1';stage.mkdir(exist_ok=False)
data=json.loads(sys.stdin.read())
for name,text in data['files'].items():
 p=root/name;assert not p.exists();p.write_text(text);assert p.read_text()==text
paths=[root/'tools'/name for name in ('cli_pretty_owner.py','generate_hia_cli_pretty.py','cli_authoring.py','cli_argv_common.py')]
paths.append(root.parent/'Hepta-agent-edit-native/tools/hia_agent_edit_source_views.py')
def pins():return [{'path':str(p),'bytes':p.stat().st_size,'sha256':sha256(p.read_bytes()).hexdigest()} for p in paths]
before=pins();(stage/'source-before.json').write_text(json.dumps(before,indent=2,sort_keys=True)+'\n')
try:
 env=dict(__import__('os').environ,PYTHONDONTWRITEBYTECODE='1',PYTHONPATH=str(root.parent/'Hepta-agent-edit-native')+':'+str(base/'source'))
 run=subprocess.run([sys.executable,str(root/'tools/generate_hia_cli_pretty.py')],cwd=root,env=env,capture_output=True,timeout=60)
 (stage/'generation.stdout').write_bytes(run.stdout);(stage/'generation.stderr').write_bytes(run.stderr);assert run.returncode==0,run.stderr.decode()
 source=root/'examples/hia_bootstrap/cli_pretty.hiaasm';raw=source.read_bytes();(stage/'cli_pretty.hiaasm').write_bytes(raw)
 compiler=base/'root-recovery/workspace/native-edit-candidate-next/development/build-r1/source/1/B3.image.bin';craw=compiler.read_bytes();assert sha256(craw).hexdigest()=='35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b'
 frozen=stage/'B3.image.bin';frozen.write_bytes(craw);sys.path.insert(0,str(base/'source'))
 from tools.qualify_hia_selfhost import compile_stage
 image,receipt=compile_stage(stage,'cli-pretty',frozen,raw);image=Path(image);iraw=image.read_bytes()
 assert receipt['source_sha256']==sha256(raw).hexdigest()==receipt['input_sha256'] and receipt['image_sha256']==sha256(craw).hexdigest()==receipt['artifact_sha256'] and receipt['produced_sha256']==sha256(iraw).hexdigest() and receipt['produced_bytes']==len(iraw)
 manifest={'schema':'hepta.hia.cli-pretty.development.v1','scope':'NEW_RECONSTRUCTION_ACTUAL_DEVELOPMENT_NOT_COLD','source':str(source),'source_sha256':sha256(raw).hexdigest(),'source_bytes':len(raw),'image':str(image),'image_sha256':sha256(iraw).hexdigest(),'image_bytes':len(iraw),'compiler':str(frozen),'compiler_sha256':sha256(craw).hexdigest(),'receipt':receipt,'python':sys.version}
 assert source.read_bytes()==raw and image.read_bytes()==iraw and compiler.read_bytes()==craw
 (stage/'cli-pretty.manifest.json').write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n')
 result={'status':'PASS_ACTUAL_COMPILE_ONLY','manifest':str(stage/'cli-pretty.manifest.json'),'source_sha256':manifest['source_sha256'],'image_sha256':manifest['image_sha256'],'generation':run.stdout.decode()}
 (stage/'result.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n');print(json.dumps(result,sort_keys=True))
except BaseException:
 failure=traceback.format_exc();(stage/'failure.txt').write_text(failure);(stage/'result.json').write_text(json.dumps({'status':'FAIL','failure':failure},sort_keys=True,indent=2)+'\n');raise
finally:
 after=pins();(stage/'source-after.json').write_text(json.dumps(after,sort_keys=True,indent=2)+'\n');assert before==after
