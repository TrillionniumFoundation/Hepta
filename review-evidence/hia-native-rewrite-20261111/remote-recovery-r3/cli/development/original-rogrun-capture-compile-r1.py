from pathlib import Path
from hashlib import sha256
import json,sys,subprocess,stat,traceback
base=Path('/var/tmp/hia9acdfa-native-resume-a3c61136-20261111');out=base/'cli-recovery';work=out/'workspace';project=work/'native-hia-cli-next'
pairs=[
(base/'root-recovery/workspace/native-edit-json-next/development/main-compile-r3/source/6/hia_agent_edit_source_views.py',work/'Hepta-agent-edit-native/tools/hia_agent_edit_source_views.py','555472263213f15deb239fcf3bf8e5b273a28caf3a67bb29ffd037f171d7ae5c'),
(base/'root-recovery/workspace/native-edit-json-next/development/main-compile-r3/source/8/hia_composite_lowering_driver_common.py',work/'native-composite-driver-reconstructed/tools/hia_composite_lowering_driver_common.py','fe63327671ea51ca950b955512a0f574d706176a4a8d050e3f8f12c83ef5e3a1')]
copied=[]
for source,target,expected in pairs:
 raw=source.read_bytes();assert sha256(raw).hexdigest()==expected
 target.parent.mkdir(parents=True,exist_ok=True);assert not target.exists();target.write_bytes(raw);target.chmod(stat.S_IMODE(source.stat().st_mode));assert target.read_bytes()==raw
 copied.append({'source':str(source),'target':str(target),'bytes':len(raw),'sha256':expected})
(out/'authoring-dependencies.json').write_text(json.dumps(copied,sort_keys=True,indent=2)+'\n')
stage=project/'development/capture-reconstructed-compile-r1';stage.mkdir(exist_ok=False)
source=project/'examples/hia_bootstrap/cli_capture.hiaasm'
pins=[project/'tools/cli_capture_owner.py',project/'tools/generate_hia_cli_capture.py',project/'tools/cli_authoring.py',project/'tools/cli_argv_common.py',pairs[0][1],base/'source/tools/qualify_hia_selfhost.py']
before=[{'path':str(p),'bytes':p.stat().st_size,'sha256':sha256(p.read_bytes()).hexdigest()} for p in pins]
(stage/'source-before.json').write_text(json.dumps(before,sort_keys=True,indent=2)+'\n')
try:
 env=dict(__import__('os').environ,PYTHONDONTWRITEBYTECODE='1',PYTHONPATH=str(work/'Hepta-agent-edit-native')+':'+str(base/'source'))
 run=subprocess.run([sys.executable,str(project/'tools/generate_hia_cli_capture.py')],cwd=project,env=env,capture_output=True,timeout=60)
 (stage/'generation.stdout').write_bytes(run.stdout);(stage/'generation.stderr').write_bytes(run.stderr);assert run.returncode==0,run.stderr.decode()
 raw=source.read_bytes();(stage/'cli_capture.hiaasm').write_bytes(raw)
 compiler=base/'root-recovery/workspace/native-edit-candidate-next/development/build-r1/source/1/B3.image.bin'
 compiler_raw=compiler.read_bytes();assert len(compiler_raw)==669556 and sha256(compiler_raw).hexdigest()=='35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b'
 frozen=stage/'B3.image.bin';frozen.write_bytes(compiler_raw)
 sys.path[:0]=[str(base/'source')]
 from tools.qualify_hia_selfhost import compile_stage
 image,receipt=compile_stage(stage,'cli-capture',frozen,raw)
 image=Path(image);compiled=image.read_bytes()
 manifest={'schema':'hepta.hia.cli-capture.development.v1','qualification':'DEVELOPMENT_ONLY_NEW_RECONSTRUCTION','source':str(source),'source_sha256':sha256(raw).hexdigest(),'image':str(image),'image_sha256':sha256(compiled).hexdigest(),'compiler':str(frozen),'compiler_sha256':sha256(compiler_raw).hexdigest(),'receipt':receipt,'source_before':before,'python':sys.version}
 assert compiler.read_bytes()==compiler_raw and frozen.read_bytes()==compiler_raw and source.read_bytes()==raw
 (stage/'cli-capture.manifest.json').write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n')
 print(json.dumps({'status':'PASS_ACTUAL_DEVELOPMENT_COMPILE','manifest':str(stage/'cli-capture.manifest.json'),'source_bytes':len(raw),'image_bytes':len(compiled),'source_sha256':manifest['source_sha256'],'image_sha256':manifest['image_sha256'],'generation':run.stdout.decode()},sort_keys=True))
except BaseException:
 (stage/'failure.txt').write_text(traceback.format_exc());raise
finally:
 after=[{'path':str(p),'bytes':p.stat().st_size,'sha256':sha256(p.read_bytes()).hexdigest()} for p in pins]
 (stage/'source-after.json').write_text(json.dumps(after,sort_keys=True,indent=2)+'\n');assert after==before
