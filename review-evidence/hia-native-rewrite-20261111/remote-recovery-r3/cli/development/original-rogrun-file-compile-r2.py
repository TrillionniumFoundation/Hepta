from pathlib import Path
from hashlib import sha256
import json,sys,subprocess,os,ast,traceback
base=Path("/var/tmp/hia9acdfa-native-resume-a3c61136-20261111");project=base/'cli-recovery/workspace/native-hia-cli-next'
files=json.loads(sys.stdin.read());stage=project/'development/file-reconstructed-compile-r2';stage.mkdir(exist_ok=False)
expected={'cli_file_owner.py':'0dd071c3c0900c71126839dd17e01f35961a6157469c085cade84034964dd84b','generate_hia_cli_file.py':'ebfac56dc0fe4cf225665efe4658743569f53de63df7999bd871391286203bdf'}
for name,text in files.items():
 ast.parse(text);p=project/'tools'/name;old=p.read_bytes();assert sha256(old).hexdigest()==expected[name]
 (stage/('precompile-draft-'+name)).write_bytes(old);p.write_text(text);(stage/name).write_bytes(p.read_bytes())
source=project/'examples/hia_bootstrap/cli_file.hiaasm'
pins=[project/'tools'/name for name in files]+[project/'tools/cli_authoring.py',project/'tools/cli_argv_common.py',base/'cli-recovery/workspace/Hepta-agent-edit-native/tools/hia_agent_edit_source_views.py',base/'source/tools/qualify_hia_selfhost.py']
before=[dict(path=str(p),bytes=p.stat().st_size,sha256=sha256(p.read_bytes()).hexdigest()) for p in pins]
(stage/'source-before.json').write_text(json.dumps(before,sort_keys=True,indent=2)+'\n')
try:
 env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',PYTHONPATH=str(base/'cli-recovery/workspace/Hepta-agent-edit-native')+':'+str(base/'source'))
 run=subprocess.run([sys.executable,str(project/'tools/generate_hia_cli_file.py')],cwd=project,env=env,capture_output=True,timeout=60)
 (stage/'generation.stdout').write_bytes(run.stdout);(stage/'generation.stderr').write_bytes(run.stderr)
 assert run.returncode==0,run.stderr.decode()
 raw=source.read_bytes();(stage/'cli_file.hiaasm').write_bytes(raw)
 compiler=base/'root-recovery/workspace/native-edit-candidate-next/development/build-r1/source/1/B3.image.bin';comp=compiler.read_bytes()
 assert len(comp)==669556 and sha256(comp).hexdigest()=='35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b'
 frozen=stage/'B3.image.bin';frozen.write_bytes(comp);sys.path.insert(0,str(base/'source'))
 from tools.qualify_hia_selfhost import compile_stage
 image,receipt=compile_stage(stage,'cli-file',frozen,raw);image=Path(image);iraw=image.read_bytes()
 manifest=dict(schema='hepta.hia.cli-file.development.v1',qualification='DEVELOPMENT_ONLY_NEW_RECONSTRUCTION',source=str(source),source_sha256=sha256(raw).hexdigest(),image=str(image),image_sha256=sha256(iraw).hexdigest(),compiler=str(frozen),compiler_sha256=sha256(comp).hexdigest(),receipt=receipt,source_before=before,python=sys.version)
 assert compiler.read_bytes()==comp and frozen.read_bytes()==comp and source.read_bytes()==raw
 mp=stage/'cli-file.manifest.json';mp.write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n')
 result=dict(status='PASS_ACTUAL_DEVELOPMENT_COMPILE',manifest=str(mp),source_bytes=len(raw),image_bytes=len(iraw),source_sha256=manifest['source_sha256'],image_sha256=manifest['image_sha256'],generation=run.stdout.decode())
 (stage/'result.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n');print(json.dumps(result,sort_keys=True))
except BaseException:
 (stage/'failure.txt').write_text(traceback.format_exc());raise
finally:
 after=[dict(path=str(p),bytes=p.stat().st_size,sha256=sha256(p.read_bytes()).hexdigest()) for p in pins]
 (stage/'source-after.json').write_text(json.dumps(after,sort_keys=True,indent=2)+'\n');assert before==after
