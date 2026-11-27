from pathlib import Path
from hashlib import sha256
import json,sys,shutil
from tools.qualify_hia_selfhost import compile_stage
source=Path('/tmp/hia-runtime-native-bootstrap-F-589c')
destination=Path('/workspace/scratch/589c0a6dd85b/runtime-c13-native-int-probe-589c')
assert destination.is_dir() and not list(destination.iterdir())
compiler=Path('/tmp/hia-runtime-589c-language-all-fixtures-20261127-v3/B1.image.bin')
assert sha256(compiler.read_bytes()).hexdigest()=='acb6478d1a466d17210611c5fcbbd5aeec3109b0813e917f0bb5c8419f3c33a9'
old=Path('/tmp/hia-historical-p3-final-cold-589c.json').read_bytes()
assert sha256(old).hexdigest()=='00ef3a2c17ec6424bc2fd61a87ea1b6c469341a6385464b3c7c9c172eb69c42e'
observer=bytes.fromhex(json.loads(old)['native_flat_observer_hex'])
assert len(observer)==1107
report={'schema':'hepta.hia.assembly-integer-component-probe.v1','scope':'component-only: historical native B1 and observer compile exact F source; no current cold or installed release qualification','source_commit':'5622dafbcfa10ad0c6f99214994ee7dcf71523e0','compiler':{'path':str(compiler),'bytes':compiler.stat().st_size,'sha256':sha256(compiler.read_bytes()).hexdigest()},'observer':{'bytes':len(observer),'sha256':sha256(observer).hexdigest()},'python':{'executable':sys.executable,'version':sys.version},'prior_attempt':{'executable':'/opt/codex/runtimes/codex-primary-runtime/dependencies/python/bin/python','version':'3.12','status':'failed-before-native-execution','exception':'AttributeError: module fcntl has no attribute F_ADD_SEALS','production_source_modified':False},'components':{},'whole_native_qualified':False}
for label,path in [('syntax','examples/hia_bootstrap/core_cli/assembly_syntax_diagnostics.hepta'),('presenter','examples/hia_bootstrap/core_cli/assembly_diagnostic_report.hepta'),('canonical','examples/hia_bootstrap/json_canonical.hepta'),('core','examples/hia_bootstrap/core_admission.hepta')]:
 if shutil.disk_usage(destination).free < 64<<20:raise RuntimeError('own component output volume below 64 MiB free')
 data=(source/path).read_bytes()
 image,receipt=compile_stage(destination,label,compiler,data,flat_observer=observer)
 report['components'][label]={'source':path,'source_bytes':len(data),'source_sha256':sha256(data).hexdigest(),'image':str(image),'bytes':image.stat().st_size,'sha256':sha256(image.read_bytes()).hexdigest(),'receipt':receipt}
 (destination/'compile-report.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
 print(label,image.stat().st_size,sha256(image.read_bytes()).hexdigest(),flush=True)
print('four actual native components compiled; whole_native_qualified=false')
