from pathlib import Path
import hashlib,json,sys,time,traceback
from bounded_support import ROOT, SOURCE, snapshot
sys.path.insert(0,str(SOURCE))
label=sys.argv[1];OUT=ROOT/'evidence'/label;OUT.mkdir(exist_ok=False)
def save(name,value):(OUT/name).write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')
before=snapshot();save('SOURCE-BEFORE.json',before);started=time.monotonic_ns()
report={'schema':'hia-cli-discovery-five-image-development-build.v1','scope':'FORMAL_ACTUAL314_BOUNDED_DEVELOPMENT_NOT_COLD','status':'FAIL','python':sys.version}
try:
 from tools.build_hia_cli_discovery_bundle import build_development
 from tools.qualify_hia_cli_discovery_bundle import inspect_build
 from tools.hia_cli_discovery_bundle_custody import binding
 compiler=ROOT/'inputs/B3.image.bin'
 assert hashlib.sha256(compiler.read_bytes()).hexdigest()=='bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0'
 report['compiler']=binding(compiler)
 manifest=build_development(OUT/'build',compiler)
 report['build']=inspect_build(manifest.parent,None)
 report['status']='PASS'
except BaseException:report['traceback']=traceback.format_exc()
finally:
 after=snapshot();save('SOURCE-AFTER.json',after);report['source_unchanged']=before==after;report['wall_ns']=time.monotonic_ns()-started
 if before!=after:report['status']='FAIL'
 save('REPORT.json',report)
print(json.dumps({key:report.get(key) for key in ('status','source_unchanged','wall_ns','traceback')}))
raise SystemExit(0 if report['status']=='PASS' else 1)
