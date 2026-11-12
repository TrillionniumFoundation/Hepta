from pathlib import Path
from hashlib import sha256
import json,sys,struct,time,traceback
ROOT=Path(__file__).resolve().parents[1];BASE=ROOT.parent;sys.path[:0]=[str(BASE/'Hepta-v67-workflow-qualified')]
from tools.qualify_hia_selfhost import invoke
from tools.qualify_hia_selfhost_cli import inspect_executable
OUT=ROOT/'development/native-build-r2';OUT.mkdir(exist_ok=False)
paths=[ROOT/'development/driver-compile-r3/clean-build-driver.manifest.json',ROOT/'development/driver-compile-r2/clean-build-packer.manifest.json',ROOT/'development/gate-compile-r2/agent-data-json.manifest.json']
pins={};images=[]
for p in paths:
 raw=p.read_bytes();pins[p]=raw;m=json.loads(raw);sp=Path(m['source_path']);ip=Path(m['image_path']);source=sp.read_bytes();image=ip.read_bytes();assert sha256(source).hexdigest()==m['source_sha256'] and sha256(image).hexdigest()==m['image_sha256'];pins[sp]=source;pins[ip]=image;images.append((ip,image))
for i,(p,b) in enumerate(pins.items()):q=OUT/'source'/str(i)/p.name;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(b)
(OUT/'pins.json').write_text(json.dumps({str(p):dict(bytes=len(b),sha256=sha256(b).hexdigest()) for p,b in pins.items()},sort_keys=True,indent=2)+'\n')
frame=struct.pack('<4Q',int.from_bytes(b'HIABPK01','little'),len(images[0][1]),len(images[2][1]),0)+images[0][1]+images[2][1]
res=dict(status='INCOMPLETE',scope='ACTUAL_HIA_PACKED_NATIVE_CLEAN_BUILD_DEVELOPMENT');start=time.monotonic_ns()
try:
 receipt,out=invoke(OUT,'clean-build-pack',images[1][0],frame);size=receipt['core_u32'];assert receipt['status']=='returned' and 0<size<=len(out)
 executable=out[:size];inspection=inspect_executable(executable);target=OUT/'hia-build';target.write_bytes(executable);target.chmod(0o700)
 bundle=dict(schema='hepta.hia.clean-native-build-development.v1',executable=str(target),executable_sha256=sha256(executable).hexdigest(),image_manifests=[str(p) for p in paths],compiler_profile_unchanged=True,scope='DEVELOPMENT_NOT_COLD',complete_hosted_cli_replaced=False)
 (OUT/'bundle.json').write_text(json.dumps(bundle,indent=2,sort_keys=True)+'\n');res.update(status='PASS',bundle=bundle,inspection=inspection,receipt=receipt)
except BaseException as e:res.update(status='FAIL',error_class=type(e).__name__,error=str(e));traceback.print_exc();raise
finally:
 res['all_pins_unchanged']=all(p.read_bytes()==b for p,b in pins.items());assert res['all_pins_unchanged'];res['elapsed_ns']=time.monotonic_ns()-start;(OUT/'summary.json').write_text(json.dumps(res,indent=2,sort_keys=True)+'\n');print(json.dumps(res,sort_keys=True),flush=True)
