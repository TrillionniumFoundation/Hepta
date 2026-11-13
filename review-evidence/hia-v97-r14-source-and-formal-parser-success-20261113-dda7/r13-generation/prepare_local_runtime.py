"""Offline, isolated actual-3.14 runtime for local full Source controls."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import time
import traceback

ROOT = Path(__file__).resolve().parent
BASE = ROOT.parent / 'v94-cli-parser-context-r11-r2/graph-probe-r2/interpreter'
OUT = ROOT / 'local-runtime-r1'
VENV = OUT / 'venv'

def pin(path):
    raw = path.read_bytes()
    return {'path':str(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
        'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}

OUT.mkdir(exist_ok=False)
wheel = BASE / 'lib/python3.14/test/wheeldata/setuptools-79.0.1-py3-none-any.whl'
inputs = [BASE/'bin/python3.14', BASE/'lib/libpython3.14.so.1.0',
    BASE/'lib/python3.14/ensurepip/_bundled/pip-26.0.1-py3-none-any.whl',wheel]
before = [pin(path) for path in inputs]
env = dict(os.environ,LD_LIBRARY_PATH=str(BASE/'lib'),PYTHONDONTWRITEBYTECODE='1',PIP_NO_INDEX='1',PIP_DISABLE_PIP_VERSION_CHECK='1')
report = {'schema':'hia.r13.local-actual314-offline-runtime.v1','status':'RUNNING','inputs':before,
    'commands':[],'scope':'LOCAL_FULL_SOURCE_DEVELOPMENT_NOT_FORMAL_COLD_OR_PORTABLE_QUALIFICATION',
    'product_source_changed':False,'network_requested':False,'whole_native':False}
(OUT/'INTENT.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')

def run(label,argv,limit):
    started = time.monotonic_ns()
    result = subprocess.run([str(x) for x in argv],env=env,cwd=ROOT,capture_output=True,timeout=limit)
    (OUT/(label+'.stdout')).write_bytes(result.stdout)
    (OUT/(label+'.stderr')).write_bytes(result.stderr)
    row = {'label':label,'argv':[str(x)for x in argv],'returncode':result.returncode,
        'elapsed_ns':time.monotonic_ns()-started,'limit_seconds':limit,
        'stdout':pin(OUT/(label+'.stdout')),'stderr':pin(OUT/(label+'.stderr'))}
    report['commands'].append(row)
    (OUT/(label+'.json')).write_text(json.dumps(row,indent=2,sort_keys=True)+'\n')
    if result.returncode:
        raise RuntimeError(label+' failed: '+str(result.returncode))
    return result.stdout

try:
    run('create-venv',[BASE/'bin/python3.14','-B','-m','venv','--copies',VENV],120)
    run('install-local-setuptools',[VENV/'bin/python3.14','-B','-m','pip','install','--no-index','--no-deps','--no-build-isolation',wheel],120)
    raw = run('actual-runtime',[VENV/'bin/python3.14','-B','-c',
        'import sys, json, setuptools, wheel, pip; print(json.dumps({"python":sys.version,"executable":sys.executable,"base_prefix":sys.base_prefix,"setuptools":setuptools.__version__,"wheel":wheel.__version__,"pip":pip.__version__,"setuptools_file":setuptools.__file__,"wheel_file":wheel.__file__}, sort_keys=True))'],30)
    report['runtime'] = json.loads(raw)
    assert report['runtime']['python'].startswith('3.14.4 ')
    assert report['runtime']['setuptools'] == '79.0.1'
    assert report['runtime']['wheel'] == '0.45.1'
    assert report['runtime']['pip'] == '26.0.1'
    assert pin(VENV/'bin/python3.14')['sha256'] == before[0]['sha256']
    assert [pin(path)for path in inputs] == before
    report['original_runtime_inputs_byte_identical'] = True
    report['status'] = 'PASS'
except BaseException as error:
    report['status'] = 'FAIL'
    report['error'] = {'type':type(error).__name__,'message':str(error),'traceback':traceback.format_exc()}
finally:
    (OUT/'RESULT.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'status':report['status'],'runtime':report.get('runtime'),'error':report.get('error')},sort_keys=True),flush=True)
raise SystemExit(0 if report['status']=='PASS' else 1)
