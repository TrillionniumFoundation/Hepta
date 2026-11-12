"""Independent complete historical importer oracle against the actual ELF."""
from hashlib import sha256
import copy
import json
from pathlib import Path
import resource
import struct
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1];BASE=ROOT.parent/'Hepta-v66-restored'
OLD=ROOT.parent/'native-composite-driver-reconstructed'
sys.path[:0]=[str(ROOT),str(OLD/'development'),str(OLD),str(BASE)]
from hepta.hia_core_upgrade import import_legacy_composite_v2
from hepta.hia_program import HIAProgramRejected
from hepta.hia_core_admission_native import ERROR_CODES
from tests.test_hia_program_composite import stored_loan_program,enum_owner_program,task_program
from pipeline_panel_support import native_error

dest=ROOT/'development/smoke-r1';dest.mkdir(parents=True,exist_ok=False)
empty=dest/'empty';empty.mkdir()
bundle_path=ROOT/'development/build-r2/bundle.json';bundle_raw=bundle_path.read_bytes();bundle=json.loads(bundle_raw)
assert bundle['status']=='PASS'
exe=Path(bundle['executable']['path']);exe_raw=exe.read_bytes()
assert sha256(exe_raw).hexdigest()==bundle['executable']['sha256']
pins={bundle_path:bundle_raw,exe:exe_raw,Path(__file__):Path(__file__).read_bytes()}
for row in bundle['components'].values():
    for key,hashkey in [('source_path','source_sha256'),('expected_source_path','source_sha256'),('image_path','image_sha256')]:
        p=Path(row[key]);raw=p.read_bytes();assert sha256(raw).hexdigest()==row[hashkey]
        if p in pins:assert pins[p]==raw
        pins[p]=raw
for folder in ('tools','examples','docs'):
    for p in (ROOT/folder).rglob('*'):
        if p.is_file() and '__pycache__' not in p.parts:pins[p]=p.read_bytes()
(dest/'source-before.json').write_text(json.dumps({str(p):{'bytes':len(raw),'sha256':sha256(raw).hexdigest()} for p,raw in pins.items()},indent=2,sort_keys=True)+'\n')
rows=[];start=time.monotonic_ns();summary={'scope':'COMPLETE_PUBLIC_HISTORICAL_IMPORTER_NATIVE_ELF_SMOKE','status':'INCOMPLETE','cases':rows,'retained_child_runtime':False,'strace_observed':False,'whole_stack_closed':False}

def cases():
    for name,make in [('stored',stored_loan_program),('enum',enum_owner_program),('task',task_program)]:
        doc=make();doc['schema']='hepta.hia.program.v2';yield name,doc
    yield 'wrong-schema',task_program()
    doc=task_program();doc['schema']='hepta.hia.program.v2';doc['proof']=True;yield 'extra-key-before-schema',doc
    doc=stored_loan_program();doc['schema']='hepta.hia.program.v2'
    op=doc['functions'][0]['blocks'][1]['ops'][5];assert op['op']=='buffer.store'
    op['op']='buffer.fill';op['args']=['parent','byte'];yield 'v6-primitive-cannot-bypass-old-v1',doc

def limits():
    resource.setrlimit(resource.RLIMIT_AS,(1536<<20,1536<<20))
    resource.setrlimit(resource.RLIMIT_STACK,(8<<20,8<<20))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))

try:
    for name,doc in cases():
        folder=dest/name;folder.mkdir()
        wire=json.dumps(doc,ensure_ascii=False,separators=(',',':')).encode();(folder/'input.json').write_bytes(wire)
        before=copy.deepcopy(doc);expected=None
        try:
            imported,report=import_legacy_composite_v2(wire)
            expected={'core':imported.as_dict(),'report':report,'structured':json.loads(imported.structured_bytes)}
            expected_bytes=json.dumps(expected,ensure_ascii=False,separators=(',',':'),sort_keys=True).encode()
            (folder/'expected.json').write_bytes(expected_bytes)
            oracle={'accepted':True,'bytes':len(expected_bytes),'sha256':sha256(expected_bytes).hexdigest()}
        except HIAProgramRejected as exc:
            oracle={'accepted':False,'code':exc.code,'error':str(exc)}
        assert doc==before
        (folder/'oracle.json').write_text(json.dumps(oracle,indent=2)+'\n')
        t=time.monotonic_ns()
        actual=subprocess.run([str(exe)],input=wire,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            cwd=empty,env={'PATH':str(empty),'HOME':str(empty),'LANG':'C'},preexec_fn=limits,timeout=120)
        (folder/'stdout.bin').write_bytes(actual.stdout);(folder/'stderr.bin').write_bytes(actual.stderr)
        row={'case':name,'oracle':oracle,'returncode':actual.returncode,'stdout_bytes':len(actual.stdout),
            'stderr_bytes':len(actual.stderr),'stdout_sha256':sha256(actual.stdout).hexdigest(),
            'stderr_sha256':sha256(actual.stderr).hexdigest(),'wall_ns':time.monotonic_ns()-t}
        if len(actual.stderr)%8==0:row['stderr_words']=list(struct.unpack('<'+'Q'*(len(actual.stderr)//8),actual.stderr))
        (folder/'actual.json').write_text(json.dumps(row,indent=2)+'\n')
        if expected is not None:
            assert actual.returncode==0 and actual.stderr==b'' and actual.stdout==expected_bytes,row
        else:
            assert actual.returncode==2 and actual.stdout==b'' and len(actual.stderr)==128,row
            frame=struct.unpack('<16Q',actual.stderr);group,error=frame[4:6]
            if group==9:code={1:'E_HIA_FORMAT',2:'E_HIA_VERSION_COLLISION',3:'E_HIA_LIMIT',4:'E_HIA_UPGRADE'}[error]
            elif group==8:code=ERROR_CODES[error]
            else:code,_=native_error(frame)
            assert code==oracle['code'],(row,code)
        row['status']='PASS';rows.append(row);print(json.dumps(row,sort_keys=True),flush=True)
    summary.update(status='PASS',cases_completed=len(rows))
except BaseException as exc:
    summary.update(status='FAIL',cases_completed=len(rows),error_class=type(exc).__name__,error=str(exc));raise
finally:
    assert all(p.read_bytes()==raw for p,raw in pins.items())
    summary['all_source_and_image_pins_unchanged']=True
    summary['wall_ns']=time.monotonic_ns()-start
    (dest/'summary.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n')
    print(json.dumps({k:v for k,v in summary.items() if k!='cases'},sort_keys=True),flush=True)
