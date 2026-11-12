"""Test-only retained oracle, immutable pins, and actual standalone ELF runner."""
from hashlib import sha256
import gzip
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
from pipeline_panel_support import native_error


def compact(value):
    return json.dumps(value,ensure_ascii=False,separators=(',',':'),sort_keys=True).encode()


def limits():
    resource.setrlimit(resource.RLIMIT_AS,(1536<<20,1536<<20))
    resource.setrlimit(resource.RLIMIT_STACK,(8<<20,8<<20))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))


def diagnosis(frame):
    group,error=frame[4:6]
    if group==9:
        return {1:'E_HIA_FORMAT',2:'E_HIA_VERSION_COLLISION',3:'E_HIA_LIMIT',4:'E_HIA_UPGRADE'}[error]
    if group==8:return ERROR_CODES[error]
    if group==7:return 'E_HIA_LIMIT' if error in (1,3) else 'E_HIA_FORMAT'
    return native_error(frame)[0]


class Panel:
    def __init__(self, name, script):
        self.dest=ROOT/'development'/name;self.dest.mkdir(parents=True,exist_ok=False)
        self.empty=self.dest/'empty';self.empty.mkdir()
        path=ROOT/'development/build-r3/bundle.json';raw=path.read_bytes();self.bundle=json.loads(raw)
        assert self.bundle['status']=='PASS'
        self.exe=Path(self.bundle['executable']['path']);exe=self.exe.read_bytes()
        assert sha256(exe).hexdigest()==self.bundle['executable']['sha256']
        self.pins={path:raw,self.exe:exe,Path(script):Path(script).read_bytes(),Path(__file__):Path(__file__).read_bytes()}
        for row in self.bundle['components'].values():
            for key,hashkey in [('source_path','source_sha256'),('expected_source_path','source_sha256'),('image_path','image_sha256')]:
                p=Path(row[key]);raw=p.read_bytes();assert sha256(raw).hexdigest()==row[hashkey]
                if p in self.pins:assert self.pins[p]==raw
                self.pins[p]=raw
        frozen=ROOT/'checkpoints/importer-source-r3/source.json'
        self.pins[frozen]=frozen.read_bytes()
        for name,row in json.loads(self.pins[frozen])['files'].items():
            p=ROOT/name;raw=p.read_bytes();assert len(raw)==row['bytes'] and sha256(raw).hexdigest()==row['sha256']
            self.pins[p]=raw
        for p in (BASE/'hepta').glob('*.py'):self.pins[p]=p.read_bytes()
        (self.dest/'source-before.json').write_text(json.dumps({str(p):{'bytes':len(raw),'sha256':sha256(raw).hexdigest()} for p,raw in self.pins.items()},indent=2,sort_keys=True)+'\n')
        self.rows=[];self.started=time.monotonic_ns()

    def run(self, label, wire, *, expected_stage=None, timeout=180):
        folder=self.dest/label;folder.mkdir()
        (folder/'input.json.gz').write_bytes(gzip.compress(wire,compresslevel=1,mtime=0))
        expected=None
        try:
            imported,report=import_legacy_composite_v2(wire)
            expected=compact({'core':imported.as_dict(),'report':report,'structured':json.loads(imported.structured_bytes)})
            oracle={'accepted':True,'bytes':len(expected),'sha256':sha256(expected).hexdigest(),
                'core_sha256':imported.sha256,'input_sha256':imported.input_sha256}
            (folder/'expected.json.gz').write_bytes(gzip.compress(expected,compresslevel=1,mtime=0))
        except HIAProgramRejected as exc:
            oracle={'accepted':False,'code':exc.code,'error':str(exc)}
        (folder/'oracle.json').write_text(json.dumps(oracle,indent=2)+'\n')
        started=time.monotonic_ns();usage=resource.getrusage(resource.RUSAGE_CHILDREN)
        try:
            process=subprocess.run([str(self.exe)],input=wire,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                cwd=self.empty,env={'PATH':str(self.empty),'HOME':str(self.empty),'LANG':'C'},preexec_fn=limits,timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            (folder/'timeout.stdout').write_bytes(exc.stdout or b'');(folder/'timeout.stderr').write_bytes(exc.stderr or b'')
            (folder/'timeout.json').write_text(json.dumps({'timeout_seconds':timeout,'wall_ns':time.monotonic_ns()-started,'error':str(exc)},indent=2)+'\n')
            raise
        after=resource.getrusage(resource.RUSAGE_CHILDREN)
        (folder/'stdout.bin.gz').write_bytes(gzip.compress(process.stdout,compresslevel=1,mtime=0))
        (folder/'stderr.bin').write_bytes(process.stderr)
        row={'case':label,'input_bytes':len(wire),'input_sha256':sha256(wire).hexdigest(),'oracle':oracle,
            'returncode':process.returncode,'stdout_bytes':len(process.stdout),'stdout_sha256':sha256(process.stdout).hexdigest(),
            'stderr_bytes':len(process.stderr),'stderr_sha256':sha256(process.stderr).hexdigest(),
            'wall_ns':time.monotonic_ns()-started,'user_cpu_seconds':after.ru_utime-usage.ru_utime,
            'system_cpu_seconds':after.ru_stime-usage.ru_stime,'development_timeout_seconds':timeout}
        if len(process.stderr)%8==0:row['stderr_words']=list(struct.unpack('<'+'Q'*(len(process.stderr)//8),process.stderr))
        (folder/'actual.json').write_text(json.dumps(row,indent=2)+'\n')
        if expected is not None:
            assert process.returncode==0 and process.stderr==b'' and process.stdout==expected,row
            actual=json.loads(process.stdout)
            assert actual['core']['schema']=='hepta.hia.program.v6'
            assert actual['structured']['schema']=='hepta.hia.composite.v1'
            assert actual['report']['claims']['producer_source_authenticated'] is False
        else:
            assert process.returncode==2 and process.stdout==b'' and len(process.stderr)==128,row
            frame=struct.unpack('<16Q',process.stderr)
            assert diagnosis(frame)==oracle['code'],(row,diagnosis(frame))
            if expected_stage is not None:assert tuple(frame[4:6])==tuple(expected_stage),(row,expected_stage)
        row['status']='PASS';self.rows.append(row)
        (folder/'result.json').write_text(json.dumps(row,indent=2)+'\n')
        print(json.dumps(row,sort_keys=True),flush=True)
        return row

    def close(self,error=None):
        assert all(p.read_bytes()==raw for p,raw in self.pins.items())
        result={'scope':'COMPLETE_PUBLIC_HISTORICAL_IMPORTER_FIXED_NATIVE_ELF_DEVELOPMENT',
            'status':'PASS' if error is None else 'FAIL','cases_completed':len(self.rows),'results':self.rows,
            'all_source_and_image_pins_unchanged':True,'retained_child_runtime':False,
            'strace_observed':False,'original_cold_compiler_language_limits_unchanged':True,
            'whole_stack_closed':False,'wall_ns':time.monotonic_ns()-self.started}
        if error is not None:result.update(error_class=type(error).__name__,error=str(error))
        (self.dest/'summary.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
        print(json.dumps({k:v for k,v in result.items() if k!='results'},sort_keys=True),flush=True)
