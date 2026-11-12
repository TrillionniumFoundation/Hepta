"""Independent old native builders and actual immutable installed rebuild.

This is a development oracle. Revision 3 resumes the immutable installed release
from the retained first-run evidence-directory collision; it does not relabel
that failed run or repeat the already completed native builders/installation.
 No Python below runs inside the produced ELF.
Every child result is retained, including a first failing assertion.
"""
from pathlib import Path
from hashlib import sha256
import json, os, resource, signal, stat, struct, subprocess, sys, time, traceback

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT.parent / 'Hepta-v67-workflow-qualified'
sys.path.insert(0, str(BASE))
from tools.build_hia_agent_stdio import build as old_stdio_build
from tools.build_hia_release_install import build as old_release_build
from tools.build_hia_json_preflight import current_sources
from hepta.hia_agent_assembly import assemble_program
from tools.qualify_hia_selfhost import invoke

OUT = ROOT/'development/installed-chain-r3'
OUT.mkdir(mode=0o700)
COMPILER = ROOT.parent/'hia-v67-0ef-qualification-local-01/cold.cold/qualification.evidence/B3.image.bin'
COLD = ROOT.parent/'hia-v67-0ef-qualification-local-01/cold.json'
PACKAGE = ROOT/'development/native-whole-r2/package.raw'
BUILDER = ROOT/'development/native-build-r2/hia-build'
pins = {p:p.read_bytes() for p in (Path(__file__), COMPILER, COLD, PACKAGE, BUILDER)}
source_before = current_sources()
(OUT/'source-before.json').write_text(json.dumps(source_before,indent=2,sort_keys=True)+'\n')
(OUT/'pins-before.json').write_text(json.dumps({str(p):{'bytes':len(b),'sha256':sha256(b).hexdigest()} for p,b in pins.items()},indent=2,sort_keys=True)+'\n')
start = time.monotonic_ns()
summary = {'status':'INCOMPLETE','scope':'DEVELOPMENT_NOT_NEW_MATCHING_SOURCE_COLD', 'calls':[]}

def unpack(raw):
    magic,count,reserved=struct.unpack_from('<3Q',raw)
    assert magic==int.from_bytes(b'HIAREL01','little') and reserved==0
    result={};at=24
    for _ in range(count):
        n,mode,size=struct.unpack_from('<3Q',raw,at);at+=24
        name=raw[at:at+n].decode('ascii');at+=n
        payload=raw[at:at+size];at+=size
        assert name not in result and len(payload)==size
        result[name]=(mode,payload)
    assert at==len(raw)
    return result

def run(label, executable, args, raw=b'', expected=0, timeout=120):
    folder=OUT/label;folder.mkdir()
    (folder/'input.raw').write_bytes(raw)
    request={'executable':str(executable),'executable_sha256':sha256(executable.read_bytes()).hexdigest(),
             'argv':list(args),'input_bytes':len(raw),'input_sha256':sha256(raw).hexdigest(),
             'environment':{'PATH':'','HOME':str(OUT)},'timeout_seconds':timeout}
    (folder/'request.json').write_text(json.dumps(request,indent=2,sort_keys=True)+'\n')
    then=time.monotonic_ns()
    p=subprocess.run([str(executable),*args],input=raw,capture_output=True,
                     env=request['environment'],timeout=timeout)
    (folder/'stdout.raw').write_bytes(p.stdout);(folder/'stderr.raw').write_bytes(p.stderr)
    record={'case':label,'returncode':p.returncode,'elapsed_ns':time.monotonic_ns()-then,
            'stdout_bytes':len(p.stdout),'stdout_sha256':sha256(p.stdout).hexdigest(),
            'stderr_bytes':len(p.stderr),'stderr_sha256':sha256(p.stderr).hexdigest()}
    (folder/'result.json').write_text(json.dumps(record,indent=2,sort_keys=True)+'\n')
    summary['calls'].append(record)
    if expected is not None: assert p.returncode==expected, (label,p.returncode,p.stderr[:512])
    return p

try:
    files=unpack(pins[PACKAGE]);assert len(files)==6
    previous=ROOT/'development/installed-chain-r1'
    previous_summary=json.loads((previous/'summary.json').read_bytes())
    assert previous_summary['status']=='FAIL' and previous_summary['error_class']=='FileExistsError'
    assert previous_summary['all_pins_unchanged'] and previous_summary['source_closure_unchanged']
    old_stdio=previous/'reference-stdio/hia-native'
    old_release=previous/'reference-release/hia-release'
    assert old_stdio.read_bytes()==files['hia'][1]
    assert old_release.read_bytes()==files['hia-release'][1]
    pins[old_stdio]=old_stdio.read_bytes();pins[old_release]=old_release.read_bytes()
    summary['prior_run']=str(previous/'summary.json')
    summary['prior_run_status']='FAIL_TEST_EVIDENCE_DIRECTORY_COLLISION_AFTER_INSTALL'
    summary['independent_native_builder_byte_equality']=previous_summary['independent_native_builder_byte_equality']
    digest=sha256(pins[PACKAGE]).hexdigest()
    target=previous/'releases';installed=target/digest
    assert stat.S_IMODE(installed.stat().st_mode)==0o500
    # The unchanged installer deliberately retains a sealed failed stage on
    # no-replace refusal. Validate that complete stage; do not delete it or
    # reinterpret it as a published release.
    retained=[]
    for q in target.iterdir():
        if q.name==digest: continue
        assert q.name.startswith('.hia-stage-') and len(q.name)==43
        assert all(c in '0123456789abcdef' for c in q.name[11:])
        assert stat.S_IMODE(q.stat().st_mode)==0o500
        assert sorted(x.name for x in q.iterdir())==sorted(files)
        for name,(mode,payload) in files.items():
            x=q/name
            assert x.read_bytes()==payload and stat.S_IMODE(x.stat().st_mode)==mode and x.stat().st_nlink==1
        retained.append({'path':str(q),'published':False,'complete_package_contents_equal':True})
    assert len(retained)==1
    summary['retained_failed_stage']=retained
    summary['prior_resume_attempt']=str(ROOT/'development/installed-chain-r2/summary.json')
    summary['actual_install_no_replace_and_verify_evidence']=str(previous)
    inventory={}
    for name,(mode,raw) in files.items():
        path=installed/name;st=path.lstat()
        assert stat.S_ISREG(st.st_mode) and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==mode
        assert path.read_bytes()==raw
        inventory[name]={'bytes':len(raw),'sha256':sha256(raw).hexdigest(),'mode':mode,'inode':st.st_ino}
    summary['installed_inventory']=inventory
    assembly=(BASE/'examples/hia_bootstrap/bytesum.hiaasm').read_bytes()
    core=json.dumps(assemble_program(assembly).as_dict(),separators=(',',':')).encode()
    cases=[('capabilities',['capabilities'],b'not JSON'),('verify',['verify'],core),
           ('compile',['compile'],core),('render',['render-assembly'],core),('assemble',['assemble'],assembly),
           ('empty-argv',[],b''),('bad-argv',['capabilities','extra'],b''),
           ('bad-json-verify',['verify'],b'{'),('bad-json-compile',['compile'],b'{'),
           ('bad-json-render',['render-assembly'],b'{'),('bad-asm',['assemble'],b'not assembly\n')]
    products={}
    for label,args,raw in cases:
        old=run('old-stdio-'+label,old_stdio,args,raw,expected=None,timeout=20)
        new=run('installed-stdio-'+label,installed/'hia',args,raw,expected=None,timeout=20)
        assert (old.returncode,old.stdout,old.stderr)==(new.returncode,new.stdout,new.stderr),label
        products[label]=new
    assert products['compile'].returncode==0 and products['compile'].stdout==products['assemble'].stdout
    compiled=OUT/'actual-installed-compiled.image.bin';compiled.write_bytes(products['compile'].stdout)
    native_result,_=invoke(OUT,'actual-installed-product',compiled,b'installed-native',capacity=1,workspace_size=1)
    expected=5381
    for byte in b'installed-native':expected=((expected*33)^byte)&0xffffffff
    assert native_result['status']=='returned' and native_result['core_u32']==expected
    summary['complete_stdio_cases']=len(cases)
    summary['actual_installed_compiled_result']=native_result

    # Rebuild from only the installed readonly bootstrap and installed kit.
    # This checks reproducibility; the bootstrap executable itself is retained.
    folder=OUT/'installed-rebuild';folder.mkdir()
    kit=installed/'source-kit.hiabuild';kit_digest=sha256(kit.read_bytes()).hexdigest()
    request={'executable':str(installed/'hia-build'),'argv':[kit_digest],'stdin':str(kit),
             'stdin_sha256':kit_digest,'environment':{'PATH':'','HOME':str(OUT)},
             'limits':{'cpu_seconds':120,'address_bytes':1<<30,'wall_seconds':150}}
    (folder/'request.json').write_text(json.dumps(request,indent=2,sort_keys=True)+'\n')
    def limit():
        resource.setrlimit(resource.RLIMIT_CPU,(120,120));resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    def alarm(signum,frame):raise TimeoutError('installed native build')
    child=None;then=time.monotonic_ns()
    try:
        with kit.open('rb') as source,(folder/'package.raw').open('xb') as dst,(folder/'terminal.raw').open('xb') as err:
            child=subprocess.Popen([str(installed/'hia-build'),kit_digest],stdin=source,stdout=dst,stderr=err,
                                   env=request['environment'],preexec_fn=limit,start_new_session=True)
            signal.signal(signal.SIGALRM,alarm);signal.alarm(150)
            pid,status,usage=os.wait4(child.pid,0);signal.alarm(0);child.returncode=os.waitstatus_to_exitcode(status)
        output=(folder/'package.raw').read_bytes();terminal=(folder/'terminal.raw').read_bytes()
        record={'case':'installed-rebuild','returncode':child.returncode,'elapsed_ns':time.monotonic_ns()-then,
                'output_bytes':len(output),'output_sha256':sha256(output).hexdigest(),'terminal_hex':terminal.hex(),
                'wait4':{'status':status,'user_seconds':usage.ru_utime,'system_seconds':usage.ru_stime,'maxrss_kib':usage.ru_maxrss}}
        (folder/'result.json').write_text(json.dumps(record,indent=2,sort_keys=True)+'\n');summary['calls'].append(record)
        assert child.returncode==0 and output==pins[PACKAGE]
        assert len(terminal)==128 and terminal[96:128]==sha256(output).digest()
        summary['installed_rebuild_complete_package_equal']=True
    finally:
        signal.alarm(0)
        if child is not None and child.returncode is None:
            os.killpg(child.pid,signal.SIGKILL);_,status,_=os.wait4(child.pid,0);child.returncode=os.waitstatus_to_exitcode(status)
    for name,(mode,raw) in files.items():
        path=installed/name;assert path.read_bytes()==raw and stat.S_IMODE(path.stat().st_mode)==mode
    summary['status']='PASS'
except BaseException as exc:
    summary.update(status='FAIL',error_class=type(exc).__name__,error=str(exc));traceback.print_exc();raise
finally:
    source_after=current_sources();(OUT/'source-after.json').write_text(json.dumps(source_after,indent=2,sort_keys=True)+'\n')
    summary['all_pins_unchanged']=all(p.read_bytes()==raw for p,raw in pins.items())
    summary['source_closure_unchanged']=source_before==source_after
    summary['elapsed_ns']=time.monotonic_ns()-start
    (OUT/'summary.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n')
    print(json.dumps({k:v for k,v in summary.items() if k not in ('calls','actual_installed_compiled_result')},sort_keys=True),flush=True)
    assert summary['all_pins_unchanged'] and summary['source_closure_unchanged']
