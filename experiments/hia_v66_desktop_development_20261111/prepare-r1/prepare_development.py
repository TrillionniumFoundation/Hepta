"""Prepare independent development sources; never run qualification or product tests."""
from __future__ import annotations
from hashlib import sha256
import importlib
import importlib.metadata
import json
import os
from pathlib import Path
import stat
import sys
import workflow_process

ROOT=Path('/home/qian-qi/he26v66devr1')
SOURCE=ROOT/'s'
BORROW=Path('/home/qian-qi/he26v65r2/s')
CONTROL=ROOT/'control'
LOGS=ROOT/'preparation-logs'
HEAD='e09c6faf5507fc4e38d8b7c36ba2650a1c0a10d6'
TREE='bfcbb39e22371cbb2292c89a2fa1ca010353a56f'
BASE='4161e8d12d87906fde144f039da07908ad52d98a'
BASE_TREE='1c6ab0228f012429149997d1f731833739f433eb'
ORIGIN='https://github.com/TrillionniumFoundation/Hepta.git'
PYTHON=Path('/home/qian-qi/hia-e26e-python314-linux-r1/venv/bin/python')
B3=Path('/home/qian-qi/he26v65r2/q/cold.cold/qualification.evidence/B3.image.bin')
B3_SHA='0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8'
OLD=json.loads((CONTROL/'old-input-pins.json').read_bytes())
ENV={k:v for k,v in os.environ.items() if not k.startswith(('GIT_','PYTHON','HEPTA_','HIA_TEST_'))}
ENV.update(PYTHONDONTWRITEBYTECODE='1',PYTHONUNBUFFERED='1',GIT_OPTIONAL_LOCKS='0',
           GIT_TERMINAL_PROMPT='0',GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null',
           GIT_CONFIG_SYSTEM='/dev/null')
GIT=['git','-c','core.hooksPath=/dev/null','-c','gc.auto=0','-c','maintenance.auto=false']
report={'schema':'hia.desktop-independent-development-preparation.v1',
        'status':'PREPARATION_HOLD','root':str(ROOT),'source':str(SOURCE),
        'head':HEAD,'tree':TREE,'steps':[],
        'qualification_requested':False,'tests_requested':False,
        'cold_180_second_gate_modified':False,'whole_native_delivery_qualified':False,
        'base_scope':'published source is held read-only; candidate clones are independently writable',
        'recovery_scope':'NEW_REMOTE_CANDIDATE_NOT_ORIGINAL_LOCAL_R7_RECOVERY',
        'outer_guardian_acceptance_required':True,
        'outer_acceptance':'EXTERNAL_OWNED_PROCESS_COMPLETED; identities preserved; ECHILD; leader reaped; no signals/errors/overflow/owned_child_sigkill'}

def require(value,message):
    if not value:raise RuntimeError(message)

def digest(path):
    return sha256(Path(path).read_bytes()).hexdigest()

def regular(path,expected):
    p=Path(path);before=p.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_uid==os.geteuid() and before.st_nlink==1,
            'non-private regular input: '+str(p))
    value=digest(p);after=p.stat()
    require((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)
            ==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
            and value==expected,'input identity changed: '+str(p))
    return {'path':str(p),'bytes':before.st_size,'sha256':value,
            'mode':oct(before.st_mode),'uid':before.st_uid,'nlink':before.st_nlink}

def old_pins():
    return [regular(p,h) for p,h in OLD.items()]

def sync_directory(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)

def save():
    p=ROOT/'preparation.next.json'
    raw=(json.dumps(report,indent=2,sort_keys=True)+'\n').encode()
    with p.open('wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    os.replace(p,ROOT/'preparation.json');sync_directory(ROOT)

def run(label,args,seconds=60):
    print(json.dumps({'stage':'DEVELOPMENT_PREPARATION','step':label}),flush=True)
    out,err,receipt=[LOGS/(label+s)for s in ('.stdout.log','.stderr.log','.owner.json')]
    result=workflow_process.run_workflow_step(list(map(str,args)),cwd=ROOT,env=ENV,
                  stdout_path=out,stderr_path=err,receipt_path=receipt,seconds=seconds)
    for p in (out,err,receipt):
        with p.open('rb')as f:os.fsync(f.fileno())
    sync_directory(LOGS)
    report['steps'].append({'name':label,'receipt':str(receipt),'sha256':digest(receipt),
                            'status':result['status']});save()
    require(result['status']=='WORKFLOW_STEP_COMPLETED','owned step failed: '+label)
    return out.read_bytes()

def git_identity(path,label,head,tree):
    actual=run(label+'-head',GIT+['-C',path,'rev-parse','HEAD']).decode().strip()
    actual_tree=run(label+'-tree',GIT+['-C',path,'rev-parse','HEAD^{tree}']).decode().strip()
    clean=run(label+'-clean',GIT+['-C',path,'status','--porcelain','--untracked-files=all'])
    require(actual==head and actual_tree==tree and clean==b'','Git source identity differs: '+str(path))
    return {'path':str(path),'head':actual,'tree':actual_tree,'clean':True}

def object_custody(path):
    git=path/'.git';require(git.is_dir()and not git.is_symlink(),'independent .git directory missing')
    require(not (git/'objects/info/alternates').exists(),'object alternates are forbidden')
    count=0
    for directory,subdirs,files in os.walk(git/'objects',followlinks=False):
        for name in subdirs:require(not (Path(directory)/name).is_symlink(),'object symlink')
        for name in files:
            p=Path(directory)/name;s=p.lstat()
            require(stat.S_ISREG(s.st_mode)and s.st_uid==os.geteuid()and s.st_nlink==1,
                    'shared or special Git object: '+str(p))
            require(not name.endswith('.promisor'),'promisor objects are forbidden')
            count+=1
    config=(git/'config').read_text()
    require('promisor' not in config.lower() and 'partialclonefilter' not in config.lower(),
            'partial object source is forbidden')
    return {'object_files':count,'hardlinks':False,'alternates':False,'promisor':False}

def seal_source(path):
    count=0
    for directory,subdirs,files in os.walk(path,topdown=False,followlinks=False):
        for name in files:
            p=Path(directory)/name;s=p.lstat()
            require(stat.S_ISREG(s.st_mode),'published base contains special file: '+str(p))
            os.chmod(p,stat.S_IMODE(s.st_mode)&~0o222);count+=1
        for name in subdirs:
            p=Path(directory)/name;require(not p.is_symlink(),'published base contains directory symlink')
            os.chmod(p,0o500)
    os.chmod(path,0o500)
    return {'files_made_read_only':count,'directories_mode':'0500','contents_unchanged':True}

try:
    require(Path(sys.executable).resolve()==PYTHON.resolve(),'wrong Python executable')
    require(digest(PYTHON)=='b2d6bc2ad950753c5ea407a30788165d8f59c110ca4e90fbad14c8c75376a493','Python pin differs')
    require(not any(os.path.lexists(p)for p in (SOURCE,ROOT/'wire-r7/s',ROOT/'cli/s')),'source destination exists')
    report['old_inputs_before']=old_pins()
    report['compiler_original_before']=regular(B3,B3_SHA)
    report['compiler_copy']=regular(ROOT/'inputs/B3.image.bin',B3_SHA)
    expected={'z3-solver':'4.15.4.0','jsonschema':'4.25.1','setuptools':'78.1.1','wheel':'0.46.3','zstandard':'0.25.0'}
    dependencies={}
    for module,distribution in [('z3','z3-solver'),('jsonschema','jsonschema'),('setuptools','setuptools'),('wheel','wheel'),('zstandard','zstandard')]:
        imported=importlib.import_module(module);version=importlib.metadata.version(distribution)
        require(version==expected[distribution],'dependency version differs: '+distribution)
        dependencies[distribution]={'version':version,'imported':True,'file':getattr(imported,'__file__',None)}
    report['python']={'executable':str(PYTHON),'version':sys.version,'sha256':digest(PYTHON)}
    report['dependencies']=dependencies
    report['borrow_before']=git_identity(BORROW,'borrow-before',BASE,BASE_TREE)
    run('independent-base-clone',GIT+['clone','--local','--no-hardlinks','--no-checkout',BORROW,SOURCE],seconds=240)
    run('single-exact-depth1-fetch',GIT+['-C',SOURCE,'fetch','--no-tags','--no-recurse-submodules','--depth','1',ORIGIN,HEAD],seconds=900)
    run('base-detached-checkout',GIT+['-C',SOURCE,'checkout','--detach',HEAD],seconds=180)
    report['published_source']=git_identity(SOURCE,'published-source',HEAD,TREE)
    report['published_object_custody']=object_custody(SOURCE)
    run('base-connectivity',GIT+['-C',SOURCE,'fsck','--connectivity-only'],seconds=180)
    report['candidate_sources']={}
    for name in ('wire-r7','cli'):
        target=ROOT/name/'s'
        run(name+'-independent-clone',GIT+['clone','--local','--no-hardlinks','--no-checkout',SOURCE,target],seconds=240)
        run(name+'-detached-checkout',GIT+['-C',target,'checkout','--detach',HEAD],seconds=180)
        report['candidate_sources'][name]=git_identity(target,name+'-source',HEAD,TREE)
        report['candidate_sources'][name]['objects']=object_custody(target)
    report['published_source_read_only']=seal_source(SOURCE)
    report['published_source_after_seal']=git_identity(SOURCE,'published-after-seal',HEAD,TREE)
    report['borrow_after']=git_identity(BORROW,'borrow-after',BASE,BASE_TREE)
    report['old_inputs_after']=old_pins()
    report['compiler_original_after']=regular(B3,B3_SHA)
    require(report['old_inputs_before']==report['old_inputs_after'],'old input facts changed')
    require(report['compiler_original_before']==report['compiler_original_after'],'old compiler facts changed')
    nested=ROOT.parent/'he26v65r2/q/cold.cold/qualification.json'
    report['old_nested_report_stat']={'path':str(nested),'exists':nested.exists()}
    if nested.exists():report['old_nested_report_stat'].update(bytes=nested.stat().st_size,regular=nested.is_file())
    report['old_nested_report_prior_wording_correction']='Earlier empty bounded read did not establish absence; this stat is the observation.'
    report['source_contract_observed']={'path':str(SOURCE/'docs/HIA_SELFHOST_CORE_SUPPORT.json'),'sha256':digest(SOURCE/'docs/HIA_SELFHOST_CORE_SUPPORT.json'),'qualified_or_current_pin_closure_claimed':False}
    report['status']='DEVELOPMENT_SOURCE_PREPARED_PENDING_OUTER_GUARDIAN'
    save()
    print(json.dumps({'status':report['status'],'source':str(SOURCE),'wire_source':str(ROOT/'wire-r7/s'),'cli_source':str(ROOT/'cli/s'),'evidence':str(ROOT/'evidence')}),flush=True)
except BaseException as error:
    report.update(status='PREPARATION_HOLD',error_type=type(error).__name__,error=str(error))
    try:save()
    except BaseException:pass
    raise
