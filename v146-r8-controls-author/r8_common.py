"""Private retained-control bindings. Importing runs no project or product call."""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import stat
import sys

ROOT = Path(__file__).resolve().parent
PLAN = json.loads((ROOT / 'EXECUTION-PLAN.json').read_bytes())
SOURCE = Path(PLAN['source']['path'])
OUTPUT = Path(PLAN['output'])
SEMANTIC_SOURCE = Path(PLAN['fixed_inputs']['R8-source']['path'])
CAPACITY = 1048576
STAT_KEYS = ('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_nlink')
CURRENT_STAGE_OUT = None
VM_CALLS = 0
VM_OBSERVATION_ERRORS = []


def require(value, message):
    if not value:
        raise AssertionError(message)


def pin(raw, mode=None):
    value = {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
             'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
    if mode is not None:
        value.update(mode=mode,git_mode='100755' if mode & 0o111 else '100644')
    return value


def read_regular(path):
    path = Path(path)
    a = path.lstat()
    require(stat.S_ISREG(a.st_mode),'fixed file is not regular: '+str(path))
    fd = os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        require(all(getattr(os.fstat(fd),k)==getattr(a,k) for k in STAT_KEYS),'opened inode differs')
        with os.fdopen(fd,'rb',closefd=False) as stream:
            raw = stream.read(a.st_size+1)
        require(len(raw)==a.st_size and all(getattr(os.fstat(fd),k)==getattr(a,k)
                and getattr(path.lstat(),k)==getattr(a,k) for k in STAT_KEYS),'fixed file changed during read')
    finally:
        os.close(fd)
    return raw,stat.S_IMODE(a.st_mode),{k:getattr(a,k) for k in STAT_KEYS}


def write(path, raw, mode=0o644):
    path=Path(path)
    path.parent.mkdir(parents=True,exist_ok=True)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    with os.fdopen(fd,'wb') as stream:
        stream.write(raw)
    path.chmod(mode)
    observed,actual_mode,_=read_regular(path)
    require(observed==raw and actual_mode==mode,'new evidence differs')


def dump(path,value):
    write(path,(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode())


def input_bytes(name):
    row=PLAN['fixed_inputs'][name]
    raw,mode,_=read_regular(row['path'])
    match_identity(pin(raw,mode),row['identity'],'fixed input differs: '+name)
    return raw


def match_identity(actual, expected, message):
    # Some large retained oracle files were already pinned by the frozen
    # original report with SHA-256, length and mode but no Git object ID.
    # Always hash their full actual bytes now; never substitute a path/stat
    # check. The full newly observed Git identity is retained in the guard.
    required={'bytes','sha256','mode','git_mode'}
    require(type(expected)is dict and required <= set(expected)
            and set(expected) <= required|{'git_blob'},'invalid fixed identity schema')
    require(all(actual[k]==v for k,v in expected.items()),message)


def guards(stage):
    require(sys.executable==PLAN['runtime']['executable']['path'],'unexpected running interpreter path')
    require(tuple(sys.version_info[:3])==(3,14,4),'unexpected running interpreter version')
    controls={}
    for name,row in PLAN['controls'].items():
        raw,mode,stamp=read_regular(ROOT/name)
        require(pin(raw,mode)==row,'control bytes/mode differ: '+name)
        controls[name]={'identity':row,'stat':stamp}
    inputs={}
    for name,row in PLAN['fixed_inputs'].items():
        if '*' not in row['phases'] and stage not in row['phases']:
            continue
        raw,mode,stamp=read_regular(row['path'])
        actual=pin(raw,mode)
        match_identity(actual,row['identity'],'actual fixed input differs: '+name)
        inputs[name]={'identity':actual,'fixed_identity':row['identity'],'stat':stamp}
    runtime={}
    for name in ('executable','library'):
        row=PLAN['runtime'][name]
        raw,mode,stamp=read_regular(row['path'])
        require(pin(raw,mode)==row['identity'],'actual runtime differs: '+name)
        runtime[name]={'identity':row['identity'],'stat':stamp}
    return {'controls':controls,'inputs':inputs,'runtime':runtime}


def source_snapshot(path):
    expected=json.loads((ROOT/'FROZEN-3180-SOURCE.json').read_bytes())
    files,states={},{}
    for directory,dirs,names in os.walk(SOURCE,followlinks=False):
        dirs.sort()
        for name in dirs:
            require(stat.S_ISDIR((Path(directory)/name).lstat().st_mode),'source directory symlink')
        for name in sorted(names):
            p=Path(directory)/name
            relative=p.relative_to(SOURCE).as_posix()
            require(relative in expected,'unexpected source path: '+relative)
            raw,mode,stamp=read_regular(p)
            files[relative],states[relative]=pin(raw,mode),stamp
    require(files==expected and len(files)==3180,'full3180 source closure differs')
    result={'files':files,'inode_states':states,'tree':PLAN['source']['tree']}
    dump(path,result)
    return result


def component_source(name):
    if name=='examples/hia_bootstrap/file_render_checker_v4.hepta':
        return input_bytes('R8-source')
    require(name=='examples/hia_bootstrap/core_representation_private.hepta','unknown private component')
    return input_bytes('representation-source')


def original_observation_path(group, label):
    # Every key and path is explicitly pinned by the original CAS manifest.
    # There is no filesystem-existence test and no fallback to a different
    # source of evidence.
    return Path(PLAN['original_observation_paths'][group+'/'+label])


def source_program():
    path=ROOT/'inputs/R8-GENERATOR.py'
    raw,_,_=read_regular(path)
    require(pin(raw,0o644)==PLAN['controls']['inputs/R8-GENERATOR.py'],'R8 symbol author differs')
    original_path=PLAN['fixed_inputs']['R8-generator']['path']
    before_binding='ROOT = Path(__file__).resolve().parents[1]'
    after_binding='ROOT = Path('+repr(str(SOURCE))+')'
    text=raw.decode()
    require(text.count(before_binding)==1,'R8 symbol root preimage differs')
    projected=text.replace(before_binding,after_binding)
    require(projected.count(after_binding)==1
            and projected.replace(after_binding,before_binding)==text,'R8 symbol inverse differs')
    namespace={'__name__':'_retained_r8_symbol_author','__file__':original_path,'__package__':None}
    before=list(sys.path)
    try:
        # Its original function bodies are unchanged. Only its dependency
        # ROOT is explicitly the full frozen 3180-file source, so the symbol
        # diagnostic cannot silently import a second historical source tree.
        exec(compile(projected,original_path,'exec'),namespace)
        return namespace['source_program']()
    finally:
        sys.path[:]=before


def public_r5_refusal():
    from hepta import hia_linux_file_roundtrip as original
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import HIAProgramRejected
    expected=PLAN['public_component_pins']
    require(original.COMPONENT_PINS==expected,'public R5 authority differs')
    components=(component_source('examples/hia_bootstrap/core_representation_private.hepta'),
                component_source('examples/hia_bootstrap/file_render_checker_v4.hepta'))
    program=assemble_program(read_regular(SOURCE/'examples/hia_bootstrap/native_file_roundtrip.hepta')[0],
                             profile=original.PROFILE)
    effects=[]
    def no_effect(request):
        effects.append(request.operation)
        raise AssertionError('the public R5 refusal unexpectedly reached execution')
    try:
        original.execute_linux_file_roundtrip(program,'f0',(b'',b'',b''),provider=no_effect,
            startup=original.LinuxStartupSnapshot((b'hia-native-file-roundtrip',),(b'LC_ALL=C.UTF-8',)),
            components=components)
    except HIAProgramRejected as error:
        require(error.code=='E_HIA_LINUX_FILE_ROUNDTRIP_COMPONENT','wrong public refusal')
        require(effects==[],'a refused public component reached a provider')
        record={'status':'EXPECTED_PUBLIC_R5_REFUSAL','error_code':error.code,
                'entry':'unmodified execute_linux_file_roundtrip, including real controller/startup checks',
                'provider_calls':0,'VM_execution_reached':False,
                'private_reference_qualification':False,'public_profile_pass':False}
    else:
        raise AssertionError('the untouched public R5 entry accepted R8')
    require(original.COMPONENT_PINS==expected,'public R5 authority mutated')
    return record


def prepare_context():
    require(not OUTPUT.exists(),'one-shot output already exists; never automatically retry')
    free=os.statvfs(OUTPUT.parent).f_bavail*os.statvfs(OUTPUT.parent).f_frsize
    require(free>=PLAN['minimum_free_bytes'],'insufficient storage before any product')
    require(tuple(sys.version_info[:3])==(3,14,4),'actual314 required')
    restore_plan=json.loads(read_regular(ROOT/'ORACLE-RESTORE-PLAN.json')[0])
    restored=json.loads(read_regular(Path(restore_plan['destination'])/'RESTORE-RESULT.json')[0])
    require(restored['status']=='PASS_EXACT_ORIGINAL_ORACLES_ONLY'
            and restored['plan_sha256']==restore_plan['authorization_pin']
            and restored['restored_files']==136 and restored['restored_logical_bytes']==578353224
            and restored['full_archive_stream_readback'] is True
            and restored['product_executions']==0,'exact original oracle restore is incomplete')
    restore_owner=json.loads(read_regular(Path(restore_plan['destination']+'.owner')/'OWNER-RETURNED.json')[0])
    require(restore_owner['status']=='OWNED_PROCESS_COMPLETED' and restore_owner['returncode']==0
            and restore_owner['qualification_seconds']==180 and restore_owner['cleanup_seconds']==3
            and restore_owner['cleanup']['complete'] is True
            and restore_owner['cleanup']['observed_echild'] is True
            and restore_owner['timed_out'] is False,'oracle restoration owner is incomplete')
    restore_final=json.loads(read_regular(Path(restore_plan['destination']+'.owner')/'FINAL.json')[0])
    require(restore_final['owner']==restore_owner and restore_final['complete_source_equal'] is True
            and restore_final['bindings_equal'] is True and restore_final['product_executions']==0,
            'oracle restoration parent source or bindings did not complete')
    owner=json.loads((ROOT/'inputs/R8-OWNER.json').read_bytes())
    require(owner['status']=='OWNED_PROCESS_COMPLETED' and owner['returncode']==0
            and owner['qualification_seconds']==180 and owner['cleanup_seconds']==3
            and owner['cleanup']['complete'] is True and owner['cleanup']['observed_echild'] is True
            and not owner['timed_out'],'actual R8 owner is incomplete')
    original=json.loads((ROOT/'inputs/R8-RESULT.json').read_bytes())
    require(original['status']=='PASS_EXPLICIT_U32_SIZE_AND_PRIVATE_PACK_ONLY'
            and original['compile_calls_attempted']==original['pack_calls_attempted']==1
            and original['semantic_native_cases']==original['semantic_vm_cases']==original['ELF_exec_calls']==0,
            'wrong actual predecessor scope')
    OUTPUT.mkdir(mode=0o700)
    for relative in ('semantic/evidence/compact-build-r1','aggregate/successor-r2/evidence/build-r2'):
        folder=OUTPUT/relative
        for name in ('REPORT.json','OUTER.json','SOURCE-AFTER.json'):
            write(folder/name,read_regular(ROOT/'fixtures'/name)[0])
        write(folder/'checker.image.bin',input_bytes('R8-image'))
    built=OUTPUT/'aggregate/successor-r2/evidence/build-r2/built'
    for name,role in (('controller','controller-image'),('representation','representation-image'),('semantic','R8-image')):
        write(built/(name+'.image.bin'),input_bytes(role))
    write(built/'private-R8.elf',input_bytes('R8-elf'),0o500)
    write(OUTPUT/'aggregate/evidence/build-r3/roundtrip-profile-compiler.image.bin',input_bytes('profile-compiler'))
    dump(OUTPUT/'FIXTURE-PROVENANCE.json',{'schema':'hepta.r8.actual-input-view-materialization.v1',
         'status':'INPUTS_MATERIALIZED_NOT_TESTED','source_result':PLAN['fixed_inputs']['R8-result'],
         'new_compile_or_pack':False,'new_cold':False,'ordinary_admission':False,
         'actual_original_ELF_mode_unchanged':True,'independent_executable_copy_mode':0o500,
         'oracle_restore_result':pin(read_regular(Path(restore_plan['destination'])/'RESTORE-RESULT.json')[0]),
         'input_view_status_meaning':'admission of actual completed size/pack only',
         'native_semantic_cases':0,'VM_cases':0})


def validate_native_frames(stage_out, stage):
    """Retain complete six logical frames without a second after-buffer copy."""
    rows=[]
    pool=OUTPUT/'initial-buffers'
    for request_path in sorted(Path(stage_out).rglob('request.json')):
        if request_path.parent.name!='native':
            continue
        request=json.loads(read_regular(request_path)[0])
        if request.get('schema')!='hia.linux-stdio.native-request.v1':
            continue
        folder=request_path.parent.parent
        if stage=='native162':
            initial=(read_regular(folder/'INPUT.hepta')[0],
                     read_regular(folder.parent/'OUTPUT-PREIMAGE.bin')[0],
                     read_regular(folder.parent/'WORKSPACE-PREIMAGE.bin')[0])
        elif stage=='semantic-edge-vm':
            initial=tuple(input_bytes(name) for name in ('edge-source','edge-output','edge-workspace'))
        else:
            raise AssertionError('unexpected native-frame stage')
        observation_path=request_path.parent/'OBSERVATION.json'
        observed=json.loads(read_regular(observation_path)[0]) if observation_path.exists() else None
        spans=[]
        for label,value,item in zip(('source','output','workspace'),initial,request['buffers'],strict=True):
            # The plan binds the retained observer's exact D3*64 literal.
            guard=bytes.fromhex(PLAN['native_guard_hex'])
            require(item['extent']==len(value) and item['bytes']==len(value)+128
                    and item['sha256']==pin(guard+value+guard)['sha256'],'actual native preimage differs')
            target=pool/pin(value)['sha256']
            if not target.exists():
                write(target,value)
            require(read_regular(target)[0]==value,'initial CAS collision')
            after,mode,_=read_regular(item['path'])
            require(len(after)==item['bytes'],'partial native physical span')
            payload=after[64:64+len(value)]
            if observed is not None:
                require(payload.hex()==observed[label+'_hex'],'native hex and actual shared span differ')
            spans.append({'name':label,'before':{'path':str(target),**pin(value)},
                          'after':{'path':item['path'],'offset':64,'extent':len(value),**pin(payload)},
                          'physical':pin(after,mode),'guard_ends':[after[:64]==guard,after[-64:]==guard]})
        rows.append({'request':str(request_path),'request_identity':pin(read_regular(request_path)[0]),
                     'observation_present':observed is not None,'complete_six_logical_buffers':True,'buffers':spans})
    dump(Path(stage_out)/'SIX-BUFFER-READBACK.json',{'stage':stage,'rows':rows,'calls':len(rows),
        'no_additional_product_execution':True,'partial_or_failed_observations_are_not_success':True})
    return len(rows)


def capture_private_vm(arguments, result, error):
    """Observe the actual immutable arguments and returned or raised VM report.

    This runs after the unchanged checked/execute path. It neither changes the
    report object nor executes a second VM. On a pre-execution rejection the
    absent after buffers remain explicitly absent.
    """
    global VM_CALLS
    require(CURRENT_STAGE_OUT is not None,'private VM observation has no phase')
    index=VM_CALLS;VM_CALLS+=1
    folder=Path(CURRENT_STAGE_OUT)/'private-reference-frames'/('%04d'%index)
    pool=OUTPUT/'VM-buffer-pool'
    report=result if type(result)is dict else getattr(error,'report',None)
    rows={}
    if type(arguments)in (tuple,list) and len(arguments)==3 and all(type(x)is bytes for x in arguments):
        for name,value in zip(('file','output','workspace'),arguments,strict=True):
            path=pool/pin(value)['sha256']
            if not path.exists():write(path,value)
            require(read_regular(path)[0]==value,'VM before CAS differs')
            rows[name+'.before']={'path':str(path),**pin(value)}
    if type(report)is dict:
        for name,key in (('file','source_hex'),('output','output_hex'),('workspace','workspace_hex')):
            if key not in report:continue
            require(type(report[key])is str,'VM after frame must be actual hex')
            value=bytes.fromhex(report[key]);path=pool/pin(value)['sha256']
            if not path.exists():write(path,value)
            require(read_regular(path)[0]==value,'VM after CAS differs')
            rows[name+'.after']={'path':str(path),**pin(value)}
    dump(folder/'FRAMES.json',{'index':index,'complete_six_buffers':len(rows)==6,'frames':rows,
         'status':report.get('status') if type(report)is dict else None,
         'steps':report.get('steps') if type(report)is dict else None,
         'original_error_type':None if error is None else type(error).__name__,
         'private_reference_only':True,'public_R5_admission':False,'VM_rerun':False})
    if type(report)is dict:
        require(len(rows)==6,'returned or raised VM report omitted an actual full buffer')


def observe_private_vm(arguments, result, error):
    """Keep an original raised exception primary, but fail incomplete custody."""
    try:
        capture_private_vm(arguments,result,error)
    except BaseException as observation_error:
        import traceback
        VM_OBSERVATION_ERRORS.append({'type':type(observation_error).__name__,
            'traceback':traceback.format_exc(),
            'original_error_type':None if error is None else type(error).__name__})
        if error is None:
            raise


def validate_semantic_vm_frames(stage_out, stage, complete):
    """Read back all original actual owner buffers, with exact input preimages."""
    rows=[]
    if stage=='semantic-edge-vm':
        specifications=[('edge-256-reversed-origin',Path(stage_out),
            tuple(input_bytes(k) for k in ('edge-source','edge-output','edge-workspace')),False)]
    else:
        require(stage=='semantic-remaining-vm','unexpected standalone VM stage')
        specifications=[]
        native=OUTPUT/'semantic/evidence/full-buffer-replay-r1'
        for group,name in PLAN['original_semantic_six_order']:
            folder=Path(stage_out)/name
            if not folder.exists():
                continue
            prior=native/group/name
            values=tuple(read_regular(p)[0] for p in
                (prior/'INPUT.hepta',prior.parent/'OUTPUT-PREIMAGE.bin',prior.parent/'WORKSPACE-PREIMAGE.bin'))
            specifications.append((name,folder,values,name=='edge-256-reversed-origin'))
    pool=OUTPUT/'VM-buffer-pool'
    for name,folder,initial,reused in specifications:
        frames={}
        for label,value in zip(('source','output','workspace'),initial,strict=True):
            path=pool/pin(value)['sha256']
            if not path.exists():write(path,value)
            require(read_regular(path)[0]==value,'semantic VM preimage pool differs')
            frames[label+'.before']={'path':str(path),**pin(value)}
            after_path=folder/(label+'.bin')
            if after_path.exists():
                actual,mode,_=read_regular(after_path)
                require(len(actual)==len(value),'semantic actual owner extent differs')
                frames[label+'.after']={'path':str(after_path),**pin(actual,mode)}
        rows.append({'name':name,'exact_current_R8_edge_reused':reused,
            'before_observation':'exact bytes passed to the unchanged original _Owner initializers',
            'after_observation':'actual original _Owner.data writes in the original finally blocks',
            'frames':frames,'complete_six_buffers':len(frames)==6})
    dump(Path(stage_out)/'VM-SIX-BUFFER-READBACK.json',{'rows':rows,'calls_or_logical_rows':len(rows),
         'VM_reruns':0,'required_complete':complete})
    if complete:
        require(len(rows)==(1 if stage=='semantic-edge-vm' else 6)
                and all(r['complete_six_buffers'] for r in rows),'standalone VM frame denominator differs')
