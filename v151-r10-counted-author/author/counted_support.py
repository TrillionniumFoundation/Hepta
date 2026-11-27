"""Private guards for one actual R10 Counted observation; no project import."""
from pathlib import Path
import hashlib
import json
import os
import stat
import sys

STAT_KEYS = ('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_nlink')

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


def load_plan(expected):
    root=Path(__file__).absolute().parent
    raw,mode,stamp=read_regular(root/'EXECUTION-PLAN.json')
    plan=json.loads(raw)
    material=dict(plan); authority=material.pop('authorization_pin')
    require(pin((json.dumps(material,sort_keys=True,indent=2,allow_nan=False)+'\n').encode())['sha256']
            ==authority==expected,'plan authorization differs')
    require(plan['author_root']==str(root) and mode==0o644,'unexpected author root or plan mode')
    require(plan['output']=='/workspace/hia-r10-cross-counted-r1-dda7','fixed one-shot output differs')
    require(plan['budgets']=={'VM_steps':10000000,'VM_heap_bytes':1048576,
            'VM_call_depth':128,'qualification_seconds':180,'cleanup_seconds':3},'original budgets differ')
    return root,plan,{'identity':pin(raw,mode),'stat':stamp}


def open_output_parent(plan):
    """Hold and verify exactly / and /workspace; caller owns returned fd."""
    expected=plan['output_ancestors']
    require(set(expected)=={'/','/workspace'},'output ancestor set differs')
    keys=('st_dev','st_ino','st_mode')
    root_fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    parent_fd=None
    try:
        def check(path,descriptor):
            held=os.fstat(descriptor);named=Path(path).lstat()
            require(stat.S_ISDIR(held.st_mode) and stat.S_ISDIR(named.st_mode)
                and {k:getattr(held,k) for k in keys}==expected[path]
                and {k:getattr(named,k) for k in keys}==expected[path],
                'output ancestor identity differs: '+path)
        check('/',root_fd)
        parent_fd=os.open('workspace',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=root_fd)
        check('/workspace',parent_fd)
        named=os.stat('workspace',dir_fd=root_fd,follow_symlinks=False)
        require({k:getattr(named,k) for k in keys}==expected['/workspace'],
            'held root names a different workspace')
        check('/',root_fd)
        return parent_fd
    except BaseException:
        if parent_fd is not None:os.close(parent_fd)
        raise
    finally:
        os.close(root_fd)


def output_parent_snapshot(plan):
    descriptor=open_output_parent(plan)
    try:
        return {path:{k:getattr(Path(path).lstat(),k) for k in ('st_dev','st_ino','st_mode')}
                for path in ('/','/workspace')}
    finally:
        os.close(descriptor)


def fixed(plan,name):
    row=plan['fixed_inputs'][name]
    raw,mode,stamp=read_regular(row['path'])
    require(pin(raw,mode)==row['identity'] and stamp==row['author_stat'],'fixed input differs: '+name)
    return raw


def guards(root,plan,plan_state):
    require(sys.executable==plan['runtime']['executable']['path']
            and tuple(sys.version_info[:3])==(3,14,4),'actual fixed CPython 3.14.4 required')
    require(sys.flags.dont_write_bytecode==1 and sys.flags.optimize==0
            and sys.flags.isolated==0 and sys.flags.no_site==0,'original -B runtime flags differ')
    require(dict(os.environ)==plan['runtime']['environment'],'actual complete runtime environment differs')
    controls={}
    for name,row in plan['controls'].items():
        raw,mode,stamp=read_regular(root/name)
        require(pin(raw,mode)==row['identity'] and stamp==row['author_stat'],'control differs: '+name)
        controls[name]={'identity':pin(raw,mode),'stat':stamp}
    raw,mode,stamp=read_regular(root/'EXECUTION-PLAN.json')
    observed={'identity':pin(raw,mode),'stat':stamp}
    require(observed==plan_state,'consumed plan changed')
    controls['EXECUTION-PLAN.json']=observed
    inputs={}
    for name,row in plan['fixed_inputs'].items():
        raw,mode,stamp=read_regular(row['path'])
        require(pin(raw,mode)==row['identity'] and stamp==row['author_stat'],'fixed input differs: '+name)
        inputs[name]={'identity':pin(raw,mode),'stat':stamp}
    runtime={}
    for name in ('executable','library'):
        row=plan['runtime'][name]
        raw,mode,stamp=read_regular(row['path'])
        require(pin(raw,mode)==row['identity'] and stamp==row['author_stat'],'runtime differs: '+name)
        runtime[name]={'identity':pin(raw,mode),'stat':stamp}
    return {'controls':controls,'inputs':inputs,'runtime':runtime,
            'environment':dict(os.environ),'python_version':sys.version,
            'output_ancestors':output_parent_snapshot(plan)}


def source_snapshot(root,plan):
    raw,mode,_=read_regular(root/'FROZEN-3180-SOURCE.json')
    require(pin(raw,mode)==plan['controls']['FROZEN-3180-SOURCE.json']['identity'],'source map changed')
    expected=json.loads(raw)
    source=Path(plan['source']['path'])
    require(source.is_absolute() and stat.S_ISDIR(source.lstat().st_mode),'source root is not a real directory')
    files,states,dirs={},{},{}
    for directory,children,names in os.walk(source,followlinks=False):
        directory=Path(directory);children.sort()
        observed=directory.lstat()
        require(stat.S_ISDIR(observed.st_mode),'source directory is not real')
        dirs[directory.relative_to(source).as_posix()]={k:getattr(observed,k) for k in STAT_KEYS}
        for name in children:
            require(stat.S_ISDIR((directory/name).lstat().st_mode),'source directory symlink')
        for name in sorted(names):
            p=directory/name;relative=p.relative_to(source).as_posix()
            require(relative in expected,'unexpected source path: '+relative)
            content,file_mode,stamp=read_regular(p)
            files[relative],states[relative]=pin(content,file_mode),stamp
    require(len(files)==3180 and files==expected,'complete frozen3180 source differs')
    return {'files':files,'inode_states':states,'directory_states':dirs,'tree':plan['source']['tree']}


def owner_protocol(raw,returned):
    original=json.loads(raw)
    require(type(original)is dict and type(returned)is dict,'owner receipt must be a dict')
    require(type(returned.get('supervisor_returncode'))is int,'real supervisor exit missing')
    expected=dict(original,supervisor_returncode=returned['supervisor_returncode'],
                  receipt_sha256=pin(raw)['sha256'])
    if expected['supervisor_returncode']!=0 and original['status']=='OWNED_PROCESS_COMPLETED':
        expected['status']='OWNER_EXIT_MISMATCH_HOLD'
    require(returned==expected,'complete raw owner / wrapper return differs')
    return original


def clean_owner(returned,code):
    return (returned.get('status')==('OWNED_PROCESS_COMPLETED' if code==0 else 'QUALIFICATION_FAILED')
        and returned.get('returncode')==code and returned.get('supervisor_returncode')==code
        and returned.get('qualification_seconds')==180 and returned.get('cleanup_seconds')==3
        and returned.get('timed_out')is False and returned.get('exit_observed_before_deadline')is True
        and returned.get('qualification_started')is True
        and returned.get('cleanup',{}).get('complete')is True
        and returned.get('cleanup',{}).get('observed_echild')is True
        and returned.get('cleanup',{}).get('remaining_direct_children')==[])


def prior_authority(plan):
    """Fully read actual old Native and VM records; execute neither product."""
    program=fixed(plan,'R10-source');image=fixed(plan,'R10-image')
    require(image==fixed(plan,'R10-native-image'),'actual image copies differ')
    initial=tuple(fixed(plan,'initial-'+name) for name in ('source','output','workspace'))
    require(tuple(map(len,initial))==(19089,1048576,1048576),'original logical extents differ')
    require(initial[1]==bytes([0xa5])*1048576 and initial[2]==bytes(1048576),'original dirty/zero preimages differ')
    old=tuple(fixed(plan,'failed-'+name) for name in ('source','output','workspace'))
    capture=json.loads(fixed(plan,'failed-capture'))
    require(capture['image']==pin(image) and capture['input_sha256']==pin(initial[0])['sha256']
        and capture['output_initial_sha256']==pin(initial[1])['sha256']
        and capture['workspace_initial_sha256']==pin(initial[2])['sha256'],'old capture does not bind these inputs')
    observation_raw=fixed(plan,'native-observation');actual=json.loads(observation_raw)
    request_raw=fixed(plan,'native-request');request=json.loads(request_raw)
    child=json.loads(fixed(plan,'native-child'))
    require(capture['observation_sha256']==pin(observation_raw)['sha256'],'old capture observation differs')
    require(request['schema']=='hia.linux-stdio.native-request.v1' and request['mode']=='ordinary'
        and request['image']==plan['fixed_inputs']['R10-native-image']['path']
        and request['image_sha256']==pin(image)['sha256']
        and request['report']==plan['fixed_inputs']['native-child']['path'],'old Native request differs')
    require(child==actual['child'] and child['status']=='returned' and child['result_u64']==0
        and child['request_sha256']==pin(request_raw)['sha256']
        and child['image_sha256']==pin(image)['sha256'] and child['forbidden_modules_loaded']==[]
        and child['limits']==plan['original_native_limits'],'old Native child differs')
    require(actual['returncode']==0 and actual['timed_out']is False and actual['timeout_seconds']==20
        and actual['cleanup_seconds']==3 and actual['stdin_consumed']==0
        and actual['stdout_hex']==actual['stderr_hex']=='' and actual['canaries']==[True]*3
        and fixed(plan,'native-stdout')==fixed(plan,'native-stderr')==b'','old Native terminal/canaries/IO differ')
    require(len(request['buffers'])==3,'old physical span count differs')
    native=[]
    for name,before,row in zip(('source','output','workspace'),initial,request['buffers']):
        guard=b'\xd3'*64;physical=fixed(plan,'native-'+name)
        require(row=={'bytes':len(before)+128,'extent':len(before),
            'path':plan['fixed_inputs']['native-'+name]['path'],
            'sha256':pin(guard+before+guard)['sha256']},'old physical preimage request differs')
        value=bytes.fromhex(actual[name+'_hex'])
        require(len(value)==len(before) and len(physical)==len(before)+128
            and physical[:64]==physical[-64:]==guard and physical[64:-64]==value,
            'old full physical span/canary/observation differs: '+name)
        native.append(value)
    require(native[0]==initial[0] and native[1]==initial[1],'old Native input/output differ')
    replay=json.loads(fixed(plan,'native-group-report'))
    require(replay['status']=='PASS' and replay['count']==replay['actual_native_entries']==162
            and replay['failures']==[],'old Native162 did not complete')
    matches=[r for r in replay['rows'] if r['group']=='retained-semantic-r1' and r['name']=='root-v8-cross-target-loans']
    require(len(matches)==1 and matches[0]['pass']is True and all(matches[0]['checks'].values())
        and matches[0]['return']==0 and matches[0]['input_sha256']==pin(initial[0])['sha256'],
        'old Native cross-target row differs')
    for prefix,code in (('native',0),('failed',1)):
        returned=json.loads(fixed(plan,prefix+'-owner-returned'))
        owner_protocol(fixed(plan,prefix+'-owner'),returned)
        require(clean_owner(returned,code),'old owner incomplete: '+prefix)
        outer=json.loads(fixed(plan,prefix+'-outer'))
        require(outer['owner']==outer['terminal']==returned and outer['status']==('PASS' if code==0 else 'FAIL'),
                'old outer differs: '+prefix)
    state=json.loads(fixed(plan,'failed-state'));vm_report=json.loads(fixed(plan,'failed-vm-report'))
    require(state==plan['expected_failure'],'old failed machine state differs')
    require(vm_report['status']==state['status'] and vm_report['steps']==state['steps']
        and vm_report['values']==state['values'] and vm_report['error']=={k:state['error'][k] for k in ('code','message')},
        'old failed report differs')
    result=json.loads(fixed(plan,'failed-result'))
    group=json.loads(fixed(plan,'failed-group-report'))
    require(group['status']=='FAIL' and group['count']==6
        and group['failures']==['root-v8-cross-target-loans'] and result in group['rows']
        and result['pass']is False and result['VM_steps']==10000001
        and result['checks']==plan['expected_old_checks'],'old VM5P1F boundary differs')
    require(old[0]==initial[0] and old[1]==initial[1] and old[2]!=native[2]
            and old[2][1047040:]==initial[2][1047040:],'old partial buffers differ')
    symbols=json.loads(fixed(plan,'edge-symbols'))
    require(symbols['HIA_source_sha256']==pin(program)['sha256'] and symbols['image']==pin(image),
            'symbol record is not from this actual HIA/image')
    require(len(symbols['symbol_order'])==107 and set(symbols['symbol_order'])=={'f'+str(i) for i in range(107)},
            'symbol map denominator differs')
    return {'program':program,'image':image,'initial':initial,'failed':old,'native':tuple(native),
            'state':state,'vm_report':vm_report,'symbol_order':symbols['symbol_order'],
            'native_return':child['result_u64']}


