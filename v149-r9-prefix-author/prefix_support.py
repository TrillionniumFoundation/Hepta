"""R9 prefix metadata guards. No project module is imported by this file."""
from pathlib import Path
import base64, hashlib, json, os, platform, stat, sys, zlib

AUTHOR=Path(__file__).resolve().parent
PLAN_RAW=(AUTHOR/'PREFIX-PLAN.json').read_bytes()
PLAN=json.loads(PLAN_RAW)
EXEC=Path(PLAN['execution_root'])
SOURCE=Path(PLAN['source']['path'])
FIELDS=('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')

def require(value, message):
    if not value: raise ValueError(message)

def encode(value):
    return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()

def pin(raw,mode=None):
    result={'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
    if mode is not None: result.update(mode=mode,git_mode='100755' if mode&0o111 else '100644')
    return result

def seven(s):
    return [getattr(s,k) for k in FIELDS]

def read(path):
    path=Path(path)
    for parent in reversed(path.parents):
        require(stat.S_ISDIR(parent.lstat().st_mode),'input ancestor is not a real directory')
    before=path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink==1,'input is not an independent regular file')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        require(seven(os.fstat(fd))==seven(before),'opened input changed')
        chunks=[];left=before.st_size+1
        while left:
            part=os.read(fd,min(left,1048576))
            if not part: break
            chunks.append(part);left-=len(part)
        raw=b''.join(chunks)
        require(len(raw)==before.st_size and seven(os.fstat(fd))==seven(before)==seven(path.lstat()),'input changed while reading')
    finally: os.close(fd)
    return raw,stat.S_IMODE(before.st_mode),seven(before)

def identity(path):
    raw,mode,stamp=read(path)
    return {'identity':pin(raw,mode),'seven_stats':stamp,'path':str(path)}

def fixed(row):
    raw,mode,stamp=read(row['path'])
    require(pin(raw,mode)==row['identity'],'fixed bytes or mode differ: '+row['path'])
    if 'seven_stats' in row: require(stamp==row['seven_stats'],'fixed seven-stat identity differs')
    return raw,stamp

def mkdir(path):
    path=Path(path)
    require(path.is_absolute() and EXEC in (path,*path.parents),'output is outside explicit execution root')
    chain=list(reversed(path.parents))+[path]
    for q in chain:
        try:s=q.lstat()
        except FileNotFoundError:
            require(q==EXEC or EXEC in q.parents,'cannot create outside execution root')
            q.mkdir(mode=0o700);s=q.lstat()
        require(stat.S_ISDIR(s.st_mode),'output ancestor is not a real directory')

def write(path,raw,mode=0o644):
    path=Path(path);mkdir(path.parent)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    path.chmod(mode)
    actual,m,_=read(path)
    require(actual==raw and m==mode,'new output readback differs')

def dump(path,value):
    write(path,encode(value))

def runtime_guard():
    expected=PLAN['runtime']
    require(sys.version_info[:3]==(3,14,4) and sys.executable==expected['executable']['path'],'wrong actual interpreter')
    require(sys.flags.isolated==sys.flags.ignore_environment==sys.flags.no_site==sys.flags.dont_write_bytecode==1,'runtime flags differ')
    require(dict(os.environ)==PLAN['environment'] and 'LD_PRELOAD' not in os.environ,'fixed runtime environment differs')
    require(platform.system()=='Linux' and platform.machine().lower() in ('x86_64','amd64'),'wrong machine')
    for name in ('executable','library'): fixed(expected[name])
    return {'executable':sys.executable,'version':sys.version,'environment':dict(os.environ)}

def controls_guard():
    observed={}
    for name,row in PLAN['fixed_controls'].items():
        _,stamp=fixed(row);observed[name]={'identity':row['identity'],'seven_stats':stamp}
    for name,row in PLAN['author_files'].items():
        raw,mode,stamp=read(AUTHOR/name)
        require(pin(raw,mode)==row,'author control differs: '+name)
        observed['author:'+name]={'identity':row,'seven_stats':stamp}
    require(read(AUTHOR/'PREFIX-PLAN.json')[0]==PLAN_RAW,'prefix plan changed')
    return observed

def snapshot(path,names=None):
    raw,_=fixed(PLAN['fresh_mapping'])
    mapping=json.loads(raw);groups=[];total=0;count=0
    for group in mapping['groups']:
        if names is not None and group['name'] not in names: continue
        root=Path(group['root']);files={};directories={}
        for here,children,leaves in os.walk(root,followlinks=False):
            here=Path(here);s=here.lstat();rel=here.relative_to(root).as_posix()
            require(stat.S_ISDIR(s.st_mode) and rel in group['directories'],'unexpected directory')
            before=group['directories'][rel]
            require(stat.S_IMODE(s.st_mode)==before['mode'] and seven(s)==before['seven_stats'],'directory changed')
            directories[rel]={'mode':stat.S_IMODE(s.st_mode),'seven_stats':seven(s)}
            for child in children:require(stat.S_ISDIR((here/child).lstat().st_mode),'directory alias')
            for name in sorted(leaves):
                p=here/name;relative=p.relative_to(root).as_posix()
                require(relative in group['files'],'unexpected fixed path')
                row=group['files'][relative];b,mode,stamp=read(p)
                require(pin(b,mode)==row['identity'] and stamp==row['seven_stats'],'fresh fixed payload differs: '+relative)
                files[relative]={'identity':pin(b,mode),'seven_stats':stamp}
                total+=len(b);count+=1
        require(set(files)==set(group['files']) and directories==group['directories'],'complete group pathset differs')
        groups.append({'name':group['name'],'root':str(root),'files':files,'directories':directories})
    if names is None:
        extras=[]
        for row in mapping['extra_authorities']:
            b,stamp=fixed(row);extras.append({'path':row['path'],'identity':row['identity'],'seven_stats':stamp})
            total+=len(b);count+=1
        require(count==6777 and total==948620735,'complete old fresh domain differs')
    else:
        extras=[];require(set(names)=={'source','runtime'} and count==5676 and total==206668287,'full source/runtime denominator differs')
    result={'groups':groups,'extra_authorities':extras,'files':count,'bytes':total}
    dump(path,result);return result

def complete_owner(owner):
    require(owner.get('status')=='OWNED_PROCESS_COMPLETED' and owner.get('returncode')==0 and owner.get('supervisor_returncode')==0
        and owner.get('qualification_seconds')==180 and owner.get('cleanup_seconds')==3 and owner.get('timed_out')is False
        and owner.get('exit_observed_before_deadline')is True and owner.get('cleanup',{}).get('complete')is True
        and owner.get('cleanup',{}).get('observed_echild')is True,'owner did not complete original budget/cleanup')

def owner_record(receipt_path,returned):
    raw=read(receipt_path)[0];expected=json.loads(raw)
    expected.update(supervisor_returncode=returned.get('supervisor_returncode'),receipt_sha256=pin(raw)['sha256'])
    if expected['supervisor_returncode']!=0 and expected['status']=='OWNED_PROCESS_COMPLETED':expected['status']='OWNER_EXIT_MISMATCH_HOLD'
    require(expected==returned,'actual owner receipt differs from returned record')

def capsule():
    raw,_=fixed(PLAN['size_author_capsule']);wrapper=json.loads(raw)
    packed=base64.b64decode(wrapper['data'],validate=True)
    require(pin(packed)==wrapper['compressed'],'original capsule compressed pin differs')
    decoder=zlib.decompressobj();data=decoder.decompress(packed,wrapper['decoded']['bytes']+1)
    require(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail and pin(data)==wrapper['decoded'],'original capsule full decode differs')
    value=json.loads(data);rows={}
    for row in value['files']:
        name=row['path'];require(name not in rows and not Path(name).is_absolute() and '..' not in Path(name).parts,'unsafe/duplicate capsule member')
        b=base64.b64decode(row['data_base64'],validate=True)
        require(pin(b,row['identity']['mode'])==row['identity'],'complete original capsule member differs')
        rows[name]=(b,row['identity'])
    require(len(rows)==70,'original complete author capsule denominator differs')
    return rows

def generation_admission():
    generated=EXEC/'generated/file_render_checker_word64.hepta'
    source,mode,stamp=read(generated)
    first=read(EXEC/'generation/generate/report.json')[0]
    second=read(EXEC/'generation/check/report.json')[0]
    require(first==second,'original generator/check reports differ')
    report=json.loads(first);g=report['generated'];p=g['word64_projection']
    require(set(g)=={'functions','blocks','ops','word64_projection'} and {k:g[k] for k in ('functions','blocks','ops')}=={'functions':107,'blocks':1456,'ops':6347},'actual new Core counts differ')
    require(p['original_counts']=={'functions':107,'blocks':1456,'ops':6664} and p['after_counts']=={'functions':107,'blocks':1456,'ops':6347}
        and len(p['removed_identity_casts'])==317 and p['fixed_word_bits']==64 and p['whole_inverse_equal']is True
        and p['all_other_operations_kept_in_order']is True and p['complete_original_Core_verifier_returned']is True
        and p['external_f0_unchanged']is True and p['public_compiler_or_VM_changed']is False and p['machine_size_or_fuel_PASS_claim']is False,'actual exact Core projection differs')
    require(len(source)==report['source_bytes'] and pin(source)['sha256']==report['source_sha256'] and 0<len(source)<=1048576 and mode==0o644,'generated HIA extent/pin differs')
    files={'source':identity(generated),'generate_report':identity(EXEC/'generation/generate/report.json'),'check_report':identity(EXEC/'generation/check/report.json')}
    for stage in ('generate','check'):
        folder=EXEC/'generation'/stage
        owner=json.loads(read(folder/'OWNER-RETURNED.json')[0]);owner_record(folder/'OWNER.json',owner);complete_owner(owner)
        result=json.loads(read(folder/'RESULT.json')[0]);require(result['status']=='PASS_ORIGINAL_R9_GENERATOR_STAGE' and result['stage']==stage and result['finalization_errors']==[] and result['frozen_source_runtime_equal']is True,'generation stage did not close')
        require(result['generated_source']['identity']==pin(source,mode) and result['generated_source']['seven_stats']==stamp,'generated source changed between owners')
        files[stage+'_result']=identity(folder/'RESULT.json');files[stage+'_owner_returned']=identity(folder/'OWNER-RETURNED.json')
    return {'schema':'hia.R9.actual-generated-candidate-binding.v1','generation_calls':1,'check_calls':1,'old_SOURCE_rebound':False,'old_source_tree':PLAN['source']['tree'],'files':files}

def generation_binding_guard(binding):
    require(binding['schema']=='hia.R9.actual-generated-candidate-binding.v1','generated binding schema differs')
    observed={}
    for name,row in binding['files'].items():
        _,stamp=fixed(row)
        observed[name]={'identity':row['identity'],'seven_stats':stamp,'path':row['path']}
    require(observed==binding['files'],'complete generated binding changed')
    return {'schema':binding['schema'],'files':observed,'actual_complete_readback':True}
