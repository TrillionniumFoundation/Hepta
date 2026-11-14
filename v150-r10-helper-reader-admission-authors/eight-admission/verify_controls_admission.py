from pathlib import Path
import ast,base64,copy,hashlib,json,os,stat,sys,time
AUTHOR=Path('/tmp/hia-r10-execution-author-r1-dda7')
PLAN_RAW=(AUTHOR/'PREFIX-PLAN.json').read_bytes()
PLAN=json.loads(PLAN_RAW)
SOURCE=Path(PLAN['source']['path'])
EXEC=Path('/tmp/hia-r10-controls-fresh-admission-r1-dda7')
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


OLD=Path('/tmp/hia-u32-r8-post-reset-r4-dda7')
NEW=Path('/tmp/hia-r10-controls-author-r1-dda7')
def bodies(raw):
    lines=raw.splitlines(keepends=True)
    return {n.name:b''.join(lines[n.lineno-1:n.end_lineno]) for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)}
def origin(row):
    return {'path':row['path'],'identity':row['identity'],'stat':dict(zip(FIELDS,row['seven_stats'],strict=True))}
def main():
    start=time.monotonic_ns()
    require(not os.path.lexists(EXEC),'fresh admission output exists')
    mkdir(EXEC)
    dump(EXEC/'INTENT.json',{'status':'ROOT_INDEPENDENT_R10_CONTROL_ADMISSION','products':0,'project_imports':0})
    raw,mode,stamp=read(NEW/'EXECUTION-PLAN.json')
    require(pin(raw,mode)=={'bytes': 664800, 'sha256': 'c14178c9cd0d7d3c5725a93ab43db28df933724fc01a1176f52fd77d28784838', 'git_blob': '64437dc3c669d41867c645128632481d386f89c4', 'mode': 420, 'git_mode': '100644'},'new plan pin')
    q=json.loads(raw);oldraw=read(OLD/'EXECUTION-PLAN.json')[0];old=json.loads(oldraw)
    original=identity(OLD/'EXECUTION-PLAN.json')
    inverse=json.loads(read(NEW/'R10-EXACT-INVERSE.json')[0])
    require(original==inverse['original_plan'],'original plan and seven stats')
    core=dict(q);auth=core.pop('authorization_pin')
    require(pin(encode(core))['sha256']==auth=='1b9079b8a38c6fcf1d97212a80af70013c6ddde770842a89a6c00b28a39660ff','authorization')
    allowed={'authorization_pin','controls','fixed_inputs','output','runtime'}
    require(set(q)==set(old)|{'R10_explicit_successor'},'plan key additions')
    require(all(q[k]==old[k] for k in set(old)-allowed),'old plan policies changed')
    oldruntime=copy.deepcopy(old['runtime']);oldruntime['environment']['HOME']=q['output']
    require(q['runtime']==oldruntime,'only runtime HOME path')
    require(len(old['fixed_inputs'])==948 and len(q['fixed_inputs'])==962,'fixed role counts')
    require(all(q['fixed_inputs'][k]==v for k,v in old['fixed_inputs'].items()),'old 948 roles changed')
    roles=q['R10_explicit_successor']['actual_candidate_roles']
    require(set(roles)==set(q['fixed_inputs'])-set(old['fixed_inputs']) and len(roles)==14,'explicit role additions')
    changes={row['path']:row for row in inverse['changed_existing_files']}
    require(len(changes)==10 and len(old['controls'])==63 and len(q['controls'])==67,'control counts')
    require(set(q['controls'])-set(old['controls'])=={'inputs/R10-GENERATOR.py','inputs/R10-OWNER.json','inputs/R10-RESULT.json','R10-EXACT-INVERSE.json'},'control additions')
    before_controls={};after_controls={};changed=[]
    for name,expected in old['controls'].items():
        b,m,s=read(OLD/name);require(pin(b,m)==expected,'old control pin: '+name)
        a,am,ss=read(NEW/name);require(pin(a,am)==q['controls'][name],'new control pin: '+name)
        before_controls[name]={'identity':pin(b,m),'seven_stats':s}
        after_controls[name]={'identity':pin(a,am),'seven_stats':ss}
        if a==b:require(name not in changes,'false changed row');continue
        changed.append(name);row=changes[name]
        require(base64.b64decode(row['before_base64'],validate=True)==b and base64.b64decode(row['after_base64'],validate=True)==a,'full inverse raw')
        require(row['before']==pin(b,m) and row['after']==pin(a,am),'inverse pins')
        if not row['explicit_fixture_JSON_projection']:
            reconstructed=b
            for replacement in row['literal_replacements']:
                x=replacement['before'].encode();y=replacement['after'].encode();count=replacement['count']
                require(reconstructed.count(x)==count,'unique replacement preimage')
                reconstructed=reconstructed.replace(x,y)
            require(reconstructed==a,'whole forward projection')
            reconstructed=a
            for replacement in reversed(row['literal_replacements']):
                x=replacement['before'].encode();y=replacement['after'].encode();count=replacement['count']
                require(reconstructed.count(y)==count,'unique replacement postimage')
                reconstructed=reconstructed.replace(y,x)
            require(reconstructed==b,'whole inverse')
    require(set(changed)==set(changes),'unexpected changed controls')
    for name in set(q['controls'])-set(old['controls']):
        b,m,s=read(NEW/name);require(pin(b,m)==q['controls'][name],'new control pin')
        after_controls[name]={'identity':pin(b,m),'seven_stats':s}
    source_function=bodies(read(NEW/'inputs/R10-GENERATOR.py')[0])['source_program']
    require(source_function==bodies(read(OLD/'inputs/R8-GENERATOR.py')[0])['source_program'],'symbol author source function differs')
    for name in ('_checked_components','execute_linux_file_roundtrip','execute_program'):
        require(bodies(read(OLD/'r8_private_reference.py')[0])[name]==bodies(read(NEW/'r8_private_reference.py')[0])[name],'private function differs')
    for name in ('semantic/authoring/support.py','aggregate/successor-r2/authoring/support.py','aggregate/successor-r3/authoring/support.py'):
        require(bodies(read(OLD/name)[0])==bodies(read(NEW/name)[0]),'support functions differ')
    for name in ('run_controls.py','ORACLE-RESTORE-PLAN.json'):
        require(read(OLD/name)[0]==read(NEW/name)[0],'driver/oracle changed')
    actual_roles={}
    for name,row in roles.items():
        b,s=fixed(row);require({k:v for k,v in q['fixed_inputs'][name].items() if k!='phases'}=={'path':row['path'],'identity':row['identity']},'role projection differs')
        actual_roles[name]={'identity':row['identity'],'seven_stats':s}
    actual=json.loads(fixed(roles['R10-result'])[0])
    require(actual['status']=='PASS_EXPLICIT_U32_SIZE_AND_PRIVATE_PACK_ONLY','actual size-pack status')
    report=json.loads(read(OLD/'fixtures/REPORT.json')[0])
    report['build']['executable']=q['output']+'/aggregate/successor-r2/evidence/build-r2/built/private-R8.elf'
    report['build']['elf_inspection']=actual['elf_inspection'];report['image']=actual['image']
    report['images']['semantic']={k:actual['image'][k] for k in ('bytes','sha256')}
    report['input_sha256']=roles['R10-source']['identity']['sha256'];report['origin']=origin(roles['R10-result'])
    report['status_meaning']='fixed input projection of actual completed R10 generation/size/pack only; no semantic result'
    require(encode(report)==read(NEW/'fixtures/REPORT.json')[0],'actual size report fixture projection')
    outer=json.loads(read(OLD/'fixtures/OUTER.json')[0]);newouter=json.loads(read(NEW/'fixtures/OUTER.json')[0])
    allowed_outer={'actual_outer','actual_owner','status_meaning'}
    require(set(outer)==set(newouter) and all(outer[k]==newouter[k] for k in set(outer)-allowed_outer),'outer fixture extraneous change')
    require(newouter['actual_outer']==origin(roles['R10-outer']) and newouter['actual_owner']==origin(roles['R10-owner']),'outer actual descriptor differs')
    proof=json.loads(fixed(roles['R10-root-proof'])[0])
    require(proof['status']=='PASS_INDEPENDENT_R10_PREFIX_TERMINAL_ONLY','Root prefix terminal status')
    before=controls_guard()
    fresh=snapshot(EXEC/'FULL-FRESH-6777.json')
    observed={};role_bytes=0
    for name,row in q['fixed_inputs'].items():
        b,m,s=read(row['path']);p=pin(b,m)
        require(all(p[k]==v for k,v in row['identity'].items()),'full fixed-role bytes/mode: '+name)
        observed[name]={'identity':p,'seven_stats':s};role_bytes+=len(b)
    dump(EXEC/'ALL-962-FULL-ROLES.json',{'roles':observed,'reference_count':len(observed),'reference_bytes':role_bytes})
    require(controls_guard()==before,'prefix controls changed')
    for name,row in after_controls.items():
        require(identity(NEW/name)=={'path':str(NEW/name),**row},'new control changed')
    require(read(NEW/'EXECUTION-PLAN.json')==(raw,mode,stamp),'plan changed')
    launch=identity(NEW/'PRODUCT-LAUNCH.json');l=json.loads(fixed(launch)[0])
    require(l['plan']=={'path':str(NEW/'EXECUTION-PLAN.json'),'identity':pin(raw,mode),'seven_stats':stamp},'launch binding')
    require(l['outer_seconds']==1800 and l['outer_cleanup_seconds']==3 and l['each_product_owner_seconds']==180 and l['each_cleanup_seconds']==3 and l['no_stage_retries'] is True,'owner budget')
    require(l['argv'][-2:]==['--plan-sha256',auth] and l['argv'][-3]==str(NEW/'run_controls.py'),'actual command')
    require(l['output']==q['output'] and not os.path.lexists(q['output']) and not os.path.lexists(l['outer_root']),'product outputs exist')
    fs=os.statvfs(Path(q['output']).parent);free=fs.f_bavail*fs.f_frsize
    require(free>=q['minimum_free_bytes']==3221225472,'original floor')
    result={'schema':'hia.root.R10.eight-groups.independent-admission.v1','status':'PASS_FULL_FRESH_R10_EIGHT_GROUP_ADMISSION_ONLY','plan':identity(NEW/'EXECUTION-PLAN.json'),'launch':launch,'controls':after_controls,'prefix_controls':before,'old948_roles_exact':True,'all962_full_roles':True,'full_original_domain_files':fresh['files'],'full_original_domain_bytes':fresh['bytes'],'original_seven_scripts_inverse_exact':True,'old_R4_failure_retained':True,'changed_control_count':10,'new_controls':67,'new_candidate_roles':actual_roles,'eight_phases_unchanged':True,'original_budgets_unchanged':True,'free_bytes_at_admission':free,'products':0,'project_imports':0,'whole_native':False,'elapsed_ns':time.monotonic_ns()-start}
    dump(EXEC/'RESULT.json',result)
    print(json.dumps({'status':result['status'],'result':identity(EXEC/'RESULT.json'),'files':fresh['files'],'old_roles':948,'new_roles':14,'products':0},sort_keys=True))
if __name__=='__main__':main()
